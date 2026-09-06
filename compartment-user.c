/*
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 * SPDX-License-Identifier: Apache-2.0
 *
 * compartment-user — userspace process isolation without root
 *
 * Applies kernel-enforced sandboxing before exec'ing a command:
 *   1. PR_SET_NO_NEW_PRIVS  — prevent privilege escalation
 *   2. Landlock              — filesystem path restrictions
 *   3. seccomp BPF           — syscall deny-list
 *   4. Environment sanitize  — strip dangerous env vars
 *
 * All mechanisms are kernel-enforced, inherited by children,
 * and cannot be removed once applied. Works on static binaries too
 * (unlike LD_PRELOAD).
 *
 * Usage:
 *   compartment-user [options] -- command [args...]
 *   compartment-user --profile ai-agent -- claude --model claude-opus-4-6
 *   compartment-user --ro /usr --rw /tmp --block ptrace -- codex --full-auto
 *
 * Designed as the rootless equivalent of chroot_wrp.c.
 * Combine with sandbox.sh for network namespace isolation.
 *
 * Requirements: Linux >= 5.13 (Landlock), >= 3.17 (seccomp BPF)
 * No dependencies: no libseccomp, no libcap, no external libs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <getopt.h>
#include <libgen.h>
#include <syslog.h>
#include <sys/utsname.h>

#include <sys/statfs.h>
#include <sys/resource.h>

/* Shared types, config, syscall table, profile loader, Landlock ruleset
 * builder, audit, env sanitize, seccomp BPF builder — all static inline. */
#include "compartment.h"

#define TOOL "compartment-user"

/* ── AI agent profile ────────────────────────────────────────────────
 * Default paths and blocked syscalls for running AI CLI agents. */

/* Location label used by the fail-closed policy-append helpers. */
#define BUILTIN_WHERE "built-in profile"
#define CLI_WHERE     "command line"

static int apply_profile_ai_agent(Config *cfg)
{
    /* Filesystem: read-only system paths.
     *
     * '/lib32?' is optional: it is absent on most 64-bit installs, and a
     * rule for a path that does not exist is a fatal error by default. */
    const char *ro_paths[] = {
        "/usr", "/lib", "/lib64", "/lib32?",
        "/etc", "/bin", "/sbin",
        "/proc", "/dev", "/sys",
        "/run",     /* resolv.conf, systemd, dbus */
        "/var/lib", /* dpkg, apt, node modules */
        NULL
    };
    for (int i = 0; ro_paths[i]; i++) {
        if (cfg_add_path(cfg, BUILTIN_WHERE, ro_paths[i], PATH_RO, 0) != 0)
            return -1;
    }

    /* Filesystem: read-write for working dirs */
    const char *rw_paths[] = {"/tmp", NULL};
    for (int i = 0; rw_paths[i]; i++) {
        if (cfg_add_path(cfg, BUILTIN_WHERE, rw_paths[i], PATH_RW, 0) != 0)
            return -1;
    }

    /* Add HOME and workdir as RWX (agents write AND execute scripts) */
    const char *home = getenv("HOME");
    if (home) {
        const char *why = NULL;
        if (!home_dir_usable(home, &why)) {
            fprintf(stderr, "compartment-user: refusing to use HOME=%s as a "
                    "sandbox root: %s\n", home, why);
            fprintf(stderr, "  Set HOME to your own home directory, or use "
                    "--profile none with explicit --ro/--rw rules.\n");
            return -1;
        }
        if (cfg_add_path(cfg, BUILTIN_WHERE, home, PATH_RWX, 0) != 0)
            return -1;
    }
    if (cfg->workdir &&
        cfg_add_path(cfg, BUILTIN_WHERE, cfg->workdir, PATH_RWX, 0) != 0)
        return -1;

    /* Syscalls to block — the table shared with compartment-root. */
    if (cfg_add_builtin_denylist(cfg, BUILTIN_WHERE) != 0)
        return -1;

    /* Dangerous env vars to strip.
     *
     * A trailing '*' is a prefix match, which is what keeps this list
     * honest: "LD_*" covers LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH,
     * LD_DEBUG, LD_PROFILE, LD_ORIGIN_PATH and whatever the loader grows
     * next, instead of naming three of them and missing the rest.
     *
     * Deliberately NOT stripped: the *_API_KEY variables an agent
     * authenticates its model provider with. compartment-user exists to
     * run those agents; removing the credential they need in order to
     * start would make the tool useless for its main job. See the
     * credential note in HOWTO.md — if an agent must not see a key, do
     * not export it into the agent's environment. */
    const char *deny_env[] = {
        /* Dynamic linker and libc behaviour */
        "LD_*",                             /* whole ld.so family */
        "GLIBC_TUNABLES",                   /* CVE-2023-4911 vector */
        "GCONV_PATH",                       /* glibc iconv arbitrary .so load */
        "HOSTALIASES",                      /* hostname resolution hijack */
        "LOCPATH", "NLSPATH",               /* locale/message catalog injection */
        "DYLD_*",                           /* macOS loader family */
        "_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS",
        /* Cloud credentials — prevent ambient credential leakage */
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
        /* VCS / CI tokens */
        "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "NPM_TOKEN",
        /* Shell startup and behaviour hijack */
        "BASH_ENV", "ENV",                  /* sourced by non-interactive bash/sh */
        "BASH_FUNC_*",                      /* exported shell functions */
        "PROMPT_COMMAND",                   /* runs on every bash prompt */
        "IFS",                              /* word-splitting hijack */
        "ZDOTDIR",                          /* zsh startup file location */
        "CDPATH", "GLOBIGNORE",
        /* Interpreter startup injection */
        "NODE_OPTIONS",                     /* Node.js flag injection */
        "PYTHON*",                          /* PYTHONPATH/HOME/STARTUP/... */
        "PERL5*", "PERLLIB",                /* Perl arbitrary code load */
        "RUBYOPT", "RUBYLIB",               /* Ruby arbitrary code load */
        /* git: each of these names a program git will execute */
        "GIT_SSH_COMMAND", "GIT_CONFIG_*", "GIT_EDITOR",
        "GIT_EXEC_PATH", "GIT_TEMPLATE_DIR",
        /* Programs launched by other programs (git, man, sudoedit, ...) */
        "PAGER", "MANPAGER", "EDITOR", "VISUAL",
        /* SSH agent — prevents key use via forwarded socket */
        "SSH_AUTH_SOCK",
        /* Database credentials */
        "DATABASE_URL", "PGPASSWORD", "MYSQL_PWD",
        NULL
    };
    for (int i = 0; deny_env[i]; i++) {
        if (cfg_add_env_deny(cfg, BUILTIN_WHERE, deny_env[i], 0) != 0)
            return -1;
    }
    return 0;
}

/* ── Strict profile: minimal access ─────────────────────────────── */

static int apply_profile_strict(Config *cfg)
{
    if (apply_profile_ai_agent(cfg) != 0)  /* start with ai-agent base */
        return -1;

    /* Also block: personality, lookup_dcookie, nfsservctl, quotactl */
    const char *extra[] = {
        "personality", "lookup_dcookie", "vhangup", "quotactl",
        "mbind", "move_pages",
        NULL
    };
    for (int i = 0; extra[i]; i++) {
        int nr = resolve_syscall(extra[i]);
        if (nr >= 0 && cfg_add_blocked(cfg, BUILTIN_WHERE, extra[i], nr) != 0)
            return -1;
    }
    return 0;
}

/* ── CLI ─────────────────────────────────────────────────────────── */

static void print_usage(void)
{
    fprintf(stderr,
        "compartment-user — userspace process isolation (no root required)\n"
        "\n"
        "Usage: compartment-user [OPTIONS] -- COMMAND [ARGS...]\n"
        "\n"
        "Profiles:\n"
        "  --profile ai-agent    Claude/Codex/Gemini CLI agents (default)\n"
        "  --profile strict      Minimal access (ai-agent + extra blocks)\n"
        "  --profile none        No defaults, only explicit rules\n"
        "  --profile FILE.conf   Load profile from file\n"
        "  --profile NAME        Search /etc/compartment/NAME.conf\n"
        "  --dump-profile NAME   Print the effective profile as .conf and exit\n"
        "  --user-profiles       Also search ~/.config/compartment/NAME.conf\n"
        "                        (off by default: the sandboxed process can\n"
        "                        usually write there)\n"
        "\n"
        "Filesystem (Landlock):\n"
        "  --ro PATH             Read-only + execute access\n"
        "                        (append '?' to skip the rule when the path\n"
        "                        does not exist: --ro /lib32?)\n"
        "  --rw PATH             Read-write access (no execute — W^X)\n"
        "  --exec PATH           Read + execute access (a rule naming a FILE\n"
        "                        is a per-binary execute grant)\n"
        "  --workdir PATH        Working directory (added as --rw)\n"
        "  --no-landlock         Disable Landlock\n"
        "\n"
        "Network (Landlock, ABI v4+ / Linux 6.7+, TCP only):\n"
        "  --net-bind PORT       Allow bind(2) on this TCP port (repeatable)\n"
        "  --net-connect PORT    Allow connect(2) to this TCP port (repeatable)\n"
        "  --net-deny            Handle TCP bind and connect; deny every port\n"
        "                        not named above.  Without any of these three\n"
        "                        the network is not restricted at all.\n"
        "\n"
        "Syscalls (seccomp BPF):\n"
        "  --block SYSCALL       Block a syscall (by name)\n"
        "  --allow SYSCALL       Switch to allow-list mode and permit SYSCALL\n"
        "                        (everything not listed then fails with EPERM)\n"
        "  --no-seccomp          Disable seccomp\n"
        "\n"
        "Environment:\n"
        "  --env-deny VAR        Strip environment variable (VAR or PREFIX*)\n"
        "  --env-allow VAR       Switch to allow-list mode and keep VAR\n"
        "                        (everything not listed is then stripped)\n"
        "  --no-env-sanitize     Don't strip dangerous env vars\n"
        "\n"
        "General:\n"
        "  --dry-run             Show what would be applied, don't enforce\n"
        "  --verbose             Print actions to stderr\n"
        "  --audit               Log events to stderr + file\n"
        "  --audit-log DIR       Set audit log directory (implies --audit)\n"
        "                        Default: /var/lib/compartment/audit/$UID if an\n"
        "                        admin provisioned it, else\n"
        "                        /var/tmp/compartment-audit-$UID\n"
        "                        (root: /var/log/compartment)\n"
        "  --insecure            Allow execution when enforcement is degraded\n"
        "                        (missing Landlock, unsupported filesystem, etc.)\n"
        "  --verify              Check system support and exit\n"
        "  --version             Print the version and exit\n"
        "  --help                This help\n"
        "\n"
        "Examples:\n"
        "  compartment-user -- claude --model claude-opus-4-6\n"
        "  compartment-user --profile strict -- codex --full-auto\n"
        "  compartment-user --rw /data --block ptrace -- ./my-agent\n"
        "  compartment-user --no-landlock --block ptrace -- bash\n"
        "\n"
        "Combine with sandbox.sh for full isolation:\n"
        "  sandbox.sh compartment-user -- claude\n"
    );
}

/* ── Pre-flight check: run before exec to detect degraded environments ── */

/* Known filesystem type magic numbers */
#define V9P_MAGIC      0x01021997
#define NFS_MAGIC      0x6969
#define FUSE_MAGIC     0x65735546
#define CIFS_MAGIC     0xFF534D42
#define TMPFS_MAGIC    0x01021994
#define OVERLAYFS_MAGIC 0x794C7630

static const char *fs_type_name(unsigned long magic)
{
    switch (magic) {
    case V9P_MAGIC:       return "9p (virtme-ng/QEMU — Landlock cannot enforce)";
    case NFS_MAGIC:       return "NFS (Landlock cannot enforce)";
    case FUSE_MAGIC:      return "FUSE (Landlock may not enforce)";
    case CIFS_MAGIC:      return "CIFS/SMB (Landlock cannot enforce)";
    case OVERLAYFS_MAGIC: return "overlayfs";
    case TMPFS_MAGIC:     return "tmpfs";
    default:              return NULL;
    }
}

static int fs_landlock_unsupported(unsigned long magic)
{
    return magic == V9P_MAGIC || magic == NFS_MAGIC ||
           magic == CIFS_MAGIC || magic == FUSE_MAGIC;
}

/* statfs on 9p can report the underlying fs type (e.g. ext4), so also
 * check /proc/mounts for the actual filesystem driver on a given path. */
static int check_proc_mounts_for_unsupported(const char *path)
{
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) return 0;

    char line[4096];   /* /proc/mounts lines can be long (NFS/overlay options) */
    char best_fstype[64] = "";
    size_t best_len = 0;

    while (fgets(line, sizeof(line), f)) {
        char dev[256], mount[256], fstype[64];
        if (sscanf(line, "%255s %255s %63s", dev, mount, fstype) < 3)
            continue;
        size_t mlen = strlen(mount);
        if (strncmp(path, mount, mlen) == 0 &&
            (path[mlen] == '/' || path[mlen] == '\0' || mlen == 1)) {
            if (mlen > best_len) {
                best_len = mlen;
                snprintf(best_fstype, sizeof(best_fstype), "%s", fstype);
            }
        }
    }
    fclose(f);

    if (best_fstype[0]) {
        if (strcmp(best_fstype, "9p") == 0 ||
            strcmp(best_fstype, "nfs") == 0 ||
            strcmp(best_fstype, "nfs4") == 0 ||
            strcmp(best_fstype, "cifs") == 0 ||
            strcmp(best_fstype, "fuse") == 0 ||
            strncmp(best_fstype, "fuse.", 5) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * preflight_check — validate that the enforcement mechanisms requested
 * in cfg will actually work on this system.  Returns 0 if all checks
 * pass, >0 count of failures.  Prints warnings to stderr.
 *
 * Called automatically before exec.  If any check fails and
 * --unsecure is NOT set, we abort with a clear message.
 */
static int preflight_check(Config *cfg)
{
    int warnings = 0;

    /* 1. PR_SET_NO_NEW_PRIVS — check availability without setting it.
     * PR_GET_NO_NEW_PRIVS returns 0 (not set) or 1 (already set).
     * Returns -1/EINVAL on kernels that don't support it. */
    if (cfg->use_no_new_privs) {
        long nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
        if (nnp < 0) {
            fprintf(stderr, "compartment-user: WARNING: PR_SET_NO_NEW_PRIVS "
                    "not available (%s)\n", strerror(errno));
            warnings++;
        }
    }

    /* 2. Landlock availability */
    if (cfg->use_landlock) {
        int abi = syscall(__NR_landlock_create_ruleset, NULL, 0,
                          LANDLOCK_CREATE_RULESET_VERSION);
        if (abi < 0) {
            fprintf(stderr, "compartment-user: WARNING: Landlock not available "
                    "(%s)\n", strerror(errno));
            fprintf(stderr, "  Filesystem restrictions will NOT be enforced.\n");
            fprintf(stderr, "  Run: compartment-user --verify\n");
            warnings++;
        } else {
            if (abi < 2)
                fprintf(stderr, "compartment-user: NOTE: Landlock ABI v%d "
                        "(cross-dir rename/link not restricted)\n", abi);

            /* 3. Check filesystem types of configured paths
             * Use both statfs and /proc/mounts (9p proxies underlying type) */
            for (int i = 0; i < cfg->path_count; i++) {
                struct statfs sfs;
                if (statfs(cfg->paths[i].path, &sfs) == 0 &&
                    fs_landlock_unsupported((unsigned long)sfs.f_type)) {
                    const char *fsname = fs_type_name((unsigned long)sfs.f_type);
                    fprintf(stderr, "compartment-user: WARNING: %s is on %s\n",
                            cfg->paths[i].path, fsname);
                    warnings++;
                } else if (check_proc_mounts_for_unsupported(
                               cfg->paths[i].path)) {
                    fprintf(stderr, "compartment-user: WARNING: %s is on a "
                            "virtual/network fs — Landlock cannot enforce\n",
                            cfg->paths[i].path);
                    warnings++;
                }
            }

            /* Check root filesystem — both statfs magic and /proc/mounts */
            struct statfs root_sfs;
            if (statfs("/", &root_sfs) == 0 &&
                fs_landlock_unsupported((unsigned long)root_sfs.f_type)) {
                const char *fsname = fs_type_name((unsigned long)root_sfs.f_type);
                fprintf(stderr, "compartment-user: WARNING: root filesystem "
                        "is %s — Landlock filesystem isolation will NOT work.\n",
                        fsname);
                warnings++;
            } else if (check_proc_mounts_for_unsupported("/")) {
                /* 9p can proxy the underlying fs type in statfs, so also
                 * check /proc/mounts for the actual driver */
                fprintf(stderr, "compartment-user: WARNING: root filesystem "
                        "is a network/virtual fs (per /proc/mounts) — "
                        "Landlock filesystem isolation will NOT work.\n");
                warnings++;
            }
        }
    }

    /* 4. seccomp BPF availability */
    if (cfg->use_seccomp) {
        /* Quick check: can we set seccomp mode? We already set no_new_privs
         * if needed, so just check the prctl is accepted. Use a no-op
         * filter that allows everything. */
        errno = 0;
        long sec = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
        if (sec < 0 && errno == EINVAL) {
            fprintf(stderr, "compartment-user: WARNING: seccomp not available "
                    "(%s)\n", strerror(errno));
            fprintf(stderr, "  Syscall restrictions will NOT be enforced.\n");
            warnings++;
        }
    }

    return warnings;
}

static int print_verify(void)
{
    int failures = 0;

    printf("=== Compartment System Verification ===\n\n");

    /* Kernel */
    printf("Kernel: ");
    struct utsname uts;
    if (uname(&uts) == 0)
        printf("%s\n", uts.release);
    else {
        printf("unknown (%s)\n", strerror(errno));
        failures++;
    }

    /* PR_SET_NO_NEW_PRIVS */
    printf("PR_SET_NO_NEW_PRIVS: ");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0)
        printf("OK\n");
    else {
        printf("FAILED (%s)\n", strerror(errno));
        failures++;
    }

    /* Landlock */
    printf("Landlock: ");
    int abi = syscall(__NR_landlock_create_ruleset, NULL, 0,
                      LANDLOCK_CREATE_RULESET_VERSION);
    if (abi >= 0)
        printf("OK (ABI v%d)\n", abi);
    else {
        printf("NOT AVAILABLE (%s)\n", strerror(errno));
        failures++;
    }

    /* seccomp */
    printf("seccomp BPF: ");
    struct sock_filter allow_all[] = {
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = sizeof(allow_all) / sizeof(allow_all[0]),
        .filter = allow_all,
    };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0)
        printf("OK\n");
    else {
        printf("FAILED (%s)\n", strerror(errno));
        failures++;
    }

    /* Root filesystem type */
    printf("Root filesystem: ");
    struct statfs root_sfs;
    int root_fs_bad = 0;
    if (statfs("/", &root_sfs) == 0) {
        const char *fsname = fs_type_name((unsigned long)root_sfs.f_type);
        if (fsname) {
            printf("%s\n", fsname);
            if (fs_landlock_unsupported((unsigned long)root_sfs.f_type))
                root_fs_bad = 1;
        } else if (check_proc_mounts_for_unsupported("/")) {
            printf("virtual/network (statfs=0x%lx, /proc/mounts disagrees)\n",
                   (unsigned long)root_sfs.f_type);
            root_fs_bad = 1;
        } else {
            printf("local (0x%lx)\n", (unsigned long)root_sfs.f_type);
        }
        if (root_fs_bad) {
            printf("  ^^^ Landlock CANNOT enforce on this filesystem.\n");
            printf("  ^^^ Use a real disk (ext4/btrfs/xfs) for filesystem isolation.\n");
            failures++;
        }
    } else {
        printf("unknown (%s)\n", strerror(errno));
    }

    /* Architecture */
    printf("Architecture: ");
#if defined(__x86_64__)
    printf("x86_64\n");
#elif defined(__aarch64__)
    printf("aarch64\n");
#elif defined(__riscv)
    printf("riscv64\n");
#elif defined(__s390x__)
    printf("s390x\n");
#elif defined(__powerpc64__)
    printf("ppc64le\n");
#elif defined(__loongarch__)
    printf("loongarch64\n");
#else
    printf("unknown\n");
#endif

    /* Syscall table */
    int count = 0;
    for (int i = 0; syscall_table[i].name; i++) count++;
    printf("Syscall table: %d entries\n", count);

    /* Network warning */
    printf("Network: NOT RESTRICTED (use sandbox.sh for network isolation)\n");

    if (failures > 0)
        printf("\n=== VERIFICATION FAILED (%d check%s) ===\n",
               failures, failures > 1 ? "s" : "");
    else
        printf("\n=== All checks passed ===\n");

    return failures > 0 ? 1 : 0;
}

#ifndef REAL_SHELL_DIR
#define REAL_SHELL_DIR "/bin/shells"
#endif

/* ── Profile dump (--dump-profile) ───────────────────────────────── */

static const char *syscall_name(int nr)
{
    for (int i = 0; syscall_table[i].name; i++)
        if (syscall_table[i].nr == nr)
            return syscall_table[i].name;
    return NULL;
}

/* Serialise the resolved policy back to .conf syntax on stdout, so
 * documentation and shipped examples can be generated from the binary
 * instead of being transcribed by hand and going stale. */
static void dump_profile(const Config *cfg)
{
    printf("# Generated by: compartment-user --dump-profile %s\n",
           cfg->profile);
    printf("# Source: %s\n#\n",
           cfg->profile_source ? cfg->profile_source : "built-in");

    printf("# Filesystem (Landlock)\n");
    for (int i = 0; i < cfg->path_count; i++) {
        static const char *modes[] = { "ro", "rw", "exec", "rwx" };
        printf("%s %s%s\n", modes[cfg->paths[i].mode], cfg->paths[i].path,
               cfg->paths[i].optional ? "?" : "");
    }
    if (cfg->net_bind_count || cfg->net_connect_count || cfg->net_default_deny) {
        printf("\n# Network (Landlock TCP ports)\n");
        for (int i = 0; i < cfg->net_bind_count; i++)
            printf("net-bind %d\n", cfg->net_bind_ports[i]);
        for (int i = 0; i < cfg->net_connect_count; i++)
            printf("net-connect %d\n", cfg->net_connect_ports[i]);
        if (cfg->net_default_deny)
            printf("net-default deny\n");
    }
    if (cfg->workdir)
        printf("\nworkdir %s\n", cfg->workdir);

    if (cfg->seccomp_default != SECCOMP_DEFAULT_ERRNO)
        printf("\nseccomp-default %s\n", seccomp_action_name(cfg));
    if (cfg->seccomp_allow_mode) {
        printf("\n# Syscall allow-list (seccomp)\nseccomp-mode allow\n");
        for (int i = 0; i < cfg->allowed_sc_count; i++) {
            const char *n = syscall_name(cfg->allowed_syscalls[i]);
            if (n) printf("allow %s\n", n);
            else   printf("# allow <unnamed syscall %d>\n",
                          cfg->allowed_syscalls[i]);
        }
    } else {
        printf("\n# Syscall deny-list (seccomp)\n");
        for (int i = 0; i < cfg->blocked_count; i++) {
            const char *n = syscall_name(cfg->blocked_syscalls[i]);
            if (n) printf("block %s\n", n);
            else   printf("# block <unnamed syscall %d>\n",
                          cfg->blocked_syscalls[i]);
        }
    }

    if (cfg->env_allow_mode) {
        printf("\n# Environment allow-list ('*' suffix = prefix match)\n"
               "env-mode allow\n");
        for (int i = 0; i < cfg->env_allow_count; i++)
            printf("env-allow %s\n", cfg->env_allow[i]);
    } else {
        printf("\n# Environment deny-list ('*' suffix = prefix match)\n");
        for (int i = 0; i < cfg->env_deny_count; i++)
            printf("env-deny %s\n", cfg->env_deny[i]);
    }

    printf("\n# Features (a profile may only turn these on)\n");
    printf("landlock on\nseccomp on\nno-new-privs on\nenv-sanitize on\n");
    if (cfg->audit)
        printf("audit on\n");
    if (cfg->audit_log_dir)
        printf("audit-log %s\n", cfg->audit_log_dir);
}

/* ── Hardening applied on every path, just before exec ───────────── */

static void apply_hardening(void)
{
    /* Clear ambient capabilities — prevents inherited caps from parent */
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

    /* Disable coredumps — prevents pipe core_pattern bypass and
     * also restricts /proc/self access from other same-UID processes */
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    /* Close inherited file descriptors — Landlock only restricts new
     * open() calls, not already-open fds leaked from the parent.
     * close_range() available since Linux 5.9, glibc 2.34. */
    if (close_range(3, ~0U, 0) != 0) {
        /* Fallback for older kernels — use rlimit to find upper bound */
        struct rlimit rl;
        int max_fd = 4096;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < (rlim_t)max_fd)
            max_fd = (int)rl.rlim_cur;
        for (int cfd = 3; cfd < max_fd; cfd++) close(cfd);
    }
}

/* ── COMPARTMENT_SHELL_DIR validation ────────────────────────────── */

/* The env var comes from the caller — in a login-shell deployment, from
 * the very user being confined — and it decides which binary the "shell"
 * actually is. The 'hardened' Makefile target randomises REAL_SHELL_DIR
 * precisely so that path is unguessable; an unchecked override defeats
 * that. Honour it only when the directory and the shell binary inside it
 * are owned by root or by the caller and are not group- or
 * world-writable. Anything else is a warning and a fall back to the
 * compile-time REAL_SHELL_DIR — never a refusal, because this code path
 * must not be able to lock a user out of their account.
 *
 * The sandbox is applied before the exec either way. */
static int shell_dir_acceptable(const char *dir, const char *shell_name)
{
    if (dir[0] != '/') {
        fprintf(stderr, "compartment-user: ignoring COMPARTMENT_SHELL_DIR "
                "'%s': must be absolute\n", dir);
        return 0;
    }
    for (const char *p = dir; *p; p++) {
        if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0') &&
            (p == dir || p[-1] == '/')) {
            fprintf(stderr, "compartment-user: ignoring COMPARTMENT_SHELL_DIR "
                    "'%s': contains '..'\n", dir);
            return 0;
        }
    }

    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) {
        fprintf(stderr, "compartment-user: ignoring COMPARTMENT_SHELL_DIR "
                "'%s': %s\n", dir, strerror(errno));
        return 0;
    }
    /* Same ownership and write rules as a profile file: root or the real
     * uid, nothing group- or world-writable. */
    int ok = profile_fd_trusted(dfd, 0, S_IFDIR, "shell directory", dir) == 0;
    if (ok) {
        /* O_PATH: we only need to stat it, and an execute-only shell
         * binary would not be readable. */
        int sfd = openat(dfd, shell_name, O_PATH | O_CLOEXEC);
        if (sfd < 0) {
            fprintf(stderr, "compartment-user: ignoring COMPARTMENT_SHELL_DIR "
                    "'%s': %s/%s: %s\n", dir, dir, shell_name, strerror(errno));
            ok = 0;
        } else {
            ok = profile_fd_trusted(sfd, 0, S_IFREG, "shell binary",
                                    shell_name) == 0;
            close(sfd);
        }
    }
    close(dfd);
    if (!ok)
        fprintf(stderr, "compartment-user: falling back to %s\n",
                REAL_SHELL_DIR);
    return ok;
}

int main(int argc, char *argv[])
{
    /*
     * Shell-replacement mode: if invoked via symlink (argv[0] is not
     * "compartment-user"), apply sandbox and exec the real shell from
     * REAL_SHELL_DIR.  This lets compartment-user replace /bin/bash etc.
     *
     *   ln -s /usr/local/bin/compartment-user /bin/bash
     *   # real shell lives at /bin/shells/bash
     */
    char *invoked_name = basename(argv[0]);
    if (strcmp(invoked_name, "compartment-user") != 0) {
        const char *shell_dir = getenv("COMPARTMENT_SHELL_DIR");
        if (shell_dir && !shell_dir_acceptable(shell_dir, invoked_name))
            shell_dir = NULL;
        if (!shell_dir) shell_dir = REAL_SHELL_DIR;

        char real_shell[PATH_MAX];
        int rsn = snprintf(real_shell, sizeof(real_shell), "%s/%s",
                           shell_dir, invoked_name);
        if (rsn < 0 || (size_t)rsn >= sizeof(real_shell)) {
            fprintf(stderr, "compartment-user: shell path too long\n");
            return 126;
        }

        /* Apply ai-agent profile sandbox, then exec real shell.
         *
         * IMPORTANT: Shell-replacement mode must NEVER block login.
         * If enforcement fails, log to syslog and continue unsecured.
         * Blocking /bin/bash would lock out the user — worse than
         * running unsandboxed. */
        Config shell_cfg = {
            .use_landlock     = 1,
            .use_seccomp      = 1,
            .use_no_new_privs = 1,
            .use_env_sanitize = 1,
            .audit_log_fd     = -1,
            .profile          = "ai-agent",
        };
        /* Try profile file first, fall back to built-in.
         *
         * A rejected profile falls back to the built-in rather than
         * aborting: shell-replacement mode must never lock the user out,
         * and the built-in ai-agent policy is strictly tighter than the
         * unconfined shell that refusing to run would leave behind. The
         * transactional loader guarantees the rejected file contributed
         * nothing. */
        /* Flags 0: shell-replacement mode reads /etc/compartment only.
         * $HOME belongs to the very user being confined. */
        int shell_pr = resolve_and_load_profile(&shell_cfg, "ai-agent", 0, 0);
        if (shell_pr == PROFILE_ERROR)
            syslog(LOG_WARNING, "compartment-user[%s]: ai-agent profile was "
                   "rejected — falling back to the built-in policy",
                   invoked_name);
        if (shell_pr != PROFILE_OK)
            (void)apply_profile_ai_agent(&shell_cfg);

        int shell_degraded = 0;

        /* Same preflight as the normal path, but advisory: a degraded
         * environment must not stop a login. */
        {
            int pf = preflight_check(&shell_cfg);
            if (pf > 0) {
                syslog(LOG_WARNING, "compartment-user[%s]: %d preflight "
                       "check%s failed — enforcement may be degraded",
                       invoked_name, pf, pf > 1 ? "s" : "");
                shell_degraded += pf;
            }
        }

        if (shell_cfg.use_no_new_privs) {
            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
                syslog(LOG_WARNING, "compartment-user[%s]: "
                       "PR_SET_NO_NEW_PRIVS failed: %s — running unsecured",
                       invoked_name, strerror(errno));
                shell_degraded++;
            }
        }
        if (shell_cfg.use_env_sanitize)
            sanitize_env(&shell_cfg);
        if (shell_cfg.use_landlock) {
            if (apply_landlock(&shell_cfg, TOOL) != 0) {
                syslog(LOG_WARNING, "compartment-user[%s]: "
                       "Landlock failed — running without filesystem restriction",
                       invoked_name);
                shell_degraded++;
            }
        }
        if (shell_cfg.use_seccomp) {
            if (apply_seccomp(&shell_cfg) != 0) {
                syslog(LOG_WARNING, "compartment-user[%s]: "
                       "seccomp failed — running without syscall restriction",
                       invoked_name);
                shell_degraded++;
            }
        }
        if (shell_degraded > 0) {
            syslog(LOG_WARNING, "compartment-user[%s]: INSECURE shell session "
                   "(%d mechanism%s failed) uid=%d pid=%d ppid=%d",
                   invoked_name, shell_degraded,
                   shell_degraded > 1 ? "s" : "",
                   getuid(), getpid(), getppid());
        }

        /* Same ambient-cap clear, PR_SET_DUMPABLE(0) and fd cleanup the
         * normal path performs — these were omissions, not choices. */
        apply_hardening();

        execv(real_shell, argv);
        fprintf(stderr, "compartment-user: exec %s: %s\n",
                real_shell, strerror(errno));
        return 127;
    }

    Config cfg = {
        .use_landlock     = 1,
        .use_seccomp      = 1,
        .use_no_new_privs = 1,
        .use_env_sanitize = 1,
        .audit_log_fd     = -1,
        .profile          = "ai-agent",
    };

    static struct option long_opts[] = {
        {"profile",         required_argument, NULL, 'P'},
        {"ro",              required_argument, NULL, 'r'},
        {"rw",              required_argument, NULL, 'w'},
        {"exec",            required_argument, NULL, 'x'},
        {"workdir",         required_argument, NULL, 'W'},
        {"block",           required_argument, NULL, 'b'},
        {"allow",           required_argument, NULL, 'l'},
        {"env-deny",        required_argument, NULL, 'E'},
        {"env-allow",       required_argument, NULL, 'e'},
        {"no-landlock",     no_argument,       NULL, 'L'},
        {"no-seccomp",      no_argument,       NULL, 'S'},
        {"no-env-sanitize", no_argument,       NULL, 'N'},
        {"dry-run",         no_argument,       NULL, 'd'},
        {"verbose",         no_argument,       NULL, 'v'},
        {"audit",           no_argument,       NULL, 'a'},
        {"audit-log",       required_argument, NULL, 'A'},
        {"insecure",        no_argument,       NULL, 'U'},
        {"unsecure",        no_argument,       NULL, 'U'},  /* alias */
        {"verify",          no_argument,       NULL, 'V'},
        {"net-bind",        required_argument, NULL, 4},
        {"net-connect",     required_argument, NULL, 5},
        {"net-deny",        no_argument,       NULL, 6},
        {"user-profiles",   no_argument,       NULL, 2},
        {"dump-profile",    required_argument, NULL, 3},
        {"version",         no_argument,       NULL, 1},
        {"help",            no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    /* Profile resolution: system profiles only unless --user-profiles is
     * given. $HOME is writable by the process we are confining. */
    unsigned profile_flags = 0;
    int dump = 0;

    int opt;
    while ((opt = getopt_long(argc, argv, "+P:r:w:x:W:b:l:E:e:A:LSNdvaUVh",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'P': cfg.profile = optarg; break;
        case 'r': /* --ro */
            if (cfg_add_path(&cfg, CLI_WHERE, optarg, PATH_RO, 0) != 0)
                return 1;
            break;
        case 'w': /* --rw */
            if (cfg_add_path(&cfg, CLI_WHERE, optarg, PATH_RW, 0) != 0)
                return 1;
            break;
        case 'x': /* --exec */
            if (cfg_add_path(&cfg, CLI_WHERE, optarg, PATH_EXEC, 0) != 0)
                return 1;
            break;
        case 'W': cfg.workdir = optarg; break;
        case 'b': { /* --block */
            int nr = resolve_syscall(optarg);
            if (nr < 0) {
                fprintf(stderr, "compartment-user: unknown syscall: %s\n", optarg);
                fprintf(stderr, "Known syscalls:");
                for (int i = 0; syscall_table[i].name; i++)
                    fprintf(stderr, " %s", syscall_table[i].name);
                fprintf(stderr, "\n");
                return 1;
            }
            if (cfg_add_blocked(&cfg, CLI_WHERE, optarg, nr) != 0)
                return 1;
            break;
        }
        case 'l': { /* --allow (syscall allowlist) */
            int nr = resolve_syscall(optarg);
            if (nr < 0) {
                fprintf(stderr, "compartment-user: unknown syscall: %s\n", optarg);
                return 1;
            }
            if (cfg_add_allowed(&cfg, CLI_WHERE, optarg, nr) != 0)
                return 1;
            break;
        }
        case 'E': /* --env-deny */
            if (cfg_add_env_deny(&cfg, CLI_WHERE, optarg, 0) != 0)
                return 1;
            break;
        case 'e': /* --env-allow */
            if (cfg_add_env_allow(&cfg, CLI_WHERE, optarg, 0) != 0)
                return 1;
            cfg.use_env_sanitize = 1;
            break;
        case 'L': cfg.use_landlock = 0; break;
        case 'S': cfg.use_seccomp = 0; break;
        case 'N': cfg.use_env_sanitize = 0; break;
        case 'd': cfg.dry_run = 1; cfg.verbose = 1; break;
        case 'v': cfg.verbose = 1; break;
        case 'a': cfg.audit = 1; break;
        case 'A': cfg.audit_log_dir = optarg; cfg.audit = 1; break;
        case 'U': cfg.allow_insecure = 1; break;
        case 'V': return print_verify();
        case  4 : /* --net-bind */
            if (cfg_add_net_port(CLI_WHERE, "net-bind", optarg,
                                 cfg.net_bind_ports, &cfg.net_bind_count) != 0)
                return 1;
            break;
        case  5 : /* --net-connect */
            if (cfg_add_net_port(CLI_WHERE, "net-connect", optarg,
                                 cfg.net_connect_ports,
                                 &cfg.net_connect_count) != 0)
                return 1;
            break;
        case  6 : cfg.net_default_deny = 1; break;
        case  2 : profile_flags |= PROFILE_SEARCH_USER; break;
        case  3 : cfg.profile = optarg; dump = 1; break;
        case  1 : printf("compartment-user %s\n", COMPARTMENT_VERSION); return 0;
        case 'h': print_usage(); return 0;
        default:  print_usage(); return 1;
        }
    }

    if (optind >= argc && !dump) {
        fprintf(stderr, "compartment-user: no command specified\n");
        print_usage();
        return 1;
    }

    /* Track which flags were explicitly disabled via CLI, so profile
     * loading cannot silently re-enable them. */
    int cli_disabled_landlock     = (cfg.use_landlock == 0);
    int cli_disabled_seccomp      = (cfg.use_seccomp == 0);
    int cli_disabled_env_sanitize = (cfg.use_env_sanitize == 0);

    /* Apply profile: try file first, then fall back to built-in.
     *
     * A profile that exists but does not parse is fatal: falling back to
     * the built-in would run a policy the operator never asked for, and
     * report it as "(built-in)" while the rejected file's already-parsed
     * rules were still in force. */
    if (strcmp(cfg.profile, "none") != 0) {
        int pr = resolve_and_load_profile(&cfg, cfg.profile, 0, profile_flags);
        if (pr == PROFILE_ERROR) {
            fprintf(stderr, "compartment-user: profile '%s' was rejected — "
                    "refusing to run\n", cfg.profile);
            return 1;
        }
        if (pr == PROFILE_NOT_FOUND) {
            if (strcmp(cfg.profile, "ai-agent") == 0) {
                if (apply_profile_ai_agent(&cfg) != 0) return 1;
                cfg.profile_source = "built-in";
            } else if (strcmp(cfg.profile, "strict") == 0) {
                if (apply_profile_strict(&cfg) != 0) return 1;
                cfg.profile_source = "built-in";
            } else {
                fprintf(stderr, "compartment-user: unknown profile: %s\n",
                        cfg.profile);
                profile_print_search_path(stderr, cfg.profile, profile_flags);
                return 1;
            }
        }
    }

    if (cfg.verbose)
        fprintf(stderr, "compartment-user: profile %s (%s)\n", cfg.profile,
                cfg.profile_source ? cfg.profile_source : "built-in");

    /* CLI --no-* flags always win over profile — if the user explicitly
     * disabled a mechanism on the command line, the profile cannot
     * silently re-enable it. */
    if (cli_disabled_landlock)     cfg.use_landlock = 0;
    if (cli_disabled_seccomp)      cfg.use_seccomp = 0;
    if (cli_disabled_env_sanitize) cfg.use_env_sanitize = 0;

    /* workdir implies rw — the user expects to write there.
     * The ai-agent built-in does this already; this ensures file-loaded
     * profiles get the same behavior. Skip if already in the path list. */
    if (cfg.workdir) {
        int already = 0;
        for (int i = 0; i < cfg.path_count; i++) {
            if (cfg.paths[i].mode == PATH_RW &&
                strcmp(cfg.paths[i].path, cfg.workdir) == 0) {
                already = 1;
                break;
            }
        }
        if (!already &&
            cfg_add_path(&cfg, CLI_WHERE, cfg.workdir, PATH_RW, 0) != 0)
            return 1;
    }

    /* ── Reject a policy Landlock cannot express (M9) ───────────── */
    if (cfg.use_landlock && config_check_additive(&cfg, TOOL) != 0)
        return 1;

    /* ── Dump the resolved policy as .conf and exit ─────────────── */
    if (dump) {
        dump_profile(&cfg);
        return 0;
    }

    /* ── Dry run: show config and exit ──────────────────────────── */
    if (cfg.dry_run) {
        fprintf(stderr, "compartment-user: DRY RUN — would apply:\n");
        fprintf(stderr, "  profile: %s (%s)\n", cfg.profile,
                cfg.profile_source ? cfg.profile_source : "built-in");
        fprintf(stderr, "  no_new_privs: %s\n",
                cfg.use_no_new_privs ? "yes" : "no");
        fprintf(stderr, "  landlock: %s (%d path rules)\n",
                cfg.use_landlock ? "yes" : "no", cfg.path_count);
        for (int i = 0; i < cfg.path_count; i++) {
            struct stat pst;
            const char *note = "";
            if (stat(cfg.paths[i].path, &pst) != 0)
                note = cfg.paths[i].optional ? "   (absent — optional, skipped)"
                                             : "   (ABSENT — this run would fail)";
            fprintf(stderr, "    %s %s%s%s\n",
                    cfg.paths[i].mode == PATH_RO ? "ro" :
                    cfg.paths[i].mode == PATH_RW ? "rw" :
                    cfg.paths[i].mode == PATH_EXEC ? "exec" : "rwx",
                    cfg.paths[i].path,
                    cfg.paths[i].optional ? "?" : "", note);
        }
        {
            int abi = landlock_abi();
            int nrules = cfg.net_bind_count + cfg.net_connect_count;
            if (nrules > 0 || cfg.net_default_deny) {
                fprintf(stderr, "  landlock net: %s (%d TCP port rule%s)\n",
                        (abi >= 4) ? "yes" : "NOT SUPPORTED on this kernel",
                        nrules, nrules == 1 ? "" : "s");
                for (int i = 0; i < cfg.net_bind_count; i++)
                    fprintf(stderr, "    net-bind %d\n", cfg.net_bind_ports[i]);
                for (int i = 0; i < cfg.net_connect_count; i++)
                    fprintf(stderr, "    net-connect %d\n",
                            cfg.net_connect_ports[i]);
                if (cfg.net_default_deny)
                    fprintf(stderr, "    net-default deny\n");
            }
        }
        fprintf(stderr, "  seccomp-default: %s\n", seccomp_action_name(&cfg));
        if (cfg.seccomp_allow_mode) {
            fprintf(stderr, "  seccomp: %s ALLOW-LIST (%d allowed, rest denied)\n",
                    cfg.use_seccomp ? "yes" : "no", cfg.allowed_sc_count);
        } else {
            fprintf(stderr, "  seccomp: %s DENY-LIST (%d blocked)\n",
                    cfg.use_seccomp ? "yes" : "no", cfg.blocked_count);
            for (int i = 0; i < cfg.blocked_count; i++) {
                const char *name = syscall_name(cfg.blocked_syscalls[i]);
                fprintf(stderr, "    block %s (%d)\n", name ? name : "?",
                        cfg.blocked_syscalls[i]);
            }
        }
        if (cfg.env_allow_mode) {
            fprintf(stderr, "  env: ALLOW-LIST (%d kept, rest stripped)\n",
                    cfg.env_allow_count);
        } else {
            fprintf(stderr, "  env: DENY-LIST (%d stripped)\n",
                    cfg.env_deny_count);
        }
        if (cfg.audit) {
            char defdir[PATH_MAX - 32];
            fprintf(stderr, "  audit: yes (log: %s)\n",
                    cfg.audit_log_dir ? cfg.audit_log_dir :
                    (audit_default_dir(defdir, sizeof(defdir)) == 0
                         ? defdir : "(none)"));
        }
        fprintf(stderr, "  command: %s\n", argv[optind]);
        return 0;
    }

    /* ── Audit (open log file BEFORE Landlock — fd survives) ──── */
    if (cfg.audit) {
        /* Fatal: auditing was explicitly requested. Continuing without a
         * durable record — or worse, with the record redirected through a
         * symlink someone else controls — is not a degraded mode worth
         * having. */
        if (audit_log_open(&cfg) != 0) {
            fprintf(stderr, "compartment-user: audit logging was requested "
                    "but could not be set up safely — refusing to run\n");
            return 1;
        }

        char detail[512];
        snprintf(detail, sizeof(detail), "command=%s profile=%s source=%s "
                 "landlock=%d seccomp=%d paths=%d blocked=%d",
                 argv[optind], cfg.profile,
                 cfg.profile_source ? cfg.profile_source : "built-in",
                 cfg.use_landlock, cfg.use_seccomp,
                 cfg.path_count, cfg.blocked_count);
        audit_log(&cfg, "COMPARTMENT_START", detail);
    }

    /* ── 0. Pre-flight check ─────────────────────────────────────── */
    int pf_warnings = preflight_check(&cfg);
    if (pf_warnings > 0 && !cfg.allow_insecure) {
        fprintf(stderr, "\ncompartment-user: REFUSING to execute — %d preflight "
                "check%s failed.\n", pf_warnings, pf_warnings > 1 ? "s" : "");
        fprintf(stderr, "  Options:\n");
        fprintf(stderr, "    --insecure      Run anyway with degraded enforcement\n");
        fprintf(stderr, "    --no-landlock   Disable Landlock (if filesystem unsupported)\n");
        fprintf(stderr, "    --verify        Show full system capabilities\n");
        return 1;
    }
    if (pf_warnings > 0 && cfg.allow_insecure) {
        fprintf(stderr, "compartment-user: INSECURE mode — running with %d "
                "degraded check%s\n", pf_warnings, pf_warnings > 1 ? "s" : "");
        if (cfg.audit) {
            char detail[256];
            snprintf(detail, sizeof(detail),
                     "INSECURE_MODE warnings=%d", pf_warnings);
            audit_log(&cfg, "COMPARTMENT_DEGRADED", detail);
        }
    }

    /* ── 1. PR_SET_NO_NEW_PRIVS (must be before seccomp) ───────── */
    if (cfg.use_no_new_privs) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            fprintf(stderr, "compartment-user: PR_SET_NO_NEW_PRIVS: %s\n",
                    strerror(errno));
            return 1;
        }
        if (cfg.verbose)
            fprintf(stderr, "compartment-user: no_new_privs set\n");
    }

    /* ── 2. Environment sanitize ───────────────────────────────── */
    if (cfg.use_env_sanitize)
        sanitize_env(&cfg);

    /* ── 3. Landlock (filesystem) ──────────────────────────────── */
    if (cfg.use_landlock) {
        if (apply_landlock(&cfg, TOOL) != 0) {
            fprintf(stderr, "compartment-user: Landlock failed — aborting. "
                    "Use --no-landlock to run without filesystem restriction.\n");
            return 1;
        }
    }

    /* ── 4. seccomp BPF (syscalls) ─────────────────────────────── */
    if (cfg.use_seccomp) {
        if (apply_seccomp(&cfg) != 0) {
            fprintf(stderr, "compartment-user: seccomp failed (%s). "
                    "Use --no-seccomp to run without syscall restriction.\n",
                    strerror(errno));
            return 1;
        }
    }

    /* ── 5. Change working directory ───────────────────────────── */
    if (cfg.workdir) {
        if (chdir(cfg.workdir) != 0) {
            fprintf(stderr, "compartment-user: chdir %s: %s\n",
                    cfg.workdir, strerror(errno));
            return 1;
        }
    }

    /* ── 6. Hardening (defense in depth) ─────────────────────── */
    apply_hardening();

    /* ── 7. exec ───────────────────────────────────────────────── */
    if (cfg.verbose)
        fprintf(stderr, "compartment-user: exec %s\n", argv[optind]);

    execvp(argv[optind], &argv[optind]);
    fprintf(stderr, "compartment-user: exec %s: %s\n",
            argv[optind], strerror(errno));
    return 127;
}
