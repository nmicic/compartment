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

#include <linux/landlock.h>
#include <sys/statfs.h>

/* Fallback defines for older kernel headers (pre-5.19 / pre-6.2) */
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER       (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE    (1ULL << 14)
#endif

/* Shared types, config, syscall table, profile loader, audit,
 * env sanitize, seccomp BPF builder — all static inline. */
#include "compartment.h"

/* ── Landlock syscall wrappers ───────────────────────────────────────── */

/* Landlock syscall numbers are architecture-independent (444-446)
 * since Linux 5.13. Provide fallback if kernel headers are too old. */
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule       445
#define __NR_landlock_restrict_self  446
#endif

/* ── AI agent profile ────────────────────────────────────────────────
 * Default paths and blocked syscalls for running Claude/Codex/etc. */

static void apply_profile_ai_agent(Config *cfg)
{
    /* Filesystem: read-only system paths */
    const char *ro_paths[] = {
        "/usr", "/lib", "/lib64", "/lib32",
        "/etc", "/bin", "/sbin",
        "/proc", "/dev", "/sys",
        "/run",     /* resolv.conf, systemd, dbus */
        "/var/lib", /* dpkg, apt, node modules */
        NULL
    };
    for (int i = 0; ro_paths[i]; i++) {
        if (cfg->path_count < MAX_PATHS) {
            cfg->paths[cfg->path_count].path = ro_paths[i];
            cfg->paths[cfg->path_count].mode = PATH_RO;
            cfg->path_count++;
        }
    }

    /* Filesystem: read-write for working dirs */
    const char *rw_paths[] = {"/tmp", NULL};
    for (int i = 0; rw_paths[i]; i++) {
        if (cfg->path_count < MAX_PATHS) {
            cfg->paths[cfg->path_count].path = rw_paths[i];
            cfg->paths[cfg->path_count].mode = PATH_RW;
            cfg->path_count++;
        }
    }

    /* Add HOME and workdir as RW */
    const char *home = getenv("HOME");
    if (home && cfg->path_count < MAX_PATHS) {
        cfg->paths[cfg->path_count].path = home;
        cfg->paths[cfg->path_count].mode = PATH_RW;
        cfg->path_count++;
    }
    if (cfg->workdir && cfg->path_count < MAX_PATHS) {
        cfg->paths[cfg->path_count].path = cfg->workdir;
        cfg->paths[cfg->path_count].mode = PATH_RW;
        cfg->path_count++;
    }

    /* Syscalls to block */
    const char *blocked[] = {
        "ptrace", "mount", "umount2", "reboot",
        "kexec_load", "kexec_file_load",
        "init_module", "finit_module", "delete_module",
        "pivot_root", "chroot", "unshare", "setns",
        "keyctl", "add_key", "request_key",
        "bpf", "userfaultfd", "perf_event_open",
        "process_vm_readv", "process_vm_writev",
        "acct", "swapon", "swapoff",
        "settimeofday", "clock_settime", "clock_adjtime", "adjtimex",
        "io_uring_setup", "io_uring_enter", "io_uring_register",
        /* Container escape vectors: handle-based file access, new mount API */
        "open_by_handle_at", "name_to_handle_at",
        "open_tree", "move_mount", "fsopen", "fsmount", "fsconfig", "fspick",
        "mount_setattr",
        /* Cross-process FD theft */
        "pidfd_getfd",
#ifdef __x86_64__
        "ioperm", "iopl",
#endif
        NULL
    };
    for (int i = 0; blocked[i]; i++) {
        int nr = resolve_syscall(blocked[i]);
        if (nr >= 0 && cfg->blocked_count < MAX_BLOCKED_SC)
            cfg->blocked_syscalls[cfg->blocked_count++] = nr;
    }

    /* Dangerous env vars to strip */
    const char *deny_env[] = {
        /* Dynamic linker injection */
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
        "GCONV_PATH",                       /* glibc iconv arbitrary .so load */
        "HOSTALIASES",                      /* hostname resolution hijack */
        "LOCPATH", "NLSPATH",               /* locale/message catalog injection */
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
        "_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS",
        /* Cloud credentials — prevent ambient credential leakage */
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
        /* VCS / CI tokens */
        "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "NPM_TOKEN",
        /* Interpreter startup injection */
        "BASH_ENV", "ENV",                  /* sourced by non-interactive bash/sh */
        "NODE_OPTIONS",                     /* Node.js flag injection */
        "PYTHONSTARTUP",                    /* Python startup code injection */
        "PERL5OPT", "PERL5LIB",            /* Perl arbitrary code load */
        "RUBYOPT", "RUBYLIB",              /* Ruby arbitrary code load */
        "CDPATH", "GLOBIGNORE",             /* shell behavior hijack */
        /* SSH agent — prevents key use via forwarded socket */
        "SSH_AUTH_SOCK",
        /* Database credentials */
        "DATABASE_URL", "PGPASSWORD", "MYSQL_PWD",
        NULL
    };
    for (int i = 0; deny_env[i]; i++) {
        if (cfg->env_deny_count < MAX_ENV_VARS)
            cfg->env_deny[cfg->env_deny_count++] = deny_env[i];
    }
}

/* ── Strict profile: minimal access ─────────────────────────────── */

static void apply_profile_strict(Config *cfg)
{
    apply_profile_ai_agent(cfg);  /* start with ai-agent base */

    /* Also block: personality, lookup_dcookie, nfsservctl, quotactl */
    const char *extra[] = {
        "personality", "lookup_dcookie", "vhangup", "quotactl",
        "mbind", "move_pages",
        NULL
    };
    for (int i = 0; extra[i]; i++) {
        int nr = resolve_syscall(extra[i]);
        if (nr >= 0 && cfg->blocked_count < MAX_BLOCKED_SC)
            cfg->blocked_syscalls[cfg->blocked_count++] = nr;
    }
}

/* ── Landlock enforcement ────────────────────────────────────────── */

static int landlock_add_path(int ruleset_fd, const char *path, uint64_t access)
{
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        /* Path doesn't exist — skip silently (e.g. /lib32 on some systems) */
        return 0;
    }
    struct landlock_path_beneath_attr attr = {
        .allowed_access = access,
        .parent_fd = fd,
    };
    int r = syscall(__NR_landlock_add_rule, ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
    close(fd);
    if (r < 0 && errno != EINVAL) {
        fprintf(stderr, "compartment-user: landlock add_rule %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    return 0;
}

static int apply_landlock(Config *cfg)
{
    /* Check Landlock ABI version */
    int abi = syscall(__NR_landlock_create_ruleset, NULL, 0,
                      LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        fprintf(stderr, "compartment-user: Landlock not available (%s)\n",
                strerror(errno));
        return -1;
    }

    /* Access rights we control — must include ALL rights we want to
     * restrict, otherwise Landlock silently allows them.
     * ABI v1: base rights (read, write, execute, remove, make_*)
     * ABI v2: REFER (cross-directory rename/link)
     * ABI v3: TRUNCATE
     * ABI v4: IOCTL_DEV (device ioctls — when kernel headers support it) */
    uint64_t handled =
        LANDLOCK_ACCESS_FS_READ_FILE   |
        LANDLOCK_ACCESS_FS_READ_DIR    |
        LANDLOCK_ACCESS_FS_WRITE_FILE  |
        LANDLOCK_ACCESS_FS_REMOVE_DIR  |
        LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_CHAR   |
        LANDLOCK_ACCESS_FS_MAKE_REG    |
        LANDLOCK_ACCESS_FS_MAKE_DIR    |
        LANDLOCK_ACCESS_FS_MAKE_SYM    |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK  |
        LANDLOCK_ACCESS_FS_MAKE_SOCK   |
        LANDLOCK_ACCESS_FS_MAKE_FIFO   |
        LANDLOCK_ACCESS_FS_EXECUTE;
    if (abi >= 2)
        handled |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3)
        handled |= LANDLOCK_ACCESS_FS_TRUNCATE;
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
    if (abi >= 4)
        handled |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
#endif

    struct landlock_ruleset_attr rs_attr = { .handled_access_fs = handled };
    int ruleset_fd = syscall(__NR_landlock_create_ruleset,
                             &rs_attr, sizeof(rs_attr), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "compartment-user: create_ruleset: %s\n", strerror(errno));
        return -1;
    }

    /* Define access masks for each mode */
    uint64_t read_access =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    uint64_t write_access =
        LANDLOCK_ACCESS_FS_WRITE_FILE  |
        LANDLOCK_ACCESS_FS_REMOVE_DIR  |
        LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_CHAR   |
        LANDLOCK_ACCESS_FS_MAKE_REG    |
        LANDLOCK_ACCESS_FS_MAKE_DIR    |
        LANDLOCK_ACCESS_FS_MAKE_SYM    |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK  |
        LANDLOCK_ACCESS_FS_MAKE_SOCK   |
        LANDLOCK_ACCESS_FS_MAKE_FIFO;
    if (abi >= 2) write_access |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) write_access |= LANDLOCK_ACCESS_FS_TRUNCATE;
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
    if (abi >= 4) write_access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
#endif
    uint64_t exec_access = LANDLOCK_ACCESS_FS_EXECUTE;

    for (int i = 0; i < cfg->path_count; i++) {
        uint64_t access = 0;
        switch (cfg->paths[i].mode) {
        case PATH_RO:   access = read_access | exec_access; break;
        case PATH_RW:   access = read_access | write_access | exec_access; break;
        case PATH_EXEC: access = read_access | exec_access; break;
        case PATH_RWX:  access = read_access | write_access | exec_access; break;
        }
        if (landlock_add_path(ruleset_fd, cfg->paths[i].path, access) != 0) {
            fprintf(stderr, "compartment-user: landlock: failed to add rule for %s\n",
                    cfg->paths[i].path);
            close(ruleset_fd);
            return -1;
        }
    }

    /* Enforce */
    if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
        fprintf(stderr, "compartment-user: restrict_self: %s\n", strerror(errno));
        close(ruleset_fd);
        return -1;
    }
    close(ruleset_fd);

    if (cfg->verbose)
        fprintf(stderr, "compartment-user: landlock enforced (ABI v%d, %d path rules)\n",
                abi, cfg->path_count);
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
        "  --profile NAME        Search ~/.config/compartment/NAME.conf,\n"
        "                        then /etc/compartment/NAME.conf\n"
        "\n"
        "Filesystem (Landlock):\n"
        "  --ro PATH             Read-only + execute access\n"
        "  --rw PATH             Read-write + execute access\n"
        "  --exec PATH           Read + execute access (alias for --ro)\n"
        "  --workdir PATH        Working directory (added as --rw)\n"
        "  --no-landlock         Disable Landlock\n"
        "\n"
        "Syscalls (seccomp BPF):\n"
        "  --block SYSCALL       Block a syscall (by name)\n"
        "  --no-seccomp          Disable seccomp\n"
        "\n"
        "Environment:\n"
        "  --env-deny VAR        Strip environment variable\n"
        "  --no-env-sanitize     Don't strip dangerous env vars\n"
        "\n"
        "General:\n"
        "  --dry-run             Show what would be applied, don't enforce\n"
        "  --verbose             Print actions to stderr\n"
        "  --audit               Log events to stderr + file\n"
        "  --audit-log DIR       Set audit log directory (implies --audit)\n"
        "                        Default: /var/tmp/compartment-audit-$UID/\n"
        "  --insecure            Allow execution when enforcement is degraded\n"
        "                        (missing Landlock, unsupported filesystem, etc.)\n"
        "  --verify              Check system support and exit\n"
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
        if (!shell_dir) shell_dir = REAL_SHELL_DIR;

        /* Validate shell_dir: must be absolute and must not contain ".." */
        if (shell_dir[0] != '/') {
            fprintf(stderr, "compartment-user: COMPARTMENT_SHELL_DIR must be absolute: %s\n",
                    shell_dir);
            return 126;
        }
        /* Check for ".." traversal in shell_dir */
        {
            const char *p = shell_dir;
            while (*p) {
                if (p[0] == '.' && p[1] == '.' &&
                    (p[2] == '/' || p[2] == '\0') &&
                    (p == shell_dir || p[-1] == '/')) {
                    fprintf(stderr, "compartment-user: COMPARTMENT_SHELL_DIR contains '..': %s\n",
                            shell_dir);
                    return 126;
                }
                p++;
            }
        }

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
        /* Try profile file first, fall back to built-in */
        if (resolve_and_load_profile(&shell_cfg, "ai-agent", 0) != 0)
            apply_profile_ai_agent(&shell_cfg);

        int shell_degraded = 0;

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
            if (apply_landlock(&shell_cfg) != 0) {
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
        {"version",         no_argument,       NULL, 1},
        {"help",            no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "+P:r:w:x:W:b:l:E:e:A:LSNdvaUVh",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'P': cfg.profile = optarg; break;
        case 'r': /* --ro */
            if (cfg.path_count < MAX_PATHS) {
                cfg.paths[cfg.path_count].path = optarg;
                cfg.paths[cfg.path_count].mode = PATH_RO;
                cfg.path_count++;
            }
            break;
        case 'w': /* --rw */
            if (cfg.path_count < MAX_PATHS) {
                cfg.paths[cfg.path_count].path = optarg;
                cfg.paths[cfg.path_count].mode = PATH_RW;
                cfg.path_count++;
            }
            break;
        case 'x': /* --exec */
            if (cfg.path_count < MAX_PATHS) {
                cfg.paths[cfg.path_count].path = optarg;
                cfg.paths[cfg.path_count].mode = PATH_EXEC;
                cfg.path_count++;
            }
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
            if (cfg.blocked_count < MAX_BLOCKED_SC)
                cfg.blocked_syscalls[cfg.blocked_count++] = nr;
            break;
        }
        case 'l': { /* --allow (syscall allowlist) */
            int nr = resolve_syscall(optarg);
            if (nr < 0) {
                fprintf(stderr, "compartment-user: unknown syscall: %s\n", optarg);
                return 1;
            }
            if (cfg.allowed_sc_count < MAX_ALLOWED_SC) {
                cfg.allowed_syscalls[cfg.allowed_sc_count++] = nr;
                cfg.seccomp_allow_mode = 1;
            }
            break;
        }
        case 'E': /* --env-deny */
            if (cfg.env_deny_count < MAX_ENV_VARS)
                cfg.env_deny[cfg.env_deny_count++] = optarg;
            break;
        case 'e': /* --env-allow */
            if (cfg.env_allow_count < MAX_ENV_VARS) {
                cfg.env_allow[cfg.env_allow_count++] = optarg;
                cfg.env_allow_mode = 1;
                cfg.use_env_sanitize = 1;
            }
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
        case  1 : printf("compartment-user %s\n", COMPARTMENT_VERSION); return 0;
        case 'h': print_usage(); return 0;
        default:  print_usage(); return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "compartment-user: no command specified\n");
        print_usage();
        return 1;
    }

    /* Apply profile: try file first, then fall back to built-in */
    if (strcmp(cfg.profile, "none") != 0) {
        if (resolve_and_load_profile(&cfg, cfg.profile, 0) == 0) {
            /* loaded from file */
        } else if (strcmp(cfg.profile, "ai-agent") == 0) {
            apply_profile_ai_agent(&cfg);
            cfg.profile_source = "built-in";
        } else if (strcmp(cfg.profile, "strict") == 0) {
            apply_profile_strict(&cfg);
            cfg.profile_source = "built-in";
        } else {
            fprintf(stderr, "compartment-user: unknown profile: %s\n", cfg.profile);
            fprintf(stderr, "  searched: ~/.config/compartment/%s.conf, "
                    "/etc/compartment/%s.conf\n", cfg.profile, cfg.profile);
            return 1;
        }
    }

    /* workdir implies rw — the user expects to write there.
     * The ai-agent built-in does this already; this ensures file-loaded
     * profiles get the same behavior. Skip if already in the path list. */
    if (cfg.workdir && cfg.path_count < MAX_PATHS) {
        int already = 0;
        for (int i = 0; i < cfg.path_count; i++) {
            if (cfg.paths[i].mode == PATH_RW &&
                strcmp(cfg.paths[i].path, cfg.workdir) == 0) {
                already = 1;
                break;
            }
        }
        if (!already) {
            cfg.paths[cfg.path_count].path = cfg.workdir;
            cfg.paths[cfg.path_count].mode = PATH_RW;
            cfg.path_count++;
        }
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
        for (int i = 0; i < cfg.path_count; i++)
            fprintf(stderr, "    %s %s\n",
                    cfg.paths[i].mode == PATH_RO ? "ro" :
                    cfg.paths[i].mode == PATH_RW ? "rw" :
                    cfg.paths[i].mode == PATH_EXEC ? "exec" : "rwx",
                    cfg.paths[i].path);
        if (cfg.seccomp_allow_mode) {
            fprintf(stderr, "  seccomp: %s ALLOW-LIST (%d allowed, rest denied)\n",
                    cfg.use_seccomp ? "yes" : "no", cfg.allowed_sc_count);
        } else {
            fprintf(stderr, "  seccomp: %s DENY-LIST (%d blocked)\n",
                    cfg.use_seccomp ? "yes" : "no", cfg.blocked_count);
            for (int i = 0; i < cfg.blocked_count; i++) {
                const char *name = "?";
                for (int j = 0; syscall_table[j].name; j++) {
                    if (syscall_table[j].nr == cfg.blocked_syscalls[i]) {
                        name = syscall_table[j].name;
                        break;
                    }
                }
                fprintf(stderr, "    block %s (%d)\n", name,
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
            fprintf(stderr, "  audit: yes (log: %s)\n",
                    cfg.audit_log_dir ? cfg.audit_log_dir :
                    "/var/tmp/compartment-audit-$UID/");
        }
        fprintf(stderr, "  command: %s\n", argv[optind]);
        return 0;
    }

    /* ── Audit (open log file BEFORE Landlock — fd survives) ──── */
    if (cfg.audit) {
        audit_log_open(&cfg);  /* non-fatal if it fails */

        char detail[512];
        snprintf(detail, sizeof(detail), "command=%s profile=%s "
                 "landlock=%d seccomp=%d paths=%d blocked=%d",
                 argv[optind], cfg.profile,
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
        if (apply_landlock(&cfg) != 0) {
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

    /* Clear ambient capabilities — prevents inherited caps from parent */
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

    /* Disable coredumps — prevents pipe core_pattern bypass and
     * also restricts /proc/self access from other same-UID processes */
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    /* Close inherited file descriptors — Landlock only restricts new
     * open() calls, not already-open fds leaked from the parent.
     * close_range() available since Linux 5.9, glibc 2.34. */
    if (close_range(3, ~0U, 0) != 0) {
        /* Fallback for older kernels */
        for (int cfd = 3; cfd < 1024; cfd++) close(cfd);
    }

    /* ── 7. exec ───────────────────────────────────────────────── */
    if (cfg.verbose)
        fprintf(stderr, "compartment-user: exec %s\n", argv[optind]);

    execvp(argv[optind], &argv[optind]);
    fprintf(stderr, "compartment-user: exec %s: %s\n",
            argv[optind], strerror(errno));
    return 127;
}
