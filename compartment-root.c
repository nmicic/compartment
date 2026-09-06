/*
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 * SPDX-License-Identifier: Apache-2.0
 *
 * compartment-root — full-namespace process isolation (requires root)
 *
 * Creates a fully isolated container using Linux namespaces:
 *   1. clone() with NEWUTS, NEWNS, NEWPID, NEWIPC, NEWNET, NEWUSER, NEWCGROUP
 *   2. Parent: UID/GID range mapping + cgroup assignment (host context)
 *   3. Child: pivot_root into new root
 *   4. Child: mount /proc, populate /dev, mask sensitive paths — all while
 *      the old root is still attached (mount_too_revealing, see step 3)
 *   5. Child: detach the old root, then hostname isolation, optional loopback
 *   6. Child: Resource limits (rlimits)
 *   7. Child: Capability bounding-set drop (raw prctl — while still root)
 *   8. Child: PR_SET_KEEPCAPS + privilege drop (setuid/setgid)
 *   8b.Child: capset() to restore effective+permitted+inheritable caps
 *   9. Child: PR_SET_DUMPABLE(0) — prevent ptrace
 *  10. Child: Environment sanitize, close inherited FDs
 *  11. Child: PR_SET_NO_NEW_PRIVS, PR_SET_PDEATHSIG, fork under a PID 1
 *      reaper, seccomp BPF (fatal on failure), exec the target command
 *
 * Synchronization model:
 *   Parent creates child via clone(), then writes UID/GID maps and assigns
 *   cgroups (both require host filesystem context and root privileges).
 *   Child blocks on a pipe until parent signals "go". This ensures maps
 *   are set up before the child does any privileged operations.
 *
 * Policy can be specified via CLI flags or profile files (.conf):
 *   compartment-root --profile container -- /bin/sh
 *   compartment-root --rootdir /srv/jail -U svc -- /usr/bin/myapp
 *
 * Requirements: root (for UID/GID mapping of range 0-65535)
 * No dependencies: no libseccomp, no libcap.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <net/if.h>
#include <getopt.h>
#include <grp.h>

/* CLONE_NEWCGROUP: Linux 4.6+, may be missing from older headers */
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

/* Shared: Config struct, syscall/cap tables, profile loader, audit,
 * env sanitize, seccomp BPF builder — all static inline, zero deps. */
#include "compartment.h"

/* mount_setattr(2): Linux 5.12+. Declared here rather than pulled in from
 * <linux/mount.h> so the build stays header-independent (and keeps the
 * zero-dependency promise). Only used to apply nosuid/nodev recursively;
 * the code falls back to MS_REMOUNT|MS_BIND when it is unavailable. */
#ifndef MOUNT_ATTR_NOSUID
#define MOUNT_ATTR_NOSUID 0x00000002
#endif
#ifndef MOUNT_ATTR_NODEV
#define MOUNT_ATTR_NODEV  0x00000004
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE      0x8000
#endif
struct compartment_mount_attr {   /* layout of struct mount_attr */
    uint64_t attr_set;
    uint64_t attr_clr;
    uint64_t propagation;
    uint64_t userns_fd;
};

/* ── Child args passed through clone() ─────────────────────────────── */

struct child_args {
    Config *config;
    int     pipe_fd;        /* read end — child waits for parent signal */
    int     pipe_fd_write;  /* write end — child closes immediately */
    char  **cmd_args;
    uid_t   drop_uid;
    gid_t   drop_gid;
};

/* ── Prototypes ──────────────────────────────────────────────────────── */

static int  child_func(void *arg);
static void write_uid_gid_map(pid_t pid, const char *map_str,
                               const char *map_file);
static void deny_setgroups(pid_t pid, Config *config);
static void drop_privileges(uid_t uid, gid_t gid);
static void drop_capabilities(Config *config, int cap_last);
static void apply_kept_caps(Config *config);
static int  assign_to_cgroups(Config *config, pid_t pid);
static int  path_has_dotdot(const char *path);
static int  mask_path(Config *config, const char *path);
static void join_netns(const char *netns_name);
static void set_rlimits(void);
static void apply_default_seccomp_denylist(Config *config);
static void container_init(void);
static void print_help(const char *prog_name);

/* Location label used by the fail-closed policy-append helpers. */
#define CLI_WHERE "command line"

/* ── Built-in container filesystem layout ───────────────────────────── */

/* Device nodes bind-mounted from the old root into the container's /dev
 * (mknod is unavailable in a user namespace — see child_func step 5). */
static const char *const default_dev_nodes[] = {
    "null", "zero", "full", "random", "urandom", "tty", NULL
};

/* Paths masked inside the container by default: a directory is covered
 * with an empty read-only tmpfs, a file with a bind of /dev/null.  Targets
 * absent on the running kernel are skipped (see mask_path). */
static const char *const default_proc_masks[] = {
    "/proc/acpi", "/proc/bus", "/proc/fs", "/proc/irq",
    "/proc/kallsyms", "/proc/kcore", "/proc/keys",
    "/proc/latency_stats", "/proc/modules", "/proc/sched_debug",
    "/proc/scsi", "/proc/sys", "/proc/sysrq-trigger",
    "/proc/timer_list", "/proc/timer_stats", NULL
};

static int count_strv(const char *const *v)
{
    int n = 0;
    while (v[n]) n++;
    return n;
}

/* Reverse syscall_table lookup, for --dry-run --verbose. */
static const char *syscall_name(int nr)
{
    for (int i = 0; syscall_table[i].name; i++)
        if (syscall_table[i].nr == nr)
            return syscall_table[i].name;
    return "?";
}

/* ── Built-in seccomp deny-list ──────────────────────────────────────── */

/*
 * apply_default_seccomp_denylist — the filter compartment-root installs
 * when the operator supplies neither --block nor --seccomp-allowed.
 *
 * Without this there was no default filter at all: apply_seccomp() warned
 * "seccomp enabled but no syscalls to block" and returned success, so
 * every container ran with Seccomp: 0 — byte-identical to --no-seccomp —
 * while --help advertised seccomp as one of the things the tool does.
 *
 * The list mirrors compartment-user's built-in ai-agent deny-list.  It is
 * deliberately kept here rather than hoisted into compartment.h: the
 * profile loader in that header is being reworked separately, and keeping
 * the two copies apart keeps this change to compartment-root.c.  Fold them
 * into one shared table once that work lands.
 *
 * Nothing in this list is needed by a container after exec: all mounts,
 * namespace setup and privilege changes happen in the child before the
 * filter is installed.
 */
static void apply_default_seccomp_denylist(Config *config)
{
    static const char *blocked[] = {
        /* Debugging and process memory access */
        "ptrace", "process_vm_readv", "process_vm_writev",
        /* Mount / namespace manipulation — nested container escape */
        "mount", "umount2", "pivot_root", "chroot", "unshare", "setns",
        "mount_setattr", "open_tree", "move_mount",
        "fsopen", "fsmount", "fsconfig", "fspick",
        /* Handle-based file access — reaches outside the mount namespace */
        "open_by_handle_at", "name_to_handle_at",
        /* Kernel code loading and reboot */
        "reboot", "kexec_load", "kexec_file_load",
        "init_module", "finit_module", "delete_module",
        /* Kernel keyring */
        "keyctl", "add_key", "request_key",
        /* Kernel interfaces with a long CVE history */
        "bpf", "userfaultfd", "perf_event_open",
        "io_uring_setup", "io_uring_enter", "io_uring_register",
        /* Host-wide state */
        "acct", "swapon", "swapoff",
        "settimeofday", "clock_settime", "clock_adjtime", "adjtimex",
        /* Cross-process FD theft */
        "pidfd_getfd",
#ifdef __x86_64__
        /* Raw I/O port access */
        "ioperm", "iopl",
#endif
        NULL
    };

    for (int i = 0; blocked[i]; i++) {
        int nr = resolve_syscall(blocked[i]);
        if (nr < 0)
            continue;   /* syscall does not exist on this architecture */
        /* cfg_add_blocked refuses rather than truncating; an overflow here
         * would mean the built-in policy itself was silently cut short. */
        if (cfg_add_blocked(config, "built-in deny-list", blocked[i], nr) != 0)
            exit(EXIT_FAILURE);
    }
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    Config config;
    memset(&config, 0, sizeof(config));
    config.audit_log_fd     = -1;

    /* Defaults — seccomp and env-sanitize on unless disabled */
    config.use_seccomp      = 1;
    config.use_no_new_privs = 1;
    config.use_env_sanitize = 1;

    static struct option long_options[] = {
        {"profile",         required_argument, 0, 'p'},
        {"rootdir",         required_argument, 0, 'c'},
        {"uid",             required_argument, 0, 'u'},
        {"gid",             required_argument, 0, 'g'},
        {"username",        required_argument, 0, 'U'},
        {"seccomp-allowed", required_argument, 0, 'a'},
        {"block",           required_argument, 0, 'B'},
        {"netns",           required_argument, 0, 'n'},
        {"cgroup",          required_argument, 0, 'C'},
        {"cap-allowed",     required_argument, 0, 'A'},
        {"env-deny",        required_argument, 0, 'E'},
        {"env-allow",       required_argument, 0, 'e'},
        {"mount-mask",      required_argument, 0, 'M'},
        {"audit-log",       required_argument, 0, 'L'},
        {"loopback",        no_argument,       0, 'l'},
        {"no-seccomp",      no_argument,       0, 'S'},
        {"no-env-sanitize", no_argument,       0, 'N'},
        {"dry-run",         no_argument,       0, 'd'},
        {"verbose",         no_argument,       0, 'v'},
        {"audit",           no_argument,       0, 'D'},
        {"verify",          no_argument,       0, 'V'},
        {"version",         no_argument,       0, 1},
        {"help",            no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    static const char *optstring =
        "+p:c:u:g:a:B:n:C:A:E:e:M:L:U:lSNdvDVh";

    /* ── Pass 1: resolve --profile only ─────────────────────────────
     *
     * The profile has to load before the rest of the command line so that
     * CLI options override it. This used to be a hand-rolled pre-scan
     * that matched only the exact tokens "--profile" and "-p", so
     * "--profile=FILE" and "-pFILE" fell through to a no-op getopt case
     * and the entire policy was discarded with no error and exit 0. Let
     * getopt_long do the parsing, twice. */
    int opt;
    opterr = 0;
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        if (opt == 'p') { config.profile = optarg; break; }
        if (opt == '?' || opt == ':') break;   /* pass 2 reports it */
    }
    optind = 0;   /* glibc: full reinitialisation for the second pass */
    opterr = 1;

    if (config.profile) {
        /* PROFILE_OWNER_ROOT and no $HOME search: this process is root,
         * and the profile decides rootdir, username, cap-allow and the
         * seccomp policy. */
        int pr = resolve_and_load_profile(&config, config.profile, 0,
                                          PROFILE_OWNER_ROOT);
        if (pr == PROFILE_ERROR) {
            fprintf(stderr, "compartment-root: profile '%s' was rejected "
                    "— refusing to run\n", config.profile);
            return 1;
        }
        if (pr == PROFILE_NOT_FOUND) {
            fprintf(stderr, "compartment-root: unknown profile: %s\n",
                    config.profile);
            profile_print_search_path(stderr, config.profile, PROFILE_OWNER_ROOT);
            return 1;
        }
    }

    /* ── Pass 2: everything else (overrides profile values) ────────── */

    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        switch (opt) {
        case 'p':
            /* Resolved in pass 1. A different value here means --profile
             * was given more than once. */
            if (!config.profile || strcmp(config.profile, optarg) != 0) {
                fprintf(stderr, "compartment-root: --profile given more than "
                        "once ('%s' after '%s') — refusing to guess\n",
                        optarg, config.profile ? config.profile : "(none)");
                return 1;
            }
            break;
        case 'c':
            free(config.rootdir);
            config.rootdir = xstrdup(optarg);
            break;
        case 'u': {
            char *endptr;
            errno = 0;
            unsigned long val = strtoul(optarg, &endptr, 10);
            if (errno != 0 || endptr == optarg || *endptr != '\0' ||
                val > (unsigned long)UINT32_MAX) {
                fprintf(stderr, "compartment-root: invalid UID: %s\n", optarg);
                return 1;
            }
            config.uid = (uid_t)val;
            break;
        }
        case 'g': {
            char *endptr;
            errno = 0;
            unsigned long val = strtoul(optarg, &endptr, 10);
            if (errno != 0 || endptr == optarg || *endptr != '\0' ||
                val > (unsigned long)UINT32_MAX) {
                fprintf(stderr, "compartment-root: invalid GID: %s\n", optarg);
                return 1;
            }
            config.gid = (gid_t)val;
            break;
        }
        case 'U':
            free(config.username);
            config.username = xstrdup(optarg);
            break;
        case 'a': { /* --seccomp-allowed */
            int nr = resolve_syscall(optarg);
            if (nr < 0) {
                fprintf(stderr, "compartment-root: unknown syscall: %s\n", optarg);
                return 1;
            }
            if (cfg_add_allowed(&config, CLI_WHERE, optarg, nr) != 0)
                return 1;
            break;
        }
        case 'B': { /* --block */
            int nr = resolve_syscall(optarg);
            if (nr < 0) {
                fprintf(stderr, "compartment-root: unknown syscall: %s\n", optarg);
                return 1;
            }
            if (cfg_add_blocked(&config, CLI_WHERE, optarg, nr) != 0)
                return 1;
            break;
        }
        case 'n':
            free(config.netns);
            config.netns = xstrdup(optarg);
            break;
        case 'C':
            if (cfg_add_str(config.cgroups, &config.cgroups_count, MAX_PATHS,
                            CLI_WHERE, "cgroup", optarg, 1) != 0)
                return 1;
            break;
        case 'A':
            if (cfg_add_str(config.cap_allowed_names, &config.cap_allowed_count,
                            MAX_ENV_VARS, CLI_WHERE, "cap-allow", optarg, 1) != 0)
                return 1;
            break;
        case 'E':
            if (cfg_add_env_deny(&config, CLI_WHERE, optarg, 0) != 0)
                return 1;
            break;
        case 'e':
            if (cfg_add_env_allow(&config, CLI_WHERE, optarg, 0) != 0)
                return 1;
            config.use_env_sanitize = 1;
            break;
        case 'M':
            if (cfg_add_str(config.mount_masks, &config.mount_mask_count,
                            MAX_PATHS, CLI_WHERE, "mount-mask", optarg, 1) != 0)
                return 1;
            break;
        case 'L': config.audit_log_dir = optarg; config.audit = 1; break;
        case 'l': config.loopback = 1; break;
        case 'S': config.use_seccomp = 0; break;
        case 'N': config.use_env_sanitize = 0; break;
        case 'd': config.dry_run = 1; break;
        case 'v': config.verbose = 1; break;
        case 'D': config.audit = 1; break;
        case 'V': {
            printf("compartment-root: system verification\n");
            printf("  uid: %u  euid: %u\n", getuid(), geteuid());
            FILE *fcap = fopen("/proc/sys/kernel/cap_last_cap", "re");
            if (fcap) {
                int cap_last = -1;
                if (fscanf(fcap, "%d", &cap_last) == 1)
                    printf("  CAP_LAST_CAP: %d\n", cap_last);
                fclose(fcap);
            }
            int sc_count = 0;
            for (int i = 0; syscall_table[i].name; i++) sc_count++;
            printf("  Syscall table: %d entries\n", sc_count);
            int cap_count = 0;
            for (int i = 0; cap_table[i].name; i++) cap_count++;
            printf("  Capability table: %d entries\n", cap_count);
            return 0;
        }
        case  1 : printf("compartment-root %s\n", COMPARTMENT_VERSION); return 0;
        case 'h': print_help(argv[0]); return 0;
        default:  print_help(argv[0]); return 1;
        }
    }

    /* ── seccomp: fall back to the built-in deny-list ─────────────── */

    int seccomp_builtin = 0;
    if (config.use_seccomp && !config.seccomp_allow_mode &&
        config.blocked_count == 0) {
        apply_default_seccomp_denylist(&config);
        seccomp_builtin = 1;
    }
    if (config.use_seccomp &&
        (config.seccomp_allow_mode ? config.allowed_sc_count
                                   : config.blocked_count) == 0) {
        fprintf(stderr, "compartment-root: seccomp is enabled but the filter "
                "would be empty — refusing to run\n");
        return 1;
    }

    /* ── no-new-privs is not negotiable for compartment-root ──────── */

    if (!config.use_no_new_privs) {
        fprintf(stderr, "compartment-root: no-new-privs cannot be disabled "
                "— ignoring 'no-new-privs off'\n");
        config.use_no_new_privs = 1;
    }

    /* Command to execute */
    if (optind >= argc) {
        fprintf(stderr, "compartment-root: no command specified\n");
        print_help(argv[0]);
        return 1;
    }

    if (!config.rootdir) {
        fprintf(stderr, "compartment-root: --rootdir is required "
                "(or set 'rootdir' in profile)\n");
        return 1;
    }
    if (config.rootdir[0] != '/') {
        fprintf(stderr, "compartment-root: rootdir must be absolute: %s\n",
                config.rootdir);
        return 1;
    }
    if (path_has_dotdot(config.rootdir)) {
        fprintf(stderr, "compartment-root: rootdir contains '..': %s\n",
                config.rootdir);
        return 1;
    }
    if (!config.username) {
        fprintf(stderr, "compartment-root: --username is required "
                "(or set 'username' in profile)\n");
        return 1;
    }

    /* ── Resolve username to numeric UID/GID (host /etc/passwd) ───── */

    uid_t drop_uid = 0, drop_gid = 0;
    {
        struct passwd *pw = getpwnam(config.username);
        if (pw) {
            drop_uid = pw->pw_uid;
            drop_gid = pw->pw_gid;
        } else if (config.uid == 0 && config.gid == 0) {
            fprintf(stderr, "compartment-root: user '%s' not found — "
                    "specify --uid/--gid if user exists only in container\n",
                    config.username);
            return 1;
        }
        /* Explicit --uid/--gid override getpwnam result */
        if (config.uid != 0) drop_uid = config.uid;
        if (config.gid != 0) drop_gid = config.gid;
    }

    /* ── Dry run: show config and exit ─────────────────────────────── */

    if (config.dry_run) {
        fprintf(stderr, "compartment-root: DRY RUN — would apply:\n");
        if (config.profile)
            fprintf(stderr, "  profile: %s (%s)\n", config.profile,
                    config.profile_source ? config.profile_source : "?");
        fprintf(stderr, "  rootdir: %s\n", config.rootdir);
        fprintf(stderr, "  username: %s (drop to uid=%u gid=%u)\n",
                config.username, drop_uid, drop_gid);
        fprintf(stderr, "  uid map: %s",
                config.uid_map ? config.uid_map : "0 0 65536 (identity)\n");
        fprintf(stderr, "  gid map: %s",
                config.gid_map ? config.gid_map : "0 0 65536 (identity)\n");
        fprintf(stderr, "  loopback: %s\n", config.loopback ? "yes" : "no");
        if (config.netns)
            fprintf(stderr, "  netns: %s\n", config.netns);
        fprintf(stderr, "  capabilities kept: %d\n", config.cap_allowed_count);
        for (int i = 0; i < config.cap_allowed_count; i++)
            fprintf(stderr, "    %s\n", config.cap_allowed_names[i]);
        if (config.seccomp_allow_mode) {
            fprintf(stderr, "  seccomp: %s ALLOW-LIST (%d allowed)\n",
                    config.use_seccomp ? "yes" : "no",
                    config.allowed_sc_count);
        } else {
            fprintf(stderr, "  seccomp: %s DENY-LIST (%d blocked%s)\n",
                    config.use_seccomp ? "yes" : "no",
                    config.blocked_count,
                    seccomp_builtin ? ", built-in default" : "");
        }
        fprintf(stderr, "  env-sanitize: %s\n",
                config.use_env_sanitize ? "yes" : "no");
        if (config.env_allow_mode)
            fprintf(stderr, "  env: ALLOW-LIST (%d kept)\n",
                    config.env_allow_count);
        else if (config.env_deny_count > 0)
            fprintf(stderr, "  env: DENY-LIST (%d stripped)\n",
                    config.env_deny_count);
        fprintf(stderr, "  no-new-privs: yes (cannot be disabled)\n");
        fprintf(stderr, "  cgroups: %d\n", config.cgroups_count);
        fprintf(stderr, "  mount-masks: %d (+ %d built-in)\n",
                config.mount_mask_count, count_strv(default_proc_masks));
        if (config.audit) {
            /* audit-log names a *directory*; the file inside it is named
             * after the day.  The banner used to print the directory as
             * though it were the log file.  audit_default_dir() has no
             * side effects, so --dry-run reports the directory a real run
             * would pick (/var/log/compartment under root) instead of a
             * hard-coded guess. */
            char defdir[PATH_MAX];
            const char *dir = config.audit_log_dir;
            if (!dir)
                dir = (audit_default_dir(defdir, sizeof(defdir)) == 0)
                    ? defdir : "(unavailable)";
            fprintf(stderr, "  audit: yes (log dir: %s, file: "
                    "%s/YYYY-MM-DD.log)\n", dir, dir);
        }
        fprintf(stderr, "  command: %s\n", argv[optind]);

        /* --verbose adds the parts of the policy that are built in and
         * therefore invisible in the summary above. */
        if (config.verbose) {
            fprintf(stderr, "  ── built-in, always applied ──\n");
            fprintf(stderr, "  container root: recursive bind of %s, "
                    "remounted nosuid,nodev\n", config.rootdir);
            fprintf(stderr, "  /proc: fresh procfs (nosuid,noexec,nodev)\n");
            fprintf(stderr, "  /sys: read-only sysfs (+ /sys/firmware "
                    "masked), or an empty tmpfs if the kernel refuses\n");
            fprintf(stderr, "  /dev: tmpfs with bind-mounted");
            for (int i = 0; default_dev_nodes[i]; i++)
                fprintf(stderr, "%s /dev/%s", i ? "," : "",
                        default_dev_nodes[i]);
            fprintf(stderr, "\n");
            fprintf(stderr, "  masked paths (%d, skipped when absent):\n",
                    count_strv(default_proc_masks));
            for (int i = 0; default_proc_masks[i]; i++)
                fprintf(stderr, "    %s\n", default_proc_masks[i]);
            for (int i = 0; i < config.mount_mask_count; i++)
                fprintf(stderr, "    %s (from policy)\n",
                        config.mount_masks[i]);
            fprintf(stderr, "  init: PID 1 reaper, forwards SIGTERM/SIGINT/"
                    "SIGHUP/SIGQUIT, PR_SET_PDEATHSIG=SIGKILL\n");
            fprintf(stderr, "  privilege drop: bounding set emptied, "
                    "setgid/setuid, PR_SET_DUMPABLE(0)\n");
            if (config.use_seccomp && !config.seccomp_allow_mode) {
                fprintf(stderr, "  blocked syscalls (%d):\n",
                        config.blocked_count);
                for (int i = 0; i < config.blocked_count; i++)
                    fprintf(stderr, "    %s (%d)\n",
                            syscall_name(config.blocked_syscalls[i]),
                            config.blocked_syscalls[i]);
            }
        }
        return 0;
    }

    /* ── Audit log (open BEFORE clone — fd is on host filesystem) ──── */

    if (config.audit) {
        if (audit_log_open(&config) != 0) {
            fprintf(stderr, "compartment-root: audit logging was requested "
                    "but could not be set up safely — refusing to run\n");
            return 1;
        }

        char detail[512];
        snprintf(detail, sizeof(detail),
                 "command=%s rootdir=%s drop_uid=%u drop_gid=%u username=%s "
                 "loopback=%d seccomp=%d caps=%d",
                 argv[optind], config.rootdir, drop_uid, drop_gid,
                 config.username, config.loopback, config.use_seccomp,
                 config.cap_allowed_count);
        audit_log(&config, "CONTAINER_START", detail);
    }

    /* ── Synchronization pipe (parent→child: parent writes maps then
     *    signals child to proceed) ────────────────────────────────── */

    int pipe_fd[2];
    if (pipe2(pipe_fd, O_CLOEXEC) != 0) {
        perror("compartment-root: pipe");
        return 1;
    }

    /* ── Clone with new namespaces ─────────────────────────────────── */

    /* Clear supplementary groups here, in the parent: once
     * /proc/<pid>/setgroups is set to "deny" below, the child can no
     * longer do it itself, and it would otherwise inherit the invoking
     * root's groups — which the identity gid map keeps meaningful inside
     * the container. */
    if (setgroups(0, NULL) != 0 && errno != EPERM) {
        perror("compartment-root: setgroups");
        return 1;
    }

    int flags = CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC |
                CLONE_NEWNET | CLONE_NEWUSER | CLONE_NEWCGROUP | SIGCHLD;

    const int STACK_SIZE = 1024 * 1024;
    char *child_stack = malloc(STACK_SIZE);
    if (!child_stack) {
        perror("compartment-root: malloc");
        return 1;
    }

    struct child_args cargs = {
        .config        = &config,
        .pipe_fd       = pipe_fd[0],    /* child reads (waits for parent) */
        .pipe_fd_write = pipe_fd[1],    /* child closes this immediately */
        .cmd_args      = &argv[optind],
        .drop_uid      = drop_uid,
        .drop_gid      = drop_gid,
    };

    pid_t child_pid = clone(child_func, child_stack + STACK_SIZE,
                            flags, &cargs);
    if (child_pid == -1) {
        perror("compartment-root: clone");
        free(child_stack);
        return 1;
    }

    /* ── Parent: set up UID/GID maps, cgroups, then signal child ──── */

    close(pipe_fd[0]);  /* parent doesn't read */

    /* Deny setgroups before the gid map is written (standard user-namespace
     * hardening sequence). */
    deny_setgroups(child_pid, &config);

    /* Write UID/GID maps — parent has root in parent namespace, can
     * write multi-entry range maps.  The default is the identity map
     * 0-65535 → 0-65535, so the child can operate as root (UID 0) during
     * setup and later setuid to the service user (drop_uid); the
     * `uid-map`/`gid-map` profile directives replace it with an explicit
     * <container-start> <host-start> <count> range. */
    write_uid_gid_map(child_pid, config.uid_map ? config.uid_map : "0 0 65536\n",
                      "uid_map");
    write_uid_gid_map(child_pid, config.gid_map ? config.gid_map : "0 0 65536\n",
                      "gid_map");

    /* Assign to cgroups — must happen from host filesystem context,
     * before the child does pivot_root. */
    if (config.cgroups_count > 0) {
        if (assign_to_cgroups(&config, child_pid) != 0) {
            kill(child_pid, SIGKILL);
            waitpid(child_pid, NULL, 0);
            free(child_stack);
            return 1;
        }
    }

    /* Signal child: maps and cgroups are ready, proceed */
    if (write(pipe_fd[1], "x", 1) != 1) {
        fprintf(stderr, "compartment-root: failed to signal child\n");
        kill(child_pid, SIGKILL);
        waitpid(child_pid, NULL, 0);
        free(child_stack);
        return 1;
    }
    close(pipe_fd[1]);

    /* Wait for child to finish */
    int status;
    if (waitpid(child_pid, &status, 0) == -1) {
        perror("compartment-root: waitpid");
        free(child_stack);
        return 1;
    }

    /* Audit: log exit */
    if (config.audit) {
        char detail[128];
        if (WIFEXITED(status))
            snprintf(detail, sizeof(detail), "exit_code=%d",
                     WEXITSTATUS(status));
        else
            snprintf(detail, sizeof(detail), "signal=%d",
                     WTERMSIG(status));
        audit_log(&config, "CONTAINER_EXIT", detail);
    }

    free(child_stack);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/* ── Child: runs inside the new namespaces ─────────────────────────── */

static int child_func(void *arg)
{
    struct child_args *cargs = arg;
    Config *config = cargs->config;
    int pipe_fd = cargs->pipe_fd;
    char **cmd_args = cargs->cmd_args;

    /* Close write end of pipe (child only reads) */
    close(cargs->pipe_fd_write);

    /* 1. Wait for parent to set up UID/GID maps and cgroups */
    char buf;
    if (read(pipe_fd, &buf, 1) != 1) {
        fprintf(stderr, "compartment-root: child failed to receive "
                "parent signal (UID/GID maps not ready)\n");
        exit(EXIT_FAILURE);
    }
    close(pipe_fd);

    /* Become root *of the new user namespace*.
     *
     * The child was cloned from the host's root, so its credentials are
     * host uid/gid 0.  With the default identity map that is also uid 0
     * inside the namespace and this is a no-op.  With a shifted
     * `uid-map`/`gid-map` (say "0 100000 65536") host uid 0 is not mapped
     * at all, so every file the child creates is owned by an unmapped uid
     * and a later open() of it fails with EOVERFLOW.  Switching to the
     * namespace's uid 0 fixes that and keeps the capability set:
     * cap_emulate_setxuid() only clears capabilities when a process moves
     * *away* from the namespace's root uid, and this moves towards it.
     *
     * Parent has also assigned cgroups from the host context. */
    if (setgid(0) != 0 || setuid(0) != 0) {
        perror("compartment-root: switch to container root");
        exit(EXIT_FAILURE);
    }

    /* 2. Join existing network namespace if specified */
    if (config->netns)
        join_netns(config->netns);

    /* 3. pivot_root — stronger than chroot (old root fully unmounted)
     *
     * Sequence:
     *   a) Make all mounts private (prevent leak to parent namespace)
     *   b) Bind-mount new root onto itself (pivot_root requires mount point)
     *   c) chdir into new root
     *   d) pivot_root(".", ".pivot_old")
     *   e) chdir("/")
     *   f) mount /proc (step 4) and populate /dev (step 5) — WHILE the old
     *      root is still attached under /.pivot_old
     *   g) umount old root, remove pivot point (step 6)
     *
     * ORDER MATTERS.  Steps f and g used to be the other way round, which
     * made the tool unusable: mounting a fresh procfs (or sysfs) from inside
     * a user namespace is gated by the kernel's mount_too_revealing()
     * check (fs/namespace.c).  It only permits the mount if a *fully
     * visible* mount of the same filesystem already exists in the current
     * mount namespace.  Detaching /.pivot_old removes the last visible
     * procfs, so a subsequent mount("proc", ...) is refused with EPERM
     * ("VFS: Mount too revealing" in dmesg).  Keeping the old root attached
     * until /proc, /sys and /dev are in place satisfies the check — and
     * gives us the host device nodes to bind from (mknod is unavailable in
     * a user namespace; see step 5).
     *
     * After step g there is no FD or path to the old root — unlike chroot,
     * which can be escaped via fchdir() to an open FD outside the root.
     */
    if (!config->rootdir) {
        fprintf(stderr, "compartment-root: rootdir not specified\n");
        exit(EXIT_FAILURE);
    }

    /* a) Make mount propagation private — MS_PRIVATE prevents host mount
     *    events from propagating into the container (MS_SLAVE would still
     *    allow host→container propagation). */
    if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) != 0) {
        perror("compartment-root: mount MS_PRIVATE");
        exit(EXIT_FAILURE);
    }

    /* b) Bind-mount new root (pivot_root requires mount point) */
    if (mount(config->rootdir, config->rootdir, NULL,
              MS_BIND | MS_REC, NULL) != 0) {
        perror("compartment-root: mount --bind rootdir");
        exit(EXIT_FAILURE);
    }

    /* b2) Re-apply the bind with MS_NOSUID|MS_NODEV.
     *
     * A bind mount inherits the mount flags of its source, so without this
     * the container root carries whatever the host filesystem had —
     * typically neither nosuid nor nodev.  A setuid-root binary sitting
     * inside rootdir then still elevates, and a device node planted there
     * is still a device node.
     *
     * MS_REMOUNT|MS_BIND changes only the per-mount flags: the filesystem
     * type, source and data arguments are ignored and the superblock is
     * left alone, so the host's own view of the same filesystem is
     * unaffected.  mount(2) ignores MS_REC on a remount, so that call
     * covers the top mount only; mount_setattr(2) (Linux 5.12+) with
     * AT_RECURSIVE also covers the submounts MS_REC dragged in.  Prefer
     * it, fall back to the plain remount on older kernels. */
    {
        int r = -1;
#ifdef __NR_mount_setattr
        struct compartment_mount_attr ma;
        memset(&ma, 0, sizeof(ma));
        ma.attr_set = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV;
        r = (int)syscall(__NR_mount_setattr, AT_FDCWD, config->rootdir,
                         AT_RECURSIVE, &ma, sizeof(ma));
#endif
        if (r != 0 && mount(NULL, config->rootdir, NULL,
                            MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV,
                            NULL) != 0) {
            perror("compartment-root: remount rootdir nosuid,nodev");
            exit(EXIT_FAILURE);
        }
        if (config->verbose)
            fprintf(stderr, "compartment-root: rootdir remounted "
                    "nosuid,nodev (%s)\n",
                    r == 0 ? "recursive" : "top mount only");
    }

    /* c) Enter new root */
    if (chdir(config->rootdir) != 0) {
        perror("compartment-root: chdir rootdir");
        exit(EXIT_FAILURE);
    }

    /* Create pivot point.  Fatal on failure: without it pivot_root() fails
     * with a bare ENOENT.  The usual cause is a non-identity uid-map whose
     * mapped host uid does not own rootdir. */
    if (mkdir(".pivot_old", 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "compartment-root: mkdir %s/.pivot_old: %s\n",
                config->rootdir, strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* d) pivot_root — no glibc wrapper, use syscall directly */
    if (syscall(SYS_pivot_root, ".", ".pivot_old") != 0) {
        perror("compartment-root: pivot_root");
        exit(EXIT_FAILURE);
    }

    /* e) Now "/" is the new root; the old root is still attached at
     *    /.pivot_old and stays there until step 6. */
    if (chdir("/") != 0) {
        perror("compartment-root: chdir /");
        exit(EXIT_FAILURE);
    }

    /* 4. Mount /proc + mask sensitive paths.
     *
     * Must run before the old root is detached — see the mount_too_revealing
     * note above. */
    (void)mkdir("/proc", 0555);
    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) != 0) {
        perror("compartment-root: mount proc");
        exit(EXIT_FAILURE);
    }
    /* Read cap_last_cap BEFORE masking /proc/sys — the mask hides
     * /proc/sys/kernel/cap_last_cap, causing drop_capabilities() to
     * use a stale fallback value and miss modern capabilities like
     * CAP_PERFMON(38), CAP_BPF(39), CAP_CHECKPOINT_RESTORE(40). */
    int cap_last_cap = 63;  /* safe max — covers all possible caps */
    {
        FILE *fcap = fopen("/proc/sys/kernel/cap_last_cap", "re");
        if (fcap) {
            if (fscanf(fcap, "%d", &cap_last_cap) != 1)
                cap_last_cap = 63;
            fclose(fcap);
        }
    }

    /* 5. Minimal /dev — tmpfs holding the host device nodes, bind-mounted
     *
     * mknod(2) can never work here.  vfs_mknod() gates character and block
     * device creation on capable(CAP_MKNOD) against the *initial* user
     * namespace, not ns_capable(), so every mknod() in a CLONE_NEWUSER
     * child returns EPERM.  The old code ignored those return values and
     * the container ended up with a /dev that had no device nodes at all:
     * `echo x > /dev/null` failed for every process inside.
     *
     * Bind-mounting the host's existing nodes is the standard workaround
     * and *is* permitted in a user namespace.  This is the second reason
     * the old root must still be attached at this point (see step 3):
     * /.pivot_old/dev is the only remaining path to real device nodes.
     *
     * The tmpfs is MS_NOSUID|MS_NOEXEC but deliberately NOT MS_NODEV —
     * MS_NODEV would make the nodes we just bound in unusable.
     */
    (void)mkdir("/dev", 0755);
    if (mount("tmpfs", "/dev", "tmpfs",
              MS_NOSUID | MS_NOEXEC, "size=64k,mode=0755") != 0) {
        perror("compartment-root: mount /dev tmpfs");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; default_dev_nodes[i]; i++) {
        char src[PATH_MAX], dst[PATH_MAX];
        snprintf(src, sizeof(src), "/.pivot_old/dev/%s", default_dev_nodes[i]);
        snprintf(dst, sizeof(dst), "/dev/%s", default_dev_nodes[i]);
        /* A bind mount needs an existing target — an empty regular file
         * is enough, the bind replaces it with the device node. */
        int dfd = open(dst, O_CREAT | O_WRONLY | O_CLOEXEC, 0666);
        if (dfd >= 0)
            close(dfd);
        if (mount(src, dst, NULL, MS_BIND, NULL) != 0) {
            fprintf(stderr, "compartment-root: bind %s -> %s: %s\n",
                    src, dst, strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (config->verbose)
            fprintf(stderr, "compartment-root: dev %s\n", dst);
    }
    (void)mkdir("/dev/pts", 0755);
    if (symlink("/proc/self/fd",   "/dev/fd")     < 0) { /* best-effort */ }
    if (symlink("/proc/self/fd/0", "/dev/stdin")  < 0) { /* best-effort */ }
    if (symlink("/proc/self/fd/1", "/dev/stdout") < 0) { /* best-effort */ }
    if (symlink("/proc/self/fd/2", "/dev/stderr") < 0) { /* best-effort */ }

    /* 5b. /sys — a fresh read-only sysfs.
     *
     * Subject to the same mount_too_revealing() constraint as /proc (see
     * step 3), so it has to happen here, while the host's /sys is still
     * reachable through /.pivot_old.  If the kernel refuses the mount
     * anyway — a host /sys with locked submounts covering non-empty
     * directories fails the visibility check — fall back to covering /sys
     * with an empty read-only tmpfs, so the container never sees a
     * writable or host-shared sysfs either way. */
    (void)mkdir("/sys", 0555);
    if (mount("sysfs", "/sys", "sysfs",
              MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) != 0) {
        if (config->verbose)
            fprintf(stderr, "compartment-root: mount sysfs: %s — masking "
                    "/sys instead\n", strerror(errno));
        if (mask_path(config, "/sys") != 0)
            exit(EXIT_FAILURE);
    } else {
        if (config->verbose)
            fprintf(stderr, "compartment-root: /sys mounted read-only\n");
        /* Hardware/firmware interfaces are of no use to a container and
         * have a history of privilege-escalation bugs. */
        if (mask_path(config, "/sys/firmware") != 0)
            exit(EXIT_FAILURE);
    }

    /* Default masks: hide kernel tunables, kernel memory and hardware
     * state.  Matches the OCI/runc baseline.  Every one of these is a
     * security control, so a mask that fails on an existing target is
     * fatal (they used to be `(void)mount(...)`, and two of them failed
     * on every run).  Targets that do not exist on this kernel are
     * skipped: /proc/timer_stats was removed in 4.11, /proc/latency_stats
     * needs CONFIG_LATENCYTOP, /proc/scsi needs CONFIG_SCSI_PROC_FS and
     * /proc/acpi needs ACPI. */
    for (int i = 0; default_proc_masks[i]; i++) {
        if (mask_path(config, default_proc_masks[i]) != 0)
            exit(EXIT_FAILURE);
    }

    /* Extra masks from profile/CLI */
    for (int i = 0; i < config->mount_mask_count; i++) {
        if (config->mount_masks[i][0] != '/') {
            fprintf(stderr, "compartment-root: mount-mask path must be absolute: %s\n",
                    config->mount_masks[i]);
            exit(EXIT_FAILURE);
        }
        if (path_has_dotdot(config->mount_masks[i])) {
            fprintf(stderr, "compartment-root: mount-mask path contains '..': %s\n",
                    config->mount_masks[i]);
            exit(EXIT_FAILURE);
        }
        if (mask_path(config, config->mount_masks[i]) != 0)
            exit(EXIT_FAILURE);
    }

    /* g) Detach the old root — everything that needed it (procfs
     *    visibility, host device nodes) is now in place. */
    if (umount2("/.pivot_old", MNT_DETACH) != 0) {
        perror("compartment-root: umount2 old root");
        exit(EXIT_FAILURE);
    }
    (void)rmdir("/.pivot_old");

    /* 6. Set hostname inside UTS namespace */
    if (sethostname("container", 9) < 0) { /* best-effort in userns */ }

    /* 7. Optional: bring up loopback in new network namespace.
     *
     * Not fatal — a container that cannot talk to itself is still a
     * usable container — but no longer silent: `loopback on` used to
     * discard both the socket() and the ioctl() result, so a container
     * with a down lo looked exactly like one with an up lo. */
    if (config->loopback && !config->netns) {
        int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (sock < 0) {
            fprintf(stderr, "compartment-root: warning: loopback socket: "
                    "%s\n", strerror(errno));
        } else {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
            ifr.ifr_flags = IFF_UP | IFF_RUNNING;
            if (ioctl(sock, SIOCSIFFLAGS, &ifr) != 0)
                fprintf(stderr, "compartment-root: warning: loopback up: "
                        "%s\n", strerror(errno));
            else if (config->verbose)
                fprintf(stderr, "compartment-root: loopback up\n");
            close(sock);
        }
    }

    /* 8. Set resource limits — AFTER close_range/FD cleanup below so the
     *    fallback loop can see the original RLIMIT_NOFILE, not the
     *    lowered value. Moved from here to step 19 below. */

    /* 9. Drop bounding-set capabilities BEFORE privilege drop
     *    (PR_CAPBSET_DROP needs CAP_SETPCAP — only available as root) */
    drop_capabilities(config, cap_last_cap);

    /* 10. Drop privileges (setgid/setuid to service user).
     *     If cap-allow is in use, preserve caps across setuid so we
     *     can restore effective+permitted for the service process. */
    if (config->cap_allowed_count > 0) {
        if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
            perror("compartment-root: PR_SET_KEEPCAPS");
            exit(EXIT_FAILURE);
        }
    }
    drop_privileges(cargs->drop_uid, cargs->drop_gid);

    /* 10b. Restore effective+permitted+inheritable caps after setuid.
     *      Without this, setuid to non-root clears all cap sets even
     *      though we kept the bounding set entries. Uses raw capset()
     *      syscall — no libcap. Also raise ambient caps so exec'd
     *      children inherit them. */
    if (config->cap_allowed_count > 0)
        apply_kept_caps(config);

    /* 11. Prevent ptrace attachment from outside */
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    /* 12. Environment sanitize */
    if (config->use_env_sanitize)
        sanitize_env(config);

    /* 13. Audit: log just before exec (while the audit fd is still open —
     *     the FD cleanup below closes it) */
    if (config->audit) {
        char detail[256];
        snprintf(detail, sizeof(detail), "command=%s", cmd_args[0]);
        audit_log(config, "CONTAINER_EXEC", detail);
    }

    /* 14. Close inherited FDs.
     *
     * This has to happen BEFORE the seccomp filter is installed.  It used
     * to run after, so a policy in allow-list mode that did not list
     * close_range/close left every inherited host fd — including the audit
     * log — open inside the container, with no diagnostic. */
#ifdef __NR_close_range
    /* close_range(2): Linux 5.9+, single syscall instead of a loop */
    if (syscall(__NR_close_range, 3U, ~0U, 0U) != 0)
#endif
    {
        /* Fallback for kernels < 5.9: use actual RLIMIT_NOFILE.
         * This runs BEFORE set_rlimits() so the original (higher) limit
         * is visible, ensuring FDs above 1024 are closed. */
        struct rlimit rl;
        int max_fd = 4096;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur > 3)
            max_fd = (int)(rl.rlim_cur < 1048576 ? rl.rlim_cur : 1048576);
        for (int i = 3; i < max_fd; i++) close(i);
    }

    /* 15. no-new-privs — unconditional.
     *
     * It is what makes the seccomp filter installable without privilege
     * and what stops a setuid binary inside rootdir from re-gaining
     * privilege after the drop.  The profile grammar has a
     * `no-new-privs off` switch for compartment-user; compartment-root
     * refuses to honour it (see main()).  Set before the fork below so the
     * container's init inherits it too. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "compartment-root: PR_SET_NO_NEW_PRIVS: %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* 16. Die with the parent.
     *
     * Set here, after the credential change: commit_creds() resets
     * pdeath_signal whenever the euid/egid or capability set changes, so
     * an earlier prctl() would have been thrown away.  Without it, killing
     * compartment-root left the whole container running. */
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0) {
        perror("compartment-root: PR_SET_PDEATHSIG");
        exit(EXIT_FAILURE);
    }

    /* 17. Fork the target under a minimal init.  Returns only in the
     *     child; this process stays behind as PID 1 of the pid namespace
     *     (see container_init).  Deliberately before the seccomp filter:
     *     PID 1 has to keep wait4/kill/rt_sigaction available even under
     *     an allow-list policy that does not mention them. */
    container_init();

    /* 18. seccomp (last enforcement step before exec) */
    if (config->use_seccomp) {
        if (apply_seccomp(config) != 0) {
            fprintf(stderr, "compartment-root: seccomp failed — aborting\n");
            exit(EXIT_FAILURE);
        }
    }

    /* 19. Set resource limits (AFTER FD cleanup so the fallback loop
     *     sees the original RLIMIT_NOFILE) */
    set_rlimits();

    execvp(cmd_args[0], cmd_args);
    perror("compartment-root: execvp");
    exit(EXIT_FAILURE);
}

/* ── Container init (PID 1 of the new pid namespace) ────────────────── */

static volatile sig_atomic_t init_target = 0;   /* pid of the exec'd command */

static void init_forward(int sig)
{
    if (init_target > 0)
        kill((pid_t)init_target, sig);      /* async-signal-safe */
}

/*
 * container_init — fork the target and stay behind as PID 1.
 *
 * The target used to be PID 1 itself, which has two consequences nobody
 * wants: PID 1 discards every signal for which it has no handler (Ctrl-C
 * does not stop a plain /bin/sh), and orphaned grandchildren are reparented
 * to it and never reaped.
 *
 * So PID 1 is this loop instead: forward SIGTERM/SIGINT/SIGHUP/SIGQUIT to
 * the target, reap everything else, and exit with the target's status
 * (128+n if it was killed).  Returns in the child; never returns in PID 1.
 *
 * PID 1 is deliberately left outside the seccomp filter, which the target
 * installs for itself after the fork: an allow-list policy that does not
 * mention wait4/kill/rt_sigaction would otherwise break the reaper.  It is
 * still inside every namespace and carries the same dropped capabilities,
 * dropped uid and no-new-privs as the target; it execs nothing and does
 * nothing but wait.
 */
static void container_init(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("compartment-root: fork (container init)");
        exit(EXIT_FAILURE);
    }
    if (pid == 0)
        return;                             /* target: caller execs */

    init_target = pid;

    static const int fwd[] = { SIGTERM, SIGINT, SIGHUP, SIGQUIT };
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = init_forward;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;    /* no SA_RESTART: waitpid() must return EINTR */
    for (size_t i = 0; i < sizeof(fwd) / sizeof(fwd[0]); i++)
        (void)sigaction(fwd[i], &sa, NULL);

    int status = 0;
    for (;;) {
        int st;
        pid_t p = waitpid(-1, &st, 0);
        if (p == -1) {
            if (errno == EINTR)
                continue;                   /* signal forwarded, keep waiting */
            break;                          /* ECHILD: nothing left */
        }
        if (p == pid) {                     /* the target itself */
            status = st;
            break;
        }
    }
    while (waitpid(-1, NULL, WNOHANG) > 0)  /* reap stragglers */
        ;

    _exit(WIFSIGNALED(status) ? 128 + WTERMSIG(status)
                              : (WIFEXITED(status) ? WEXITSTATUS(status) : 1));
}

/* ── UID/GID map writer (called by parent) ──────────────────────────── */

/*
 * deny_setgroups — write "deny" to /proc/<pid>/setgroups before gid_map
 *
 * Standard user-namespace hardening: while setgroups(2) is still allowed
 * inside the namespace, a process can drop a supplementary group that
 * carried a *negative* permission (a group named in a deny ACL) and gain
 * access it did not have.  compartment-root's parent is real root, so the
 * gid_map write succeeds either way — this is defence in depth, and it has
 * to happen before the gid map is written.
 *
 * Skipped when the policy explicitly keeps CAP_SETGID: a container that is
 * allowed to change its groups needs setgroups() to work.
 */
static void deny_setgroups(pid_t pid, Config *config)
{
    for (int i = 0; i < config->cap_allowed_count; i++) {
        if (resolve_cap(config->cap_allowed_names[i]) == CAP_SETGID) {
            if (config->verbose)
                fprintf(stderr, "compartment-root: setgroups left enabled "
                        "(policy keeps CAP_SETGID)\n");
            return;
        }
    }

    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);

    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd == -1) {
        /* Kernels before 3.19 have no such file — nothing to deny. */
        if (errno == ENOENT)
            return;
        fprintf(stderr, "compartment-root: open %s: %s\n",
                path, strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (write(fd, "deny", 4) != 4) {
        fprintf(stderr, "compartment-root: write %s: %s\n",
                path, strerror(errno));
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
    if (config->verbose)
        fprintf(stderr, "compartment-root: setgroups denied\n");
}

static void write_uid_gid_map(pid_t pid, const char *map_str,
                               const char *map_file)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/%s", pid, map_file);

    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd == -1) {
        fprintf(stderr, "compartment-root: open %s: %s\n",
                path, strerror(errno));
        exit(EXIT_FAILURE);
    }

    ssize_t len = (ssize_t)strlen(map_str);
    if (write(fd, map_str, (size_t)len) != len) {
        fprintf(stderr, "compartment-root: write %s: %s\n",
                path, strerror(errno));
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
}

/* ── Privilege drop ──────────────────────────────────────────────────── */

static void drop_privileges(uid_t uid, gid_t gid)
{
    /* Clear supplementary groups.  Normally a no-op: the parent already
     * cleared them before clone() and then wrote "deny" to
     * /proc/<pid>/setgroups, so this call is expected to return EPERM. */
    if (setgroups(0, NULL) != 0 && errno != EPERM) {
        perror("compartment-root: setgroups");
        exit(EXIT_FAILURE);
    }
    if (setgid(gid) != 0) {
        perror("compartment-root: setgid");
        exit(EXIT_FAILURE);
    }
    if (setuid(uid) != 0) {
        perror("compartment-root: setuid");
        exit(EXIT_FAILURE);
    }
}

/*
 * drop_capabilities — drop bounding-set capabilities not in the allow list
 *
 * Uses raw prctl(PR_CAPBSET_DROP) — no libcap required.
 * Reads CAP_LAST_CAP from /proc/sys/kernel/cap_last_cap so we handle
 * future kernel capability additions without code changes.
 *
 * This only modifies the bounding set. After privilege drop (setuid to
 * non-root), effective+permitted caps are cleared by the kernel.
 * apply_kept_caps() must be called after drop_privileges() to restore
 * the effective+permitted sets via raw capset() syscall.
 *
 * MUST be called while still root (UID 0 inside the user namespace) —
 * PR_CAPBSET_DROP requires CAP_SETPCAP, which is lost after setuid.
 */
static void drop_capabilities(Config *config, int cap_last)
{

    /* Build the allow-set from cap_allowed_names[] */
    int allowed[64] = {0};
    for (int i = 0; i < config->cap_allowed_count; i++) {
        int nr = resolve_cap(config->cap_allowed_names[i]);
        if (nr < 0 || nr > 63) {
            fprintf(stderr, "compartment-root: invalid capability: %s\n",
                    config->cap_allowed_names[i]);
            exit(EXIT_FAILURE);
        }
        allowed[nr] = 1;
    }

    /* Drop everything not explicitly allowed from the bounding set */
    for (int cap = 0; cap <= cap_last; cap++) {
        if (!allowed[cap]) {
            if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0 && errno != EINVAL) {
                fprintf(stderr, "compartment-root: prctl(PR_CAPBSET_DROP, %d): %s\n",
                        cap, strerror(errno));
            }
        }
    }

    if (config->verbose)
        fprintf(stderr, "compartment-root: capabilities dropped "
                "(%d of %d kept)\n", config->cap_allowed_count, cap_last + 1);
}

/*
 * apply_kept_caps — restore effective+permitted+inheritable caps after setuid
 *
 * After PR_SET_KEEPCAPS + setuid(), the permitted set is preserved but
 * effective is cleared. This function:
 *   1. Uses raw capset() syscall to set effective = permitted = inheritable
 *      to the allowed cap set
 *   2. Raises ambient caps (PR_CAP_AMBIENT_RAISE) so exec'd children
 *      inherit them without needing setuid binaries
 *
 * No libcap — uses raw capset(2) via syscall().
 */
static void apply_kept_caps(Config *config)
{
    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0  /* current process */
    };
    struct __user_cap_data_struct data[2] = {{0}};

    /* Build cap mask from allowed list */
    for (int i = 0; i < config->cap_allowed_count; i++) {
        int cap = resolve_cap(config->cap_allowed_names[i]);
        if (cap < 0 || cap > 63) continue;  /* already validated in drop_capabilities */
        unsigned idx = (unsigned)cap >> 5;
        unsigned bit = 1U << ((unsigned)cap & 31);
        data[idx].effective   |= bit;
        data[idx].permitted   |= bit;
        data[idx].inheritable |= bit;
    }

    if (syscall(SYS_capset, &hdr, data) != 0) {
        fprintf(stderr, "compartment-root: capset: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Raise ambient caps so children inherit without setuid.
     * Requires cap in both permitted and inheritable sets (done above).
     * Available since Linux 4.3. */
    for (int i = 0; i < config->cap_allowed_count; i++) {
        int cap = resolve_cap(config->cap_allowed_names[i]);
        if (cap < 0) continue;
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) != 0) {
            if (config->verbose)
                fprintf(stderr, "compartment-root: PR_CAP_AMBIENT_RAISE(%d): %s\n",
                        cap, strerror(errno));
            /* Non-fatal: ambient caps are optional (kernel < 4.3) */
        }
    }

    if (config->verbose)
        fprintf(stderr, "compartment-root: effective+permitted caps restored "
                "for service user (%d caps)\n", config->cap_allowed_count);
}

/* ── Mount masking (child, inside the new mount namespace) ─────────── */

/*
 * mask_path — hide one path from the container.
 *
 * A directory is covered with an empty read-only tmpfs; anything else is
 * covered with a bind of /dev/null, which is why the /dev nodes have to be
 * in place first (step 5).  Both are ordinary bind/tmpfs mounts, so unlike
 * the procfs and sysfs mounts they are not subject to mount_too_revealing()
 * and can run after the old root is gone.
 *
 * Returns 0 when the path was masked or does not exist on this kernel,
 * -1 when it exists and could not be masked.
 */
static int mask_path(Config *config, const char *path)
{
    struct stat st;

    if (lstat(path, &st) != 0) {
        if (errno == ENOENT) {
            if (config->verbose)
                fprintf(stderr, "compartment-root: mask %s: absent, skipped\n",
                        path);
            return 0;
        }
        fprintf(stderr, "compartment-root: mask %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    int is_dir = S_ISDIR(st.st_mode);
    int r = is_dir
        ? mount("tmpfs", path, "tmpfs",
                MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV, "size=0")
        : mount("/dev/null", path, NULL, MS_BIND, NULL);

    if (r != 0) {
        fprintf(stderr, "compartment-root: mask %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    if (config->verbose)
        fprintf(stderr, "compartment-root: mask %s (%s)\n", path,
                is_dir ? "empty tmpfs" : "/dev/null");
    return 0;
}

/* ── Cgroup assignment (called by parent, host filesystem context) ──── */

/* Return non-zero if path contains a ".." component (path traversal guard). */
static int path_has_dotdot(const char *path)
{
    const char *p = path;
    while (*p) {
        /* Match a ".." segment: at start, after '/', or before '/' or '\0' */
        if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0') &&
            (p == path || p[-1] == '/'))
            return 1;
        p++;
    }
    return 0;
}

static int assign_to_cgroups(Config *config, pid_t pid)
{
    /* Every cgroup path must live under the cgroup filesystem.  Without
     * this check the code below happily created <path>/cgroup.procs
     * anywhere a root process can write: `--cgroup /etc/cron.d` produced
     * /etc/cron.d/cgroup.procs. */
    static const char CGROUP_ROOT[] = "/sys/fs/cgroup/";
    const size_t CGROUP_ROOT_LEN = sizeof(CGROUP_ROOT) - 1;

    for (int i = 0; i < config->cgroups_count; i++) {
        const char *want = config->cgroups[i];

        /* Reject relative paths and paths with ".." traversal components */
        if (want[0] != '/') {
            fprintf(stderr, "compartment-root: cgroup path must be absolute: %s\n",
                    want);
            return -1;
        }
        if (path_has_dotdot(want)) {
            fprintf(stderr, "compartment-root: cgroup path contains '..': %s\n",
                    want);
            return -1;
        }
        if (strncmp(want, CGROUP_ROOT, CGROUP_ROOT_LEN) != 0) {
            fprintf(stderr, "compartment-root: cgroup path must be under %s: %s\n",
                    CGROUP_ROOT, want);
            return -1;
        }

        /* Resolve symlinks and re-check the prefix: a symlinked component
         * could otherwise redirect the write out of the cgroup tree. */
        char resolved[PATH_MAX];
        if (!realpath(want, resolved)) {
            fprintf(stderr, "compartment-root: cgroup %s: %s\n",
                    want, strerror(errno));
            return -1;
        }
        if (strncmp(resolved, CGROUP_ROOT, CGROUP_ROOT_LEN) != 0) {
            fprintf(stderr, "compartment-root: cgroup path resolves outside "
                    "%s: %s -> %s\n", CGROUP_ROOT, want, resolved);
            return -1;
        }

        char procs_file[PATH_MAX];
        int n = snprintf(procs_file, sizeof(procs_file), "%s/cgroup.procs",
                         resolved);
        if (n < 0 || (size_t)n >= sizeof(procs_file)) {
            fprintf(stderr, "compartment-root: cgroup path too long: %s\n",
                    want);
            return -1;
        }

        /* No O_CREAT — cgroup.procs is created by the kernel and must
         * already exist.  O_NOFOLLOW so a symlink planted at the final
         * component is refused rather than followed. */
        int fd = open(procs_file, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            fprintf(stderr, "compartment-root: cgroup %s: %s\n",
                    procs_file, strerror(errno));
            return -1;
        }
        char buf[32];
        int len = snprintf(buf, sizeof(buf), "%d\n", pid);
        if (len < 0 || write(fd, buf, (size_t)len) != len) {
            fprintf(stderr, "compartment-root: cgroup %s: %s\n",
                    procs_file, strerror(errno));
            close(fd);
            return -1;
        }
        close(fd);
        if (config->verbose)
            fprintf(stderr, "compartment-root: cgroup %s\n", resolved);
    }
    return 0;
}

/* ── Network namespace join ──────────────────────────────────────────── */

static void join_netns(const char *netns_name)
{
    /* Reject names with '/' — only simple names are valid under /var/run/netns/ */
    if (strchr(netns_name, '/') != NULL) {
        fprintf(stderr, "compartment-root: invalid netns name (contains '/'): %s\n",
                netns_name);
        exit(EXIT_FAILURE);
    }

    /* Ensure the constructed path fits (prefix is 16 chars: "/var/run/netns/") */
    if (strlen(netns_name) >= PATH_MAX - 16) {
        fprintf(stderr, "compartment-root: netns name too long: %s\n", netns_name);
        exit(EXIT_FAILURE);
    }

    char netns_path[PATH_MAX];
    snprintf(netns_path, sizeof(netns_path), "/var/run/netns/%s", netns_name);

    int fd = open(netns_path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        perror("compartment-root: open netns");
        exit(EXIT_FAILURE);
    }
    if (setns(fd, CLONE_NEWNET) == -1) {
        perror("compartment-root: setns");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
}

/* ── Resource limits ─────────────────────────────────────────────────── */

static void set_rlimits(void)
{
    struct rlimit rl;

    /* Limit open files */
    rl.rlim_cur = 1024;
    rl.rlim_max = 1024;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        perror("compartment-root: setrlimit RLIMIT_NOFILE");
        exit(EXIT_FAILURE);
    }

    /* CPU time: unlimited (can be overridden via cgroups) */
    rl.rlim_cur = RLIM_INFINITY;
    rl.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_CPU, &rl) != 0) {
        perror("compartment-root: setrlimit RLIMIT_CPU");
        exit(EXIT_FAILURE);
    }
}

/* ── Help ────────────────────────────────────────────────────────────── */

/* Size of the built-in deny-list on this architecture (for --help). */
static int builtin_denylist_size(void)
{
    Config tmp;
    memset(&tmp, 0, sizeof(tmp));
    apply_default_seccomp_denylist(&tmp);
    return tmp.blocked_count;
}


static void print_help(const char *prog_name)
{
    printf("compartment-root — full-namespace process isolation (requires root)\n\n");
    printf("Usage: %s [OPTIONS] -- COMMAND [ARGS...]\n", prog_name);
    printf("\nProfile:\n");
    printf("  -p, --profile <name|file>        Load policy from profile file\n");
    printf("                                   A name resolves to /etc/compartment/<name>.conf\n");
    printf("                                   and nowhere else; an argument containing '/'\n");
    printf("                                   is loaded as a path. $HOME is never searched:\n");
    printf("                                   the policy of a root tool must not come from a\n");
    printf("                                   directory the caller controls.\n");
    printf("                                   The file and its directory must be root-owned\n");
    printf("                                   and not group- or world-writable.\n");
    printf("\nNamespace:\n");
    printf("  -c, --rootdir <dir>              Root filesystem directory (required)\n");
    printf("  -u, --uid <uid>                  Override UID for privilege drop\n");
    printf("  -g, --gid <gid>                  Override GID for privilege drop\n");
    printf("  -U, --username <username>        Service user for privilege drop (required)\n");
    printf("  -n, --netns <namespace>          Network namespace to join\n");
    printf("  -l, --loopback                   Bring up loopback in new netns\n");
    printf("  -C, --cgroup <path>              Cgroup path (repeatable)\n");
    printf("  -M, --mount-mask <path>          Extra path to mask in /proc (repeatable)\n");
    printf("\nCapabilities:\n");
    printf("  -A, --cap-allowed <cap>          Allowed capability (repeatable)\n");
    printf("                                   Accepts: CAP_NET_BIND_SERVICE or net_bind_service\n");
    printf("\nSyscalls (seccomp BPF):\n");
    printf("  -a, --seccomp-allowed <syscall>  Allowed syscall, allow-list mode (repeatable)\n");
    printf("  -B, --block <syscall>            Blocked syscall, deny-list mode (repeatable)\n");
    printf("      --no-seccomp                 Disable seccomp entirely\n");
    printf("                                   With neither -a nor -B and no profile\n");
    printf("                                   list, the built-in deny-list (%d\n",
           builtin_denylist_size());
    printf("                                   syscalls) is installed.\n");
    printf("\nEnvironment:\n");
    printf("  -E, --env-deny <var>             Strip environment variable (repeatable)\n");
    printf("  -e, --env-allow <var>            Keep only listed env vars (repeatable)\n");
    printf("      --no-env-sanitize            Don't strip environment variables\n");
    printf("\nGeneral:\n");
    printf("      --dry-run                    Show what would be applied, don't enforce\n");
    printf("  -v, --verbose                    Print actions to stderr; with\n");
    printf("                                   --dry-run, also list the built-in\n");
    printf("                                   masks, devices and blocked syscalls\n");
    printf("      --audit                      Log events to stderr + file\n");
    printf("  -L, --audit-log <dir>            Audit log DIRECTORY (implies --audit);\n");
    printf("                                   the log file is <dir>/YYYY-MM-DD.log\n");
    printf("      --verify                     Check system support and exit\n");
    printf("  -h, --help                       This help\n");
    printf("\nHardening (always on):\n");
    printf("  pivot_root (old root unmounted), container root remounted\n");
    printf("  nosuid+nodev, /dev with bind-mounted device nodes, read-only\n");
    printf("  /sys, %d masked /proc paths, UTS hostname isolation,\n",
           count_strv(default_proc_masks));
    printf("  setgroups denied, PID 1 reaper + PR_SET_PDEATHSIG,\n");
    printf("  PR_SET_DUMPABLE(0), PR_SET_NO_NEW_PRIVS, seccomp BPF\n");
    printf("\nExamples:\n");
    printf("  %s --profile container -- /bin/sh\n", prog_name);
    printf("  %s -c /srv/jail -u 1000 -g 1000 -U svc -- /usr/bin/myapp\n", prog_name);
    printf("  %s -c /srv/jail -U svc -l --audit -- /bin/bash\n", prog_name);
    printf("  %s --profile container --dry-run -- /bin/sh\n", prog_name);
    printf("\nSee also: compartment-user (rootless), sandbox.sh (network namespace)\n");
}
