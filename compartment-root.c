/*
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 * SPDX-License-Identifier: Apache-2.0
 *
 * compartment-root — full-namespace process isolation (requires root)
 *
 * Creates a fully isolated container using Linux namespaces:
 *   1. clone() with NEWUTS, NEWNS, NEWPID, NEWIPC, NEWNET, NEWUSER, NEWCGROUP
 *   2. Parent: UID/GID range mapping + cgroup assignment (host context)
 *   3. Child: pivot_root into new root (old root fully unmounted)
 *   4. Child: Minimal /dev, mount /proc, mask sensitive paths
 *   5. Child: Hostname isolation, optional loopback
 *   6. Child: Resource limits (rlimits)
 *   7. Child: Capability bounding-set drop (raw prctl — while still root)
 *   8. Child: PR_SET_KEEPCAPS + privilege drop (setuid/setgid)
 *   8b.Child: capset() to restore effective+permitted+inheritable caps
 *   9. Child: PR_SET_DUMPABLE(0) — prevent ptrace
 *  10. Child: Environment sanitize, seccomp BPF (fatal on failure)
 *  11. Child: Close inherited FDs, exec the target command
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
#include <sys/sysmacros.h>
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
static void drop_privileges(uid_t uid, gid_t gid);
static void drop_capabilities(Config *config);
static void apply_kept_caps(Config *config);
static int  assign_to_cgroups(Config *config, pid_t pid);
static int  path_has_dotdot(const char *path);
static void join_netns(const char *netns_name);
static void set_rlimits(void);
static void print_help(const char *prog_name);

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

    /* ── Pre-scan for --profile (loads BEFORE CLI so CLI overrides) ── */
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--profile") == 0 || strcmp(argv[i], "-p") == 0)
            && i + 1 < argc) {
            config.profile = argv[i + 1];
            if (resolve_and_load_profile(&config, config.profile, 0) != 0) {
                fprintf(stderr, "compartment-root: unknown profile: %s\n",
                        config.profile);
                fprintf(stderr, "  searched: ~/.config/compartment/%s.conf, "
                        "/etc/compartment/%s.conf\n",
                        config.profile, config.profile);
                return 1;
            }
            break;
        }
    }

    /* ── Parse CLI (overrides profile values) ───────────────────────── */

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

    int opt;
    while ((opt = getopt_long(argc, argv, "+p:c:u:g:a:B:n:C:A:E:e:M:L:U:lSNdvDVh",
                              long_options, NULL)) != -1) {
        switch (opt) {
        case 'p': /* already handled in pre-scan */ break;
        case 'c':
            free(config.rootdir);
            config.rootdir = strdup(optarg);
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
            config.username = strdup(optarg);
            break;
        case 'a': { /* --seccomp-allowed */
            int nr = resolve_syscall(optarg);
            if (nr < 0) {
                fprintf(stderr, "compartment-root: unknown syscall: %s\n", optarg);
                return 1;
            }
            if (config.allowed_sc_count < MAX_ALLOWED_SC) {
                config.allowed_syscalls[config.allowed_sc_count++] = nr;
                config.seccomp_allow_mode = 1;
            }
            break;
        }
        case 'B': { /* --block */
            int nr = resolve_syscall(optarg);
            if (nr < 0) {
                fprintf(stderr, "compartment-root: unknown syscall: %s\n", optarg);
                return 1;
            }
            if (config.blocked_count < MAX_BLOCKED_SC)
                config.blocked_syscalls[config.blocked_count++] = nr;
            break;
        }
        case 'n':
            free(config.netns);
            config.netns = strdup(optarg);
            break;
        case 'C':
            if (config.cgroups_count < MAX_PATHS)
                config.cgroups[config.cgroups_count++] = strdup(optarg);
            break;
        case 'A':
            if (config.cap_allowed_count < MAX_ENV_VARS)
                config.cap_allowed_names[config.cap_allowed_count++] = strdup(optarg);
            break;
        case 'E':
            if (config.env_deny_count < MAX_ENV_VARS)
                config.env_deny[config.env_deny_count++] = optarg;
            break;
        case 'e':
            if (config.env_allow_count < MAX_ENV_VARS) {
                config.env_allow[config.env_allow_count++] = optarg;
                config.env_allow_mode = 1;
                config.use_env_sanitize = 1;
            }
            break;
        case 'M':
            if (config.mount_mask_count < MAX_PATHS)
                config.mount_masks[config.mount_mask_count++] = strdup(optarg);
            break;
        case 'L': config.audit_log_dir = optarg; config.audit = 1; break;
        case 'l': config.loopback = 1; break;
        case 'S': config.use_seccomp = 0; break;
        case 'N': config.use_env_sanitize = 0; break;
        case 'd': config.dry_run = 1; config.verbose = 1; break;
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
        fprintf(stderr, "  namespace mapping: 0-65535 → 0-65535 (range)\n");
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
            fprintf(stderr, "  seccomp: %s DENY-LIST (%d blocked)\n",
                    config.use_seccomp ? "yes" : "no",
                    config.blocked_count);
        }
        fprintf(stderr, "  env-sanitize: %s\n",
                config.use_env_sanitize ? "yes" : "no");
        if (config.env_allow_mode)
            fprintf(stderr, "  env: ALLOW-LIST (%d kept)\n",
                    config.env_allow_count);
        else if (config.env_deny_count > 0)
            fprintf(stderr, "  env: DENY-LIST (%d stripped)\n",
                    config.env_deny_count);
        fprintf(stderr, "  cgroups: %d\n", config.cgroups_count);
        fprintf(stderr, "  mount-masks: %d (+ 4 default)\n",
                config.mount_mask_count);
        if (config.audit)
            fprintf(stderr, "  audit: yes (log: %s)\n",
                    config.audit_log_dir ? config.audit_log_dir :
                    "/var/tmp/compartment-audit-$UID/");
        fprintf(stderr, "  command: %s\n", argv[optind]);
        return 0;
    }

    /* ── Audit log (open BEFORE clone — fd is on host filesystem) ──── */

    if (config.audit) {
        audit_log_open(&config);

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

    /* Write UID/GID maps — parent has root in parent namespace, can
     * write multi-entry range maps. Maps inside 0-65535 → outside
     * 0-65535 so the child can operate as root (UID 0) during setup
     * and later setuid to the service user (drop_uid). */
    write_uid_gid_map(child_pid, "0 0 65536\n", "uid_map");
    write_uid_gid_map(child_pid, "0 0 65536\n", "gid_map");

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

    /* Now we're root inside the user namespace (0→0 range mapping).
     * Parent has also assigned cgroups from the host context. */

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
     *   e) umount old root, remove pivot point
     *   f) chdir("/")
     *
     * After this, there is no FD or path to the old root — unlike chroot,
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

    /* c) Enter new root */
    if (chdir(config->rootdir) != 0) {
        perror("compartment-root: chdir rootdir");
        exit(EXIT_FAILURE);
    }

    /* Create pivot point */
    (void)mkdir(".pivot_old", 0700);

    /* d) pivot_root — no glibc wrapper, use syscall directly */
    if (syscall(SYS_pivot_root, ".", ".pivot_old") != 0) {
        perror("compartment-root: pivot_root");
        exit(EXIT_FAILURE);
    }

    /* e) Unmount and remove old root */
    if (umount2("/.pivot_old", MNT_DETACH) != 0) {
        perror("compartment-root: umount2 old root");
        exit(EXIT_FAILURE);
    }
    (void)rmdir("/.pivot_old");

    /* f) Now "/" is the new root, old root is gone */
    if (chdir("/") != 0) {
        perror("compartment-root: chdir /");
        exit(EXIT_FAILURE);
    }

    /* 4. Minimal /dev — tmpfs with only safe devices */
    (void)mkdir("/dev", 0755);
    if (mount("tmpfs", "/dev", "tmpfs",
              MS_NOSUID | MS_NOEXEC, "size=64k,mode=0755") == 0) {
        mknod("/dev/null",    S_IFCHR | 0666, makedev(1, 3));
        mknod("/dev/zero",    S_IFCHR | 0666, makedev(1, 5));
        mknod("/dev/full",    S_IFCHR | 0666, makedev(1, 7));
        mknod("/dev/random",  S_IFCHR | 0666, makedev(1, 8));
        mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9));
        (void)mkdir("/dev/pts", 0755);
        if (symlink("/proc/self/fd",   "/dev/fd")     < 0) { /* best-effort */ }
        if (symlink("/proc/self/fd/0", "/dev/stdin")  < 0) { /* best-effort */ }
        if (symlink("/proc/self/fd/1", "/dev/stdout") < 0) { /* best-effort */ }
        if (symlink("/proc/self/fd/2", "/dev/stderr") < 0) { /* best-effort */ }
    }
    /* If /dev mount fails (no CAP_SYS_ADMIN inside userns), use existing /dev */

    /* 5. Mount /proc + mask sensitive paths */
    (void)mkdir("/proc", 0555);
    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) != 0) {
        perror("compartment-root: mount proc");
        exit(EXIT_FAILURE);
    }
    /* Default masks: hide kernel tunables and memory */
    (void)mount("tmpfs", "/proc/sys", "tmpfs",
                MS_RDONLY | MS_NOSUID | MS_NOEXEC, "size=0");
    (void)mount("/dev/null", "/proc/sysrq-trigger", NULL, MS_BIND, NULL);
    (void)mount("/dev/null", "/proc/kcore", NULL, MS_BIND, NULL);
    (void)mount("tmpfs", "/proc/acpi", "tmpfs",
                MS_RDONLY | MS_NOSUID | MS_NOEXEC, "size=0");
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
        if (config->verbose)
            fprintf(stderr, "compartment-root: mount-mask %s\n",
                    config->mount_masks[i]);
        (void)mount("tmpfs", config->mount_masks[i], "tmpfs",
                    MS_RDONLY | MS_NOSUID | MS_NOEXEC, "size=0");
    }

    /* 6. Set hostname inside UTS namespace */
    if (sethostname("container", 9) < 0) { /* best-effort in userns */ }

    /* 7. Optional: bring up loopback in new network namespace */
    if (config->loopback && !config->netns) {
        int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (sock >= 0) {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
            ifr.ifr_flags = IFF_UP | IFF_RUNNING;
            (void)ioctl(sock, SIOCSIFFLAGS, &ifr);
            close(sock);
        }
    }

    /* 8. Set resource limits */
    set_rlimits();

    /* 9. Drop bounding-set capabilities BEFORE privilege drop
     *    (PR_CAPBSET_DROP needs CAP_SETPCAP — only available as root) */
    drop_capabilities(config);

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

    /* 13. seccomp (must be after no_new_privs, last before exec) */
    if (config->use_no_new_privs) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            fprintf(stderr, "compartment-root: PR_SET_NO_NEW_PRIVS: %s\n",
                    strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    if (config->use_seccomp) {
        if (apply_seccomp(config) != 0) {
            fprintf(stderr, "compartment-root: seccomp failed — aborting\n");
            exit(EXIT_FAILURE);
        }
    }

    /* Audit: log just before exec (while audit fd is still open) */
    if (config->audit) {
        char detail[256];
        snprintf(detail, sizeof(detail), "command=%s", cmd_args[0]);
        audit_log(config, "CONTAINER_EXEC", detail);
    }

    /* 14. Close inherited FDs and exec */
#ifdef __NR_close_range
    /* close_range(2): Linux 5.9+, single syscall instead of a loop */
    if (syscall(__NR_close_range, 3U, ~0U, 0U) != 0)
#endif
    {
        /* Fallback for kernels < 5.9: use actual RLIMIT_NOFILE, not hardcoded 4096 */
        struct rlimit rl;
        int max_fd = 4096;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur > 3)
            max_fd = (int)(rl.rlim_cur < 1048576 ? rl.rlim_cur : 1048576);
        for (int i = 3; i < max_fd; i++) close(i);
    }
    execvp(cmd_args[0], cmd_args);
    perror("compartment-root: execvp");
    exit(EXIT_FAILURE);
}

/* ── UID/GID map writer (called by parent) ──────────────────────────── */

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
    /* Clear supplementary groups */
    if (setgroups(0, NULL) != 0) {
        if (errno != EPERM) {
            perror("compartment-root: setgroups");
            exit(EXIT_FAILURE);
        }
        /* EPERM can happen if setgroups was denied — non-fatal,
         * supplementary groups are empty in a new user namespace */
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
static void drop_capabilities(Config *config)
{
    /* Read the highest valid capability number from the kernel */
    int cap_last = 37;  /* safe fallback (covers up to CAP_AUDIT_READ) */
    FILE *f = fopen("/proc/sys/kernel/cap_last_cap", "re");
    if (f) {
        if (fscanf(f, "%d", &cap_last) != 1)
            cap_last = 37;
        fclose(f);
    }

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
    for (int i = 0; i < config->cgroups_count; i++) {
        /* Reject relative paths and paths with ".." traversal components */
        if (config->cgroups[i][0] != '/') {
            fprintf(stderr, "compartment-root: cgroup path must be absolute: %s\n",
                    config->cgroups[i]);
            return -1;
        }
        if (path_has_dotdot(config->cgroups[i])) {
            fprintf(stderr, "compartment-root: cgroup path contains '..': %s\n",
                    config->cgroups[i]);
            return -1;
        }
        char tasks_file[PATH_MAX];
        int n = snprintf(tasks_file, sizeof(tasks_file), "%s/cgroup.procs",
                 config->cgroups[i]);
        if (n < 0 || (size_t)n >= sizeof(tasks_file)) {
            fprintf(stderr, "compartment-root: cgroup path too long: %s\n",
                    config->cgroups[i]);
            return -1;
        }

        FILE *f = fopen(tasks_file, "we");
        if (!f) {
            fprintf(stderr, "compartment-root: cgroup %s: %s\n",
                    tasks_file, strerror(errno));
            return -1;
        }
        fprintf(f, "%d\n", pid);
        fclose(f);
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

static void print_help(const char *prog_name)
{
    printf("compartment-root — full-namespace process isolation (requires root)\n\n");
    printf("Usage: %s [OPTIONS] -- COMMAND [ARGS...]\n", prog_name);
    printf("\nProfile:\n");
    printf("  -p, --profile <name|file>        Load policy from profile file\n");
    printf("                                   Search: ~/.config/compartment/<name>.conf\n");
    printf("                                           /etc/compartment/<name>.conf\n");
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
    printf("\nEnvironment:\n");
    printf("  -E, --env-deny <var>             Strip environment variable (repeatable)\n");
    printf("  -e, --env-allow <var>            Keep only listed env vars (repeatable)\n");
    printf("      --no-env-sanitize            Don't strip environment variables\n");
    printf("\nGeneral:\n");
    printf("      --dry-run                    Show what would be applied, don't enforce\n");
    printf("  -v, --verbose                    Print actions to stderr\n");
    printf("      --audit                      Log events to stderr + file\n");
    printf("  -L, --audit-log <dir>            Set audit log directory (implies --audit)\n");
    printf("      --verify                     Check system support and exit\n");
    printf("  -h, --help                       This help\n");
    printf("\nHardening (always on):\n");
    printf("  pivot_root (old root unmounted), minimal /dev, /proc masking,\n");
    printf("  UTS hostname isolation, PR_SET_DUMPABLE(0), PR_SET_NO_NEW_PRIVS\n");
    printf("\nExamples:\n");
    printf("  %s --profile container -- /bin/sh\n", prog_name);
    printf("  %s -c /srv/jail -u 1000 -g 1000 -U svc -- /usr/bin/myapp\n", prog_name);
    printf("  %s -c /srv/jail -U svc -l --audit -- /bin/bash\n", prog_name);
    printf("  %s --profile container --dry-run -- /bin/sh\n", prog_name);
    printf("\nSee also: compartment-user (rootless), sandbox.sh (network namespace)\n");
}
