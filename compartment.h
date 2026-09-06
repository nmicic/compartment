/*
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 * SPDX-License-Identifier: Apache-2.0
 *
 * compartment.h — shared code for compartment-user and compartment-root
 *
 * All functions are static inline so both tools remain single-file builds:
 *   cc -o compartment-user compartment-user.c   (just #includes this header)
 *   cc -o compartment-root compartment-root.c   (just #includes this header)
 *
 * No separate compilation unit, no linking, no build system complexity.
 * The header is included directly — each binary gets its own copy.
 *
 * Version: defined by COMPARTMENT_VERSION below.
 *
 * Contents:
 *   - PathRule, PathMode types and constants
 *   - Config struct (shared fields: paths, syscalls, env, flags, audit)
 *   - SyscallEntry table (x86_64 + aarch64) and resolve_syscall()
 *   - CapEntry table and resolve_cap() [for compartment-root cap drop]
 *   - expand_var()
 *   - load_profile_file() + resolve_and_load_profile()
 *   - audit_log_open() + audit_log() + get_ppid_chain()
 *   - sanitize_env()
 *   - build_seccomp_bpf() + apply_seccomp() (raw BPF, no libseccomp)
 */
#ifndef COMPARTMENT_H
#define COMPARTMENT_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define COMPARTMENT_VERSION "1.3.3"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

/* SECCOMP_RET_LOG needs Linux 4.14 headers; SECCOMP_RET_KILL_PROCESS 4.14
 * as well.  Both are part of the stable seccomp ABI. */
#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG          0x7ffc0000U
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

/* ── Constants ─────────────────────────────────────────────────────── */

#define MAX_PATHS         64
#define MAX_BLOCKED_SC    256
#define MAX_ALLOWED_SC    512
#define MAX_ENV_VARS      64
#define MAX_NET_PORTS     64
#define MAX_LINE          1024
#define MAX_INHERIT_DEPTH 2

/* ── seccomp default action ─────────────────────────────────────────
 *
 * What happens to a syscall the filter does not permit.  ERRNO(EPERM) is
 * the historical default and stays the default for compatibility, but it
 * is the weakest of the three: a program that does not check the return
 * value corrupts its own logic instead of dying, and an attacker can probe
 * the filter one call at a time because every denial returns cleanly.
 * KILL terminates the process with SIGSYS (and leaves an audit record);
 * LOG permits the call and records it, for working out what a policy needs
 * before enforcing it. */
typedef enum {
    SECCOMP_DEFAULT_ERRNO = 0,
    SECCOMP_DEFAULT_KILL,
    SECCOMP_DEFAULT_LOG
} SeccompAction;

/* ── Path rule ──────────────────────────────────────────────────────── */

typedef enum { PATH_RO, PATH_RW, PATH_EXEC, PATH_RWX } PathMode;

typedef struct {
    const char *path;
    PathMode    mode;
    int         optional;   /* trailing '?': skip silently when absent */
} PathRule;

/* ── Mount flag rule (compartment-root) ─────────────────────────────
 *
 * One `mount-ro` / `mount-noexec` / `mount-nosuid` / `mount-nodev`
 * directive: a path inside the new root and the MS_* flag to force on it. */
typedef struct {
    const char   *path;
    unsigned long flags;
} MountFlagRule;

/* ── Configuration (shared base fields) ────────────────────────────── */

typedef struct {
    PathRule    paths[MAX_PATHS];
    int         path_count;

    /* Landlock TCP port rules (ABI 4+).  Ports are host byte order. */
    int         net_bind_ports[MAX_NET_PORTS];
    int         net_bind_count;
    int         net_connect_ports[MAX_NET_PORTS];
    int         net_connect_count;
    int         net_default_deny;    /* 0 = ignore (network unhandled) */

    int         blocked_syscalls[MAX_BLOCKED_SC];
    int         blocked_count;

    int         allowed_syscalls[MAX_ALLOWED_SC];
    int         allowed_sc_count;
    int         seccomp_allow_mode;  /* 0=deny-list (block), 1=allow-list (allow only) */
    SeccompAction seccomp_default;   /* action for a call the filter denies */

    const char *env_deny[MAX_ENV_VARS];
    int         env_deny_count;

    const char *env_allow[MAX_ENV_VARS];
    int         env_allow_count;
    int         env_allow_mode;      /* 0=deny-list, 1=allow-list */

    int         use_landlock;
    int         use_seccomp;
    int         use_no_new_privs;
    int         use_env_sanitize;
    int         dry_run;
    int         verbose;
    int         audit;
    int         audit_log_fd;   /* -1 = not open; callers must init to -1 */
    const char *audit_log_dir;
    const char *workdir;
    const char *profile;
    const char *profile_source;   /* "built-in" or file path */
    int         allow_insecure;   /* --insecure: run with degraded enforcement */

    /* Root-specific fields (compartment-root only, ignored by compartment-user) */
    char       *rootdir;
    uid_t       uid;
    gid_t       gid;
    char       *username;
    char       *netns;
    const char *cgroups[MAX_PATHS];
    int         cgroups_count;
    const char *cap_allowed_names[MAX_ENV_VARS];
    int         cap_allowed_count;
    int         loopback;
    const char *mount_masks[MAX_PATHS];
    int         mount_mask_count;
    unsigned long rootdir_flags;     /* extra MS_* for the rootdir bind */
    MountFlagRule mount_flags[MAX_PATHS];
    int         mount_flags_count;
    char       *uid_map;        /* "<inside> <outside> <count>\n", NULL = identity */
    char       *gid_map;        /* idem for gids */
} Config;

/* ── Syscall name → number table ────────────────────────────────────
 * Comprehensive: includes common syscalls for allow-list profiles and
 * dangerous ones for deny-list mode. Uses __NR_* macros from
 * <sys/syscall.h> for architecture portability (x86_64, aarch64, etc.).
 * Entries guarded by #ifdef for syscalls that may not exist on all
 * architectures (e.g. open, stat, dup2 absent on aarch64). */

typedef struct { const char *name; int nr; } SyscallEntry;

static const SyscallEntry syscall_table[] = {
    /* ── File I/O ─────────────────────────────────────────────────── */
    {"openat",              __NR_openat},
    {"close",               __NR_close},
    {"lseek",               __NR_lseek},
    {"pread64",             __NR_pread64},
    {"pwrite64",            __NR_pwrite64},
    {"readv",               __NR_readv},
    {"writev",              __NR_writev},
    {"pipe2",               __NR_pipe2},
    {"dup",                 __NR_dup},
    {"dup3",                __NR_dup3},
    {"fcntl",               __NR_fcntl},
    {"read",                __NR_read},
    {"write",               __NR_write},
    {"ioctl",               __NR_ioctl},
#ifdef __NR_open
    {"open",                __NR_open},
#endif
#ifdef __NR_dup2
    {"dup2",                __NR_dup2},
#endif
#ifdef __NR_pipe
    {"pipe",                __NR_pipe},
#endif
#ifdef __NR_fadvise64
    {"fadvise64",           __NR_fadvise64},
#endif
#ifdef __NR_close_range
    {"close_range",         __NR_close_range},
#endif

    /* ── File metadata ────────────────────────────────────────────── */
    {"fstat",               __NR_fstat},
    {"newfstatat",          __NR_newfstatat},
    {"faccessat",           __NR_faccessat},
    {"readlinkat",          __NR_readlinkat},
    {"getcwd",              __NR_getcwd},
#ifdef __NR_stat
    {"stat",                __NR_stat},
#endif
#ifdef __NR_lstat
    {"lstat",               __NR_lstat},
#endif
#ifdef __NR_access
    {"access",              __NR_access},
#endif
#ifdef __NR_readlink
    {"readlink",            __NR_readlink},
#endif
#ifdef __NR_statx
    {"statx",               __NR_statx},
#endif
#ifdef __NR_faccessat2
    {"faccessat2",          __NR_faccessat2},
#endif

    /* ── Directory / filesystem ───────────────────────────────────── */
    {"getdents64",          __NR_getdents64},
    {"chdir",               __NR_chdir},
    {"mkdirat",             __NR_mkdirat},
    {"unlinkat",            __NR_unlinkat},
    {"fchmod",              __NR_fchmod},
    {"fchown",              __NR_fchown},
    {"umask",               __NR_umask},
#ifdef __NR_mkdir
    {"mkdir",               __NR_mkdir},
#endif
#ifdef __NR_rmdir
    {"rmdir",               __NR_rmdir},
#endif
#ifdef __NR_unlink
    {"unlink",              __NR_unlink},
#endif
#ifdef __NR_rename
    {"rename",              __NR_rename},
#endif
#ifdef __NR_renameat2
    {"renameat2",           __NR_renameat2},
#endif
#ifdef __NR_chmod
    {"chmod",               __NR_chmod},
#endif
#ifdef __NR_chown
    {"chown",               __NR_chown},
#endif

    /* ── Memory ───────────────────────────────────────────────────── */
    {"mmap",                __NR_mmap},
    {"mprotect",            __NR_mprotect},
    {"munmap",              __NR_munmap},
    {"brk",                 __NR_brk},
    {"mremap",              __NR_mremap},
    {"madvise",             __NR_madvise},

    /* ── Signals ──────────────────────────────────────────────────── */
    {"rt_sigaction",        __NR_rt_sigaction},
    {"rt_sigprocmask",      __NR_rt_sigprocmask},
    {"rt_sigreturn",        __NR_rt_sigreturn},
    {"sigaltstack",         __NR_sigaltstack},
    {"kill",                __NR_kill},
    {"tgkill",              __NR_tgkill},

    /* ── Process ──────────────────────────────────────────────────── */
    {"execve",              __NR_execve},
    {"exit",                __NR_exit},
    {"exit_group",          __NR_exit_group},
    {"clone",               __NR_clone},
    {"wait4",               __NR_wait4},
    {"waitid",              __NR_waitid},
    {"getpid",              __NR_getpid},
    {"getppid",             __NR_getppid},
    {"gettid",              __NR_gettid},
    {"getuid",              __NR_getuid},
    {"getgid",              __NR_getgid},
    {"geteuid",             __NR_geteuid},
    {"getegid",             __NR_getegid},
    {"setuid",              __NR_setuid},
    {"setgid",              __NR_setgid},
    {"setgroups",           __NR_setgroups},
    {"setsid",              __NR_setsid},
    {"prctl",               __NR_prctl},
    {"uname",               __NR_uname},
#ifdef __NR_fork
    {"fork",                __NR_fork},
#endif
#ifdef __NR_vfork
    {"vfork",               __NR_vfork},
#endif
#ifdef __NR_clone3
    {"clone3",              __NR_clone3},
#endif
#ifdef __NR_execveat
    {"execveat",            __NR_execveat},
#endif
#ifdef __NR_arch_prctl
    {"arch_prctl",          __NR_arch_prctl},
#endif

    /* ── Scheduling / resources ───────────────────────────────────── */
    {"sched_yield",         __NR_sched_yield},
    {"sched_getaffinity",   __NR_sched_getaffinity},
    {"prlimit64",           __NR_prlimit64},
#ifdef __NR_getrlimit
    {"getrlimit",           __NR_getrlimit},
#endif

    /* ── Time ─────────────────────────────────────────────────────── */
    {"clock_gettime",       __NR_clock_gettime},
    {"clock_getres",        __NR_clock_getres},
    {"clock_nanosleep",     __NR_clock_nanosleep},
    {"nanosleep",           __NR_nanosleep},
#ifdef __NR_gettimeofday
    {"gettimeofday",        __NR_gettimeofday},
#endif

    /* ── I/O multiplexing ─────────────────────────────────────────── */
    {"ppoll",               __NR_ppoll},
#ifdef __NR_select
    {"select",              __NR_select},
#endif
#ifdef __NR_poll
    {"poll",                __NR_poll},
#endif

    /* ── Threading / sync ─────────────────────────────────────────── */
    {"futex",               __NR_futex},
    {"set_tid_address",     __NR_set_tid_address},
    {"set_robust_list",     __NR_set_robust_list},
#ifdef __NR_rseq
    {"rseq",                __NR_rseq},
#endif
#ifdef __NR_membarrier
    {"membarrier",          __NR_membarrier},
#endif

    /* ── Random ───────────────────────────────────────────────────── */
    {"getrandom",           __NR_getrandom},

    /* ── Dangerous syscalls (deny-list mode) ──────────────────────── */
    {"ptrace",              __NR_ptrace},
    {"mount",               __NR_mount},
    {"umount2",             __NR_umount2},
    {"reboot",              __NR_reboot},
    {"kexec_load",          __NR_kexec_load},
    {"init_module",         __NR_init_module},
    {"finit_module",        __NR_finit_module},
    {"delete_module",       __NR_delete_module},
    {"pivot_root",          __NR_pivot_root},
    {"chroot",              __NR_chroot},
    {"unshare",             __NR_unshare},
    {"setns",               __NR_setns},
    {"keyctl",              __NR_keyctl},
    {"add_key",             __NR_add_key},
    {"request_key",         __NR_request_key},
    {"bpf",                 __NR_bpf},
    {"userfaultfd",         __NR_userfaultfd},
    {"perf_event_open",     __NR_perf_event_open},
    {"personality",         __NR_personality},
    {"process_vm_readv",    __NR_process_vm_readv},
    {"process_vm_writev",   __NR_process_vm_writev},
    {"acct",                __NR_acct},
    {"swapon",              __NR_swapon},
    {"swapoff",             __NR_swapoff},
    {"settimeofday",        __NR_settimeofday},
    {"clock_settime",       __NR_clock_settime},
    {"clock_adjtime",       __NR_clock_adjtime},
    {"adjtimex",            __NR_adjtimex},
    {"vhangup",             __NR_vhangup},
#ifdef __NR_quotactl
    {"quotactl",            __NR_quotactl},
#endif
#ifdef __NR_kexec_file_load
    {"kexec_file_load",     __NR_kexec_file_load},
#endif
#ifdef __NR_lookup_dcookie
    {"lookup_dcookie",      __NR_lookup_dcookie},
#endif
#ifdef __NR_mbind
    {"mbind",               __NR_mbind},
#endif
#ifdef __NR_move_pages
    {"move_pages",          __NR_move_pages},
#endif
#ifdef __NR_ioperm
    {"ioperm",              __NR_ioperm},
#endif
#ifdef __NR_iopl
    {"iopl",                __NR_iopl},
#endif
#ifdef __NR_nfsservctl
    {"nfsservctl",          __NR_nfsservctl},
#endif
#ifdef __NR_io_uring_setup
    {"io_uring_setup",      __NR_io_uring_setup},
#endif
#ifdef __NR_io_uring_enter
    {"io_uring_enter",      __NR_io_uring_enter},
#endif
#ifdef __NR_io_uring_register
    {"io_uring_register",   __NR_io_uring_register},
#endif
#ifdef __NR_open_by_handle_at
    {"open_by_handle_at",   __NR_open_by_handle_at},
#endif
#ifdef __NR_name_to_handle_at
    {"name_to_handle_at",   __NR_name_to_handle_at},
#endif
#ifdef __NR_open_tree
    {"open_tree",           __NR_open_tree},
#endif
#ifdef __NR_move_mount
    {"move_mount",          __NR_move_mount},
#endif
#ifdef __NR_fsopen
    {"fsopen",              __NR_fsopen},
#endif
#ifdef __NR_fsmount
    {"fsmount",             __NR_fsmount},
#endif
#ifdef __NR_fsconfig
    {"fsconfig",            __NR_fsconfig},
#endif
#ifdef __NR_fspick
    {"fspick",              __NR_fspick},
#endif
#ifdef __NR_mount_setattr
    {"mount_setattr",       __NR_mount_setattr},
#endif
#ifdef __NR_pidfd_getfd
    {"pidfd_getfd",         __NR_pidfd_getfd},
#endif

    {NULL, 0}
};

static inline int resolve_syscall(const char *name)
{
    /* Try name lookup first */
    for (int i = 0; syscall_table[i].name; i++) {
        if (strcmp(syscall_table[i].name, name) == 0)
            return syscall_table[i].nr;
    }
    /* Accept numeric syscall numbers (for allow-list profiles).
     * Handles "42" and "42  # comment" from profile files. */
    char *end;
    long nr = strtol(name, &end, 0);
    if (end != name && nr >= 0 && nr <= 0x7fffffff) {
        /* Accept if end of string, whitespace, or comment follows */
        while (*end == ' ' || *end == '\t') end++;
        if (*end == '\0' || *end == '#')
            return (int)nr;
    }
    return -1;
}

/* ── Capability name → number table ────────────────────────────────
 * Used by compartment-root to replace cap_from_name() without libcap.
 * Names are the short form (without "CAP_" prefix); resolve_cap()
 * strips the prefix before matching so both forms work. */

typedef struct { const char *name; int nr; } CapEntry;

static const CapEntry cap_table[] = {
    {"chown",              0},
    {"dac_override",       1},
    {"dac_read_search",    2},
    {"fowner",             3},
    {"fsetid",             4},
    {"kill",               5},
    {"setgid",             6},
    {"setuid",             7},
    {"setpcap",            8},
    {"linux_immutable",    9},
    {"net_bind_service",  10},
    {"net_broadcast",     11},
    {"net_admin",         12},
    {"net_raw",           13},
    {"ipc_lock",          14},
    {"ipc_owner",         15},
    {"sys_module",        16},
    {"sys_rawio",         17},
    {"sys_chroot",        18},
    {"sys_ptrace",        19},
    {"sys_pacct",         20},
    {"sys_admin",         21},
    {"sys_boot",          22},
    {"sys_nice",          23},
    {"sys_resource",      24},
    {"sys_time",          25},
    {"sys_tty_config",    26},
    {"mknod",             27},
    {"lease",             28},
    {"audit_write",       29},
    {"audit_control",     30},
    {"setfcap",           31},
    {"mac_override",      32},
    {"mac_admin",         33},
    {"syslog",            34},
    {"wake_alarm",        35},
    {"block_suspend",     36},
    {"audit_read",        37},
    {"perfmon",           38},
    {"bpf",               39},
    {"checkpoint_restore",40},
    {NULL,                -1}
};

/* resolve_cap: accepts "CAP_NET_ADMIN", "cap_net_admin", "net_admin",
 * or a raw decimal number. Returns -1 if not recognized. */
static inline int resolve_cap(const char *name)
{
    const char *n = name;
    /* Strip "CAP_" or "cap_" prefix if present */
    if (strncasecmp(n, "cap_", 4) == 0)
        n += 4;

    for (int i = 0; cap_table[i].name; i++) {
        if (strcasecmp(cap_table[i].name, n) == 0)
            return cap_table[i].nr;
    }
    /* Also accept raw numeric capability numbers */
    char *end;
    long nr = strtol(name, &end, 0);
    if (end != name && nr >= 0 && nr <= 63)
        return (int)nr;
    return -1;
}

/* ── Allocation helper ──────────────────────────────────────────── */

/* A sandboxing tool must never continue with a partially materialised
 * policy: a NULL path or environment-variable name silently drops a rule
 * (or is dereferenced later). Fail loudly instead of degrading. */
static inline char *xstrdup(const char *s)
{
    char *p = strdup(s);
    if (!p) {
        fputs("compartment: out of memory\n", stderr);
        exit(1);
    }
    return p;
}

/* ── Policy array appends (fail closed, never silently truncate) ── */

/* Each helper returns 0 on success, or prints a diagnostic and returns -1
 * when the fixed-size array is full. Silent truncation drops rules the
 * operator explicitly asked for: with the old 64-entry blocked-syscall
 * array, adding a handful of --block flags on top of the built-in
 * ai-agent profile deleted pidfd_getfd, mount_setattr, ioperm and iopl
 * from the policy with no output at all. */
static inline int policy_full(const char *where, const char *what,
                              const char *item, int limit)
{
    fprintf(stderr, "compartment: %s: %s limit (%d) reached adding '%s' — "
            "refusing to run with a truncated policy\n",
            where, what, limit, item);
    return -1;
}

/* dup != 0 duplicates the string; use it whenever the source is a parse
 * buffer rather than argv or a string literal. */
static inline int cfg_add_path(Config *c, const char *where,
                               const char *path, PathMode mode, int dup)
{
    if (c->path_count >= MAX_PATHS)
        return policy_full(where, "path", path, MAX_PATHS);

    /* A trailing '?' marks the rule optional.  A rule naming a path that
     * does not exist is otherwise fatal — it silently grants nothing, and
     * a policy that believes it granted something is worse than one that
     * refuses to start.  '?' is the escape hatch for the genuinely
     * conditional entries (`ro /lib32?`), and it is deliberately visible in
     * the profile rather than an invisible property of the tool.
     *
     * A path whose last character really is '?' cannot be written; no such
     * path exists in any policy this tool is meant for. */
    size_t len = strlen(path);
    int optional = (len > 1 && path[len - 1] == '?');
    if (optional) {
        char *trimmed = xstrdup(path);
        trimmed[len - 1] = '\0';
        c->paths[c->path_count].path = trimmed;
    } else {
        c->paths[c->path_count].path = dup ? xstrdup(path) : path;
    }
    c->paths[c->path_count].mode     = mode;
    c->paths[c->path_count].optional = optional;
    c->path_count++;
    return 0;
}

/* Append a TCP port rule.  Ports are validated here so a typo in a profile
 * is reported with a line number rather than as a bare EINVAL from the
 * kernel. */
static inline int cfg_add_net_port(const char *where,
                                   const char *what, const char *val,
                                   int *arr, int *count)
{
    char *end;
    errno = 0;
    long port = strtol(val, &end, 10);
    while (end && (*end == ' ' || *end == '\t')) end++;
    if (errno != 0 || end == val || (end && *end != '\0') ||
        port < 0 || port > 65535) {
        fprintf(stderr, "compartment: %s: invalid %s port '%s' "
                "(expected 0-65535)\n", where, what, val);
        return -1;
    }
    if (*count >= MAX_NET_PORTS)
        return policy_full(where, what, val, MAX_NET_PORTS);
    arr[(*count)++] = (int)port;
    return 0;
}

static inline int cfg_add_blocked(Config *c, const char *where,
                                  const char *name, int nr)
{
    if (c->blocked_count >= MAX_BLOCKED_SC)
        return policy_full(where, "blocked-syscall", name, MAX_BLOCKED_SC);
    c->blocked_syscalls[c->blocked_count++] = nr;
    return 0;
}

static inline int cfg_add_allowed(Config *c, const char *where,
                                  const char *name, int nr)
{
    if (c->allowed_sc_count >= MAX_ALLOWED_SC)
        return policy_full(where, "allowed-syscall", name, MAX_ALLOWED_SC);
    c->allowed_syscalls[c->allowed_sc_count++] = nr;
    c->seccomp_allow_mode = 1;
    return 0;
}

static inline int cfg_add_env_deny(Config *c, const char *where,
                                   const char *name, int dup)
{
    if (c->env_deny_count >= MAX_ENV_VARS)
        return policy_full(where, "env-deny", name, MAX_ENV_VARS);
    c->env_deny[c->env_deny_count++] = dup ? xstrdup(name) : name;
    return 0;
}

static inline int cfg_add_env_allow(Config *c, const char *where,
                                    const char *name, int dup)
{
    if (c->env_allow_count >= MAX_ENV_VARS)
        return policy_full(where, "env-allow", name, MAX_ENV_VARS);
    c->env_allow[c->env_allow_count++] = dup ? xstrdup(name) : name;
    c->env_allow_mode = 1;
    return 0;
}

/* ── Mount flags (compartment-root) ──────────────────────────────
 *
 * The MS_* values are spelled out rather than taken from <sys/mount.h>:
 * compartment.h is included by compartment-user too, which has no business
 * pulling in the mount API.  They are part of the kernel ABI and have been
 * stable since 2.4. */
#define COMPARTMENT_MS_RDONLY  1UL
#define COMPARTMENT_MS_NOSUID  2UL
#define COMPARTMENT_MS_NODEV   4UL
#define COMPARTMENT_MS_NOEXEC  8UL

/* Suffix of a `mount-<flag> PATH` directive → the flag it forces on.
 * Returns 0 for anything else, which is how the parser tells a real
 * directive from a typo such as `mount-readonly`. */
static inline unsigned long mount_flag_for_directive(const char *suffix)
{
    if (strcmp(suffix, "ro") == 0)     return COMPARTMENT_MS_RDONLY;
    if (strcmp(suffix, "nosuid") == 0) return COMPARTMENT_MS_NOSUID;
    if (strcmp(suffix, "nodev") == 0)  return COMPARTMENT_MS_NODEV;
    if (strcmp(suffix, "noexec") == 0) return COMPARTMENT_MS_NOEXEC;
    return 0;
}

/* "nosuid,nodev,noexec,ro" → the corresponding MS_* bitmask. */
static inline int parse_mount_flag_list(const char *where, const char *val,
                                        unsigned long *out)
{
    char buf[MAX_LINE];
    if (strlen(val) >= sizeof(buf)) {
        fprintf(stderr, "compartment: %s: mount flag list too long\n", where);
        return -1;
    }
    memcpy(buf, val, strlen(val) + 1);
    unsigned long flags = 0;
    int any = 0;
    for (char *tok = strtok(buf, ", \t"); tok; tok = strtok(NULL, ", \t")) {
        unsigned long f = mount_flag_for_directive(tok);
        if (f == 0) {
            fprintf(stderr, "compartment: %s: unknown mount flag '%s' "
                    "(use ro, nosuid, nodev, noexec)\n", where, tok);
            return -1;
        }
        flags |= f;
        any = 1;
    }
    if (!any) {
        fprintf(stderr, "compartment: %s: empty mount flag list\n", where);
        return -1;
    }
    *out = flags;
    return 0;
}

static inline int cfg_add_mount_flag(Config *c, const char *where,
                                     const char *path, unsigned long flags)
{
    if (c->mount_flags_count >= MAX_PATHS)
        return policy_full(where, "mount-flag", path, MAX_PATHS);
    /* Two directives naming the same path are merged rather than stored
     * twice: each one costs a bind + remount pass inside the container. */
    for (int i = 0; i < c->mount_flags_count; i++) {
        if (strcmp(c->mount_flags[i].path, path) == 0) {
            c->mount_flags[i].flags |= flags;
            return 0;
        }
    }
    c->mount_flags[c->mount_flags_count].path  = xstrdup(path);
    c->mount_flags[c->mount_flags_count].flags = flags;
    c->mount_flags_count++;
    return 0;
}

/* Generic string-array append (cgroup, cap-allow, mount-mask). */
static inline int cfg_add_str(const char **arr, int *count, int limit,
                              const char *where, const char *what,
                              const char *val, int dup)
{
    if (*count >= limit)
        return policy_full(where, what, val, limit);
    arr[(*count)++] = dup ? xstrdup(val) : val;
    return 0;
}

/* ── Boolean value parsing (case-insensitive, fail-closed) ──────── */

static inline int parse_bool(const char *val, int *out)
{
    if (strcasecmp(val, "on") == 0 || strcasecmp(val, "yes") == 0 ||
        strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0) {
        *out = 1;
        return 0;
    }
    if (strcasecmp(val, "off") == 0 || strcasecmp(val, "no") == 0 ||
        strcasecmp(val, "false") == 0 || strcmp(val, "0") == 0) {
        *out = 0;
        return 0;
    }
    return -1; /* unrecognized value */
}

/* ── One-way security switches ──────────────────────────────────── */

/* landlock, seccomp, no-new-privs and env-sanitize are one-way: a profile
 * may turn a mechanism on, never off. A profile file is data — it may sit
 * in a directory the sandboxed process can reach, and "seccomp off" in it
 * would be a complete escape. Only the invoking user, on the command line,
 * may disable enforcement.
 *
 * cli_flag names the command-line escape hatch, or is NULL when the
 * mechanism cannot be disabled at all. */
static inline int profile_switch(const char *where, const char *name,
                                 const char *cli_flag, const char *val,
                                 int *out)
{
    int on;
    if (parse_bool(val, &on) != 0) {
        fprintf(stderr, "compartment: %s: invalid value for %s: '%s' "
                "(use on/off)\n", where, name, val);
        return -1;
    }
    if (!on) {
        fprintf(stderr, "compartment: %s: '%s off' is not allowed in a "
                "profile — a profile may only tighten policy.\n",
                where, name);
        if (cli_flag)
            fprintf(stderr, "  Pass %s on the command line if you really "
                    "need to disable it.\n", cli_flag);
        else
            fprintf(stderr, "  %s cannot be disabled.\n", name);
        return -1;
    }
    *out = 1;
    return 0;
}

/* ── $HOME sanity ───────────────────────────────────────────────── */

/* $HOME reaches the policy twice: the built-in ai-agent profile adds it as
 * a read-write-execute Landlock root, and profiles expand it inside path
 * values. It is entirely caller-supplied, and Landlock is additive, so
 * HOME=/ used to grant "rwx /" — every path not named by a narrower rule
 * became writable, bounded only by DAC.
 *
 * Returns home on success, or NULL with *why set to a short reason. */
static inline const char *home_dir_usable(const char *home, const char **why)
{
    struct stat st;
    if (!home || home[0] == '\0')  { *why = "not set";                 return NULL; }
    if (home[0] != '/')            { *why = "not an absolute path";    return NULL; }
    if (strcmp(home, "/") == 0)    { *why = "the filesystem root";     return NULL; }
    if (stat(home, &st) != 0)      { *why = strerror(errno);           return NULL; }
    if (!S_ISDIR(st.st_mode))      { *why = "not a directory";         return NULL; }
    if (st.st_uid != getuid())     { *why = "not owned by you";        return NULL; }
    return home;
}

/* ── Variable expansion ($HOME, $USER only) ─────────────────────── */

static inline const char *expand_var(const char *input, char *buf, size_t bufsz)
{
    if (!strchr(input, '$')) return input;

    const char *why = NULL;
    const char *home = home_dir_usable(getenv("HOME"), &why);
    const char *user = getenv("USER");
    if (!user) {
        struct passwd *pw = getpwuid(getuid());
        user = pw ? pw->pw_name : NULL;
    }

    if (user && user[0] == '\0') user = NULL;

    size_t pos = 0;
    const char *p = input;
    while (*p && pos < bufsz - 1) {
        if (*p == '$') {
            if (strncmp(p, "$HOME", 5) == 0) {
                if (!home) return NULL; /* $HOME referenced but unset */
                size_t len = strlen(home);
                if (pos + len >= bufsz) return NULL; /* truncation → error */
                memcpy(buf + pos, home, len);
                pos += len;
                p += 5;
                continue;
            } else if (strncmp(p, "$USER", 5) == 0) {
                if (!user) return NULL; /* $USER referenced but unset */
                size_t len = strlen(user);
                if (pos + len >= bufsz) return NULL; /* truncation → error */
                memcpy(buf + pos, user, len);
                pos += len;
                p += 5;
                continue;
            }
        }
        buf[pos++] = *p++;
    }
    if (*p) return NULL; /* input not fully consumed → truncation */
    buf[pos] = '\0';
    return buf;
}

/* ── Profile file loading ───────────────────────────────────────── */

/* Resolution flags. A profile file is policy: whoever can write it
 * decides what the sandbox does, so where we are willing to look for one
 * and who we are willing to accept it from are explicit choices. */
#define PROFILE_SEARCH_USER  (1u << 0)  /* also search $HOME/.config/compartment */
#define PROFILE_OWNER_ROOT   (1u << 1)  /* file and directory must be root-owned */

/* Three-way result. "not found" lets the caller keep searching or fall
 * back to a built-in; "error" means the file exists but its contents are
 * not trustworthy, and nothing may run. Collapsing the two was how a
 * rejected profile still got its already-parsed lines applied. */
#define PROFILE_OK         0
#define PROFILE_NOT_FOUND  1
#define PROFILE_ERROR    (-1)


/* ── Profile file trust ─────────────────────────────────────────── */

/* umask 002 plus user-private groups — the default for interactive users
 * on Debian/Ubuntu and Fedora — leaves everything you create at 0664 or
 * 0775. Group-write is then no wider than owner-write, because the group
 * has exactly one member: you. Tolerate that single case and nothing
 * else. A root-owned object never qualifies, so /etc policy files and
 * every compartment-root profile keep the strict rule. */
static inline int group_is_private(uid_t owner, gid_t gid)
{
    if (owner == 0 || owner != getuid() || gid != getgid())
        return 0;
    struct group *gr = getgrgid(gid);
    if (!gr || !gr->gr_mem)
        return 0;
    struct passwd *pw = getpwuid(owner);
    for (char **m = gr->gr_mem; *m; m++)
        if (!pw || strcmp(*m, pw->pw_name) != 0)
            return 0;   /* somebody else is in the group */
    return 1;
}

/* Check the object behind an already-open fd, so the thing we validate
 * and the thing we read are the same inode. A policy source must be the
 * expected type, must be owned by root or by the real uid of the caller
 * (root only when PROFILE_OWNER_ROOT is set), and must not be writable by
 * group or other. */
static inline int profile_fd_trusted(int fd, unsigned flags, mode_t want_type,
                                     const char *what, const char *path)
{
    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "compartment: %s %s: %s\n", what, path, strerror(errno));
        return -1;
    }
    if ((st.st_mode & S_IFMT) != want_type) {
        fprintf(stderr, "compartment: %s %s: not a %s\n", what, path,
                want_type == S_IFDIR ? "directory" : "regular file");
        return -1;
    }
    if (st.st_uid != 0 &&
        ((flags & PROFILE_OWNER_ROOT) || st.st_uid != getuid())) {
        fprintf(stderr, "compartment: %s %s is owned by uid %u — it must be "
                "owned by root%s\n", what, path, (unsigned)st.st_uid,
                (flags & PROFILE_OWNER_ROOT) ? "" : " or by you");
        return -1;
    }
    /* A sticky directory (/tmp, /var/tmp) may be world-writable: the
     * sticky bit is exactly what stops anyone but the owner from
     * unlinking or renaming the file inside it, which is the only way a
     * third party could swap the policy we just validated. Regular files
     * get no such exemption. */
    mode_t bad = st.st_mode & (S_IWGRP | S_IWOTH);
    if ((bad & S_IWGRP) && group_is_private(st.st_uid, st.st_gid))
        bad &= (mode_t)~S_IWGRP;
    if ((want_type == S_IFDIR) && (st.st_mode & S_ISVTX))
        bad = 0;
    if (bad) {
        fprintf(stderr, "compartment: %s %s is mode %04o — group- or "
                "world-writable policy is not trusted\n",
                what, path, (unsigned)(st.st_mode & 07777));
        fprintf(stderr, "  fix with: chmod go-w %s\n", path);
        return -1;
    }
    return 0;
}

/* Anyone who can write the containing directory can replace the file, or
 * repoint a symlink at one they own, so the directory needs the same
 * check as the file. */
static inline int profile_dir_trusted(const char *path, unsigned flags)
{
    char dir[PATH_MAX];
    size_t plen = strlen(path);
    if (plen >= sizeof(dir)) {
        fprintf(stderr, "compartment: profile path too long: %s\n", path);
        return -1;
    }
    memcpy(dir, path, plen + 1);

    char *slash = strrchr(dir, '/');
    if (!slash) {
        dir[0] = '.'; dir[1] = '\0';
    } else if (slash == dir) {
        dir[1] = '\0';               /* "/x.conf" -> "/" */
    } else {
        *slash = '\0';
    }

    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) {
        fprintf(stderr, "compartment: profile directory %s: %s\n",
                dir, strerror(errno));
        return -1;
    }
    int r = profile_fd_trusted(dfd, flags, S_IFDIR, "profile directory", dir);
    close(dfd);
    return r;
}

/* Open a profile file for reading, refusing anything an untrusted user
 * could have written. Symlinks are followed — /etc/alternatives-style
 * indirection is legitimate — but the target, the directory named by the
 * path, and (when they differ) the directory the target really lives in
 * all have to pass. On failure *rc carries PROFILE_NOT_FOUND or
 * PROFILE_ERROR. */
static inline FILE *profile_fopen_trusted(const char *path, unsigned flags,
                                          int *rc)
{
    *rc = PROFILE_ERROR;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            *rc = PROFILE_NOT_FOUND;
            return NULL;
        }
        fprintf(stderr, "compartment: profile %s: %s\n", path, strerror(errno));
        return NULL;
    }

    if (profile_fd_trusted(fd, flags, S_IFREG, "profile", path) != 0) {
        close(fd);
        return NULL;
    }
    if (profile_dir_trusted(path, flags) != 0) {
        close(fd);
        return NULL;
    }

    char resolved[PATH_MAX];
    if (realpath(path, resolved) && strcmp(resolved, path) != 0 &&
        profile_dir_trusted(resolved, flags) != 0) {
        close(fd);
        return NULL;
    }

    FILE *fp = fdopen(fd, "r");
    if (!fp) {
        fprintf(stderr, "compartment: profile %s: %s\n", path, strerror(errno));
        close(fd);
        return NULL;
    }
    *rc = PROFILE_OK;
    return fp;
}

/* Forward declaration needed because the loader calls
 * resolve_and_load_profile for "inherit" directives. */
static inline int resolve_and_load_profile(Config *cfg, const char *name,
                                           int depth, unsigned flags);
static inline int load_profile_file(Config *cfg, const char *path, int depth,
                                    unsigned flags);

static inline int load_profile_into(Config *cfg, const char *path, int depth,
                                    unsigned flags)
{
    int orc;
    FILE *fp = profile_fopen_trusted(path, flags, &orc);
    if (!fp) return orc;

    char line[MAX_LINE];
    char expanded[PATH_MAX];
    int lineno = 0;

    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        /* Strip trailing newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        /* Detect truncated lines (no newline and not EOF) — a truncated
         * line could cause the remainder to parse as a new directive,
         * silently changing the security policy. Fail-closed. */
        if (len > 0 && len >= sizeof(line) - 1 && !feof(fp)) {
            fprintf(stderr, "compartment: %s:%d: error: line too long "
                    "(max %d chars)\n", path, lineno, MAX_LINE - 2);
            fclose(fp);
            return PROFILE_ERROR;
        }

        /* Strip an inline comment, then right-trim.
         *
         * A '#' that begins a whitespace-separated token starts a comment;
         * a '#' inside a token stays literal, so a path such as
         * "/tmp/issue#42" still works. Without this, "ro /usr  # libs"
         * became the literal path "/usr  # libs" (no rule installed) and
         * "env-deny LD_PRELOAD  # injection" stripped nothing. */
        for (char *q = line; *q; q++) {
            if (*q == '#' && (q == line || q[-1] == ' ' || q[-1] == '\t')) {
                *q = '\0';
                break;
            }
        }
        len = strlen(line);
        while (len > 0 && (line[len-1] == ' ' || line[len-1] == '\t'))
            line[--len] = '\0';

        /* Skip blank lines and comment-only lines */
        const char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '\0') continue;

        char directive[64] = "";
        char value[MAX_LINE] = "";
        if (sscanf(s, "%63s %1023[^\n]", directive, value) < 1)
            continue;

        const char *val = expand_var(value, expanded, sizeof(expanded));
        if (!val) {
            fprintf(stderr, "compartment: %s:%d: cannot expand '%s' "
                    "($HOME or $USER unset or unusable, or the result is "
                    "too long)\n", path, lineno, value);
            fclose(fp);
            return PROFILE_ERROR;
        }

        /* Location prefix for policy-limit diagnostics */
        char where[PATH_MAX + 24];
        snprintf(where, sizeof(where), "%s:%d", path, lineno);

        if (strcmp(directive, "ro") == 0) {
            if (cfg_add_path(cfg, where, val, PATH_RO, 1) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "rw") == 0) {
            if (cfg_add_path(cfg, where, val, PATH_RW, 1) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "exec") == 0) {
            if (cfg_add_path(cfg, where, val, PATH_EXEC, 1) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "rwx") == 0) {
            if (cfg_add_path(cfg, where, val, PATH_RWX, 1) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "block") == 0) {
            int nr = resolve_syscall(val);
            if (nr >= 0) {
                if (cfg_add_blocked(cfg, where, val, nr) != 0) {
                    fclose(fp); return PROFILE_ERROR;
                }
            } else {
                /* Cannot distinguish arch-absent syscalls (e.g. ioperm on
                 * aarch64) from genuine typos — both return -1. Warn loudly
                 * but don't abort, since the same .conf file may be used
                 * across architectures. The block is NOT applied. */
                fprintf(stderr, "compartment: %s:%d: warning: unknown syscall '%s' "
                        "— block NOT applied (typo? or arch-specific syscall)\n",
                        path, lineno, val);
            }
        } else if (strcmp(directive, "allow") == 0) {
            int nr = resolve_syscall(val);
            if (nr >= 0) {
                if (cfg_add_allowed(cfg, where, val, nr) != 0) {
                    fclose(fp); return PROFILE_ERROR;
                }
            } else {
                fprintf(stderr, "compartment: %s:%d: warning: unknown syscall '%s' "
                        "— allow NOT applied (typo? or arch-specific syscall)\n",
                        path, lineno, val);
            }
        } else if (strcmp(directive, "net-bind") == 0) {
            if (cfg_add_net_port(where, "net-bind", val,
                                 cfg->net_bind_ports, &cfg->net_bind_count) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "net-connect") == 0) {
            if (cfg_add_net_port(where, "net-connect", val,
                                 cfg->net_connect_ports,
                                 &cfg->net_connect_count) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "net-default") == 0) {
            if (strcmp(val, "deny") == 0) {
                cfg->net_default_deny = 1;
            } else if (strcmp(val, "ignore") == 0) {
                /* One-way, like every other security switch: a profile may
                 * turn the port policy on, never off.  Otherwise an
                 * inherited profile could undo its parent's `net-default
                 * deny` with one line. */
                if (cfg->net_default_deny) {
                    fprintf(stderr, "compartment: %s: 'net-default ignore' "
                            "cannot undo an earlier 'net-default deny' — a "
                            "profile may only tighten policy.\n", where);
                    fclose(fp); return PROFILE_ERROR;
                }
            } else {
                fprintf(stderr, "compartment: %s: invalid value for "
                        "net-default: '%s' (use deny/ignore)\n", where, val);
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "seccomp-default") == 0) {
            if (strcmp(val, "errno") == 0)      cfg->seccomp_default = SECCOMP_DEFAULT_ERRNO;
            else if (strcmp(val, "kill") == 0)  cfg->seccomp_default = SECCOMP_DEFAULT_KILL;
            else if (strcmp(val, "log") == 0)   cfg->seccomp_default = SECCOMP_DEFAULT_LOG;
            else {
                fprintf(stderr, "compartment: %s: invalid value for "
                        "seccomp-default: '%s' (use errno/kill/log)\n",
                        where, val);
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "seccomp-mode") == 0) {
            if (strcmp(val, "allow") == 0 || strcmp(val, "allowlist") == 0)
                cfg->seccomp_allow_mode = 1;
            else
                cfg->seccomp_allow_mode = 0;
        } else if (strcmp(directive, "env-deny") == 0) {
            if (cfg_add_env_deny(cfg, where, val, 1) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "env-allow") == 0) {
            if (cfg_add_env_allow(cfg, where, val, 1) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "env-mode") == 0) {
            if (strcmp(val, "allow") == 0 || strcmp(val, "allowlist") == 0)
                cfg->env_allow_mode = 1;
            else
                cfg->env_allow_mode = 0;
        } else if (strcmp(directive, "workdir") == 0) {
            cfg->workdir = xstrdup(val);
        } else if (strcmp(directive, "landlock") == 0) {
            if (profile_switch(where, "landlock", "--no-landlock", val, &cfg->use_landlock) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "seccomp") == 0) {
            if (profile_switch(where, "seccomp", "--no-seccomp", val, &cfg->use_seccomp) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "no-new-privs") == 0) {
            if (profile_switch(where, "no-new-privs", NULL, val, &cfg->use_no_new_privs) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "env-sanitize") == 0) {
            if (profile_switch(where, "env-sanitize", "--no-env-sanitize", val, &cfg->use_env_sanitize) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "audit") == 0) {
            if (parse_bool(val, &cfg->audit) != 0) {
                fprintf(stderr, "compartment: %s:%d: invalid value for audit: '%s' (use on/off)\n", path, lineno, val);
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "audit-log") == 0) {
            cfg->audit_log_dir = xstrdup(val);
            cfg->audit = 1;
        } else if (strcmp(directive, "inherit") == 0) {
            if (depth >= MAX_INHERIT_DEPTH) {
                fprintf(stderr, "compartment: %s:%d: inherit depth limit reached\n",
                        path, lineno);
                fclose(fp);
                return PROFILE_ERROR;
            }
            /* Try loading the inherited profile. Search order:
             * 1. Same directory as the current profile file
             * 2. The normal search path for this load — /etc/compartment/,
             *    and ~/.config/compartment/ only when PROFILE_SEARCH_USER
             *    is still set, which a profile loaded from /etc never has.
             * Step 1 is what makes "inherit ai-agent" work when strict.conf
             * and ai-agent.conf sit in the same directory. */
            int found = PROFILE_NOT_FOUND;
            if (!strchr(val, '/')) {
                /* Extract directory from current profile path */
                char dir_copy[PATH_MAX];
                snprintf(dir_copy, sizeof(dir_copy), "%s", path);
                char *slash = strrchr(dir_copy, '/');
                if (slash) {
                    *slash = '\0';
                    char sibling[PATH_MAX];
                    int n = snprintf(sibling, sizeof(sibling),
                                     "%s/%s.conf", dir_copy, val);
                    if (n > 0 && (size_t)n < sizeof(sibling))
                        found = load_profile_file(cfg, sibling, depth + 1, flags);
                }
            }
            if (found == PROFILE_NOT_FOUND)
                found = resolve_and_load_profile(cfg, val, depth + 1, flags);
            if (found == PROFILE_NOT_FOUND) {
                fprintf(stderr, "compartment: %s:%d: inherited profile '%s' "
                        "not found\n", path, lineno, val);
                fclose(fp);
                return PROFILE_ERROR;
            }
            if (found != PROFILE_OK) {
                /* Diagnostic already printed by the inner load. */
                fprintf(stderr, "compartment: %s:%d: inherited profile '%s' "
                        "was rejected\n", path, lineno, val);
                fclose(fp);
                return PROFILE_ERROR;
            }
        /* ── Root-specific directives (compartment-root only) ─────── */
        } else if (strcmp(directive, "rootdir") == 0) {
            /* No free(): on a failed transaction the caller still owns
             * the previous value. A few bytes leak per overridden
             * directive, which a short-lived launcher can afford. */
            cfg->rootdir = xstrdup(val);
        } else if (strcmp(directive, "uid") == 0) {
            char *endptr;
            errno = 0;
            unsigned long v = strtoul(val, &endptr, 10);
            if (errno != 0 || endptr == val || *endptr != '\0' ||
                v > (unsigned long)UINT32_MAX) {
                fprintf(stderr, "compartment: %s:%d: invalid uid: %s\n",
                        path, lineno, val);
                fclose(fp);
                return PROFILE_ERROR;
            }
            cfg->uid = (uid_t)v;
        } else if (strcmp(directive, "gid") == 0) {
            char *endptr;
            errno = 0;
            unsigned long v = strtoul(val, &endptr, 10);
            if (errno != 0 || endptr == val || *endptr != '\0' ||
                v > (unsigned long)UINT32_MAX) {
                fprintf(stderr, "compartment: %s:%d: invalid gid: %s\n",
                        path, lineno, val);
                fclose(fp);
                return PROFILE_ERROR;
            }
            cfg->gid = (gid_t)v;
        } else if (strcmp(directive, "username") == 0) {
            /* No free(): on a failed transaction the caller still owns
             * the previous value. A few bytes leak per overridden
             * directive, which a short-lived launcher can afford. */
            cfg->username = xstrdup(val);
        } else if (strcmp(directive, "netns") == 0) {
            /* No free(): on a failed transaction the caller still owns
             * the previous value. A few bytes leak per overridden
             * directive, which a short-lived launcher can afford. */
            cfg->netns = xstrdup(val);
        } else if (strcmp(directive, "cgroup") == 0) {
            if (cfg_add_str(cfg->cgroups, &cfg->cgroups_count, MAX_PATHS, where, "cgroup", val, 1) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "cap-allow") == 0) {
            if (cfg_add_str(cfg->cap_allowed_names, &cfg->cap_allowed_count, MAX_ENV_VARS, where, "cap-allow", val, 1) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "loopback") == 0) {
            if (parse_bool(val, &cfg->loopback) != 0) {
                fprintf(stderr, "compartment: %s:%d: invalid value for loopback: '%s' (use on/off)\n", path, lineno, val);
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "uid-map") == 0 ||
                   strcmp(directive, "gid-map") == 0) {
            /* <container-start> <host-start> <count> — the range written to
             * /proc/<pid>/uid_map (or gid_map) of the container's user
             * namespace.  Without these directives the map is the identity
             * map "0 0 65536", which gives a capability boundary but no uid
             * isolation: container uid 0 is host uid 0 for DAC purposes.
             * "0 100000 65536" maps the container onto an unprivileged
             * subuid range instead. */
            /* unsigned long long, not unsigned long: on a 32-bit build
             * UINT32_MAX + 1 would wrap and reject every valid range. */
            unsigned long long inside, outside, count;
            const unsigned long long UID_LIMIT = (unsigned long long)UINT32_MAX + 1ULL;
            char extra[2];
            if (sscanf(val, "%llu %llu %llu %1s",
                       &inside, &outside, &count, extra) != 3 ||
                count == 0 ||
                inside  >= UID_LIMIT || outside >= UID_LIMIT ||
                count   >  UID_LIMIT ||
                inside  + count > UID_LIMIT ||
                outside + count > UID_LIMIT) {
                fprintf(stderr, "compartment: %s:%d: invalid %s: '%s' "
                        "(expected: <container-start> <host-start> <count>)\n",
                        path, lineno, directive, val);
                fclose(fp);
                return PROFILE_ERROR;
            }
            char map[64];
            snprintf(map, sizeof(map), "%llu %llu %llu\n",
                     inside, outside, count);
            /* A superseded map is deliberately not free()d: this Config is
             * the loader's scratch copy and still shares the pointer with
             * the caller's until the file parses cleanly (load_profile_file).
             * Freeing here would leave the caller holding a dangling pointer
             * when a later line rejects the profile.  Same leak-on-rollback
             * convention as every other string the loader adds. */
            if (directive[0] == 'u')
                cfg->uid_map = xstrdup(map);
            else
                cfg->gid_map = xstrdup(map);
        } else if (strcmp(directive, "mount-mask") == 0) {
            if (cfg_add_str(cfg->mount_masks, &cfg->mount_mask_count, MAX_PATHS, where, "mount-mask", val, 1) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else if (strcmp(directive, "rootdir-flags") == 0) {
            unsigned long f = 0;
            if (parse_mount_flag_list(where, val, &f) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
            cfg->rootdir_flags |= f;
        } else if (strncmp(directive, "mount-", 6) == 0 &&
                   mount_flag_for_directive(directive + 6) != 0) {
            if (cfg_add_mount_flag(cfg, where, val,
                                   mount_flag_for_directive(directive + 6)) != 0) {
                fclose(fp); return PROFILE_ERROR;
            }
        } else {
            /* Warn on unknown directives — typos silently weakening
             * policy is a real risk in corporate deployments. */
            fprintf(stderr, "compartment: %s:%d: warning: unknown directive '%s' (typo?)\n",
                    path, lineno, directive);
        }
    }
    fclose(fp);
    return PROFILE_OK;
}

/* Transactional wrapper: parse into a scratch Config and commit only if
 * the whole file (including anything it inherits) parsed cleanly.
 * Without this, a profile rejected on line N had already applied lines
 * 1..N-1 — and the caller then layered the built-in on top and reported
 * the result as "(built-in)". */
static inline int load_profile_file(Config *cfg, const char *path, int depth,
                                    unsigned flags)
{
    Config tmp = *cfg;   /* arrays are by value; strings added to tmp and
                          * then discarded leak, which is fine because a
                          * rejected profile always ends the process */
    int rc = load_profile_into(&tmp, path, depth, flags);
    if (rc == PROFILE_OK)
        *cfg = tmp;
    return rc;
}

/* Print, for a name that could not be resolved, exactly where we looked.
 * An explicit path is not a search — say so instead of inventing
 * "~/.config/compartment//abs/path.conf". */
static inline void profile_print_search_path(FILE *out, const char *name,
                                             unsigned flags)
{
    if (strchr(name, '/')) {
        fprintf(out, "  looked for the file: %s\n", name);
        return;
    }
    size_t nl = strlen(name);
    if (nl > 5 && strcmp(name + nl - 5, ".conf") == 0)
        fprintf(out, "  '%s' has no '/', so it was treated as a profile name "
                "and '.conf' was appended.\n  To load a file in the current "
                "directory, write ./%s\n", name, name);
    fprintf(out, "  searched: /etc/compartment/%s.conf", name);
    if (flags & PROFILE_SEARCH_USER)
        fprintf(out, ", ~/.config/compartment/%s.conf", name);
    else if (!(flags & PROFILE_OWNER_ROOT))
        fprintf(out, "  (pass --user-profiles to also search "
                "~/.config/compartment/)");
    fputc('\n', out);
}

/* Search order:
 *   1. an explicit --profile /path/file.conf (a name containing '/')
 *   2. /etc/compartment/<name>.conf
 *   3. $HOME/.config/compartment/<name>.conf — compartment-user only, and
 *      only when the caller passed --user-profiles
 *   4. the caller's built-in
 *
 * $HOME used to come first, which meant the sandboxed process could write
 * its own next-run policy: the built-in ai-agent profile grants RWX on
 * $HOME, so an agent could drop a file there and un-sandbox every future
 * invocation of the same command line. A profile loaded from /etc also
 * drops PROFILE_SEARCH_USER, so a system profile can never pull in a user
 * file through 'inherit'. */
static inline int resolve_and_load_profile(Config *cfg, const char *name,
                                           int depth, unsigned flags)
{
    /* If it contains a slash, treat as explicit path */
    if (strchr(name, '/')) {
        int r = load_profile_file(cfg, name, depth, flags);
        if (r == PROFILE_OK) cfg->profile_source = xstrdup(name);
        return r;
    }

    char path[PATH_MAX];
    int r;

    int n = snprintf(path, sizeof(path), "/etc/compartment/%s.conf", name);
    if (n > 0 && (size_t)n < sizeof(path)) {
        r = load_profile_file(cfg, path, depth, flags & ~PROFILE_SEARCH_USER);
        if (r != PROFILE_NOT_FOUND) {
            if (r == PROFILE_OK) cfg->profile_source = xstrdup(path);
            return r;
        }
    }

    if (flags & PROFILE_SEARCH_USER) {
        const char *home = getenv("HOME");
        if (home && home[0] == '/') {
            n = snprintf(path, sizeof(path),
                         "%s/.config/compartment/%s.conf", home, name);
            if (n > 0 && (size_t)n < sizeof(path)) {
                r = load_profile_file(cfg, path, depth, flags);
                if (r != PROFILE_NOT_FOUND) {
                    if (r == PROFILE_OK) cfg->profile_source = xstrdup(path);
                    return r;
                }
            }
        }
    }

    return PROFILE_NOT_FOUND;  /* caller falls back to a built-in */
}

/* ── PPID chain (who launched us?) ─────────────────────────────── */

static inline int get_ppid_chain(pid_t pid, pid_t chain[], int max_len)
{
    int len = 0;
    pid_t cur = pid;

    while (cur > 1 && len < max_len) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/status", cur);
        FILE *fp = fopen(path, "re");
        if (!fp) break;

        char line[256];
        pid_t ppid = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "PPid:", 5) == 0) {
                sscanf(line, "PPid:\t%d", &ppid);
                break;
            }
        }
        fclose(fp);

        if (ppid == 0 || ppid == cur) break;
        chain[len++] = ppid;
        cur = ppid;
    }
    return len;
}

/* ── Audit logging ───────────────────────────────────────────────── */

/* Every field below is interpolated into a single-line record, and some
 * of them (the command path, the profile name, the cwd) are chosen by
 * whoever runs the tool. A newline in any of them forges a log record.
 * Replace everything outside printable ASCII with '_'. */
static inline const char *audit_scrub(const char *in, char *buf, size_t bufsz)
{
    size_t i = 0;
    if (!in) in = "";
    for (; in[i] && i + 1 < bufsz; i++) {
        unsigned char c = (unsigned char)in[i];
        buf[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '_';
    }
    buf[i] = '\0';
    return buf;
}

static inline void audit_log(Config *cfg, const char *event, const char *detail)
{
    if (!cfg->audit) return;

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    const char *user = pw ? pw->pw_name : "unknown";

    /* Build PPID chain string */
    pid_t chain[32];
    int chain_len = get_ppid_chain(getpid(), chain, 32);
    char chain_str[512] = "";
    int pos = 0;
    for (int i = 0; i < chain_len && pos < (int)sizeof(chain_str) - 16; i++) {
        pos += snprintf(chain_str + pos, sizeof(chain_str) - pos,
                        "%s%d", i ? "->" : "", chain[i]);
    }

    /* Get CWD */
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) { cwd[0] = '?'; cwd[1] = '\0'; }

    /* Get TTY */
    const char *tty = ttyname(STDIN_FILENO);

    char s_user[128], s_event[128], s_cwd[PATH_MAX], s_tty[256], s_detail[1024];
    audit_scrub(user, s_user, sizeof(s_user));
    audit_scrub(event, s_event, sizeof(s_event));
    audit_scrub(cwd, s_cwd, sizeof(s_cwd));
    audit_scrub(tty ? tty : "none", s_tty, sizeof(s_tty));
    audit_scrub(detail, s_detail, sizeof(s_detail));

    fprintf(stderr,
            "compartment: [%s] user=%s uid=%u event=%s ppid_chain=%s "
            "cwd=%s tty=%s %s\n",
            ts, s_user, uid, s_event,
            chain_str[0] ? chain_str : "?",
            s_cwd, s_tty, s_detail);

    /* Also write to audit log file if open */
    if (cfg->audit_log_fd >= 0) {
        dprintf(cfg->audit_log_fd,
                "[%s] user=%s uid=%u event=%s ppid_chain=%s "
                "cwd=%s tty=%s %s\n",
                ts, s_user, uid, s_event,
                chain_str[0] ? chain_str : "?",
                s_cwd, s_tty, s_detail);
    }
}

/* ── Audit log file (must be opened BEFORE Landlock — fd survives) ── */

/* ── Audit log directory ─────────────────────────────────────────── */

/* Where the default log goes matters as much as how it is opened: the
 * built-in ai-agent profile grants the sandboxed process read, write and
 * execute on $HOME, so an audit trail under $HOME (or under
 * $XDG_STATE_HOME, which normally is $HOME) is one the confined process
 * can rewrite. Neither of the defaults below is inside any path the
 * built-in profiles grant for writing.
 *
 * An administrator can provision a per-user directory that is outside the
 * ruleset entirely:
 *
 *     install -d -m 0755 -o root -g root /var/lib/compartment/audit
 *     install -d -m 0700 -o alice        /var/lib/compartment/audit/1000
 */
#define AUDIT_VARLIB_PARENT "/var/lib/compartment/audit"

/* The per-uid directory is only trustworthy if nobody but root can
 * replace it, which means the parent must be root-owned and not group- or
 * world-writable. A parent that simply does not exist is not an error —
 * the feature is opt-in. */
static inline int audit_varlib_parent_ok(void)
{
    int pfd = open(AUDIT_VARLIB_PARENT,
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (pfd < 0)
        return 0;                       /* not provisioned; stay quiet */

    struct stat st;
    int ok = (fstat(pfd, &st) == 0 && st.st_uid == 0 &&
              !(st.st_mode & (S_IWGRP | S_IWOTH)));
    close(pfd);
    if (!ok)
        fprintf(stderr, "compartment: %s must be root-owned and not group- "
                "or world-writable — ignoring it\n", AUDIT_VARLIB_PARENT);
    return ok;
}

/* Choose the default audit directory. No side effects: nothing is created
 * and nothing is opened, so --dry-run can report the same answer a real
 * run would use. */
static inline int audit_default_dir(char *dir, size_t dirsz)
{
    int n;

    if (geteuid() == 0) {
        n = snprintf(dir, dirsz, "/var/log/compartment");
        return (n > 0 && (size_t)n < dirsz) ? 0 : -1;
    }

    uid_t uid = getuid();

    if (audit_varlib_parent_ok()) {
        n = snprintf(dir, dirsz, AUDIT_VARLIB_PARENT "/%u", (unsigned)uid);
        if (n > 0 && (size_t)n < dirsz) {
            struct stat st;
            if (lstat(dir, &st) == 0 && S_ISDIR(st.st_mode) &&
                st.st_uid == uid && (st.st_mode & 07777) == 0700)
                return 0;
        }
    }

    n = snprintf(dir, dirsz, "/var/tmp/compartment-audit-%u", (unsigned)uid);
    return (n > 0 && (size_t)n < dirsz) ? 0 : -1;
}

/* Open a directory that must be exactly ours: a real directory rather
 * than a symlink, owned by want_uid, mode 0700 and nothing looser.
 * /var/tmp is sticky and world-writable, so another user can create
 * compartment-audit-<uid> before we do; that has to be fatal, not a
 * directory we quietly append to. */
static inline int audit_open_private_dir(const char *path, uid_t want_uid)
{
    int dfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dfd < 0) {
        fprintf(stderr, "compartment: audit dir %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(dfd, &st) != 0) {
        fprintf(stderr, "compartment: audit dir %s: %s\n",
                path, strerror(errno));
        close(dfd);
        return -1;
    }
    if (st.st_uid != want_uid || (st.st_mode & 07777) != 0700) {
        fprintf(stderr, "compartment: audit dir %s is uid %u mode %04o — "
                "expected uid %u mode 0700\n", path, (unsigned)st.st_uid,
                (unsigned)(st.st_mode & 07777), (unsigned)want_uid);
        close(dfd);
        return -1;
    }
    return dfd;
}

/* An audit trail the confined process can rewrite is not a trail.  Landlock
 * grants are per-subtree, so a log directory anywhere under a `rw`/`rwx`
 * rule is fully reachable from inside the sandbox.  This is a warning, not
 * a refusal: an operator may deliberately want the log inside the workspace,
 * and only they can weigh that. */
static inline void audit_warn_if_writable(const Config *cfg, const char *dir)
{
    char real[PATH_MAX];
    if (!realpath(dir, real))
        snprintf(real, sizeof(real), "%s", dir);

    for (int i = 0; i < cfg->path_count; i++) {
        if (cfg->paths[i].mode != PATH_RW && cfg->paths[i].mode != PATH_RWX)
            continue;
        char outer[PATH_MAX];
        if (!realpath(cfg->paths[i].path, outer))
            snprintf(outer, sizeof(outer), "%s", cfg->paths[i].path);
        size_t olen = strlen(outer);
        while (olen > 1 && outer[olen - 1] == '/')
            olen--;
        if (strncmp(real, outer, olen) != 0)
            continue;
        if (real[olen] != '/' && real[olen] != '\0')
            continue;
        fprintf(stderr, "compartment: WARNING: the audit log directory %s is "
                "inside the writable rule '%s' — the sandboxed process can "
                "rewrite its own audit trail\n", dir, cfg->paths[i].path);
        return;
    }
}

static inline int audit_log_open(Config *cfg)
{
    char dir[PATH_MAX - 32];  /* leave room for /YYYY-MM-DD.log */
    int dfd;

    if (cfg->audit_log_dir) {
        /* Operator's choice: created if missing, then checked for owner
         * and write bits. Note that an operator-chosen directory inside a
         * granted rw/rwx path IS reachable by the sandboxed process. */
        int n = snprintf(dir, sizeof(dir), "%s", cfg->audit_log_dir);
        if (n < 0 || (size_t)n >= sizeof(dir)) {
            fprintf(stderr, "compartment: audit log dir path too long\n");
            return -1;
        }
        if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
            fprintf(stderr, "compartment: mkdir %s: %s\n", dir, strerror(errno));
            return -1;
        }
        /* Validate the directory on its own fd, then create the day file
         * relative to it. O_NOFOLLOW on the final component alone left
         * the directory component followable: a symlink at the audit path
         * redirected every record somewhere else. */
        dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (dfd < 0) {
            fprintf(stderr, "compartment: audit dir %s: %s\n",
                    dir, strerror(errno));
            return -1;
        }
        struct stat st;
        if (fstat(dfd, &st) != 0) {
            fprintf(stderr, "compartment: audit dir %s: %s\n",
                    dir, strerror(errno));
            close(dfd);
            return -1;
        }
        mode_t bad = st.st_mode & (S_IWGRP | S_IWOTH);
        if ((bad & S_IWGRP) && group_is_private(st.st_uid, st.st_gid))
            bad &= (mode_t)~S_IWGRP;
        if (st.st_uid != geteuid() || bad) {
            fprintf(stderr, "compartment: audit dir %s is not a private, "
                    "self-owned directory (uid %u, mode %04o)\n",
                    dir, (unsigned)st.st_uid, (unsigned)(st.st_mode & 07777));
            close(dfd);
            return -1;
        }
    } else {
        if (audit_default_dir(dir, sizeof(dir)) != 0) {
            fprintf(stderr, "compartment: cannot determine an audit log "
                    "directory — use --audit-log DIR\n");
            return -1;
        }
        /* The admin-provisioned directory is never created here; the two
         * fallbacks are, mode 0700 (umask cannot widen that). */
        if (strncmp(dir, AUDIT_VARLIB_PARENT "/",
                    sizeof(AUDIT_VARLIB_PARENT)) != 0 &&
            mkdir(dir, 0700) != 0 && errno != EEXIST) {
            fprintf(stderr, "compartment: mkdir %s: %s\n", dir, strerror(errno));
            return -1;
        }
        dfd = audit_open_private_dir(dir, getuid());
        if (dfd < 0) {
            fprintf(stderr, "compartment: refusing to write the audit log "
                    "to %s\n", dir);
            return -1;
        }
    }

    audit_warn_if_writable(cfg, dir);

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char name[32];
    strftime(name, sizeof(name), "%Y-%m-%d.log", tm);

    int fd = openat(dfd, name,
                    O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    close(dfd);
    if (fd < 0) {
        fprintf(stderr, "compartment: open %s/%s: %s\n",
                dir, name, strerror(errno));
        return -1;
    }

    cfg->audit_log_fd = fd;
    if (cfg->verbose)
        fprintf(stderr, "compartment: audit log: %s/%s\n", dir, name);
    return 0;
}

/* ── Environment sanitize ────────────────────────────────────────── */

/* A trailing '*' makes an entry a prefix, so one "LD_*" covers the whole
 * loader family — including the variables that did not exist when the
 * list was written. Anything else is an exact name. */
static inline int env_name_matches(const char *pattern, const char *name)
{
    size_t plen = strlen(pattern);
    if (plen > 0 && pattern[plen - 1] == '*')
        return strncmp(pattern, name, plen - 1) == 0;
    return strcmp(pattern, name) == 0;
}

static inline void sanitize_env(Config *cfg)
{
    const char **pats;
    int npats, keep_on_match;

    if (cfg->env_allow_mode) {
        pats = cfg->env_allow;
        npats = cfg->env_allow_count;
        keep_on_match = 1;   /* allow-list: drop everything unmatched */
    } else {
        pats = cfg->env_deny;
        npats = cfg->env_deny_count;
        keep_on_match = 0;   /* deny-list: drop everything matched */
    }

    /* unsetenv() rebuilds environ, so find one victim, remove it, and
     * start over. At most one pass per variable. */
    for (;;) {
        char *victim = NULL;
        for (char **e = environ; *e && !victim; e++) {
            const char *eq = strchr(*e, '=');
            /* An entry with no '=' cannot be removed: unsetenv() reports
             * success but leaves it in place, which would spin this loop
             * forever. Such an entry is also invisible to getenv(), so
             * skipping it costs nothing. A caller can only produce one by
             * crafting envp for execve() by hand. */
            if (!eq) continue;
            size_t nlen = (size_t)(eq - *e);
            if (nlen == 0) continue;
            char *name = strndup(*e, nlen);
            if (!name) {
                fputs("compartment: out of memory\n", stderr);
                exit(1);
            }
            int matched = 0;
            for (int i = 0; i < npats && !matched; i++)
                matched = env_name_matches(pats[i], name);
            if (matched == keep_on_match)
                free(name);
            else
                victim = name;
        }
        if (!victim) break;
        if (cfg->verbose)
            fprintf(stderr, "compartment: unset %s\n", victim);
        unsetenv(victim);
        free(victim);
    }
}

/* ── Landlock ────────────────────────────────────────────────────── */

/* Landlock syscall numbers are architecture-independent (444-446) since
 * Linux 5.13.  Provide fallbacks if the kernel headers are too old. */
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule       445
#define __NR_landlock_restrict_self  446
#endif
#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

/* Fallback definitions for build hosts whose headers are older than the
 * kernel the binary will run on.  Every Landlock constant this file uses
 * is listed, because a missing one is invisible: the right simply drops
 * out of the handled mask and nothing says so.  That is not theoretical —
 * Ubuntu 24.04 ships linux-libc-dev 6.8, whose <linux/landlock.h> has the
 * ABI-4 network constants but *not* LANDLOCK_ACCESS_FS_IOCTL_DEV, so the
 * old `#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV` guard silently left device
 * ioctls unhandled on every kernel.
 *
 * ABI → kernel:  1 = 5.13, 2 = 5.19 (REFER), 3 = 6.2 (TRUNCATE),
 *                4 = 6.7 (TCP bind/connect), 5 = 6.10 (IOCTL_DEV),
 *                6 = 6.12 (scoping). */
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER        (1ULL << 13)   /* ABI 2 */
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE     (1ULL << 14)   /* ABI 3 */
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV    (1ULL << 15)   /* ABI 5 */
#endif
#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP    (1ULL << 0)    /* ABI 4 */
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)    /* ABI 4 */
#endif

/* LANDLOCK_RULE_NET_PORT is an *enumerator*, not a macro, so `#ifndef`
 * can never see it and a fallback #define would collide on a new header.
 * struct landlock_net_port_attr does not exist at all before 6.7.  Both
 * are therefore spelled out here and used unconditionally — the same
 * approach compartment-root already takes for struct mount_attr. */
#define COMPARTMENT_RULE_NET_PORT 2

struct compartment_net_port_attr {
    uint64_t allowed_access;
    uint64_t port;      /* HOST byte order.  Every other port field in this
                         * project is network order; this one is not. */
};

/* struct landlock_ruleset_attr grew handled_access_net in 6.7 and
 * handled_access_scoped in 6.12, and the size passed to
 * landlock_create_ruleset(2) is what tells the kernel which ABI the
 * caller speaks.  Declaring our own keeps that decision here instead of
 * in whatever <linux/landlock.h> the build host happens to ship. */
struct compartment_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
};

static inline int landlock_abi(void)
{
    return (int)syscall(__NR_landlock_create_ruleset, NULL, 0,
                        LANDLOCK_CREATE_RULESET_VERSION);
}

/* Rights that a rule on a non-directory may carry.  Asking for a
 * directory-only right (READ_DIR, MAKE_*, REMOVE_*, REFER) on a regular
 * file or a device node is rejected by the kernel with EINVAL, which is
 * how every per-file rule used to install nothing at all. */
static inline uint64_t landlock_file_rights(int abi)
{
    uint64_t r = LANDLOCK_ACCESS_FS_EXECUTE |
                 LANDLOCK_ACCESS_FS_READ_FILE |
                 LANDLOCK_ACCESS_FS_WRITE_FILE;
    if (abi >= 3) r |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) r |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    return r;
}

/*
 * landlock_add_path — install one path rule.
 *
 * Returns 1 when a rule was installed, 0 when an optional rule was skipped
 * because the path does not exist, and -1 on any error.
 *
 * Symlinks are followed deliberately.  O_PATH|O_NOFOLLOW on a symlink does
 * not fail with ELOOP — it succeeds and hands back an fd to the *symlink*,
 * which the kernel then rejects with EINVAL.  On every usr-merged distro
 * /lib and /lib64 are symlinks, so the two rules that matter most for
 * running any dynamically linked program installed nothing.  Following the
 * link is also the correct semantics: it is what the confined process
 * experiences at open() time.
 */
static inline int landlock_add_path(const char *tool, int ruleset_fd,
                                    const PathRule *rule, uint64_t access,
                                    uint64_t file_rights, int verbose)
{
    int fd = open(rule->path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT && rule->optional) {
            if (verbose)
                fprintf(stderr, "%s: landlock: %s does not exist — optional "
                        "rule skipped\n", tool, rule->path);
            return 0;
        }
        fprintf(stderr, "%s: landlock: %s: %s\n",
                tool, rule->path, strerror(errno));
        if (errno == ENOENT)
            fprintf(stderr, "  A rule for a path that does not exist grants "
                    "nothing.  Write '%s?' to make it optional.\n", rule->path);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "%s: landlock: fstat %s: %s\n",
                tool, rule->path, strerror(errno));
        close(fd);
        return -1;
    }
    if (!S_ISDIR(st.st_mode))
        access &= file_rights;

    if (access == 0) {
        fprintf(stderr, "%s: landlock: %s: no applicable access right "
                "for this file type\n", tool, rule->path);
        close(fd);
        return -1;
    }

    struct landlock_path_beneath_attr attr = {
        .allowed_access = access,
        .parent_fd      = fd,
    };
    int r = (int)syscall(__NR_landlock_add_rule, ruleset_fd,
                         LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
    close(fd);
    if (r < 0) {
        /* EINVAL used to be swallowed here, which is what made both of the
         * failures above silent.  Never again: a rule that did not install
         * is a policy the operator does not have. */
        fprintf(stderr, "%s: landlock add_rule %s: %s\n",
                tool, rule->path, strerror(errno));
        return -1;
    }
    return 1;
}

static inline int landlock_add_port(const char *tool, int ruleset_fd,
                                    int port, uint64_t access,
                                    const char *what)
{
    struct compartment_net_port_attr attr = {
        .allowed_access = access,
        .port           = (uint64_t)port,
    };
    if (syscall(__NR_landlock_add_rule, ruleset_fd,
                COMPARTMENT_RULE_NET_PORT, &attr, 0) != 0) {
        fprintf(stderr, "%s: landlock add_rule %s %d: %s\n",
                tool, what, port, strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * config_check_additive — refuse a policy Landlock cannot express.
 *
 * Landlock unions the rights of every rule matching an ancestor of the
 * path being opened, so a narrower rule *never* takes anything away from a
 * wider one.  `rw $W/proj` together with `ro $W/proj/secrets` reads like a
 * carve-out and is not one: the secrets stay writable.  The syntax invites
 * the mistake, so the only safe answer is to make it unsayable.
 *
 * Only `ro` is refused, not `exec`.  `ro` is restriction-shaped — it says
 * "read-only here" and does not deliver.  `exec` is grant-shaped: writing
 * `rw /work` plus `exec /work/run.sh` really does add execute to one file
 * inside a W^X workspace, which is a pattern worth keeping.
 *
 * Compares canonicalised paths on component boundaries, so /a/bc is not
 * treated as living inside /a/b.
 */
static inline int config_check_additive(const Config *cfg, const char *tool)
{
    for (int i = 0; i < cfg->path_count; i++) {
        if (cfg->paths[i].mode != PATH_RO)
            continue;
        char inner[PATH_MAX];
        if (!realpath(cfg->paths[i].path, inner))
            snprintf(inner, sizeof(inner), "%s", cfg->paths[i].path);

        for (int j = 0; j < cfg->path_count; j++) {
            if (i == j)
                continue;
            if (cfg->paths[j].mode != PATH_RW && cfg->paths[j].mode != PATH_RWX)
                continue;
            char outer[PATH_MAX];
            if (!realpath(cfg->paths[j].path, outer))
                snprintf(outer, sizeof(outer), "%s", cfg->paths[j].path);

            size_t olen = strlen(outer);
            while (olen > 1 && outer[olen - 1] == '/')
                olen--;
            if (strncmp(inner, outer, olen) != 0)
                continue;
            if (inner[olen] != '/')     /* strict descendant only */
                continue;

            fprintf(stderr, "%s: '%s' is inside the writable path '%s'\n",
                    tool, cfg->paths[i].path, cfg->paths[j].path);
            fprintf(stderr,
                "  Landlock is additive: the rights of every matching rule\n"
                "  are unioned, so a 'ro' rule under a 'rw'/'rwx' rule cannot\n"
                "  restrict anything — '%s' would stay writable.\n"
                "  Split the writable rules instead of carving one out.\n",
                cfg->paths[i].path);
            return -1;
        }
    }
    return 0;
}

/*
 * apply_landlock — build and enforce the ruleset.
 *
 * `tool` is the program name used in diagnostics.  Returns 0 on success.
 */
static inline int apply_landlock(Config *cfg, const char *tool)
{
    int abi = landlock_abi();
    if (abi < 0) {
        fprintf(stderr, "%s: Landlock not available (%s)\n",
                tool, strerror(errno));
        return -1;
    }

    /* Access rights we control — must include ALL rights we want to
     * restrict, otherwise Landlock silently allows them. */
    uint64_t handled_fs =
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
    if (abi >= 2) handled_fs |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) handled_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) handled_fs |= LANDLOCK_ACCESS_FS_IOCTL_DEV;

    /* Network.  Handle only the access types the policy actually names:
     * handling a right with no matching rule denies it outright, so
     * `net-connect 443` must not also forbid every bind().  `net-default
     * deny` is the explicit "handle both, allow only what is listed". */
    uint64_t handled_net = 0;
    if (cfg->net_default_deny)
        handled_net = LANDLOCK_ACCESS_NET_BIND_TCP |
                      LANDLOCK_ACCESS_NET_CONNECT_TCP;
    if (cfg->net_bind_count > 0)
        handled_net |= LANDLOCK_ACCESS_NET_BIND_TCP;
    if (cfg->net_connect_count > 0)
        handled_net |= LANDLOCK_ACCESS_NET_CONNECT_TCP;
    if (handled_net != 0 && abi < 4) {
        fprintf(stderr, "%s: WARNING: Landlock ABI v%d has no network "
                "support (v4 / Linux 6.7 is the minimum) — the TCP port "
                "policy in this profile is NOT active\n", tool, abi);
        handled_net = 0;
    }

    /* An empty ruleset (0 paths) with a non-zero handled mask would deny
     * ALL filesystem access — the process could not even load libc. */
    if (cfg->path_count == 0) {
        fprintf(stderr, "%s: landlock enabled but no paths "
                "configured — this would deny all filesystem access\n", tool);
        return -1;
    }

    struct compartment_ruleset_attr rs_attr = {
        .handled_access_fs  = handled_fs,
        .handled_access_net = handled_net,
    };
    /* Pass only the fs field when there is no network policy: an ABI-1..3
     * kernel knows nothing about the second word. */
    size_t attr_size = handled_net
        ? sizeof(rs_attr)
        : offsetof(struct compartment_ruleset_attr, handled_access_net);

    int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset,
                                  &rs_attr, attr_size, 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "%s: create_ruleset: %s\n", tool, strerror(errno));
        return -1;
    }

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
    if (abi >= 5) write_access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    uint64_t exec_access = LANDLOCK_ACCESS_FS_EXECUTE;
    uint64_t file_rights = landlock_file_rights(abi);

    int installed = 0;
    for (int i = 0; i < cfg->path_count; i++) {
        uint64_t access = 0;
        switch (cfg->paths[i].mode) {
        case PATH_RO:   access = read_access | exec_access; break;
        case PATH_RW:   access = read_access | write_access; break; /* W^X */
        /* `exec` is read + execute and nothing else.  On a directory it
         * also needs READ_DIR to be traversable and listable; on a file it
         * is exactly the per-binary execute grant that makes
         * `exec /bin/ls` an allow-list entry. */
        case PATH_EXEC: access = LANDLOCK_ACCESS_FS_READ_FILE | exec_access |
                                 LANDLOCK_ACCESS_FS_READ_DIR; break;
        case PATH_RWX:  access = read_access | write_access | exec_access; break;
        }
        int r = landlock_add_path(tool, ruleset_fd, &cfg->paths[i], access,
                                  file_rights, cfg->verbose);
        if (r < 0) {
            fprintf(stderr, "%s: landlock: failed to add rule for %s\n",
                    tool, cfg->paths[i].path);
            close(ruleset_fd);
            return -1;
        }
        installed += r;
    }

    int net_rules = 0;
    if (handled_net & LANDLOCK_ACCESS_NET_BIND_TCP) {
        for (int i = 0; i < cfg->net_bind_count; i++) {
            if (landlock_add_port(tool, ruleset_fd, cfg->net_bind_ports[i],
                                  LANDLOCK_ACCESS_NET_BIND_TCP,
                                  "net-bind") != 0) {
                close(ruleset_fd);
                return -1;
            }
            net_rules++;
        }
    }
    if (handled_net & LANDLOCK_ACCESS_NET_CONNECT_TCP) {
        for (int i = 0; i < cfg->net_connect_count; i++) {
            if (landlock_add_port(tool, ruleset_fd, cfg->net_connect_ports[i],
                                  LANDLOCK_ACCESS_NET_CONNECT_TCP,
                                  "net-connect") != 0) {
                close(ruleset_fd);
                return -1;
            }
            net_rules++;
        }
    }

    if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
        fprintf(stderr, "%s: restrict_self: %s\n", tool, strerror(errno));
        close(ruleset_fd);
        return -1;
    }
    close(ruleset_fd);

    if (cfg->verbose) {
        fprintf(stderr, "%s: landlock enforced (ABI v%d, %d of %d path "
                "rules installed", tool, abi, installed, cfg->path_count);
        if (handled_net)
            fprintf(stderr, ", %d TCP port rule%s", net_rules,
                    net_rules == 1 ? "" : "s");
        fprintf(stderr, ")\n");
    }
    return 0;
}

/* ── seccomp BPF (raw, no libseccomp) ────────────────────────────── */

/*
 * BPF program layout (same structure for both modes):
 *   [0]   load arch
 *   [1]   if arch == target → skip kill
 *   [2]   kill (wrong arch)
 *   [3]   load syscall nr
 *   [4]   (x86_64 only) if nr & 0x40000000 (x32 ABI) → kill
 *   For each rule (2 instructions each):
 *   [N+i*2]   if nr == syscall[i] → fall through to RET
 *   [N+i*2+1] RET (action for match)
 *   [last]    RET (default action)
 *
 * Deny-list:  match → ERRNO, default → ALLOW
 * Allow-list: match → ALLOW, default → ERRNO
 */
static inline int build_seccomp_bpf(int *syscalls, int count,
                                     uint32_t match_action,
                                     uint32_t default_action)
{
    int x32_insns = 0;
#if defined(__x86_64__)
    x32_insns = 2;  /* JSET + KILL for x32 ABI bypass prevention */
#endif
    int prog_len = 4 + x32_insns + count * 2 + 1;
    struct sock_filter *f = calloc((size_t)prog_len, sizeof(struct sock_filter));
    if (!f) return -1;

    int p = 0;

    f[p++] = (struct sock_filter)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, arch));

#if defined(__x86_64__)
    f[p++] = (struct sock_filter)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
#elif defined(__aarch64__)
    f[p++] = (struct sock_filter)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0);
#elif defined(__riscv) && __riscv_xlen == 64
    f[p++] = (struct sock_filter)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_RISCV64, 1, 0);
#elif defined(__s390x__)
    f[p++] = (struct sock_filter)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_S390X, 1, 0);
#elif defined(__powerpc64__)
    f[p++] = (struct sock_filter)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_PPC64LE, 1, 0);
#elif defined(__loongarch__)
    f[p++] = (struct sock_filter)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_LOONGARCH64, 1, 0);
#else
#error "Unsupported architecture: add AUDIT_ARCH_* entry for your platform"
#endif

    f[p++] = (struct sock_filter)
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    f[p++] = (struct sock_filter)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr));

#if defined(__x86_64__)
    /* Kill any x32 ABI syscall (bit 30 set). Without this, an attacker
     * can invoke blocked syscalls via x32 numbering (nr | 0x40000000)
     * and bypass the deny-list since the filter only matches native nrs. */
    f[p++] = (struct sock_filter)
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000, 0, 1);
    f[p++] = (struct sock_filter)
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif

    for (int i = 0; i < count; i++) {
        f[p++] = (struct sock_filter)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                     (uint32_t)syscalls[i], 0, 1);
        f[p++] = (struct sock_filter)
            BPF_STMT(BPF_RET | BPF_K, match_action);
    }

    f[p++] = (struct sock_filter)
        BPF_STMT(BPF_RET | BPF_K, default_action);

    struct sock_fprog prog = { .len = (unsigned short)p, .filter = f };
    int r = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    free(f);
    return r;
}

/* The action taken on a syscall the policy denies.  In deny-list mode this
 * is the action for a *listed* syscall; in allow-list mode it is the action
 * for everything not listed. */
static inline uint32_t seccomp_deny_action(const Config *cfg)
{
    switch (cfg->seccomp_default) {
    case SECCOMP_DEFAULT_KILL: return SECCOMP_RET_KILL_PROCESS;
    case SECCOMP_DEFAULT_LOG:  return SECCOMP_RET_LOG;
    case SECCOMP_DEFAULT_ERRNO:
    default:                   return SECCOMP_RET_ERRNO | (EPERM & 0xFFFF);
    }
}

static inline const char *seccomp_action_name(const Config *cfg)
{
    switch (cfg->seccomp_default) {
    case SECCOMP_DEFAULT_KILL: return "kill";
    case SECCOMP_DEFAULT_LOG:  return "log";
    case SECCOMP_DEFAULT_ERRNO:
    default:                   return "errno";
    }
}

static inline int apply_seccomp(Config *cfg)
{
    int r;

    if (cfg->seccomp_allow_mode) {
        /* Allow-list: only these syscalls permitted, default deny */
        if (cfg->allowed_sc_count == 0) {
            fprintf(stderr, "compartment: seccomp allow-mode with empty list\n");
            return -1;
        }
        r = build_seccomp_bpf(cfg->allowed_syscalls, cfg->allowed_sc_count,
                               SECCOMP_RET_ALLOW,
                               SECCOMP_RET_ERRNO | (EPERM & 0xFFFF));
        if (r != 0) {
            fprintf(stderr, "compartment: seccomp load failed: %s\n",
                    strerror(errno));
            return -1;
        }
        if (cfg->verbose)
            fprintf(stderr, "compartment: seccomp ALLOW-LIST enforced "
                    "(%d syscalls allowed, rest denied)\n", cfg->allowed_sc_count);
    } else {
        /* Deny-list: block these syscalls, default allow */
        if (cfg->blocked_count == 0) {
            fprintf(stderr, "compartment: warning: seccomp enabled but no "
                    "syscalls to block — no filter installed\n");
            return 0;
        }
        r = build_seccomp_bpf(cfg->blocked_syscalls, cfg->blocked_count,
                               SECCOMP_RET_ERRNO | (EPERM & 0xFFFF),
                               SECCOMP_RET_ALLOW);
        if (r != 0) {
            fprintf(stderr, "compartment: seccomp load failed: %s\n",
                    strerror(errno));
            return -1;
        }
        if (cfg->verbose)
            fprintf(stderr, "compartment: seccomp DENY-LIST enforced "
                    "(%d syscalls blocked)\n", cfg->blocked_count);
    }
    return 0;
}

#endif /* COMPARTMENT_H */
