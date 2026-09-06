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
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

/* ── Constants ─────────────────────────────────────────────────────── */

#define MAX_PATHS         64
#define MAX_BLOCKED_SC    256
#define MAX_ALLOWED_SC    512
#define MAX_ENV_VARS      64
#define MAX_LINE          1024
#define MAX_INHERIT_DEPTH 2

/* ── Path rule ──────────────────────────────────────────────────────── */

typedef enum { PATH_RO, PATH_RW, PATH_EXEC, PATH_RWX } PathMode;

typedef struct {
    const char *path;
    PathMode    mode;
} PathRule;

/* ── Configuration (shared base fields) ────────────────────────────── */

typedef struct {
    PathRule    paths[MAX_PATHS];
    int         path_count;

    int         blocked_syscalls[MAX_BLOCKED_SC];
    int         blocked_count;

    int         allowed_syscalls[MAX_ALLOWED_SC];
    int         allowed_sc_count;
    int         seccomp_allow_mode;  /* 0=deny-list (block), 1=allow-list (allow only) */

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
    c->paths[c->path_count].path = dup ? xstrdup(path) : path;
    c->paths[c->path_count].mode = mode;
    c->path_count++;
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
             * 2. Standard search paths (~/.config/compartment/, /etc/compartment/)
             * This ensures "inherit ai-agent" works when strict.conf and
             * ai-agent.conf sit in the same directory. */
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
        } else if (strcmp(directive, "mount-mask") == 0) {
            if (cfg_add_str(cfg->mount_masks, &cfg->mount_mask_count, MAX_PATHS, where, "mount-mask", val, 1) != 0) {
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

/* Create dir and any missing parent. Intermediates get 0755, the leaf the
 * requested mode. */
static inline int mkdir_parents(const char *dir, mode_t mode)
{
    char tmp[PATH_MAX];
    size_t n = strlen(dir);
    if (n == 0 || n >= sizeof(tmp)) { errno = ENAMETOOLONG; return -1; }
    memcpy(tmp, dir, n + 1);
    while (n > 1 && tmp[n-1] == '/') tmp[--n] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* Default audit directory. $XDG_STATE_HOME/compartment (or
 * ~/.local/state/compartment) for an ordinary user, /var/log/compartment
 * for root. The old default lived under world-writable /var/tmp. */
static inline int audit_default_dir(char *dir, size_t dirsz)
{
    if (geteuid() == 0) {
        int n = snprintf(dir, dirsz, "/var/log/compartment");
        return (n > 0 && (size_t)n < dirsz) ? 0 : -1;
    }
    const char *xdg = getenv("XDG_STATE_HOME");
    const char *why = NULL;
    const char *home = home_dir_usable(getenv("HOME"), &why);
    int n;
    if (xdg && xdg[0] == '/')
        n = snprintf(dir, dirsz, "%s/compartment", xdg);
    else if (home)
        n = snprintf(dir, dirsz, "%s/.local/state/compartment", home);
    else {
        fprintf(stderr, "compartment: no usable audit log directory "
                "($XDG_STATE_HOME unset and $HOME %s) — use --audit-log DIR\n",
                why ? why : "unusable");
        return -1;
    }
    return (n > 0 && (size_t)n < dirsz) ? 0 : -1;
}

static inline int audit_log_open(Config *cfg)
{
    char dir[PATH_MAX - 32];  /* leave room for /YYYY-MM-DD.log */
    int explicit_dir = cfg->audit_log_dir != NULL;

    if (explicit_dir) {
        int n = snprintf(dir, sizeof(dir), "%s", cfg->audit_log_dir);
        if (n < 0 || (size_t)n >= sizeof(dir)) {
            fprintf(stderr, "compartment: audit log dir path too long\n");
            return -1;
        }
        if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
            fprintf(stderr, "compartment: mkdir %s: %s\n", dir, strerror(errno));
            return -1;
        }
    } else {
        if (audit_default_dir(dir, sizeof(dir)) != 0)
            return -1;
        if (mkdir_parents(dir, 0700) != 0) {
            fprintf(stderr, "compartment: mkdir %s: %s\n", dir, strerror(errno));
            return -1;
        }
    }

    /* Validate the directory on its own fd, then create the day file
     * relative to it. O_NOFOLLOW on the final component alone left the
     * directory component followable: a symlink at the audit path
     * redirected every record somewhere else. */
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dfd < 0) {
        fprintf(stderr, "compartment: audit dir %s: %s\n", dir, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(dfd, &st) != 0) {
        fprintf(stderr, "compartment: audit dir %s: %s\n", dir, strerror(errno));
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
