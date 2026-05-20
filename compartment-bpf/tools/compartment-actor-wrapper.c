/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 * compartment-actor-wrapper — clean-exec launch hygiene for actor binaries.
 *
 * One source file, two build shapes:
 *   - Option A (default): generic wrapper. Usage:
 *       compartment-actor-wrapper --actor NAME -- /abs/target [args...]
 *   - Option B: compile with -DWRAPPER_GENERATED -DTARGET_PATH=\"/abs\"
 *       -DACTOR_NAME=\"name\" so the binary's target is baked in.
 *       Generated per-actor wrappers (tools/compartment-actor-build.sh).
 *
 * Hardening sequence (fail-closed unless --insecure-allow-degraded):
 *   1. PR_SET_DUMPABLE  = 0     (no core dumps, no ptrace via core)
 *   2. PR_SET_NO_NEW_PRIVS = 1  (mandatory; required before seccomp)
 *   3. PR_CAP_AMBIENT_CLEAR_ALL (best-effort; warn if kernel too old)
 *   4. close inherited fds >= 3 via close_range, fallback fcntl loop
 *   5. env: clearenv() + allowlist (PATH fixed default + optional opt-ins)
 *   6. seccomp BPF denylist (ptrace, process_vm_*, pidfd_getfd, kcmp, bpf,
 *      perf_event_open, userfaultfd, keyctl/add_key/request_key,
 *      open_by_handle_at/name_to_handle_at, mount/umount2/move_mount/
 *      open_tree/fsopen/fsmount/fsconfig/fspick/mount_setattr,
 *      PR_SET_MM via prctl arg0 (best effort, arch-dependent))
 *   7. execve(target, argv, envp)
 *
 * Inspired by ~/compartment/compartment-user.c (Apache-2.0, same license).
 * Zero deps: libc + linux headers only. No libseccomp, no libcap.
 *
 * Build requirement: STATIC LINK (-static). A dynamically-linked wrapper
 * is compromised by LD_PRELOAD against ITSELF — ld.so loads the attacker
 * .so into the wrapper's address space and runs its constructor BEFORE
 * main() can scrub env. A statically-linked wrapper has no ld.so and is
 * immune. Tests:
 * actor-wrapper/run.sh which asserts both shapes.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/auxv.h>      /* HIGH-11: getauxval(AT_BASE) static-link check */
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>

/* Shared dangerous-env-name list. Single
 * source of truth between the wrapper (runtime scrub) and the
 * compartment-bpf loader (parse-time invariant). The header defines
 * COMPARTMENT_DANGEROUS_ENV_NAMES + compartment_env_name_is_dangerous(). */
#include "compartment-dangerous-env.h"

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif
#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif
#ifndef PR_SET_MM
#define PR_SET_MM 35
#endif
#ifndef PR_SET_MM_EXE_FILE
#define PR_SET_MM_EXE_FILE 13
#endif

#ifndef __NR_close_range
#  if defined(__x86_64__)
#    define __NR_close_range 436
#  endif
#endif

/* Arch audit + syscall number selection. Wrapper supports x86_64 only here;
 * extend with care for other arches because syscall numbers differ. */
#if defined(__x86_64__)
#  define WRAPPER_AUDIT_ARCH AUDIT_ARCH_X86_64
#else
#  error "compartment-actor-wrapper: only x86_64 is supported in v0; \
extend syscall numbers + AUDIT_ARCH for additional arches"
#endif

static const char *g_actor = NULL;
static int g_insecure_allow_degraded = 0;
static int g_verbose = 0;

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "compartment-actor-wrapper: FATAL: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    _exit(127);
}

static void warn_or_die(const char *what) {
    if (g_insecure_allow_degraded) {
        fprintf(stderr, "compartment-actor-wrapper: WARN: %s failed: %s "
                "(degraded mode allowed)\n", what, strerror(errno));
        return;
    }
    die("%s failed: %s", what, strerror(errno));
}

static void vlog(const char *fmt, ...) {
    if (!g_verbose) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "compartment-actor-wrapper: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/* ------- step 1/2/3: prctl baseline ------- */
static void harden_prctl(void) {
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
        warn_or_die("PR_SET_DUMPABLE=0");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        die("PR_SET_NO_NEW_PRIVS failed: %s (mandatory for seccomp)",
            strerror(errno));
    /* PR_CAP_AMBIENT_CLEAR_ALL added in 4.3; warn on older kernels. */
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) {
        if (errno != EINVAL && errno != ENOSYS) {
            warn_or_die("PR_CAP_AMBIENT_CLEAR_ALL");
        } else {
            vlog("PR_CAP_AMBIENT_CLEAR_ALL not supported by kernel (ok)");
        }
    }
    vlog("prctl: dumpable=0, no_new_privs=1, ambient cleared");
}

/* ------- step 4: close inherited fds >= 3 ------- */
static void close_inherited_fds(void) {
#ifdef __NR_close_range
    long r = syscall(__NR_close_range, (unsigned)3, ~0U, 0);
    if (r == 0) { vlog("close_range(3, ~0U) ok"); return; }
    if (errno != ENOSYS) {
        /* close_range present but failed for some fd; not fatal — fall back. */
        vlog("close_range returned %ld errno=%d, falling back", r, errno);
    }
#endif
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd <= 0) maxfd = 1024;
    for (int fd = 3; fd < maxfd; fd++) {
        (void)close(fd);
    }
    vlog("close fd loop done (maxfd=%ld)", maxfd);
}

/* ------- step 5: env scrub ------- */
/* Brief §111-127 — these names MUST never reach the target.
 *
 * The original 16-entry list mirrored glibc's
 * `elf/dl-tunable-list.h` ld.so subset only. Extended to mirror the
 * canonical `elf/unsecvars.h` enumeration AND the application-tooling
 * vectors that downstream interpreters and crypto / resolver libraries
 * honour. New buckets are commented inline so future drift against a
 * glibc update is auditable.
 *
 * Categories:
 *  - dynamic-linker (LD_*, GLIBC_TUNABLES, GCONV_PATH, LOCPATH, NLSPATH,
 *    RES_OPTIONS, RESOLV_*, HOSTALIASES, IFS, NIS_PATH, MALLOC_*,
 *    TMPDIR via shell pollution avoidance — kept narrow);
 *  - shell-script attack vectors (BASH_ENV, ENV, CDPATH, BASHOPTS,
 *    SHELLOPTS, BASH_FUNC_* — wildcard matched by env_is_dangerous
 *    via the BASH_FUNC_ prefix check below);
 *  - OpenSSL / crypto config (OPENSSL_CONF, OPENSSL_ENGINES, OPENSSL_-
 *    MODULES, SSL_CERT_FILE, SSL_CERT_DIR, CURL_CA_BUNDLE, CURL_HOME,
 *    KRB5_CONFIG, SASL_PATH);
 *  - language interpreters (PYTHONPATH/STARTUP, PERL5LIB/OPT, RUBYLIB/
 *    OPT, NODE_OPTIONS, JAVA_TOOL_OPTIONS, _JAVA_OPTIONS, JDK_JAVA_-
 *    OPTIONS, GIT_TRACE / GIT_EXEC_PATH).
 *
 * BASH_FUNC_* exported-function vector is matched by prefix (see
 * env_is_dangerous below) — glibc accepts the export across exec
 * even with the `()` shellshock fix because the prefix landed.
 *
 */
/* The canonical list moved to
 * `compartment-dangerous-env.h` (included above). Keep the symbol name
 * `DANGEROUS_ENV_NAMES` as a #define alias so the existing wrapper
 * test surface (`tests/actor-wrapper/run.sh`) and any external symbol-
 * grep tooling continue to find it. */
#define DANGEROUS_ENV_NAMES COMPARTMENT_DANGEROUS_ENV_NAMES

/* Default allowlist: empty. PATH is set explicitly below regardless of
 * caller. LANG, LC_xxx, TZ, TERM are opt-in via --allow-env (MINOR-4).
 *
 * For Option A, callers pass
 * --allow-env NAME repeatedly. For Option B, generator bakes these. */
#ifndef WRAPPER_GENERATED_ALLOW_ENV_NAMES
#  define WRAPPER_GENERATED_ALLOW_ENV_NAMES NULL
#endif

#define WRAPPER_FIXED_PATH "PATH=/usr/sbin:/usr/bin:/sbin:/bin"

/* Runtime helper now lives in the shared
 * header (compartment_env_name_is_dangerous). Keep `env_is_dangerous`
 * as a thin alias so the surrounding wrapper code (and the existing
 * tests/actor-wrapper/run.sh witnesses) need no edits. */
static int env_is_dangerous(const char *name)
{
    return compartment_env_name_is_dangerous(name);
}

struct allow_list {
    const char **names;
    int count;
    int cap;
};

static void allow_add(struct allow_list *al, const char *name) {
    if (env_is_dangerous(name)) {
        die("env allow request for explicitly-denied name: %s", name);
    }
    if (al->count == al->cap) {
        al->cap = al->cap ? al->cap * 2 : 8;
        al->names = realloc(al->names, sizeof(*al->names) * al->cap);
        if (!al->names) die("oom");
    }
    al->names[al->count++] = name;
}

static void scrub_env(const struct allow_list *al, char ***out_envp) {
    extern char **environ;
    /* Snapshot allowed values BEFORE clearenv (clearenv destroys environ). */
    int snap_cap = al->count + 4;
    char **snap = calloc(snap_cap, sizeof(*snap));
    if (!snap) die("oom");
    int n_snap = 0;
    for (int i = 0; al->names && i < al->count; i++) {
        const char *v = getenv(al->names[i]);
        if (!v) continue;
        size_t len = strlen(al->names[i]) + 1 + strlen(v) + 1;
        char *kv = malloc(len);
        if (!kv) die("oom");
        snprintf(kv, len, "%s=%s", al->names[i], v);
        snap[n_snap++] = kv;
    }
    if (clearenv() != 0) warn_or_die("clearenv");
    /* Build new envp: fixed PATH + snapshotted allowed names + NULL. */
    int envp_cap = n_snap + 4;
    char **envp = calloc(envp_cap, sizeof(*envp));
    if (!envp) die("oom");
    int n = 0;
    envp[n++] = strdup(WRAPPER_FIXED_PATH);
    if (!envp[n - 1]) die("oom");
    for (int i = 0; i < n_snap; i++) envp[n++] = snap[i];
    envp[n] = NULL;
    /* Mirror onto process environ as well so any libc consumer between
     * here and execve sees the same view. */
    if (setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1) != 0)
        warn_or_die("setenv PATH");
    for (int i = 0; i < n_snap; i++) {
        char *eq = strchr(snap[i], '=');
        if (!eq) continue;
        *eq = '\0';
        setenv(snap[i], eq + 1, 1);
        *eq = '=';
    }
    free(snap);
    *out_envp = envp;
    vlog("env scrub: kept %d names + fixed PATH", n_snap);
}

/* ------- step 6: seccomp denylist ------- */
/* Raw cBPF builder, no libseccomp.
 * Architecture-gated: refuses to install if syscall arch differs from build.
 * Returns 0 on success; aborts on failure unless degraded mode. */

#define BPF_LD_ABS_W(off) \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (off))
#define BPF_JEQ_K_NEXT(k, jt_to_kill) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (k), (jt_to_kill), 0)

/* offsetof seccomp_data fields */
#define SD_NR          0
#define SD_ARCH        4
#define SD_ARG0_LO     16
#define SD_ARG0_HI     20

/* List of syscalls to deny. We will jump to KILL label if any matches.
 * Note: some of these may be undefined on some arches; we guard with #ifdef. */
struct deny_entry { const char *name; int nr; };

static const struct deny_entry DENY[] = {
#ifdef __NR_ptrace
    {"ptrace", __NR_ptrace},
#endif
#ifdef __NR_process_vm_readv
    {"process_vm_readv", __NR_process_vm_readv},
#endif
#ifdef __NR_process_vm_writev
    {"process_vm_writev", __NR_process_vm_writev},
#endif
#ifdef __NR_pidfd_getfd
    {"pidfd_getfd", __NR_pidfd_getfd},
#endif
#ifdef __NR_kcmp
    {"kcmp", __NR_kcmp},
#endif
#ifdef __NR_bpf
    {"bpf", __NR_bpf},
#endif
#ifdef __NR_perf_event_open
    {"perf_event_open", __NR_perf_event_open},
#endif
#ifdef __NR_userfaultfd
    {"userfaultfd", __NR_userfaultfd},
#endif
#ifdef __NR_keyctl
    {"keyctl", __NR_keyctl},
#endif
#ifdef __NR_add_key
    {"add_key", __NR_add_key},
#endif
#ifdef __NR_request_key
    {"request_key", __NR_request_key},
#endif
#ifdef __NR_open_by_handle_at
    {"open_by_handle_at", __NR_open_by_handle_at},
#endif
#ifdef __NR_name_to_handle_at
    {"name_to_handle_at", __NR_name_to_handle_at},
#endif
#ifdef __NR_mount
    {"mount", __NR_mount},
#endif
#ifdef __NR_umount2
    {"umount2", __NR_umount2},
#endif
#ifdef __NR_move_mount
    {"move_mount", __NR_move_mount},
#endif
#ifdef __NR_open_tree
    {"open_tree", __NR_open_tree},
#endif
#ifdef __NR_fsopen
    {"fsopen", __NR_fsopen},
#endif
#ifdef __NR_fsmount
    {"fsmount", __NR_fsmount},
#endif
#ifdef __NR_fsconfig
    {"fsconfig", __NR_fsconfig},
#endif
#ifdef __NR_fspick
    {"fspick", __NR_fspick},
#endif
#ifdef __NR_mount_setattr
    {"mount_setattr", __NR_mount_setattr},
#endif
};

#define DENY_COUNT (int)(sizeof(DENY)/sizeof(DENY[0]))

static void install_seccomp(void) {
    /* Filter layout:
     *   1) arch != WRAPPER_AUDIT_ARCH         -> RET_KILL_PROCESS
     *   2) if nr == prctl, inspect arg0; arg0==PR_SET_MM -> RET_ERRNO(EPERM)
     *   3) chained checks: for each deny entry, if nr == entry -> RET_ERRNO(EPERM)
     *   4) default                            -> RET_ALLOW
     *
     * We use a simple linear chain rather than the optimal jump-table; the
     * actor process has dozens to a few-hundred syscalls per request, so the
     * O(n) scan cost is negligible vs the file ops they drive. KISS.
     */
    /* Size: 3 arch + 1 ld_nr + 5 prctl + 2*DENY + 1 allow = 10 + 2*DENY.
     * Pad to 16+2*DENY for headroom against future inserts. */
    int prog_cap = 16 + 2 * DENY_COUNT;
    struct sock_filter *filt = calloc(prog_cap, sizeof(*filt));
    if (!filt) die("oom seccomp");
    int p = 0;

    /* 1. Arch guard. Load arch; if != WRAPPER_AUDIT_ARCH kill. */
    filt[p++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_ARCH);
    filt[p++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                              WRAPPER_AUDIT_ARCH, 1, 0);
    filt[p++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                              SECCOMP_RET_KILL_PROCESS);

    /* Load syscall nr once. */
    filt[p++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_NR);

#ifdef __NR_prctl
    /* 2. prctl arg0==PR_SET_MM -> EPERM. We don't yet narrow to EXE_FILE

     * We deny the entire PR_SET_MM (option) here; it is the only path to
     * EXE_FILE swap and the actor never needs PR_SET_MM in normal life. */
    /* if nr != prctl, jump over the prctl-arg block (3 insns ahead). */
    filt[p++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                              __NR_prctl, 0, 3);
    filt[p++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                              SD_ARG0_LO);
    filt[p++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                              PR_SET_MM, 0, 1);
    filt[p++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                              SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    /* Reload nr because arg load clobbered A. */
    filt[p++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_NR);
#endif

    /* 3. Linear deny chain. */
    for (int i = 0; i < DENY_COUNT; i++) {
        filt[p++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  DENY[i].nr, 0, 1);
        filt[p++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                                  SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    }

    /* 4. Default allow. */
    filt[p++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    struct sock_fprog prog = {
        .len = (unsigned short)p,
        .filter = filt,
    };
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) {
        /* Fallback to legacy prctl path on very old kernels. */
        if (errno == ENOSYS) {
            if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
                warn_or_die("seccomp install (prctl path)");
        } else {
            warn_or_die("seccomp install");
        }
    }
    vlog("seccomp installed: arch-guard + %d deny entries + prctl(PR_SET_MM) deny",
         DENY_COUNT);
    free(filt);
}

/* ------- argv parsing for Option A ------- */
#ifndef WRAPPER_GENERATED
static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s [options] --actor NAME -- /abs/target [target-args...]\n"
        "\n"
        "Options:\n"
        "  --actor NAME              Logical actor name (for logs only).\n"
        "  --allow-env NAME          Allow passthrough of env var NAME (repeatable).\n"
        "                            NAME may not be on the dangerous-env list.\n"
        "  --insecure-allow-degraded Continue if hardening setup fails (dev only).\n"
        "  -v, --verbose             Verbose hardening trace on stderr.\n"
        "  -h, --help                This help.\n"
        "\n"
        "Hardening: PR_SET_NO_NEW_PRIVS, PR_SET_DUMPABLE=0, cap-ambient clear,\n"
        "close fds>=3, env scrub (clearenv + fixed PATH + allowlist),\n"
        "seccomp denylist (ptrace, process_vm_*, pidfd_getfd, kcmp, bpf,\n"
        "perf_event_open, userfaultfd, key*, *_handle_at, mount/fs*,\n"
        "prctl(PR_SET_MM)).\n",
        argv0);
}
#endif

int main(int argc, char **argv) {
    struct allow_list al = {0};

    /* Static linking
     * MANDATORY. A site admin who rebuilds without -static (or who
     * substitutes their own compile invocation) gets a dynamic binary
     * that fails the LD_PRELOAD defense silently if T8 isn't part of
     * their regression. Assert at startup: getauxval(AT_BASE) returns
     * 0 for statically-linked binaries, non-zero (the runtime base
     * address of ld.so) for dynamically-linked binaries. Fail-closed
     * before any seccomp / env / argv work so a misbuilt wrapper
     * cannot be coerced into executing the target. */
    if (getauxval(AT_BASE) != 0) {
        fprintf(stderr,
            "compartment-actor-wrapper: FATAL: dynamically-linked "
            "binary detected (AT_BASE=0x%lx; expected 0). Static "
            "linking is MANDATORY — rebuild with -static. "
            "Rebuild with -static.\n",
            (unsigned long)getauxval(AT_BASE));
        return 2;
    }

#ifdef WRAPPER_GENERATED
    /* Option B: target is baked in at build time. No --actor / -- needed. */
#  ifndef TARGET_PATH
#    error "WRAPPER_GENERATED requires -DTARGET_PATH=\"...\""
#  endif
#  ifndef ACTOR_NAME
#    define ACTOR_NAME "(generated)"
#  endif
    g_actor = ACTOR_NAME;
    /* Pass through caller's argv as TARGET argv1..argvN. argv[0] is fixed
     * to basename(TARGET_PATH). */
    const char *target = TARGET_PATH;
    /* Parse only options understood in generated mode. */
    int idx = 1;
    while (idx < argc) {
        const char *a = argv[idx];
        if (strcmp(a, "--insecure-allow-degraded") == 0) {
            g_insecure_allow_degraded = 1; idx++; continue;
        }
        if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) {
            g_verbose = 1; idx++; continue;
        }
        break;  /* everything else is target argv */
    }
    char **target_argv = calloc(argc - idx + 2, sizeof(char *));
    if (!target_argv) die("oom");
    const char *base = strrchr(target, '/');
    target_argv[0] = (char *)(base ? base + 1 : target);
    int j = 1;
    for (int i = idx; i < argc; i++) target_argv[j++] = argv[i];
    target_argv[j] = NULL;
#  ifdef WRAPPER_GENERATED_ALLOW_ENV_LIST
    /* Optional baked-in env allowlist from generator. */
    {
        static const char *const baked[] = WRAPPER_GENERATED_ALLOW_ENV_LIST;
        for (int i = 0; baked[i]; i++) allow_add(&al, baked[i]);
    }
#  endif
#else
    /* Option A: parse argv. */
    const char *target = NULL;
    int idx = 1;
    while (idx < argc) {
        const char *a = argv[idx];
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(argv[0]); return 0;
        }
        if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) {
            g_verbose = 1; idx++; continue;
        }
        if (strcmp(a, "--insecure-allow-degraded") == 0) {
            g_insecure_allow_degraded = 1; idx++; continue;
        }
        if (strcmp(a, "--actor") == 0) {
            if (idx + 1 >= argc) die("--actor requires NAME");
            g_actor = argv[idx + 1];
            idx += 2; continue;
        }
        if (strcmp(a, "--allow-env") == 0) {
            if (idx + 1 >= argc) die("--allow-env requires NAME");
            allow_add(&al, argv[idx + 1]);
            idx += 2; continue;
        }
        if (strcmp(a, "--") == 0) { idx++; break; }
        die("unknown option: %s (use --help)", a);
    }
    if (idx >= argc)
        die("no target specified after '--' (use --help)");
    target = argv[idx++];
    if (target[0] != '/')
        die("target must be an absolute path, got: %s", target);

    /* Build target argv. argv[0] = basename(target) unless override is
     * provided via --argv0 (not in v0 scope per brief §146 default). */
    char **target_argv = calloc(argc - idx + 2, sizeof(char *));
    if (!target_argv) die("oom");
    const char *base = strrchr(target, '/');
    target_argv[0] = (char *)(base ? base + 1 : target);
    int j = 1;
    for (int i = idx; i < argc; i++) target_argv[j++] = argv[i];
    target_argv[j] = NULL;
#endif

    if (g_actor) vlog("actor=%s target=%s", g_actor, target);
    else vlog("target=%s (no actor name)", target);

    /* Order matters. fds first (before clearenv touches anything libc may
     * keep an fd for); then open the target_fd (the only fd we want to
     * outlive the close sweep); then prctl baseline; then env scrub
     * (writes environ); then seccomp (last, locks down everything
     * else); then execveat.
     *
     * Pre-fix used lstat(target) followed
     * by execve(target) — between the two syscalls an attacker with
     * write access to target's parent directory could swap target with
     * a symlink, bypassing the S_ISLNK refuse. Replaced with O_PATH +
     * O_NOFOLLOW open, fstat() on the held fd, and execveat(fd, "",
     * argv, envp, AT_EMPTY_PATH) — pins the inode between check and
     * exec so a path-swap race cannot alter what runs. close_inherited_-
     * fds() runs FIRST (it would otherwise close target_fd as part of
     * its [3, ~0U) sweep — even O_CLOEXEC is honoured at exec, not at
     * the close-loop layer). The pin window covers the rest of the
     * hardening sequence (prctl + scrub_env + seccomp) and execveat
     * resolves the new image from the held inode, not from any path
     * lookup. Option B (baked TARGET_PATH + sealed actor binary) is
     * the primary defender; this is belt-and-braces for Option A.

    close_inherited_fds();

    int target_fd = -1;
    {
        struct stat st;
        target_fd = open(target, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (target_fd < 0)
            die("open(%s, O_PATH|O_NOFOLLOW): %s", target, strerror(errno));
        if (fstat(target_fd, &st) != 0)
            die("fstat(%s): %s", target, strerror(errno));
        if (S_ISLNK(st.st_mode))
            die("target %s is a symlink — refusing", target);
        if (!S_ISREG(st.st_mode))
            die("target %s is not a regular file", target);
        if (st.st_size == 0)
            die("target %s is 0 bytes", target);
        if (st.st_mode & S_IWOTH)
            die("target %s is world-writable", target);
        if ((st.st_mode & S_IXUSR) == 0)
            die("target %s is not executable (u+x)", target);
    }

    harden_prctl();
    char **envp = NULL;
    scrub_env(&al, &envp);
    install_seccomp();

    execveat(target_fd, "", target_argv, envp, AT_EMPTY_PATH);
    /* execveat only returns on failure. */
    die("execveat(%s) failed: %s", target, strerror(errno));
    return 127;  /* not reached */
}
