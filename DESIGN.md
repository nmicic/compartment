<!-- Copyright (c) 2026 Nenad Mićić <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Compartment — Design Notes

## Lineage

compartment-user descends from **shell-guard** (~2003), a shell
replacement that intercepted every `execve("/bin/bash")` on a server,
walked the PPID chain, checked parent names/paths/sockets, and logged
everything to syslog. It was written as a stop-gap for servers where
kernel-level MAC (LIDS/lidsadm) could not be deployed.

The core idea — replace the shell binary, inspect who is calling it,
allow or deny — carries forward into compartment-user's
shell-replacement mode, now backed by Landlock and seccomp instead of
userspace policy checks.

shell-guard is preserved in `archive/shell-guard/` as a self-contained
tool. It still works on legacy Linux boxes that lack modern kernel
features (namespaces, Landlock, seccomp).

## Architecture: Shared Header

```
compartment.h           <- shared code (static inline, zero deps)
  |-- Profile file parser (load_profile_file, resolve_and_load_profile)
  |-- Audit logging (PPID chain, file-per-day, O_CLOEXEC)
  |-- Environment sanitization (deny-list + allow-list)
  |-- Variable expansion ($HOME, $USER)
  |-- Syscall name->number table (135 entries, __NR_* macros, portable)
  |-- Capability name->number table (41 entries)
  |-- seccomp BPF builder (raw, no libseccomp)
  +-- Common Config fields and types

compartment-user.c      <- includes compartment.h
  |-- Landlock enforcement
  |-- Shell-replacement mode (argv[0] detection)
  |-- AI-agent built-in profiles
  +-- main() with rootless CLI

compartment-root.c      <- includes compartment.h
  |-- Namespace creation (clone flags)
  |-- pivot_root + /dev + /proc setup
  |-- UID/GID mapping
  |-- Capability drop + preserve (raw prctl + capset, no libcap)
  |-- Cgroup assignment
  |-- Network namespace (join or create)
  +-- main() with root CLI
```

Both tools are single-file builds:
```bash
cc -o compartment-user compartment-user.c          # zero deps
cc -o compartment-root compartment-root.c          # zero deps
```

The header is `#include`d directly — no separate compilation unit, no
linking, no build system complexity.

## Unification History

### Phase 1: Extract shared code into compartment.h

Moved from compartment-user.c into compartment.h: `PathRule`/`PathMode`
types, `Config` struct, `SyscallEntry` table, `resolve_syscall()`,
`expand_var()`, profile file loader, audit logging, `sanitize_env()`,
`apply_seccomp()` (raw BPF). Both tools now `#include "compartment.h"`.

### Phase 2: Drop libseccomp from compartment-root

Replaced `seccomp_init()`/`seccomp_rule_add()`/`seccomp_load()` with
the raw BPF builder from compartment.h. No `-lseccomp` needed.

### Phase 3: Drop libcap from compartment-root

Replaced `cap_init()`/`cap_set_flag()`/`cap_set_proc()` with raw
`prctl(PR_CAPBSET_DROP, cap)` + static capability table. No `-lcap`.

### Phase 4: Wire profile files into compartment-root

Added `--profile` flag, root-specific directives (rootdir, uid, gid,
username, netns, cgroup, cap-allow, loopback, mount-mask), and
`--dry-run`, `--verify`, `--verbose`, `--audit` flags.

### Phase 5: Environment sanitization in compartment-root

Wired `sanitize_env()` from compartment.h into child setup (after
pivot_root, before exec). Supports deny-list and allow-list modes.

### Phase 6: Audit logging in compartment-root

Wired `audit_log_open()` + `audit_log()`. Log opened before `clone()`
(host filesystem). Events: CONTAINER_START, CONTAINER_EXEC, CONTAINER_EXIT.

### Bonus: Portable syscall table

Replaced architecture-split table (35 hardcoded entries for x86_64 +
aarch64 separately) with 135-entry table using `__NR_*` macros from
`<sys/syscall.h>`. Single table, portable across architectures
(x86_64, aarch64, riscv64, s390x, ppc64le, loongarch64).

## Security Review (2026-03-31)

External review + automated testing uncovered these bugs:

### Bugs found and fixed

| # | Severity | Component | Issue | Fix |
|---|----------|-----------|-------|-----|
| 1 | **High** | compartment-user | Landlock `handled` mask missing `REMOVE_FILE`, `REMOVE_DIR`, `MAKE_CHAR`, `MAKE_BLOCK` — sandboxed processes could delete files and create device nodes even in read-only paths | Added all four to `handled` and `write_access` masks |
| 2 | **High** | compartment-root | UID/GID mapping written from child (TOCTOU race) — child wrote its own maps but parent hadn't finished setup | Reversed pipe sync: parent writes maps + assigns cgroups, then signals child |
| 3 | **High** | compartment-root | `apply_seccomp()` return value ignored — exec proceeded even if seccomp failed | Added fatal check: `if (apply_seccomp() != 0) exit(EXIT_FAILURE)` |
| 4 | **High** | compartment-root | Capability drop after privilege drop — `PR_CAPBSET_DROP` requires `CAP_SETPCAP`, lost after `setuid()` | Moved `drop_capabilities()` before `drop_privileges()` |
| 5 | **Medium** | compartment-root | Cgroup assignment after `pivot_root` — host cgroup paths unreachable | Moved `assign_to_cgroups()` to parent process (before child enters namespace) |
| 6 | **Medium** | compartment-root | `setgroups(1, &gid)` — should be `setgroups(0, NULL)` with EPERM tolerance | Fixed; some user-ns configs disallow `setgroups(2)` |
| 7 | **Low** | sandbox.sh | Missing `--mount` flag on `unshare` — bind mounts for shell interception failed | Added `--mount` to both HARD and SOFT paths |
| 8 | **Low** | sandbox.sh | SOFT mode misleadingly claimed "airgapped" — slirp4netns provides outbound NAT | Fixed log messages to accurately describe SOFT mode |
| 9 | **Low** | compartment-root | FD cleanup range 1024 too small — leaked fds from parent | Changed to 4096 |
| 10 | **Medium** | compartment.h | `expand_var()` returned truncated path on buffer overflow — could create broader policy than intended | Returns NULL on truncation; caller aborts with error message |
| 11 | **Low** | compartment-root | Missing `CLONE_NEWCGROUP` — container could see host cgroup hierarchy | Added to clone flags (Linux 4.6+, with fallback define) |
| 12 | **High** | compartment-root | `cap-allow` only dropped bounding set — after `setuid()`, service user had zero effective caps despite profile | Added `PR_SET_KEEPCAPS` + raw `capset()` + `PR_CAP_AMBIENT_RAISE` |
| 13 | **Medium** | compartment-user | Shell-replacement mode fail-open — ignored `prctl`/Landlock/seccomp failures | Made fail-closed: abort with rc=126 if any enforcement fails |
| 14 | **Medium** | compartment-user | `workdir` directive only implied `rw` in built-in ai-agent profile, not file-loaded profiles | Auto-add `rw` for `workdir` after all profile loading |
| 15 | **High** | compartment-root | `join_netns()` path traversal — `netns_name` containing `/` could open arbitrary files instead of `/var/run/netns/<name>` | Reject any `netns_name` that contains `/` |
| 16 | **High** | compartment-root | `assign_to_cgroups()` path traversal — cgroup paths with `..` components could write PID to arbitrary files | Reject relative paths and paths containing `..` components |
| 17 | **High** | compartment-user | Shell-replacement `COMPARTMENT_SHELL_DIR` path traversal — env var could point outside intended directory | Reject non-absolute paths and paths containing `..` components |
| 18 | **Medium** | sandbox.sh | Predictable proxy socket path in world-writable `/tmp` — race window for socket hijack | Move socket into a private `mktemp -d` directory (mode 700) |
| 19 | **Medium** | sandbox.sh | `slirp4netns` success not verified — SOFT mode proceeded with broken networking on slirp failure | Poll for `tap0` interface appearance; abort if it does not appear |
| 20 | **High** | compartment.h | Profile `uid`/`gid` parsed with `strtoul(val, NULL, 10)` — no error/range check; value `4294967296` silently truncates to UID 0 (root) | Added endptr/errno/range validation matching CLI parser |
| 21 | **High** | compartment-root | CLI `--uid`/`--gid` accepted values > UINT32_MAX — truncation to UID 0 on 64-bit systems | Added `val > UINT32_MAX` range check |
| 22 | **High** | sandbox.sh | `UPSTREAM_PROXY` passed through `bash -c` in `--verify` — shell injection via attacker-controlled proxy env var | Replaced with direct socat call + host:port format validation |
| 23 | **High** | compartment.h | Profile limit truncation (paths/syscalls/env) returned success — silently weakened policy | Made fail-closed: abort profile loading when any limit exceeded |
| 24 | **High** | compartment-user | `landlock_add_path()` return value ignored in `apply_landlock()` — failed rules silently weakened filesystem policy | Check return; abort on failure |
| 25 | **Medium** | compartment.h | Profile line >1024 chars silently wrapped — remainder parsed as new directive, could alter security policy | Detect truncated lines and abort with error |
| 26 | **Medium** | compartment.h | Boolean directives only accepted exact string `"on"` — `"yes"`, `"true"`, `"ON"` silently disabled security features | Accept on/off/yes/no/true/false/1/0 (case-insensitive); reject unrecognized values |
| 27 | **Medium** | compartment.h | Unknown profile directives silently ignored — typos like `blokc ptrace` had no effect with no warning | Emit warning on unrecognized directives |
| 28 | **Medium** | sandbox.sh | `PROXY_HOSTPORT` and `SANDBOX_PROXY_PORT` not validated — potential socat argument injection via env vars | Validate host:port regex and numeric port before use |
| 29 | **Low** | compartment-root | Missing `O_CLOEXEC` on netns fd, loopback socket, uid_map fd — potential fd leak across exec boundary | Added `O_CLOEXEC`/`SOCK_CLOEXEC` to all short-lived fds |
| 30 | **Low** | compartment.h/user | Multiple `snprintf` calls unchecked for truncation — silently truncated paths could match wrong files | Added truncation checks with error returns |
| 31 | **High** | compartment-user | seccomp deny-list missing container escape syscalls: `open_by_handle_at`, `name_to_handle_at`, new mount API (`move_mount`, `fsopen`, `fsmount`, `fsconfig`, `fspick`), `pidfd_getfd` | Added to ai-agent deny-list (built-in + conf) |
| 32 | **Medium** | compartment-user | Environment sanitization missed cloud/VCS/SSH credential variables (AWS, GCP, GitHub, SSH_AUTH_SOCK, DB passwords) | Added 13 credential env vars to deny-list |
| 33 | **Low** | compartment.h | `MAX_ENV_VARS` was 32 — too tight with expanded env-deny list, risked silent truncation | Increased to 64 |
| 34 | **High** | compartment.h | x32 ABI seccomp bypass on x86_64 — attacker could invoke blocked syscalls via x32 numbering (`nr \| 0x40000000`) and the BPF deny-list would not match | Added `BPF_JSET` check: kill any syscall with x32 bit set (credit: Gemini review) |
| 35 | **Medium** | compartment-user | FD close fallback only iterated to 1024 — leaked inherited FDs above 1023 when `close_range(2)` unavailable | Use `getrlimit(RLIMIT_NOFILE)` for upper bound (credit: Codex review) |
| 36 | **Medium** | compartment.h | Unknown syscall in `block`/`allow` directive only warned, did not indicate the block was NOT applied | Warning now explicitly says "block NOT applied" to make silent weakening visible |
| 37 | **Medium** | compartment-user | CLI `--no-landlock`/`--no-seccomp`/`--no-env-sanitize` could be undone by a profile loaded after CLI parsing | CLI disable flags now always take precedence over profile (credit: Codex review) |
| 38 | **Medium** | compartment-root | Mount propagation used `MS_SLAVE` (allows host→container events) but comment said "private" | Changed to `MS_PRIVATE` — fully isolates mount propagation (credit: Codex review) |

### seccomp Return Action: EPERM vs KILL

The BPF deny-list returns `SECCOMP_RET_ERRNO | EPERM` rather than
`SECCOMP_RET_KILL_PROCESS`. This is deliberate:

- **EPERM** lets well-behaved applications handle blocked syscalls
  gracefully (retry, fallback, log). Most runtimes (Node.js, Python,
  Go) check return values and degrade gracefully on EPERM.
- **KILL_PROCESS** terminates the entire process group on the first
  blocked syscall, which makes debugging difficult and can cause data
  loss in applications that were writing output.

The tradeoff: a sandboxed process can observe which syscalls return
EPERM and fingerprint its sandbox. If your threat model includes
sandbox-aware adversaries that probe their environment, consider using
the allow-list mode (`--allow` / `allow` directives) instead, which
blocks everything not explicitly permitted. For the default deny-list
use case (AI agents, development tools), EPERM provides the right
balance of safety and usability.

### Testing

52 automated tests across 4 suites:

- **Compartment-user matrix** (46 tests): Landlock ro/rw paths, seccomp
  deny-list (ptrace, unshare, process_vm_*, userfaultfd, perf_event_open,
  io_uring), environment sanitization (deny-list + preserve), combined
  profiles, built-in profiles (ai-agent, strict + inheritance), --dry-run,
  --verify, shell-replacement mode
- **Child inheritance** (6 tests): seccomp survives fork/exec via /bin/sh
  and /bin/bash, Landlock inherited by children, env sanitization inherited,
  grandchild (depth-2) inherits seccomp
- **Sandbox.sh** (skipped in containers): HARD/SOFT network modes, proxy bridge
- **Claude CLI smoke** (4 tests): `claude --version` + `claude --print` under
  full sandbox, audit logging captures PPID chain, --dry-run policy display

Tests use `deny_probe`, a purpose-built binary with subcommands for each
operation (fs_read, fs_write, sc_ptrace_traceme, env_get, spawn_sh, etc.)
that reports machine-parseable results.
