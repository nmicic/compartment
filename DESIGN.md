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
  |-- Syscall name->number table (__NR_* macros, portable)
  |-- Capability name->number table (41 entries)
  |-- seccomp BPF builder (raw, no libseccomp)
  |-- Built-in seccomp deny-list (one table, used by both tools)
  |-- Landlock ruleset builder (path rules, TCP port rules, ABI gating)
  +-- Common Config fields and types

compartment-user.c      <- includes compartment.h
  |-- Shell-replacement mode (argv[0] detection)
  |-- AI-agent built-in profiles
  +-- main() with rootless CLI

compartment-root.c      <- includes compartment.h
  |-- Namespace creation (clone flags)
  |-- pivot_root, then /proc + /sys + /dev + devpts + shm, then detach
  |-- rootdir ownership validation and mount-flag hardening
  |-- /proc mask table
  |-- Container init (PID 1 reaper: signal forwarding + orphan reaping)
  |-- UID/GID mapping (identity by default; uid-map/gid-map to shift)
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
aarch64 separately) with a 200+ entry table using `__NR_*` macros from
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
| 13 | **Medium** | compartment-user | Shell-replacement mode ignored `prctl`/Landlock/seccomp failures silently | Kept fail-open by design (a login shell must never be blocked) but made it visible: each failure is counted and reported to syslog at `LOG_WARNING` with uid, pid and ppid |
| 14 | **Medium** | compartment-user | `workdir` directive only implied `rw` in built-in ai-agent profile, not file-loaded profiles | Auto-add `rw` for `workdir` after all profile loading |
| 15 | **High** | compartment-root | `join_netns()` path traversal — `netns_name` containing `/` could open arbitrary files instead of `/var/run/netns/<name>` | Reject any `netns_name` that contains `/` |
| 16 | **High** | compartment-root | `assign_to_cgroups()` path traversal — cgroup paths with `..` components could write PID to arbitrary files | Reject relative paths and paths containing `..` components |
| 17 | **High** | compartment-user | Shell-replacement `COMPARTMENT_SHELL_DIR` path traversal — env var could point outside intended directory | Reject non-absolute paths and paths containing `..` components (extended later — see fix 53) |
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
| 39 | **Medium** | compartment-root | `drop_capabilities()` read `cap_last_cap` from `/proc/sys/kernel/cap_last_cap` AFTER `/proc/sys` was masked with tmpfs — fallback of 37 missed CAP_PERFMON(38), CAP_BPF(39), CAP_CHECKPOINT_RESTORE(40) | Read `cap_last_cap` before masking `/proc/sys`, pass to `drop_capabilities()` |
| 40 | **Medium** | compartment-root | `set_rlimits()` lowered RLIMIT_NOFILE to 1024 before `close_range` fallback — FDs >= 1024 not closed on kernels < 5.9 | Moved `set_rlimits()` to after FD cleanup |
| 41 | **Medium** | compartment.h | `expand_var()` copied literal `$HOME` when env var was unset, or resolved to filesystem root when empty — silently weakened path rules | Return NULL (error) when `$HOME`/`$USER` is referenced but unset or empty |
| 42 | **Medium** | compartment-user | Empty Landlock ruleset (0 paths, `landlock on`) denied ALL filesystem access with no warning | Detect and reject with clear error message |
| 43 | **Medium** | compartment-user | `PATH_RW` included EXECUTE — no W^X enforcement, writable `/tmp` was executable | `PATH_RW` = read+write (no exec), `PATH_RWX` = read+write+exec (explicit opt-in). `$HOME`/`workdir` use RWX, `/tmp` uses RW |
| 44 | **Medium** | compartment-user | `landlock_add_path()` followed symlinks via `O_PATH` — attacker could symlink a path to `/` to expand sandbox | Added `O_NOFOLLOW` + `realpath()` fallback for symlinks |
| 45 | **Medium** | sandbox.sh | Mount propagation not set to private inside namespace — host mount events could propagate in, shell intercept bind mounts could propagate out | Added `mount --make-rprivate /` as first operation inside both HARD and SOFT namespaces |
| 46 | **Medium** | sandbox.sh | Shell intercept only covered `/bin/bash` and `/bin/sh` — bypassed by `/bin/dash`, `/usr/bin/bash`, etc. | Expanded to cover bash, sh, dash, zsh in both `/bin` and `/usr/bin` |
| 47 | **Medium** | sandbox.sh | SOFT mode: background processes survived sandbox teardown — reparented to host PID 1 | Added `unshare --pid --fork` in SOFT mode nsenter to kill all descendants on exit |
| 48 | **Info** | sandbox.sh | `SHELL_STASH` discoverable via `/proc/self/mountinfo` | Documented as known limitation — real security boundary is Landlock + seccomp, not path hiding |

### Profile trust review

A second review concentrated on everything upstream of enforcement: where
the policy comes from and how the parser behaves when it goes wrong.

| # | Severity | Component | Issue | Fix |
|---|----------|-----------|-------|-----|
| 49 | **Critical** | compartment.h | `$HOME/.config/compartment/<name>.conf` was searched before `/etc/compartment/`, and the built-in `ai-agent` profile grants RWX on `$HOME` — a sandboxed agent could write its own next-run profile and disable every mechanism for all later runs | System profiles first; `$HOME` only for compartment-user, only behind the new `--user-profiles` flag, never in shell-replacement mode, and never reachable through `inherit` from a `/etc` profile |
| 50 | **Critical** | compartment.h | Profile files were read with no ownership or mode check, so `compartment-root` (uid 0) took `rootdir`, `username`, `cap-allow` and the seccomp policy from a `$HOME`-relative file | Validate every profile on the fd it is read from: regular file, owned by root or the caller's real uid (root only for compartment-root), no group/other write, containing directory the same. Symlinks stay usable; the target's directory is checked too |
| 51 | **High** | compartment.h | A profile rejected mid-file kept its already-parsed rules, and the caller then layered a built-in on top and reported the result as `(built-in)` | Parse into a scratch `Config`, commit only on success, and give the loader a three-way result so "not found" and "found but invalid" are distinguishable. Invalid is always fatal, `--dry-run` included |
| 52 | **High** | compartment.h | `landlock`/`seccomp`/`no-new-privs`/`env-sanitize` could be turned **off** from a profile — a complete escape for anyone who can write one | One-way switches: `off` in a profile is a fatal parse error. Only `--no-landlock`, `--no-seccomp` and `--no-env-sanitize` on the command line can disable enforcement; `no_new_privs` is now genuinely always on |
| 53 | **Medium** | compartment-user | `COMPARTMENT_SHELL_DIR` chose which binary the replaced shell runs, defeating the `hardened` target's randomised `REAL_SHELL_DIR` | Honoured only when the directory and the shell binary are owned by root or the caller and are not group/other-writable; otherwise a warning and a fall back to the compile-time path. The sandbox is applied before the exec either way |
| 54 | **High** | compartment.h | Inline `#` comments were swallowed into the value: `ro /usr  # libs` installed no rule and `env-deny LD_PRELOAD  # x` stripped nothing | A `#` beginning a whitespace-separated token starts a comment; values are right-trimmed; a `#` inside a token stays literal |
| 55 | **High** | compartment.h | `block` entries past `MAX_BLOCKED_SC` (64) were dropped silently, deleting `pidfd_getfd`, `mount_setattr`, `ioperm` and `iopl` from the shipped policy | Limit raised to 256 (519 BPF instructions at the limit); every append goes through a helper that names the overflowing entry and refuses to run |
| 56 | **Medium** | compartment-user | `$HOME` was used unvalidated as an RWX Landlock root, so `HOME=/` granted `rwx /` | Must be absolute, not `/`, and an existing directory owned by the caller's real uid |
| 57 | **Medium** | compartment.h | Audit directory unvalidated: `O_NOFOLLOW` covered only the final component, an existing 0777 directory was accepted, and the default lived under world-writable `/var/tmp` | Default is now `/var/lib/compartment/audit/<uid>` when an admin provisioned it (root-owned parent, per-uid dir 0700), else `/var/tmp/compartment-audit-<uid>` created 0700 and **fail-closed** if squatted, and `/var/log/compartment` for root — none of them inside a path the built-in profiles grant for writing, so the confined process cannot rewrite its own trail. The directory is validated on its own fd and opened `O_DIRECTORY` + `O_NOFOLLOW`, the day file created with `openat`, and control characters scrubbed from every logged field |
| 58 | **Medium** | compartment-user | Environment deny-list missed `GLIBC_TUNABLES`, most of the `LD_*` family, `PYTHON*`, `PROMPT_COMMAND`, `IFS`, `ZDOTDIR`, `GIT_SSH_COMMAND`, `PAGER`/`EDITOR` and more | Entries may end in `*` for a prefix match; the built-in uses `LD_*`, `DYLD_*`, `BASH_FUNC_*`, `PYTHON*`, `PERL5*` and `GIT_CONFIG_*`. Model-provider API keys stay deliberately untouched |
| 59 | **High** | compartment-root | `--profile=FILE` and `-pFILE` silently discarded the entire policy: a hand-rolled pre-scan matched only the exact tokens `--profile` and `-p`, and getopt's own case was a no-op | Two `getopt_long` passes over the same optstring — the first resolves `-p/--profile`, the second applies everything else |
| 60 | **Low** | compartment-user | Shell-replacement mode skipped `preflight_check()`, the ambient-capability clear, `PR_SET_DUMPABLE(0)` and `close_range()` | Hardening factored into `apply_hardening()` and called from both paths; preflight runs advisory so it still cannot block a login |
| 61 | **Low** | compartment.h | Every `strdup()` return was unchecked — a rule could silently become `NULL` | `xstrdup()` fails loudly; a sandboxing tool must not run a partially materialised policy |

`--dump-profile NAME` was added alongside these: it serialises the
resolved policy back to `.conf` syntax, so `examples/ai-agent.conf` and
the HOWTO are generated from the binary rather than transcribed by hand.

### seccomp Return Action: EPERM vs KILL

The BPF deny-list returns `SECCOMP_RET_ERRNO | EPERM` rather than
`SECCOMP_RET_KILL_PROCESS` **by default**; `seccomp-default kill|log`
overrides it per policy. The default is deliberate:

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

`seccomp-default` exists because that argument is much weaker for an
*allow-list*. An allow-list that is one syscall short does not degrade
gracefully: the observed failure was a `SIGSEGV` from `ld.so` after `mmap`
returned EPERM, which is both harder to diagnose than a `SIGSYS` and, in a
security tool, an outcome that looks like a crash rather than a denial.
`seccomp-default kill` turns those into `SECCOMP_RET_KILL_PROCESS`;
`seccomp-default log` permits and records, which is the shape you want while
working out what a policy needs. The default stays `errno` because changing
it would alter the behaviour of every existing profile.

### Testing

`make test-integration` runs every unprivileged suite; `sudo make test-root`
runs the root-only ones. Both print the assertion totals they measured —
counts are deliberately not repeated here, because the three places that
used to repeat them each quoted a different, wrong figure.

- **Compartment-user matrix** (`run_compartment_user_matrix.sh`): Landlock
  ro/rw paths, seccomp deny-list (ptrace, unshare, process_vm_*,
  userfaultfd, perf_event_open, io_uring), environment sanitization
  (deny-list + preserve), combined profiles, built-in profiles (ai-agent,
  strict + inheritance), --dry-run, --verify, shell-replacement mode, FD
  inheritance, and self-tests of the harness's own assertion helpers
- **Child inheritance** (`run_child_inheritance_tests.sh`): seccomp survives
  fork/exec via /bin/sh and /bin/bash, Landlock inherited by children, env
  sanitization inherited, grandchild (depth-2) inherits seccomp
- **Discovered suites**: every executable `tests/scripts/rootless.d/*.sh`
  runs as its own suite, and every `tests/scripts/root.d/*.sh` under
  `sudo make test-root`. Adding a test means adding a file, not editing a
  runner. `core-matrix-extra.sh` covers the x32-ABI bypass, W^X in both
  directions, exact seccomp errnos, profile parser limits and inherit
  depth, --dry-run/--verify shape, and env sanitization as observed by the
  exec'd process
- **Sandbox.sh** (skipped without user namespaces): HARD/SOFT network
  modes, proxy bridge
- **External CLI smoke** (`run_claude_smoke.sh`): a third-party CLI under
  full sandbox, audit logging captures the PPID chain, --dry-run policy
  display. Skipped when that CLI is missing or unauthenticated, or with
  `--no-external`

Tests use `deny_probe`, a purpose-built binary with subcommands for each
operation (fs_read, fs_write, sc_ptrace_traceme, sc_ptrace_x32, env_get,
env_dump, fd_list, spawn_sh, etc.) that reports machine-parseable results.
It prints `PROBE_START op=<op> pid=<n>` before anything else: without a
positive "the probe ran" marker, an assertion cannot distinguish a blocked
operation from a probe the sandbox refused to exec, and six assertions
used to pass on exactly that ambiguity.

Everything above is rootless. compartment-root needs real root, so it has
its own suites under `tests/scripts/root.d/`, which the rootless targets do
not run:

```bash
sudo make test-root
```

`root.d/compartment-root.sh` exercises a real container: start-up with a
plain-directory rootdir, the `/dev` device nodes, the default seccomp
filter, the privilege drop and `no-new-privs`, `/proc` and `/sys` masking,
namespace isolation and escape attempts (host mounts, `/proc/1/root`, a
pre-opened directory fd, a setuid-root binary), the PID 1 reaper and signal
handling, the network namespace, uid/gid mapping, cgroup path confinement,
and what `--dry-run` and `--audit` report.
`root.d/compartment-root-landlock.sh` covers Landlock inside the
container, the `exec` binary allow-list, `rootdir-flags` and the
`mount-*` hardening, `rootdir` ownership, the `--netns` join, and the
private `devpts` and `/dev/shm`. `root.d/profile-trust-root.sh` covers
profile trust under root, and `root.d/00-discovery-smoke.sh` proves the
runner actually discovers what is in the directory. All of them build
their own scratch trees under `mktemp -d` and remove everything they
created on exit, including on failure. Green on kernel 6.8 (Ubuntu 24.04, gcc 13.3) and kernel 7.0
(Ubuntu 26.04, gcc 15.2); the runner prints the assertion totals it
measured rather than a number kept in this file.

CI (`.github/workflows/ci.yml`) runs the build, the full rootless suite,
the root suites under `sudo`, an ASan+UBSan build over the rootless suite,
shellcheck, and file-mode checks, on ubuntu-22.04 and ubuntu-24.04.

### Mount order in compartment-root

`compartment-root` as shipped in 1.3.3 could not start with a
plain-directory `rootdir`: it detached the old root immediately after
`pivot_root` and then tried to `mount("proc", ...)`, which the kernel
refused with `EPERM` ("VFS: Mount too revealing"). `mount_too_revealing()`
only allows a fresh `proc`/`sysfs` mount inside a user namespace when a
fully visible mount of the same filesystem already exists in the current
mount namespace, and detaching `/.pivot_old` removed the last one.

The order is therefore: `pivot_root` → mount `/proc` → mount read-only
`/sys` → tmpfs `/dev` plus bind-mounts of the old root's device nodes, a
private `devpts` and a tmpfs `/dev/shm` → `/proc` masks →
`umount2("/.pivot_old", MNT_DETACH)` → the `mount-*` flag passes →
`rootdir-flags ro`. Keeping the old root attached across the first steps is
also what makes the device nodes reachable at all: `mknod(2)` checks
`CAP_MKNOD` against the initial user namespace and always fails in a
`CLONE_NEWUSER` child.

The two tails matter as much as the head. `mount-ro` and friends have to
run *after* the detach, because they bind paths inside the new root onto
themselves and there is nothing to remount until then. `rootdir-flags ro`
has to run last of all and non-recursively: every mount point above had to
be created in a writable tree, and a recursive read-only pass would sweep
`/proc`, `/dev` and `/sys` in with the root filesystem.

### Landlock in compartment-root

The ruleset is applied at step 8b — after all the mounts, before
`drop_capabilities()`. Both halves of that are load-bearing. After the
mounts, so the paths in the policy resolve to what the target will actually
see rather than to whatever the host had at the same path. Before the
capability drop, because `landlock_restrict_self(2)` requires either
`no_new_privs` or `CAP_SYS_ADMIN`, and the child still holds the latter in
its own user namespace at that point; `no_new_privs` is not set until step
15, after the privilege drop, for reasons of its own. The ruleset survives
`setuid` and is inherited by everything the container execs.

Landlock is off by default here and on by default in compartment-user. That
asymmetry is deliberate: compartment-user has always had it, and a
compartment-root profile written before this release names paths that were
previously inert. Turning it on silently would confine containers that were
never tested confined. A policy with path rules and no `landlock on` gets a
warning instead.

### Why `exec` on a file is a real allow-list

`LANDLOCK_ACCESS_FS_EXECUTE` is a path-subtree right, so Landlock cannot
express "beneath `/usr/bin`, only these three". But a `path_beneath` rule
may name a regular file, and a rule on a file carries only file-level
rights — so granting execute on individual files and on no directory does
produce "only these binaries run here". Verified on 6.8 and 7.0.

Two kernel details decide whether such a policy works, and both were checked
against the running kernel rather than inferred from the documentation:

* The **ELF interpreter needs its own execute grant.** Landlock's
  `file_open` hook maps `FMODE_EXEC` to `LANDLOCK_ACCESS_FS_EXECUTE`, and
  `execve(2)` opens the interpreter with that flag. A policy that grants
  execute on `/usr/bin/foo` but not on `/lib64/ld-linux-x86-64.so.2` fails
  with `EACCES` at exec time.
* **Shared libraries do not.** `ld.so` opens a `.so` read-only and maps it
  `PROT_EXEC`; Landlock has no mmap or mprotect hook for this, so read
  access to the library directory is sufficient. Confirmed by running a
  dynamically linked binary with `rw` (read + write, no execute) on the
  library directory.

The limits are worth stating in the same breath. The policy belongs to the
sandbox and not to a caller, so "root included, but only when launched by
sshd" is unreachable. It keys on the inode, so a busybox rootdir is
all-or-nothing. And a shell builtin is not an `execve`, so a shell in the
allow-list gives away far more than the shell.

### Landlock network rules

`net-bind`/`net-connect` build `struct landlock_net_port_attr` with
`LANDLOCK_RULE_NET_PORT`. Three traps are handled explicitly:

1. **The port is in host byte order.** Every other port field in this
   project is network order; this one is not.
2. **`handled_access_net` denies what it handles.** Setting it with no
   matching rule refuses all TCP bind and connect, the same trap the
   filesystem side already guards for an empty ruleset. It is therefore set
   only when the ABI is ≥ 4 *and* the policy names something — and only for
   the access types the policy names, so `net-connect 443` does not also
   forbid every `bind()`.
3. **`LANDLOCK_RULE_NET_PORT` is an enumerator, not a macro.** `#ifndef`
   can never see it, so the value is spelled out and used unconditionally,
   along with a locally declared `struct landlock_net_port_attr` and a
   locally declared ruleset attribute — the same approach compartment-root
   already takes for `struct mount_attr`.

The ABI table the code gates on, verified rather than assumed:
1 = 5.13, 2 = 5.19 (REFER), 3 = 6.2 (TRUNCATE), 4 = 6.7 (TCP bind/connect),
5 = 6.10 (IOCTL_DEV), 6 = 6.12 (scoping). The previous code gated
`LANDLOCK_ACCESS_FS_IOCTL_DEV` on ABI ≥ 4, which is wrong by one release;
it was invisible only because Ubuntu 24.04's `linux-libc-dev` 6.8 does not
define that constant at all, so the `#ifdef` around it was always false and
the right was silently unhandled. Adding the fallback `#define` without
fixing the gate would have made every ABI-4 kernel refuse the ruleset.
