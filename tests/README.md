<!-- Copyright (c) 2026 Nenad Mićić <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Compartment Test Suite

Integration tests for `compartment-user`, `compartment-root` and
`sandbox.sh`.

Note: compartment-root needs real root, so its checks are not part of the
unprivileged run. They live in `tests/scripts/root.d/` and must be started
explicitly, as root:

```bash
sudo make test-root
```

Those suites build their own busybox rootdir under `mktemp -d`, refuse to
run without root, and remove everything they created on exit — including
on failure.

## Quick Start

```bash
make test-integration          # everything that runs unprivileged
make test-quick                # core suites only (skips sandbox.sh + external CLI)
sudo make test-root            # the root-only suites

./tests/scripts/run_all.sh --verbose        # same, with per-command tracing
./tests/scripts/run_all.sh --no-external    # skip suites needing a third-party
                                            # CLI or an outbound proxy
```

`run_all.sh` prints the totals at the end, summed from what each suite
reports:

```
  Suites run:     10
  Suites failed:  0
  Suites skipped: 1
  Assertions:     pass=420 fail=0 skip=3 (reported by 10/10 suites)
```

Those numbers move as suites are added — read them from a run rather than
from prose. `skip` is not a soft failure: it means a precondition the
machine cannot satisfy (no Landlock, no user namespaces, a syscall the
host already denies so a seccomp denial cannot be attributed to the
filter).

## Test Suites

| Suite | Script | What it tests |
|-------|--------|---------------|
| **Filesystem/seccomp/env matrix** | `run_compartment_user_matrix.sh` | Landlock (ro/rw), seccomp deny-list, env sanitization, profiles, dry-run, verify, FD inheritance, and self-tests of the harness's own assertion helpers |
| **Child inheritance** | `run_child_inheritance_tests.sh` | Sandbox restrictions survive fork/exec across 2 levels |
| **Sandbox proxy/network** | `run_sandbox_proxy_matrix.sh` | sandbox.sh HARD mode against a real namespace, via `lib/sandbox-hard.sh`: the interface list, loopback, the routing table, an off-host connect, mapped-root identity, the proxy bridge. Counts a skip per assertion when the host has no unprivileged user namespace — `root.d/sandbox-hard.sh` runs the same assertions there |
| **External CLI smoke** | `run_claude_smoke.sh` | A third-party CLI under compartment-user; skipped when the CLI is missing or unauthenticated, or with `--no-external` |

Discovered suites — every executable script in these two directories is run
as its own suite, in glob order, with no runner edit:

| Suite | Script | What it tests |
|-------|--------|---------------|
| **Discovery smoke** | `rootless.d/00-discovery-smoke.sh` | That discovery, the fixture root and the harness helpers work at all |
| **Aux tools** | `rootless.d/aux-tools.sh` | `tools/syscall.py` profile generation and credential filtering; the `extra/` squid and tinyproxy helpers (ACL baseline, crontab handling, PID-file validation, file modes) |
| **Core matrix extra** | `rootless.d/core-matrix-extra.sh` | x32-ABI bypass, exact-errno seccomp denials, W^X in both directions, parser limits, `--dry-run` self-consistency, `--verify`, env sanitization observed after exec, child `NoNewPrivs`/`Seccomp` state |
| **Examples** | `rootless.d/examples.sh` | Every shipped `examples/*.conf` and `paranoid-ssh.sh`: profiles parse, advertised flags exist, host-key verification against a throwaway sshd, `--rw` grants no execute, `container.conf`'s network block and `restricted-root.conf`'s allow-list |
| **Landlock rules** | `rootless.d/landlock-rules.sh` | Per-file rules, fatal vs optional (`?`) missing paths, the installed-rule count, the refusal of a `ro` rule nested in a `rw`/`rwx` rule, `exec` semantics and what a dynamically linked binary needs, TCP `net-bind`/`net-connect` against a loopback listener, `seccomp-default`, `make install` vs `install-profiles`, the audit-dir warning |
| **Profile trust** | `rootless.d/profile-trust.sh` | Profile search order and file trust, transactional parsing, one-way switches, `$HOME` validation, `COMPARTMENT_SHELL_DIR`, audit-log hardening, environment deny-list, `--dump-profile` |
| **sandbox.sh** | `rootless.d/sandbox.sh` | `sandbox.sh` HARD-mode shell intercept, dependency checks and `--verify`, driven through stubbed `unshare`/`ip`/`mount` so the path runs without a usable user namespace |
| **Discovery smoke (root)** | `root.d/00-discovery-smoke.sh` | That the root runner refuses to run unprivileged and discovers `root.d/` |
| **compartment-root** | `root.d/compartment-root.sh` | A real container: start-up, `/dev` nodes, default seccomp deny-list, privilege and capability drop, `/proc` and `/sys` masking (all 15 masks, by the mechanism that implements them), user-namespace credential hardening (`setgroups deny`, the id maps, `PR_SET_DUMPABLE`), escape attempts, PID 1 reaper, netns, uid/gid maps, cgroup confinement, reporting |
| **compartment-root Landlock** | `root.d/compartment-root-landlock.sh` | The exec allow-list inside a container, shared libraries vs the ELF interpreter, `mount-ro`/`-noexec`/`-nosuid`, `rootdir-flags`, `rootdir` ownership refusals, the `--netns` join, devpts and `/dev/shm`, TCP port rules inside the container, and `container.conf`'s network block |
| **Limited root over SSH** | `root.d/limited-root.sh` | The `examples/limited-root.conf` deployment end to end: a temporary uid-0 account logs in through the machine's own sshd under the wrapper, interactive (`argv[0] = -bash`) and non-interactive; `no_new_privs`, the seccomp filter and the dropped bounding set survive into the session and cannot be widened from inside it; the allow-list stays usable; twenty-four privileged vectors are refused, each non-destructive one paired with an unconfined uid-0 control that proves it is otherwise reachable; `compartment-bpf/profiles/limited-root-authpath.conf` seals the auth path against the session; and, with `PRISTINE_SRC` set, three before/after witnesses that fail against a pre-fix build |
| **Profile trust (root)** | `root.d/profile-trust-root.sh` | compartment-root never reads `$HOME`; `/etc/compartment` ownership and mode checks; every `--profile` spelling; root audit directory; profile search **precedence** (`/etc` beats `$HOME`, and `inherit` from `/etc` cannot reach it); the group-writable half of file trust, which needs a group the caller is not in |
| **sandbox.sh HARD (root)** | `root.d/sandbox-hard.sh` | Clears `kernel.apparmor_restrict_unprivileged_userns` for the duration, restores it from a trap, and runs `lib/sandbox-hard.sh` as the invoking user — the only place the HARD-mode namespace is exercised for real |

Two gates keep this table honest. `make check-orphans` fails when a tracked
`tests/**/*.sh` with a shebang is named by no runner, no Makefile target and
no workflow — a suite nothing runs still reads as coverage in this file.
And every suite declares its own assertion count with `harness_expect_total`,
so a block that quietly stops running changes the total and fails, instead
of reporting a smaller number nobody compares against anything. One `skip`
standing in for a block counts the assertions it replaces (`skip_group`),
which is what makes the total the same on a developer host, on the test
guests and in a bare container.

`compartment-root` used to have no automated coverage at all. It now has a
runner (`run_root_tests.sh`, refuses to run unprivileged) and a discovery
directory; what that directory contains is what is actually covered — run
`sudo make test-root` to see.

Both profile-trust suites accept `COMPARTMENT_USER` and `COMPARTMENT_ROOT`
environment overrides, so the same assertions can be pointed at an older
build to confirm they fail there:

```bash
COMPARTMENT_USER=/path/to/old/compartment-user \
COMPARTMENT_ROOT=/path/to/old/compartment-root \
  bash tests/scripts/rootless.d/profile-trust.sh
```

## Adding a test

Drop an executable script into `tests/scripts/rootless.d/` (or
`tests/scripts/root.d/`). It is picked up automatically — no runner needs
editing. The contract each script must honour is in the README of each
directory:

- [`scripts/rootless.d/README.md`](scripts/rootless.d/README.md)
- [`scripts/root.d/README.md`](scripts/root.d/README.md)

In short: independent, executable with a shebang, one
`SUMMARY <name>: pass=N fail=N skip=N` line, non-zero exit on any failure,
cleans up after itself including on failure, and skips rather than fails
when a precondition is missing. `root.d/` scripts additionally skip
themselves with exit 0 when not run as uid 0.

`tests/scripts/lib/harness.sh` is optional and provides `pass`/`fail`/`skip`,
`harness_summary`, `harness_fixtures`, `harness_profile` and
`harness_cleanup_add`.

## Directory Structure

```
tests/
├── probes/
│   └── deny_probe.c            — synthetic test binary (subcommand-driven)
├── profiles/                   — test profile templates (@FIXTURES@ is
│   │                             substituted per run; see Fixtures below)
│   ├── test-fs-readonly.conf   — Landlock ro-only
│   ├── test-fs-rw.conf         — Landlock with rw area
│   ├── test-seccomp-deny.conf  — seccomp deny-list only
│   ├── test-env-deny.conf      — env sanitization only
│   ├── test-combined.conf      — all three combined
│   └── test-claude-smoke.conf  — external CLI profile
├── scripts/
│   ├── run_all.sh              — rootless entrypoint (make test-integration)
│   ├── run_root_tests.sh       — root entrypoint  (sudo make test-root)
│   ├── make_fixtures.sh        — build a fixture tree
│   ├── lib/harness.sh          — shared helpers (sourced, not executed)
│   ├── rootless.d/             — discovered unprivileged suites + README
│   ├── root.d/                 — discovered root-only suites + README
│   ├── run_compartment_user_matrix.sh
│   ├── run_child_inheritance_tests.sh
│   ├── run_sandbox_proxy_matrix.sh
│   ├── run_claude_smoke.sh
│   └── run_kernel_matrix.sh    — virtme-ng kernel matrix, `make test-kernels`
├── output/                     — test output files (git-ignored)
└── README.md                   — this file
```

## Fixtures

Every run creates its own fixture tree with `mktemp -d` and removes it on
exit. There is deliberately no fixed path: the tree used to live at
`/tmp/compartment-fixtures`, where any local user could pre-create it or
swap a file between the moment a test wrote it and the moment the
sandboxed probe read it.

The root is created under `${HOME}/.cache` by default, not `${TMPDIR}`,
because the built-in `ai-agent` profile maps `${HOME}` `rwx` but `/tmp`
only `rw` — W^X then makes a probe under `/tmp` unexecutable, and the
assertions that depend on it silently never run. Override with
`COMPARTMENT_FIXTURE_BASE`.

`tests/profiles/*.conf` are templates: `@FIXTURES@` is replaced with the
per-run root and the result is written to `$FIXTURES/profiles/`. Suites
load the rendered copies (`harness_profile test-fs-rw.conf`).

| Variable | Meaning |
|---|---|
| `COMPARTMENT_FIXTURES` | Fixture root to reuse; `run_all.sh` exports one for the whole run |
| `COMPARTMENT_FIXTURE_BASE` | Directory the root is created under (default `${HOME}/.cache`) |
| `COMPARTMENT_SKIP_EXTERNAL` | `1` skips suites needing a third-party CLI or an outbound proxy |

## deny_probe

A purpose-built test binary that exercises specific operations and reports
results in a machine-parseable format:

```
PROBE_START op=<operation> pid=<n>
RESULT op=<operation> <key>=<value>... rc=<return_code> errno=<errno> name=<error_name>
```

`PROBE_START` is a positive "the probe really executed" marker, printed
before anything else and line buffered so it survives a `SIGSYS` kill. A
harness cannot otherwise tell an empty capture caused by a blocked
operation from one caused by the sandbox refusing to exec the probe — six
assertions in this suite used to pass on exactly that ambiguity. Assert on
the marker before asserting on anything else.

Subcommands: `fs_read`, `fs_write`, `fs_create`, `fs_unlink`, `fs_mkdir`,
`fs_exec`, `env_get`, `env_dump`, `fd_list`, `net_tcp`, `spawn_sh`,
`sc_ptrace_traceme`, `sc_ptrace_x32`, `sc_unshare_user`, and more. Run
`deny_probe` with no arguments for help.

## Writing an assertion that means something

The failure mode this suite has already been bitten by is an assertion
that passes for the wrong reason:

- **Require the probe to have run.** Check for `PROBE_START op=<op>` before
  evaluating any expectation. `expect_not_contains "rc=0"` is trivially
  true of an empty string.
- **Compare exact errnos.** `grep "rc="` matches every RESULT line ever
  printed. `rc=-1 errno=1 name=EPERM` does not.
- **Take a baseline.** A syscall the host already refuses (sysctl, LSM, an
  outer container) fails identically with and without a seccomp filter. If
  the unsandboxed run fails the same way, skip the case instead of
  claiming a pass.
- **Prefer a control case.** `--no-seccomp` really leaving `Seccomp: 0`, or
  `--no-env-sanitize` really keeping a variable, is what proves the
  positive case measured what it claimed to.

`run_compartment_user_matrix.sh` ends with four self-tests that feed its
own helpers a probe that never ran, a syscall with no filter installed and
a syscall the host already denies, and assert the helpers report FAIL or
SKIP rather than PASS.

## Prerequisites

- Linux >= 5.13 (Landlock support)
- GCC or Clang (to build `deny_probe`)
- For the root suites: root, and user namespaces
- For sandbox tests: `unshare`, optionally `socat`, `slirp4netns`
- For `run_claude_smoke.sh`: the CLI it drives, installed and authenticated
- Optional: Squid proxy on localhost:8080
