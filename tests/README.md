<!-- Copyright (c) 2026 Nenad Mićić <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Compartment Test Suite

Integration tests for `compartment-user`, `compartment-root` and
`sandbox.sh`.

## Quick Start

```bash
make test-integration          # everything that runs unprivileged
make test-quick                # core suites only (skips sandbox.sh + Claude)
sudo make test-root            # the root-only suites

./tests/scripts/run_all.sh --verbose        # same, with per-command tracing
./tests/scripts/run_all.sh --no-external    # skip suites needing a third-party
                                            # CLI or an outbound proxy
```

`run_all.sh` prints the totals at the end, summed from what each suite
reports:

```
  Suites run:     5
  Suites failed:  0
  Suites skipped: 1
  Assertions:     pass=116 fail=0 skip=2 (reported by 5/5 suites)
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
| **Discovered rootless suites** | `rootless.d/*.sh` | Anything unprivileged; each script is its own suite (see below) |
| **Discovered root suites** | `root.d/*.sh` | Root-only paths; run by `sudo make test-root` |
| **Sandbox proxy/network** | `run_sandbox_proxy_matrix.sh` | sandbox.sh HARD/SOFT modes, network isolation, proxy bridge |
| **Claude CLI smoke** | `run_claude_smoke.sh` | Third-party CLI under compartment-user; skipped without the CLI, without `~/.claude`, or with `--no-external` |

`compartment-root` used to have no automated coverage at all. It now has a
runner (`run_root_tests.sh`, refuses to run unprivileged) and a discovery
directory; what that directory contains is what is actually covered — run
`sudo make test-root` to see.

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
when a precondition is missing.

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
│   └── test-claude-smoke.conf  — Claude CLI profile
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
│   └── run_kernel_matrix.sh    — virtme-ng kernel matrix, run by hand
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
- For the Claude smoke test: `claude` CLI installed and authenticated
- Optional: Squid proxy on localhost:8080
