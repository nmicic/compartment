<!-- Copyright (c) 2026 Nenad Mićić <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Compartment Test Suite

Integration tests for compartment-user and sandbox.sh.

Note: compartment-root requires root and is not covered by this automated
suite. Test it manually with `sudo ./compartment-root --dry-run --profile examples/container.conf -- /bin/sh`.

## Quick Start

```bash
# Build and run all tests
make test-integration

# Or run directly
./tests/scripts/run_all.sh

# Quick mode (skip Claude smoke + sandbox proxy)
./tests/scripts/run_all.sh --quick

# Verbose output
./tests/scripts/run_all.sh --verbose
```

## Test Suites

| Suite | Script | What it tests |
|-------|--------|---------------|
| **Filesystem/seccomp/env matrix** | `run_compartment_user_matrix.sh` | Landlock (ro/rw), seccomp deny-list, env sanitization, profiles, dry-run, verify |
| **Child inheritance** | `run_child_inheritance_tests.sh` | Sandbox restrictions survive fork/exec across 2 levels |
| **Sandbox proxy/network** | `run_sandbox_proxy_matrix.sh` | sandbox.sh HARD/SOFT modes, network isolation, proxy bridge |
| **Claude CLI smoke** | `run_claude_smoke.sh` | Claude CLI runs under compartment-user, API reachable, audit logging |

## Directory Structure

```
tests/
├── probes/
│   └── deny_probe.c       — synthetic test binary (subcommand-driven)
├── profiles/
│   ├── test-fs-readonly.conf   — Landlock ro-only
│   ├── test-fs-rw.conf         — Landlock with rw area
│   ├── test-seccomp-deny.conf  — seccomp deny-list only
│   ├── test-env-deny.conf      — env sanitization only
│   ├── test-combined.conf      — all three combined
│   └── test-claude-smoke.conf  — Claude CLI profile
├── scripts/
│   ├── run_all.sh              — top-level entrypoint
│   ├── make_fixtures.sh        — create /tmp/compartment-fixtures/
│   ├── run_compartment_user_matrix.sh
│   ├── run_child_inheritance_tests.sh
│   ├── run_sandbox_proxy_matrix.sh
│   └── run_claude_smoke.sh
├── output/                 — test output files (git-ignored)
└── README.md               — this file
```

## deny_probe

A purpose-built test binary that exercises specific operations and reports
results in a machine-parseable format:

```
RESULT op=<operation> <key>=<value>... rc=<return_code> errno=<errno> name=<error_name>
```

Subcommands: `fs_read`, `fs_write`, `fs_create`, `fs_unlink`, `fs_mkdir`,
`env_get`, `env_dump`, `net_tcp`, `spawn_sh`, `sc_ptrace_traceme`,
`sc_unshare_user`, and more. Run `deny_probe` with no arguments for help.

## Prerequisites

- Linux >= 5.13 (Landlock support)
- GCC or Clang (to build deny_probe)
- For sandbox tests: `unshare`, optionally `socat`, `slirp4netns`
- For Claude smoke test: `claude` CLI installed and authenticated
- Optional: Squid proxy on localhost:8080

## Test Profiles

Test profiles are minimal — each isolates one mechanism:

- `test-fs-readonly.conf` — Landlock only, no rw paths (verifies writes fail)
- `test-fs-rw.conf` — Landlock with rw fixtures area (verifies writes succeed)
- `test-seccomp-deny.conf` — seccomp only, no Landlock (verifies syscall blocking)
- `test-env-deny.conf` — env sanitization only (verifies var stripping)
- `test-combined.conf` — all three together (realistic scenario)
- `test-claude-smoke.conf` — full profile with `$HOME` rw for Claude CLI
