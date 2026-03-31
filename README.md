<!-- Copyright (c) 2026 Nenad Mićić <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Compartment — Linux Process Isolation Toolkit

Kernel-enforced sandboxing for untrusted processes. Two tools, one
profile format, zero dependencies.

> **Note:** This is an open-source Linux isolation toolkit, not a
> formally validated security product. The code has been through
> multiple review rounds and 51 automated tests, but it has not
> undergone professional penetration testing or formal verification.
> The automated tests do not yet cover all bypass vectors (e.g.,
> direct network egress in sandbox mode, compartment-root under
> root). Use it as a defense-in-depth layer, not as your sole
> security boundary. See [DESIGN.md](DESIGN.md) for documented
> limits and the full security review log.

## What

| Tool | Purpose | Root? | Deps |
|------|---------|-------|------|
| **compartment-user** | Landlock + seccomp + env sanitize + audit | no | none |
| **compartment-root** | Full namespace container + seccomp + audit | yes | none |
| **sandbox.sh** | Network namespace + proxy bridge | no | unshare, socat, newuidmap |

Same `.conf` profile files drive both tools. Write your policy once,
enforce it at whatever privilege level you have.

## Quick Start

```bash
make
./compartment-user -- /bin/sh          # sandboxed shell in 2 commands
./compartment-user --dry-run -- /bin/sh # see what would be applied
```

## Build

```bash
make                    # builds both tools (zero dependencies)
make test               # run core tests (Landlock + seccomp + env + inheritance)
make test-integration   # run all tests (includes Claude CLI smoke test)
make hardened           # build with randomized shell stash path
```

## Usage

```bash
# Sandbox an AI agent (Landlock + seccomp, rootless)
./compartment-user -- claude --model claude-opus-4-6

# Use a profile file
./compartment-user --profile strict -- codex --full-auto

# See what would be applied without running
./compartment-user --dry-run -- claude

# Full namespace container (requires root)
./compartment-root --profile examples/container.conf -- /bin/sh
./compartment-root --rootdir /srv/jail -U svc --audit -- /usr/bin/myapp

# Full isolation (network namespace + proxy + Landlock + seccomp)
./sandbox.sh claude --model claude-opus-4-6
```

## How It Works

**compartment-user** applies kernel-enforced restrictions before exec:

1. `PR_SET_NO_NEW_PRIVS` — prevent privilege escalation
2. **Landlock** — filesystem path restrictions (read-only system paths, writable workdir)
3. **seccomp BPF** — block dangerous syscalls (ptrace, mount, kexec, bpf, io_uring, ...)
4. **Environment sanitize** — strip LD_PRELOAD, LD_LIBRARY_PATH, etc.
5. **Audit logging** — file-per-day log with PPID chain

All restrictions are inherited by child processes and cannot be removed.

**compartment-root** creates a fully isolated container:

1. `clone()` with new UTS, mount, PID, IPC, net, user namespaces
2. **pivot_root** — old root fully unmounted (stronger than chroot)
3. Minimal `/dev`, masked `/proc`, isolated hostname
4. **Capability drop** — raw prctl + capset, no libcap. `cap-allow` preserves
   named capabilities for the service user via `PR_SET_KEEPCAPS` + `capset()`
5. **seccomp BPF** — raw BPF, no libseccomp
6. **Environment sanitize** + **audit logging** (same as compartment-user)

**sandbox.sh** wraps the command in a network-isolated user+mount namespace:

1. `unshare --user --mount --net` — HARD mode: loopback-only (no external interfaces);
   SOFT fallback: slirp4netns with `--disable-host-loopback`
2. Unix socket proxy bridge — API traffic routed through corporate proxy
3. Bind-mount shell replacement — every `/bin/bash` subprocess gets sandboxed
   (requires mount namespace, which sandbox.sh creates)

In HARD mode with a proxy configured, the namespace has no external
interfaces — network traffic is intended to flow only through the unix
socket proxy bridge. (The automated tests verify proxy reachability
but do not yet include direct-bypass resistance tests.)

## Profile Files

Both tools share the same `.conf` format:

```conf
# Filesystem (compartment-user: Landlock)
ro /usr
rw $HOME

# Filesystem (compartment-root: namespaces)
rootdir /srv/containers/default
uid 1000
gid 1000
username svc
loopback on

# Syscalls
block ptrace
block mount
# Or allow-list mode:
# allow read
# allow write

# Environment
env-deny LD_PRELOAD

# Features
seccomp on
no-new-privs on
env-sanitize on
audit on
```

Search order: `--profile /path/file.conf` → `~/.config/compartment/<name>.conf` → `/etc/compartment/<name>.conf` → built-in.

See [HOWTO.md](HOWTO.md) for full format reference.

## Shell Replacement

compartment-user can transparently intercept `/bin/bash` so every
subprocess an AI agent spawns gets sandboxed:

```
/bin/bash (bind mount) → compartment-user
  → Landlock + seccomp applied
  → exec /bin/shells/bash (the real shell)
```

This happens automatically inside `sandbox.sh` when compartment-user
is built and available. See [HOWTO.md](HOWTO.md) for manual setup options.

## Requirements

- Linux >= 5.13 (Landlock) — compartment-user
- Linux >= 4.6 (cgroup namespace) — compartment-root
- Linux >= 3.8 (user namespaces) — sandbox.sh
- No external libraries. No root for compartment-user.

## Files

```
compartment.h          — shared code: profiles, audit, seccomp BPF, env sanitize
compartment-user.c     — Landlock + seccomp + audit (zero deps, rootless)
compartment-root.c     — Full namespace container (zero deps, requires root)
sandbox.sh             — Network namespace + proxy bridge
Makefile               — Build targets
HOWTO.md               — Detailed setup guide
DESIGN.md              — Architecture, security review, lineage from shell-guard
SECURITY.md            — Vulnerability reporting policy
examples/
  ai-agent.conf        — Profile for Claude/Codex/Gemini
  strict.conf          — Locked-down profile (inherits ai-agent)
  container.conf       — Full namespace isolation profile
  dev.conf             — Relaxed profile for development
tests/
  probes/deny_probe.c  — Sandbox validation probe (machine-parseable output)
  profiles/            — Test-specific .conf profiles
  scripts/run_all.sh   — Top-level test runner (52 tests across 4 suites)
  README.md            — Test documentation
archive/
  shell-guard/         — Archived shell-replacement tool (~2003, self-contained)
```

## vs Alternatives

```
                          root required?
                          no              yes
                        ┌───────────────┬───────────────┐
  filesystem            │ compartment-  │ compartment-  │
  restriction           │ user          │ root          │
  mechanism             │ (Landlock)    │ (pivot_root)  │
                        │               │               │
                        │ Firejail      │ bwrap (setuid)│
                        │ bwrap (userns)│ Docker/Podman │
                        ├───────────────┼───────────────┤
  no filesystem         │ seccomp-only  │ AppArmor      │
  restriction           │ wrappers      │ SELinux       │
                        └───────────────┴───────────────┘
```

- **Firejail** (~100K lines) — closest comparison; mature profile ecosystem
  for desktop apps, but large attack surface with CVE history.
  compartment-user is 100x smaller and auditable in one sitting.
- **bwrap** (~3K lines) — mount/PID/network namespaces. Architecturally
  different (namespaces vs Landlock). Use bwrap when you need full mount
  isolation or kernel < 5.13; use compartment-user when you need profiles,
  shell-replacement, or work in containers where user namespaces are disabled.
- **Minijail** (Google) — expressive seccomp arg filtering, but requires
  libminijail. compartment-user trades arg filtering for zero-dep deployment.
- **AppArmor/SELinux** — system-wide MAC, finer granularity, but requires
  admin access and system policy installation. compartment-user is
  user-deployable with no system configuration changes.

No existing tool combines: zero deps, profile files with inheritance,
shell-replacement mode, and PPID chain audit logging in ~1600 lines.

## Related

- [bubblewrap](https://github.com/containers/bubblewrap) — Namespace-based sandboxing (complementary)
- [firejail](https://github.com/netblue30/firejail) — Namespace + seccomp (setuid, profile files)

## Development

This project was developed with AI assistance:

- **[Claude Code](https://claude.ai/code)** (Anthropic) — primary coding,
  testing, debugging, and implementation across all C source, shell scripts,
  profiles, and test infrastructure
- **ChatGPT** (OpenAI), **Gemini** (Google), **Codex** (OpenAI) — independent
  code review rounds that identified 18 security bugs, all fixed before release
- **Human** — architecture, design decisions, review coordination, and final
  approval

## License

Apache-2.0. See [LICENSE](LICENSE).
