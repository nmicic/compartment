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

## Example: Hardened SSH (Privilege Separation for Network Clients)

Compartment can lock down any network client — not just AI agents.
Here is a worked example using SSH, showing how to split a process
into privilege-separated components so that no single compromise can
both access secrets AND exfiltrate them.

### Problem

If a remote SSH server is compromised, it can reverse-exploit the SSH
client. A trojanized client could:
- Write stolen credentials to `~/.ssh/exfil.txt`
- Log keystrokes to a hidden file
- Exfiltrate data over the network to a third-party host

### Solution 1: Read-Only SSH (`ssh.conf`)

Lock the SSH client to read-only filesystem access. It can read keys
to authenticate but cannot write anything to disk:

```bash
# One-liner: SSH with no filesystem writes
./compartment-user --profile examples/ssh.conf -- ssh user@host

# What happens if the SSH binary tries to write:
#   touch /tmp/exfil.txt     → EACCES (blocked by Landlock)
#   echo x > ~/.ssh/log.txt  → EACCES (blocked by Landlock)
#   cat ~/.ssh/id_ed25519    → OK (read allowed)
```

### Solution 2: Paranoid SSH (`paranoid-ssh.sh`)

Split SSH into two sandboxed processes with complementary restrictions:

```
┌──────────────────────────┐     ┌──────────────────────────┐
│  SSH (read-only fs)      │────▶│  socat (no user files)   │────▶ remote:PORT
│  • can read keys         │     │  • no $HOME access       │
│  • cannot write anywhere │     │  • cannot read SSH keys  │
│  • Landlock + seccomp    │     │  • Landlock + seccomp    │
└──────────────────────────┘     └──────────────────────────┘
         localhost:RANDOM_PORT
```

```bash
# Paranoid SSH to a remote server
./examples/paranoid-ssh.sh user@remote-host

# With a custom port
./examples/paranoid-ssh.sh user@remote-host -p 2222

# Run a command
./examples/paranoid-ssh.sh user@remote-host "uptime"
```

**Security properties:**
- **SSH process** can read `~/.ssh/` keys but cannot write to disk
  → a reverse-exploited SSH cannot save stolen data locally
- **socat process** has network access but cannot read any user files
  → even if socat is exploited, attacker cannot access credentials
- **Neither process alone** can both access secrets AND exfiltrate them

This is the same principle as OpenSSH's own privilege separation, but
applied at the OS level with Landlock + seccomp instead of trusting the
application to separate itself.

### Why This Matters (2026 Paradigm)

Traditional sysadmin thinking: "SSH is trusted, the network is untrusted."

Compartment thinking: "Nothing is fully trusted. Split every process so
that compromise of any single component cannot achieve both data access
and data exfiltration."

This pattern applies to any network client:
- **curl/wget** — read-only profile prevents saving downloaded malware
- **git** — read-only profile for fetch, write-only for the workdir
- **database clients** — prevent credential logging to disk
- **AI agents** — the primary use case (see `sandbox.sh`)

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

## Examples

Each profile addresses a different threat model. Pick the one that
matches what you're protecting against.

| File | Use when | Protects against |
|------|----------|------------------|
| `ai-agent.conf` | Running Claude, Codex, Gemini CLIs | Agent reads/writes outside working directory, spawns unexpected processes |
| `strict.conf` | Untrusted code, tighter than ai-agent | Same as above, smaller syscall surface |
| `ssh.conf` | Running SSH client on a box you don't fully trust | Compromised SSH binary writing credentials to disk |
| `socat-proxy.conf` | Used internally by `paranoid-ssh.sh` | socat having access to your SSH keys |
| `container.conf` | Full namespace isolation via compartment-root | Process escaping its root directory |
| `dev.conf` | Development and debugging | Nothing — this is intentionally relaxed |

**Which one should I use?**

- **Sandboxing an AI agent** → `ai-agent.conf` (default) or `strict.conf` (tighter)
- **Connecting to a remote server** → `paranoid-ssh.sh`, which combines
  `ssh.conf` + `socat-proxy.conf`. The SSH process can read your keys but
  cannot write anywhere. The socat process handles the network connection
  but cannot read your keys. Neither alone can both steal credentials and
  exfiltrate them.
- **Running an untrusted service** → `container.conf` with `compartment-root`
- **Figuring out why something is being blocked** → `dev.conf`, then tighten
  from there

## Profiling Any Program

Don't write profiles by hand. Use `tools/syscall.py` to generate one
for any program automatically:

```bash
# Step 1: Check — will the default profile break your program?
python3 tools/syscall.py check --profile ai-agent -- wget -q -O /dev/null https://example.com

# Step 2: If it breaks, generate a custom profile
python3 tools/syscall.py profile -o examples/wget.conf -- wget -q -O /dev/null https://example.com

# Step 3: Use it
./compartment-user --profile examples/wget.conf -- wget https://example.com
```

Works with anything: `curl`, `git`, `ssh`, `rsync`, `python3`, database
clients — any program you can run, you can profile and sandbox.

```bash
# More examples
python3 tools/syscall.py profile -o curl.conf -- curl -s https://example.com
python3 tools/syscall.py profile -o git.conf  -- git clone https://github.com/user/repo
python3 tools/syscall.py profile -o psql.conf -- psql -c "SELECT 1"

# Strict allow-list (only permit observed syscalls, deny everything else)
python3 tools/syscall.py profile --seccomp-mode allow -o strict-curl.conf -- curl https://example.com

# See what syscalls a program actually uses
python3 tools/syscall.py trace -- ssh user@host "echo hello"
```

Requires `strace` (`apt install strace`). See
[tools/HOWTO-syscall-profiling.md](tools/HOWTO-syscall-profiling.md)
for the full guide.

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

## Advanced Deployment: Compartmented Login Shell

Compartment can be deployed as the login shell for non-admin users,
so that every interactive session and every `execve("/bin/sh", ...)`
— including remote exploit payloads — enters a sandboxed shell
automatically.

This is an opinionated setup for controlled environments (hardened
servers, jump boxes, CI runners), not a universal recommendation.

### Setup

```bash
# Build with a randomized shell stash path
make hardened
# Output: REAL_SHELL_DIR=/bin/.shells_a1b2c3d4e5f6

# Preserve real shells in the stash directory
sudo mkdir -p /bin/.shells_a1b2c3d4e5f6
sudo mv /bin/bash /bin/.shells_a1b2c3d4e5f6/bash
sudo mv /bin/sh   /bin/.shells_a1b2c3d4e5f6/sh

# Install compartment-user as the system shell
sudo cp compartment-user /bin/bash
sudo ln -sf /bin/bash /bin/sh

# Preserve a normal shell for the designated admin account
sudo chsh -s /bin/.shells_a1b2c3d4e5f6/bash root
sudo chsh -s /bin/.shells_a1b2c3d4e5f6/bash your-admin-user
```

When invoked as `bash` or `sh` (detected via `argv[0]`),
compartment-user applies the `ai-agent` profile and execs the real
shell from the stash directory.

### Privilege model

```
root / admin  →  /bin/.shells_.../bash  (real shell, no sandbox)
all others    →  /bin/bash              (compartment → sandboxed shell)
                 Landlock + seccomp + env sanitize + audit
```

### What this stops

A remote exploit that calls `execve("/bin/sh", ...)` gets compartment,
not bash. The payload hits Landlock filesystem restrictions and seccomp
syscall filtering before executing a single attacker-controlled
instruction. The sandboxed shell cannot `ptrace`, cannot load kernel
modules, cannot mount filesystems, and writes only to allowed paths.

### Caveats

- **Compatibility**: some workflows expect an unrestricted interactive
  shell and may break. Test thoroughly before deploying to production.
- **Not a substitute** for correct host hardening, patching, and
  privilege separation. This is a defense-in-depth layer.
- **Bypass paths exist**: an attacker who can write an ELF binary to
  an executable path and invoke it directly (not through `/bin/sh`)
  will bypass the shell-replacement layer. Landlock on the parent
  process limits where they can write, but this is not airtight.
- **Recovery**: always keep at least one admin account with a real
  shell. If compartment-user has a bug, you need a way back in.

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
  ssh.conf             — Read-only SSH client (no filesystem writes)
  socat-proxy.conf     — Network-only socat bridge (no user file access)
  paranoid-ssh.sh      — Privilege-separated SSH (SSH+socat split)
tools/
  syscall.py           — Profile generator: trace any program, emit .conf
  HOWTO-syscall-profiling.md — Full guide to syscall profiling
man/
  compartment-user.1   — Man page (section 1: user commands)
  compartment-root.8   — Man page (section 8: system administration)
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
