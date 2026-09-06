<!-- Copyright (c) 2026 Nenad Mićić <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Compartment — Linux Process Isolation Toolkit

Kernel-enforced sandboxing for untrusted processes. Two zero-dependency
core tools, one shared profile format, plus an optional BPF-LSM module.

> **v1.3.0 note:** `compartment-user` and `compartment-root` are
> unchanged and remain the zero-dependency core. `compartment-bpf`
> is a new optional advanced module for kernel-level inode sealing,
> with its own kernel and toolchain requirements.

> **Note:** This is an open-source Linux isolation toolkit, not a
> formally validated security product. The code has been through
> multiple review rounds and an automated test suite (run
> `make test-integration` and `sudo make test-root` for the current
> counts), but it has not undergone professional penetration testing
> or formal verification. The automated tests do not yet cover all
> bypass vectors (e.g. direct network egress in sandbox mode).
> compartment-root is covered by root-only suites — see
> [tests/scripts/root.d/](tests/scripts/root.d/). Use it as a
> defense-in-depth layer, not as your sole
> security boundary. See [DESIGN.md](DESIGN.md) for documented
> limits and the full security review log.

## What

| Tool | Purpose | Root? | Deps |
|------|---------|-------|------|
| **compartment-user** | Landlock + seccomp + env sanitize + audit | no | none |
| **compartment-root** | Full namespace container + seccomp + audit | yes | none |
| **sandbox.sh** | Network namespace + proxy bridge | no | unshare, ip; socat only with an upstream proxy; slirp4netns + nsenter only for the SOFT fallback |
| **compartment-bpf** | Optional BPF LSM inode sealing (kernel-side deny, even root) | yes (CAP_BPF + CAP_SYS_ADMIN) | clang ≥ 12, libbpf, bpftool, libsodium, BTF, kernel ≥ 6.6 with `lsm=...,bpf` |

`compartment-user` / `compartment-root` use Landlock + seccomp
(userspace policy) and are the default zero-dependency path.
`compartment-bpf` seals individual inodes at the BPF LSM level —
enforcement lives in the kernel and survives even root. The two
approaches are complementary. See `compartment-bpf/HOWTO.md` for
the BPF tool and its requirements.

## Quick Start

```bash
make
./compartment-user -- /bin/sh          # sandboxed shell in 2 commands
./compartment-user --dry-run -- /bin/sh # see what would be applied
```

## Build

```bash
make                    # builds the zero-dependency core tools
make test               # core suites (Landlock + seccomp + env + inheritance)
make test-integration   # every unprivileged suite (sandbox.sh, external CLI)
sudo make test-root     # the root-only suites
make hardened           # build with randomized shell stash path
make show-hardening     # print the hardening flags this toolchain accepted
make check              # shellcheck + file-mode checks (same gates as CI)
```

Hardening flags (`-fPIE -pie`, full RELRO, `-z noexecstack`,
`-fstack-clash-protection`, `-fcf-protection`, `_FORTIFY_SOURCE=3`) are
stated by the Makefile rather than inherited from the distribution's gcc
specs, and each one a toolchain might not have is chosen by a compile-and-
link probe, so an older or non-x86 target drops it instead of failing.

Optional BPF module:

```bash
cd compartment-bpf
make vmlinux.h && make
```

Requires Linux kernel 6.6+ with BPF LSM enabled, plus clang,
libbpf-dev, bpftool, libsodium-dev, and BTF for the running kernel.

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

Kernel-enforced, inherited across `fork`/`exec`, and impossible for the
sandboxed process or its descendants to remove:

1. `PR_SET_NO_NEW_PRIVS` — prevent privilege escalation
2. **Landlock** — filesystem path restrictions (read-only system paths,
   writable workdir) and, from ABI v4 (Linux 6.7), TCP port restrictions.
   A rule may name a directory *or a single file*: `rw /dev/null` and
   `exec /usr/bin/psql` are per-file grants, and a policy that grants
   execute on individual files and on no directory is a binary allow-list
3. **seccomp BPF** — block dangerous syscalls (ptrace, mount, kexec, bpf, io_uring, ...)

Applied once, immediately before `exec`, and *not* kernel restrictions:

4. **Environment sanitize** — strip `LD_*`, cloud credentials, SSH agent
   socket, etc. from the environment handed to the command. A sandboxed
   process can re-export any of them for its own children and the loader
   will honour it; use `compartment-bpf` for durable environment policy.
5. **Working directory** and **file-descriptor cleanup** — one-time actions.
6. **Audit logging** — a record, not a restriction: file-per-day log with
   PPID chain.

Run-time order: audit log → preflight → no_new_privs → environment →
Landlock → seccomp → `chdir` → hardening → `exec`.

Two properties of Landlock decide how a policy has to be written:

* **It is additive.** The rights of every rule matching an ancestor of the
  path being opened are unioned, so a narrower rule never takes anything
  away from a wider one. `rw /work` plus `ro /work/secrets` leaves the
  secrets writable. Both tools refuse that policy rather than pretend.
* **A rule for a path that does not exist grants nothing.** That is now a
  fatal error; append `?` to the path (`ro /lib32?`) for the entries that
  are genuinely conditional. `--verbose` reports how many rules were
  *installed*, not how many were asked for.

**compartment-root** creates a fully isolated container:

1. `clone()` with new UTS, mount, PID, IPC, net, user, cgroup namespaces
2. **pivot_root** — the new root is bind-mounted `nosuid,nodev` onto itself
   first, so a setuid binary inside it cannot elevate (stronger than chroot).
   `rootdir-flags` adds `noexec` and `ro` on top; `mount-ro`, `mount-noexec`,
   `mount-nosuid` and `mount-nodev` do the same for one path at a time.
   The rootdir itself must be root-owned (or owned by the mapped host uid of
   the container's root under a shifted `uid-map`) and not group- or
   world-writable
3. Fresh `/proc`, read-only `/sys`, a `/dev` tmpfs with `null`, `zero`,
   `full`, `random`, `urandom` and `tty` bind-mounted from the old root, a
   private `devpts` on `/dev/pts` with `/dev/ptmx` bound to it, a tmpfs
   `/dev/shm`, 15 masked `/proc` paths, isolated hostname — all of it
   applied *before* the old root is detached, which is what the kernel's
   `mount_too_revealing()` check requires
4. **Landlock**, opt-in with `landlock on` — the same ruleset builder
   compartment-user uses, applied after the mounts and before the privilege
   drop, so `exec /usr/bin/psql` is a per-binary allow-list entry inside the
   container
5. **Capability drop** — raw prctl + capset, no libcap. `cap-allow` preserves
   named capabilities for the service user via `PR_SET_KEEPCAPS` + `capset()`
6. **seccomp BPF** — raw BPF, no libseccomp; a 43-syscall deny-list is
   installed by default, and `seccomp-default` chooses what a denied call
   does (`errno`, `kill` or `log`)
7. **Environment sanitize** + **audit logging** (same as compartment-user),
   FD cleanup, `PR_SET_NO_NEW_PRIVS` (which no profile can turn off), and a
   minimal PID 1 reaper that forwards signals and reaps orphans — itself
   under the same filter whenever the policy permits the syscalls it needs

**sandbox.sh** wraps the command in a network-isolated user+mount namespace:

1. `unshare --user --mount --net --map-root-user --fork` — HARD mode:
   loopback-only, no external interfaces, no routes. Needs an unprivileged
   user namespace with a uid map, which some distributions block; run
   `./sandbox.sh --verify` to see whether this host allows it.
   SOFT fallback: slirp4netns with `--disable-host-loopback`, which also
   needs `nsenter`
2. Unix socket proxy bridge — API traffic routed through corporate proxy
3. Bind-mount shell replacement — every `/bin/bash` subprocess gets sandboxed
   (requires mount namespace, which sandbox.sh creates)

In HARD mode with a proxy configured, the namespace has no external
interfaces — network traffic is intended to flow only through the unix
socket proxy bridge. (The automated tests verify proxy reachability
but do not yet include direct-bypass resistance tests.)

## Profile Files

Both tools read the same `.conf` syntax. The filesystem, network, syscall
and environment directives are honoured by both; the namespace and mount
directives are compartment-root only and are parsed and silently ignored by
compartment-user, so keep the two kinds in separate files.

| Directive | Tools | Meaning |
|---|---|---|
| `ro PATH` | both | Read + execute on PATH and everything beneath it |
| `rw PATH` | both | Read + write, **no execute** (W^X) |
| `rwx PATH` | both | Read + write + execute |
| `exec PATH` | both | Read + execute. On a *file* this is a per-binary grant — see below |
| `PATH?` | both | A trailing `?` makes the rule optional: skipped when the path is absent instead of fatal |
| `workdir PATH` | compartment-user | Working directory, added as `rw` |
| `net-bind PORT` | both | Allow `bind(2)` on this TCP port (repeatable) |
| `net-connect PORT` | both | Allow `connect(2)` to this TCP port (repeatable) |
| `net-default deny\|ignore` | both | `deny` handles TCP bind and connect and refuses every port not listed. Default `ignore`: the network is not restricted |
| `block NAME` | both | Deny-list one syscall |
| `allow NAME` | both | Switch to allow-list mode and permit one syscall |
| `seccomp-mode allow` | both | Switch to allow-list mode explicitly (`allowlist` is accepted as a synonym; any other value means deny-list mode) |
| `seccomp-default errno\|kill\|log` | both | What a denied syscall does. Default `errno` (EPERM) |
| `env-deny NAME` / `env-allow NAME` | both | Environment policy; a trailing `*` is a prefix match |
| `env-mode allow` | both | Switch the environment policy to allow-list mode (`allowlist` is accepted as a synonym; any other value means deny-list mode) |
| `landlock`/`seccomp`/`no-new-privs`/`env-sanitize` `on` | both | One-way switches: a profile may turn a mechanism on, never off. Landlock defaults to **on** for compartment-user and **off** for compartment-root |
| `audit on` / `audit-log DIR` | both | Audit trail |
| `inherit NAME` | both | Load another profile first, then apply these rules on top |
| `rootdir DIR` | compartment-root | The container root. Must be root-owned and not group- or world-writable |
| `rootdir-flags LIST` | compartment-root | Extra mount flags for the rootdir bind: `ro`, `noexec` (`nosuid` and `nodev` are always applied) |
| `mount-ro PATH` | compartment-root | Bind PATH onto itself inside the new root and remount it read-only |
| `mount-noexec` / `mount-nosuid` / `mount-nodev PATH` | compartment-root | The same, for the other three flags (repeatable) |
| `uid` / `gid` / `username` | compartment-root | The service user to drop to |
| `uid-map` / `gid-map` | compartment-root | `<container-start> <host-start> <count>`; default is the identity map |
| `netns NAME` | compartment-root | Join `/var/run/netns/NAME` instead of creating a new network namespace |
| `cgroup PATH` / `cap-allow CAP` / `loopback on` / `mount-mask PATH` | compartment-root | Cgroup, capability, loopback and masking policy |

**`exec` on a file is a binary allow-list.** A Landlock rule may name a
regular file, and a rule on a file carries only the file-level rights. So

```conf
landlock on
exec /usr/bin/exampled
exec /usr/bin/psql
ro   /usr/lib
```

means "these two binaries may be executed and nothing else", because no
directory in the policy carries execute. Two things to know before relying
on it: the dynamic loader has to be listed as well (`execve(2)` opens the
ELF interpreter with `FMODE_EXEC`, so Landlock checks execute on it), while
shared libraries do *not* (`ld.so` opens them read-only, and Landlock has no
mmap hook — `ro`/`rw` on the library directory is enough); and the rule keys
on the file, so a busybox-style multi-call binary cannot be split into
applets. `ro` grants execute too, which is why no directory holding binaries
may appear as `ro` in an allow-list policy.

**Landlock network rules are TCP-only and allow-list-only.** `net-bind` and
`net-connect` map onto `LANDLOCK_RULE_NET_PORT`, which covers `bind(2)` and
`connect(2)` on TCP and nothing else: no UDP, no unix sockets, no netlink,
no raw sockets, no `listen`/`accept` granularity, and no per-address rules —
a rule for port 443 allows connecting to port 443 on any address, v4 and v6
alike. There is no way to express "everything except port N"; that needs a
BPF LSM and is left to a sibling tool. Below Landlock ABI v4 (Linux 6.7)
both tools warn loudly that the port policy is not active.

```conf
# compartment-user: filesystem (Landlock)
ro /usr
rwx $HOME

# Syscalls
block ptrace
block mount
# Or allow-list mode:
# seccomp-mode allow
# allow read
# allow write

# Environment ('*' at the end is a prefix match)
env-deny LD_*
# Or allow-list mode:
# env-mode allow
# env-allow PATH

# Features — a profile may only turn these on; use --no-landlock,
# --no-seccomp or --no-env-sanitize on the command line to disable them
landlock on
seccomp on
no-new-privs on
env-sanitize on
audit on
```

```conf
# compartment-root: namespace container
rootdir /srv/containers/default
uid 1000
gid 1000
username svc
loopback on
cap-allow net_bind_service
mount-mask /proc/keys

# Landlock inside the container (opt-in), mount hardening, TCP ports
landlock on
exec /usr/bin/myapp
ro   /usr/lib
rw   /srv/data
rootdir-flags ro
mount-noexec /tmp
net-connect 5432
net-default deny
```

`examples/restricted-root.conf` is a worked example of that shape, with a
comment block on what it does and does not guarantee.

Print the effective policy at any time with
`compartment-user --dump-profile <name>`.

Search order: `--profile /path/file.conf` → `/etc/compartment/<name>.conf` →
`~/.config/compartment/<name>.conf` (compartment-user with `--user-profiles`
only) → built-in. compartment-root searches `/etc/compartment/` only.

Every profile file must be a regular file owned by root or by you (root only
for compartment-root), in a directory with the same ownership, and neither
may be group- or world-writable.

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
| `restricted-root.conf` | A service container with an `exec` binary allow-list and one outbound TCP port | Anything but the named binaries running inside the container; egress to any other port |
| `curl-wget.conf` | Running `curl`, `wget` or `aria2c` | An HTTP client reading or writing outside its download directory |
| `dns-client.conf` | Running `dig`, `host`, `nslookup`, `drill`, `kdig` | A resolver tool touching anything but its own configuration |
| `net-trace.conf` | Running `ping`, `traceroute`, `mtr`, `nmap`, `arping` | A raw-socket diagnostic tool with filesystem access it does not need |
| `tcpdump.conf` | Running `tcpdump`, `tshark`, `dumpcap` | A capture tool reading the filesystem or writing outside its capture directory |
| `net-admin-ro.conf` | Read-only network administration: `ip`, `ss`, `nft list`, `iptables -L` | A query command mutating network state or the filesystem |
| `tcp-udp-relay.conf` | Running `socat`, `nc`, `ncat` as a relay | A relay tool reaching your files |
| `dhclient.conf` | Running the ISC DHCP client (root) | A DHCP client writing outside `/var/lib/dhcp` |

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
README.md              — This file
HOWTO.md               — Detailed setup guide
DESIGN.md              — Architecture, security review, lineage from shell-guard
SECURITY.md            — Vulnerability reporting policy
LICENSE                — Apache-2.0
.gitignore             — Build products and operational artifacts, never committed
compartment-bpf/       — Optional BPF-LSM inode-sealing module, its own build,
                         profiles, tests and documentation (see its README.md,
                         HOWTO.md, LIMITATIONS.md and CHANGELOG.md)
examples/
  ai-agent.conf        — Profile for AI coding assistants
  strict.conf          — Locked-down profile (inherits ai-agent)
  container.conf       — Full namespace isolation profile (compartment-root)
  restricted-root.conf — Container with an exec allow-list and one TCP port
  dev.conf             — Relaxed profile for development
  ssh.conf             — Read-only SSH client (no filesystem writes)
  socat-proxy.conf     — Network-only socat bridge (no user file access)
  curl-wget.conf       — HTTP(S) clients: curl, wget, aria2c
  dns-client.conf      — DNS clients: dig, host, nslookup, drill, kdig
  net-trace.conf       — Raw-socket diagnostics: ping, traceroute, mtr, nmap
  tcpdump.conf         — Packet capture: tcpdump, tshark, dumpcap
  net-admin-ro.conf    — Read-only network admin: ip, ss, nft list, iptables -L
  tcp-udp-relay.conf   — Relay tools: socat, nc, ncat
  dhclient.conf        — ISC DHCP client (root)
  paranoid-ssh.sh      — Privilege-separated SSH (SSH+socat split)
tools/
  syscall.py           — Profile generator: trace any program, emit .conf
  HOWTO-syscall-profiling.md — Full guide to syscall profiling
man/
  compartment-user.1   — Man page (section 1: user commands)
  compartment-root.8   — Man page (section 8: system administration)
tests/
  probes/deny_probe.c  — Sandbox validation probe (machine-parseable output)
  profiles/            — Test-specific .conf profile templates
  scripts/run_all.sh   — Rootless test runner (make test-integration)
  scripts/run_root_tests.sh — Root-only test runner (sudo make test-root)
  scripts/rootless.d/  — Discovered unprivileged suites (drop a script in)
  scripts/root.d/      — Discovered root-only suites
  README.md            — Test documentation
scripts/
  timestamp.sh         — SHA256 + OpenTimestamps proof-of-existence
extra/
  squid-proxy/, tinyproxy/ — Optional egress-proxy helpers
.github/workflows/
  ci.yml               — Build, rootless + root suites, sanitizers, lint
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
