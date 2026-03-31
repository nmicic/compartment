<!-- Copyright (c) 2026 Nenad Mićić <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# HOWTO: Isolation Tools for AI Agents

Rootless sandboxing for AI CLI agents (Claude, Codex, Gemini) in
corporate environments where you don't have root on the host.

## Tools

| Tool | What it does | Root? | Deps |
|------|-------------|-------|------|
| **compartment-user** | Landlock + seccomp + env sanitize + audit | no | none |
| **compartment-root** | Full namespace container + seccomp + audit | yes | none |

Both tools share the same profile file format and header (`compartment.h`).
`compartment-user` is the primary tool for rootless environments.

## Quick Start

```bash
# Build (zero dependencies)
make

# Run an AI agent in a sandbox
./compartment-user -- claude --model claude-opus-4-6

# See what would be applied without running
./compartment-user --dry-run -- claude

# Verify kernel support
./compartment-user --verify
```

## Profiles

```bash
# AI agent (default): system paths read-only, HOME+/tmp writable,
# dangerous syscalls blocked, env sanitized
./compartment-user -- claude

# Strict: ai-agent + extra syscall blocks
./compartment-user --profile strict -- claude

# Custom: explicit paths and blocks
./compartment-user --ro /usr --rw /workspace --block ptrace -- ./my-agent

# Load profile from file (by name — searches config dirs)
./compartment-user --profile my-custom -- claude

# Load profile from explicit path
./compartment-user --profile /path/to/profile.conf -- claude
```

---

## Profile Files

Instead of CLI flags, profiles can be defined in `.conf` files.
compartment-user searches for them in order:

1. **Explicit path** — `--profile /path/to/file.conf`
2. **User config** — `~/.config/compartment/<name>.conf`
3. **System config** — `/etc/compartment/<name>.conf`
4. **Built-in** — `ai-agent` and `strict` (compiled in)

If a file is found, it is loaded. Otherwise the built-in profile is used
(if one exists with that name). This means you can override the built-in
`ai-agent` profile by placing a file at `~/.config/compartment/ai-agent.conf`.

### Format

One directive per line. Blank lines and `#` comments are ignored.
`$HOME` and `$USER` are expanded in values.

```conf
# ~/.config/compartment/ai-agent.conf

# Inherit another profile (loads it first, then applies these rules on top)
# inherit ai-agent

# Filesystem (Landlock)
ro /usr
ro /lib
ro /lib64
ro /lib32
ro /etc
ro /bin
ro /sbin
ro /proc
ro /dev
ro /sys
ro /run
ro /var/lib
rw /tmp
rw $HOME

# Syscall blocklist (seccomp)
block ptrace
block mount
block umount2
block reboot
block kexec_load
block kexec_file_load
block init_module
block finit_module
block delete_module
block pivot_root
block chroot
block unshare
block setns
block keyctl
block add_key
block request_key
block bpf
block userfaultfd
block perf_event_open
block process_vm_readv
block process_vm_writev
block acct
block swapon
block swapoff
block settimeofday
block clock_settime
block clock_adjtime
block adjtimex

# Environment deny list
env-deny LD_PRELOAD
env-deny LD_LIBRARY_PATH
env-deny LD_AUDIT
env-deny DYLD_INSERT_LIBRARIES
env-deny DYLD_LIBRARY_PATH
env-deny _JAVA_OPTIONS
env-deny JAVA_TOOL_OPTIONS

# Feature toggles (on/off)
landlock on
seccomp on
no-new-privs on
env-sanitize on

# Audit logging
audit on
audit-log /var/tmp/compartment-audit-$USER

# Working directory
# workdir $HOME/projects
```

### Directives

| Directive | Value | Example |
|-----------|-------|---------|
| `ro` | path | `ro /usr` |
| `rw` | path | `rw $HOME` |
| `exec` | path | `exec /opt/bin` |
| `block` | syscall name | `block ptrace` |
| `env-deny` | variable name | `env-deny LD_PRELOAD` |
| `landlock` | on/off | `landlock on` |
| `seccomp` | on/off | `seccomp on` |
| `no-new-privs` | on/off | `no-new-privs on` |
| `env-sanitize` | on/off | `env-sanitize on` |
| `audit` | on/off | `audit on` |
| `audit-log` | directory path | `audit-log /var/tmp/my-audit` |
| `workdir` | path | `workdir $HOME/projects` |
| `inherit` | profile name | `inherit ai-agent` |

### Inheritance

Profiles can inherit from other profiles with the `inherit` directive.
The inherited profile is loaded first, then the current file's directives
are applied on top (additive — paths and blocks accumulate).

```conf
# ~/.config/compartment/strict.conf
inherit ai-agent

# Add extra syscall blocks on top of ai-agent defaults
block personality
block lookup_dcookie
block vhangup
block quotactl
block mbind
block move_pages
```

Inheritance depth is limited to 2 levels to prevent loops.

---

## Audit Logging

compartment-user logs events to stderr and to daily log files.

### Enable

```bash
# Stderr + default log dir (/var/tmp/compartment-audit-$UID/)
./compartment-user --audit -- claude

# Stderr + custom log dir
./compartment-user --audit-log /path/to/logs -- claude

# Via profile file
audit on
audit-log /var/tmp/my-audit-dir
```

### Log Location

Default: `/var/tmp/compartment-audit-<UID>/YYYY-MM-DD.log`

Why `/var/tmp`?
- **World-writable** with sticky bit — any user can create dirs, no root needed
- **Survives reboot** — unlike `/tmp` on tmpfs distros
- **Not in the Landlock allowed set** — the sandboxed child process cannot
  see, read, or tamper with audit logs

The log file is opened **before** Landlock is applied. The file descriptor
has `O_CLOEXEC`, so it does not leak to the exec'd child. This gives us:

```
1. audit_log_open()    ← opens fd (no restrictions yet)
2. audit_log()         ← writes COMPARTMENT_START event
3. apply_landlock()    ← from here, /var/tmp is inaccessible
4. apply_seccomp()
5. execv(child)        ← child inherits restrictions, fd is closed
```

The child literally cannot `open()`, `stat()`, or `ls` the audit directory.

### File Permissions

- Directory: `0700` (only your user)
- Files: `0600` (only your user)
- Writes are `O_APPEND` (atomic for lines under 4096 bytes)

### Log Format

One line per event, structured for grep:

```
[2026-03-31 01:27:10] user=claude uid=1000 event=COMPARTMENT_START ppid_chain=1234->5678->1 cwd=/home/claude/project tty=/dev/pts/0 command=/bin/echo profile=ai-agent landlock=1 seccomp=1 paths=14 blocked=30
```

Fields: timestamp, user, uid, event type, PPID chain (who launched us),
working directory, TTY, and event-specific detail.

### Rotation

No rotation logic needed — the date **is** the rotation. One file per day.
Clean up old logs with cron:

```bash
find /var/tmp/compartment-audit-$(id -u) -name '*.log' -mtime +30 -delete
```

---

## Shell Replacement Mode

compartment-user can transparently intercept `/bin/bash` (or any shell)
so that every subprocess spawned by an AI agent gets sandboxed — even
when the agent hardcodes `/bin/bash -c "..."`.

When invoked via a symlink with a name other than `compartment-user`,
it detects `argv[0]`, applies the ai-agent sandbox profile, and execs
the real shell from a configurable directory.

```
/bin/bash (symlink) → compartment-user
  → applies Landlock + seccomp + env sanitize
  → execs /bin/shells/bash (the real shell)
```

The real shell directory defaults to `/bin/shells` and can be overridden:
- At compile time: `cc -DREAL_SHELL_DIR='"/opt/shells"' ...`
- At runtime: `export COMPARTMENT_SHELL_DIR=/path/to/real/shells`
- Via `make hardened`: generates a random 12-char suffix (e.g.
  `/bin/.shells_a7f3b2c1e4cc`) so the path isn't guessable.
  `sandbox.sh` also randomizes the path per invocation.

---

## Corporate Environment: Sandboxing Without Root

In a corporate environment you can't modify `/bin/bash` on the host.
Two options for intercepting shell calls inside a sandbox namespace.

### Option A: Bind Mount (full interception)

**Intercepts all shell calls, including hardcoded absolute paths like
`/bin/bash`.**  Requires a mount namespace (provided by `sandbox.sh`
or `unshare --mount`).

```bash
# 1. Enter a user+mount namespace (no root needed on host)
unshare --user --mount --net bash

# 2. Save the real shells
mkdir -p /bin/shells
mount --bind /bin/bash /bin/shells/bash
mount --bind /bin/sh   /bin/shells/sh
# repeat for any other shells you want to intercept

# 3. Replace with compartment-user
mount --bind /path/to/compartment-user /bin/bash
mount --bind /path/to/compartment-user /bin/sh

# 4. Now every /bin/bash call hits compartment-user
#    The agent doesn't know — it gets a bash with Landlock+seccomp applied
claude --model claude-opus-4-6
```

With `sandbox.sh`, steps 1-3 happen automatically when
compartment-user is built and found on the system:

```bash
# sandbox.sh sets up the namespace and bind mounts
./sandbox.sh claude --model claude-opus-4-6
```

**How it works:**

```
sandbox.sh
  └── unshare --user --mount --net
        ├── mount --bind /bin/bash → /bin/shells/bash   (save real)
        ├── mount --bind compartment-user → /bin/bash    (replace)
        └── exec compartment-user -- claude ...
              └── claude spawns: /bin/bash -c "git diff"
                    → compartment-user (via bind mount)
                    → Landlock + seccomp applied
                    → exec /bin/shells/bash -c "git diff"
```

**Pros:** Catches everything — absolute paths, shebang lines, system().
**Cons:** Needs mount namespace. Slightly more setup.

### Option B: PATH Override (lightweight)

**Intercepts PATH-resolved shell calls only.** No mount namespace needed.
Simpler but does not catch hardcoded `/bin/bash`.

```bash
# 1. Create a directory for the interceptor symlinks
mkdir -p ~/.local/bin/sandboxed

# 2. Symlink compartment-user as each shell name
ln -s /path/to/compartment-user ~/.local/bin/sandboxed/bash
ln -s /path/to/compartment-user ~/.local/bin/sandboxed/sh
ln -s /path/to/compartment-user ~/.local/bin/sandboxed/zsh

# 3. Tell compartment-user where the real shells are
export COMPARTMENT_SHELL_DIR=/bin

# 4. Prepend to PATH
export PATH=~/.local/bin/sandboxed:$PATH

# 5. Now "bash" resolves to compartment-user, which execs /bin/bash
#    after applying the sandbox
claude --model claude-opus-4-6
```

**How it works:**

```
claude spawns: bash -c "git diff"
  → PATH lookup finds ~/.local/bin/sandboxed/bash
  → compartment-user (argv[0]="bash")
  → reads COMPARTMENT_SHELL_DIR=/bin
  → Landlock + seccomp applied
  → exec /bin/bash -c "git diff"
```

**Pros:** No namespace needed. Works anywhere. Easy to set up.
**Cons:** Does not catch `/bin/bash` (absolute path). Scripts with
`#!/bin/bash` shebang bypass it.

### Which Option?

| | Option A (bind mount) | Option B (PATH) |
|---|---|---|
| Catches `/bin/bash` | yes | no |
| Catches `bash` | yes | yes |
| Catches `#!/bin/bash` | yes | no |
| Needs namespace | yes | no |
| Setup complexity | medium | low |
| **Use when** | `sandbox.sh` or `unshare --mount` available | quick local sandboxing |

**Recommendation:** Use Option A inside `sandbox.sh` for production
AI agent containment. Use Option B for quick local experiments.

---

## Combining with bubblewrap

compartment-user (Landlock + seccomp) and bubblewrap (namespaces) are
complementary, not alternatives:

```bash
# bubblewrap provides: mount isolation, PID namespace, net namespace
# compartment-user provides: Landlock path rules, seccomp syscall filter

bwrap \
  --ro-bind / / \
  --dev /dev \
  --tmpfs /tmp \
  --bind $HOME $HOME \
  --unshare-net \
  --unshare-pid \
  -- compartment-user -- claude --model claude-opus-4-6
```

Or use compartment-user in shell-replacement mode inside bwrap:

```bash
bwrap \
  --ro-bind / / \
  --dev /dev \
  --tmpfs /tmp \
  --bind $HOME $HOME \
  --ro-bind /path/to/compartment-user /bin/bash \
  --ro-bind /bin/bash /bin/shells/bash \
  --unshare-net \
  -- claude --model claude-opus-4-6
```

---

## compartment-root

compartment-root provides full namespace isolation. It uses the same
profile file format and shared header as compartment-user.

```bash
# Build (zero dependencies)
make compartment-root

# Full container from profile
./compartment-root --profile examples/container.conf -- /bin/sh

# CLI flags (override profile)
./compartment-root --rootdir /srv/jail -u 1000 -g 1000 -U svc -l -- /bin/bash

# Dry run
./compartment-root --profile examples/container.conf --dry-run -- /bin/sh

# With audit logging
./compartment-root --profile examples/container.conf --audit -- /bin/sh
```

### What compartment-root does (in order)

1. Load profile file (if `--profile`)
2. Resolve username to UID/GID (host `/etc/passwd`)
3. Open audit log (host filesystem, before namespace setup)
4. `clone()` with new namespaces (UTS, mount, PID, IPC, net, user)
5. Parent: UID/GID range mapping (0-65535), cgroup assignment
6. Child: `pivot_root` (old root fully unmounted)
7. Child: Minimal `/dev`, masked `/proc`
8. Child: Hostname isolation, optional loopback, resource limits
9. Child: Capability bounding-set drop (raw `prctl` — while still root)
10. Child: `PR_SET_KEEPCAPS` + privilege drop (`setgid`/`setuid`)
10b. Child: `capset()` — restore effective+permitted caps for service user
11. Child: Environment sanitize
12. Child: seccomp BPF (raw, fatal on failure)
13. Child: Close inherited FDs, `exec` the command

### Root-specific profile directives

| Directive | Example | Description |
|-----------|---------|-------------|
| `rootdir` | `rootdir /srv/jail` | pivot_root target (required) |
| `uid` | `uid 1000` | Override UID for privilege drop |
| `gid` | `gid 1000` | Override GID for privilege drop |
| `username` | `username svc` | Service user for privilege drop (required) |
| `netns` | `netns my-ns` | Join existing network namespace |
| `loopback` | `loopback on` | Bring up lo in new netns |
| `cgroup` | `cgroup /sys/fs/cgroup/cpu/sandbox` | Cgroup assignment (repeatable) |
| `cap-allow` | `cap-allow CAP_NET_BIND_SERVICE` | Preserve capability for service user (repeatable) |
| `mount-mask` | `mount-mask /proc/timer_list` | Extra path to mask (repeatable) |

---

## File Layout

```
compartment.h          — shared code: profiles, audit, seccomp BPF, env sanitize
compartment-user.c     — Landlock + seccomp (zero deps, rootless)
compartment-root.c     — Full namespace container (zero deps, requires root)
sandbox.sh             — Network namespace + proxy bridge
Makefile               — Build targets
HOWTO.md               — This file
DESIGN.md              — Architecture, security review, lineage from shell-guard
examples/
  ai-agent.conf        — Profile for Claude/Codex/Gemini
  strict.conf          — Locked-down profile (inherits ai-agent)
  container.conf       — Full namespace isolation profile
  dev.conf             — Relaxed profile for development
archive/
  shell-guard/         — Archived shell-replacement tool (~2003, self-contained)
```
