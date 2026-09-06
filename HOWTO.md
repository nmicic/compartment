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
2. **System config** — `/etc/compartment/<name>.conf`
3. **User config** — `~/.config/compartment/<name>.conf`, **only** when
   `--user-profiles` is given, and never in shell-replacement mode
4. **Built-in** — `ai-agent` and `strict` (compiled in)

If a file is found, it is loaded. If it exists but does not parse, nothing
runs and the exit status is non-zero — the built-in is used only when no
file was found at all.

compartment-root never looks in `$HOME`; it searches `/etc/compartment/`
only, and requires the file to be owned by root.

### Why `$HOME` is not searched by default

The built-in `ai-agent` profile grants the sandboxed process read, write
**and execute** on `$HOME`. If `~/.config/compartment/` outranked `/etc`,
an agent could write its own next-run policy and the following invocation
of the same command line would run unconfined. `--user-profiles` is the
opt-in for deployments where the invoking user is trusted to write their
own policy — an interactive developer sandboxing a build, say — and it is
never honoured when compartment-user is standing in for a login shell.

### Profile file trust

Every profile file is checked on the file descriptor it is read from:

* it must be a regular file;
* it must be owned by **root** or by **you** (by root only for
  compartment-root);
* it must not be group- or world-writable — with one exception: a file or
  directory that **you** own, in **your own primary group**, may be
  group-writable when that group has no other members, because
  `umask 002` plus user-private groups is the default on Debian, Ubuntu
  and Fedora and group-write there is no wider than owner-write. A
  root-owned file never qualifies, so `/etc/compartment/` and every
  compartment-root profile keep the strict rule;
* its containing directory must pass the same ownership and write check.

Symlinks are followed, so `/etc/alternatives`-style indirection works, but
the target and the directory the target really lives in are checked too. A
sticky directory (`/tmp`, `/var/tmp`) may be world-writable: the sticky bit
is what prevents anyone but the owner from replacing the file.

A violation is fatal and names the fix:

```
compartment: profile /home/you/.config/compartment/ai-agent.conf is mode 0664
— group- or world-writable policy is not trusted
  fix with: chmod go-w /home/you/.config/compartment/ai-agent.conf
```

### Format

One directive per line. Blank lines and `#` comments are ignored.
`$HOME` and `$USER` are expanded in values.

```conf
# /etc/compartment/my-agent.conf

# Inherit another profile (loads it first, then applies these rules on top)
# inherit ai-agent

# Filesystem (Landlock)
ro /usr
ro /lib
ro /lib64
ro /etc
ro /bin
ro /proc
ro /dev
rw /tmp
rwx $HOME

# Syscall blocklist (seccomp)
block ptrace
block mount
block unshare
block bpf

# Environment deny list ('*' at the end is a prefix match)
env-deny LD_*
env-deny GLIBC_TUNABLES
env-deny PYTHON*
env-deny PROMPT_COMMAND
env-deny GIT_SSH_COMMAND
env-deny JAVA_TOOL_OPTIONS

# Feature toggles — these may only be turned on from a profile
landlock on
seccomp on
no-new-privs on
env-sanitize on

# Audit logging
audit on
audit-log $HOME/.local/state/compartment

# Working directory
# workdir $HOME/projects
```

That is a sketch, not the shipped policy. **Do not transcribe the
built-in profile into a file by hand** — earlier releases of this guide
did, and the copy drifted to 28 syscall blocks and 7 environment entries
against a built-in that had 43 and 34, quietly dropping every
container-escape block and all credential stripping from anyone who
followed it.

Print the real thing instead:

```bash
# See exactly what the tool would apply
compartment-user --dump-profile ai-agent

# Start a system profile from it
compartment-user --dump-profile ai-agent | sudo tee /etc/compartment/my-agent.conf
sudo chmod 644 /etc/compartment/my-agent.conf
```

`--dump-profile` serialises the resolved policy — built-in, file, and
anything inherited — back into `.conf` syntax, so what you edit is what
the binary actually enforces. `examples/ai-agent.conf` is generated the
same way and is equivalent to the built-in.

### Directives

Used by **compartment-user**:

| Directive | Value | Example |
|-----------|-------|---------|
| `ro` | path | `ro /usr` |
| `rw` | path (read + write, no execute) | `rw /tmp` |
| `rwx` | path (read + write + execute) | `rwx $HOME` |
| `exec` | path (alias for `ro`) | `exec /opt/bin` |
| `workdir` | path | `workdir $HOME/projects` |
| `landlock` | `on` only | `landlock on` |

Used by **both** tools:

| Directive | Value | Example |
|-----------|-------|---------|
| `block` | syscall name | `block ptrace` |
| `allow` | syscall name (switches to allow-list) | `allow read` |
| `seccomp-mode` | `allow` or `deny` | `seccomp-mode allow` |
| `env-deny` | variable name or `PREFIX*` | `env-deny LD_*` |
| `env-allow` | variable name or `PREFIX*` (switches to allow-list) | `env-allow PATH` |
| `env-mode` | `allow` or `deny` | `env-mode allow` |
| `seccomp` | `on` only | `seccomp on` |
| `no-new-privs` | `on` only | `no-new-privs on` |
| `env-sanitize` | `on` only | `env-sanitize on` |
| `audit` | on/off | `audit on` |
| `audit-log` | directory path | `audit-log /srv/audit/compartment` |
| `inherit` | profile name | `inherit ai-agent` |

Used by **compartment-root** only:

| Directive | Value | Example | CLI equivalent |
|-----------|-------|---------|----------------|
| `rootdir` | path | `rootdir /srv/jail` | `--rootdir` |
| `uid` | number | `uid 1000` | `--uid` |
| `gid` | number | `gid 1000` | `--gid` |
| `username` | user name | `username svc` | `--username` |
| `netns` | namespace name | `netns sandbox` | `--netns` |
| `cgroup` | cgroup path | `cgroup /sys/fs/cgroup/svc` | `--cgroup` |
| `cap-allow` | capability name | `cap-allow net_bind_service` | `--cap-allowed` |
| `loopback` | on/off | `loopback on` | `--loopback` |
| `mount-mask` | path | `mount-mask /proc/keys` | `--mount-mask` |

Note the one name that differs between the two spellings: the profile
directive is `cap-allow`, the command-line flag is `--cap-allowed`.
Writing `cap-allowed` in a profile produces only an "unknown directive"
warning and the capability is dropped.

Each tool silently ignores the other's directives — they are recognised
by the shared parser, so no "unknown directive" warning appears. Keep
compartment-user and compartment-root policy in separate files.

### Environment name patterns

A trailing `*` in an `env-deny` or `env-allow` entry makes it a prefix
match; anything else is an exact variable name. `env-deny LD_*` covers
`LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, `LD_DEBUG`, `LD_PROFILE`,
`LD_ORIGIN_PATH` and whatever the loader grows next — which is the point,
because an exhaustive list of injection variables goes stale the moment
it is written. The built-in profile uses `LD_*`, `DYLD_*`, `BASH_FUNC_*`,
`PYTHON*`, `PERL5*` and `GIT_CONFIG_*` for exactly that reason.

### What the built-in profile does *not* strip

Model-provider credentials — `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
`GEMINI_API_KEY` and the like — are **deliberately left in place**.
compartment-user exists to run those agents; stripping the key the agent
needs to start would make the tool useless for its main job.

Cloud, VCS and database credentials (`AWS_*` keys,
`GOOGLE_APPLICATION_CREDENTIALS`, `AZURE_CLIENT_SECRET`, `GITHUB_TOKEN`,
`GH_TOKEN`, `GITLAB_TOKEN`, `NPM_TOKEN`, `DATABASE_URL`, `PGPASSWORD`,
`MYSQL_PWD`, `SSH_AUTH_SOCK`) *are* stripped, because an agent that needs
them is the exception rather than the rule.

The honest rule: **environment sanitization removes what the sandboxed
process should not have; it cannot protect a secret you hand it on
purpose.** If a key must not reach the agent, do not export it into the
agent's environment — use `--env-allow` to name exactly what should
survive, or keep the credential in a file the Landlock ruleset does not
grant.

### Security switches are one-way

`landlock`, `seccomp`, `no-new-privs` and `env-sanitize` may only be
turned **on** from a profile. Writing `seccomp off` (or `no`, `false`,
`0`) in a profile is a fatal parse error and nothing runs:

```
compartment: /etc/compartment/x.conf:12: 'seccomp off' is not allowed in a
profile — a profile may only tighten policy.
  Pass --no-seccomp on the command line if you really need to disable it.
```

A profile file is data. It may live somewhere the sandboxed process can
reach, so it must never be able to switch enforcement off. Only the
invoking user can, with `--no-landlock`, `--no-seccomp` or
`--no-env-sanitize` on the command line. `no_new_privs` has no
command-line escape hatch: it is always on.

### Comments

`#` starts a comment when it begins a whitespace-separated token, and
trailing whitespace is trimmed, so both of these work:

```conf
# a whole-line comment
ro /usr           # and a trailing one
```

A `#` inside a token is literal, so a path such as `rw /srv/build#3`
still means what it says.

### Inheritance

Profiles can inherit from other profiles with the `inherit` directive.
The inherited profile is loaded first, then the current file's directives
are applied on top (additive — paths and blocks accumulate).

```conf
# /etc/compartment/strict.conf
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
`inherit` resolves through the same search order and the same trust
checks as `--profile`, so a system profile can never pull in a file
from `$HOME`. If the inherited profile exists but does not parse,
the whole load is rejected and nothing runs.

---

## Audit Logging

compartment-user logs events to stderr and to daily log files.

### Enable

```bash
# Stderr + default log dir (~/.local/state/compartment/)
./compartment-user --audit -- claude

# Stderr + custom log dir
./compartment-user --audit-log /path/to/logs -- claude

# Via profile file
audit on
audit-log /srv/audit/compartment
```

### Log Location

Default: `$XDG_STATE_HOME/compartment/YYYY-MM-DD.log`, or
`~/.local/state/compartment/YYYY-MM-DD.log` when `$XDG_STATE_HOME` is
unset. compartment-root running as root uses `/var/log/compartment/`.
Either directory is created mode 0700.

The directory must be owned by the effective uid and must not be group-
or world-writable. It is opened with `O_DIRECTORY|O_NOFOLLOW` and the
daily file is created relative to that descriptor with `O_NOFOLLOW`, so
neither the directory nor the file may be a symlink someone else
controls. Every field written to a record has control characters
replaced with `_`, so a command path containing a newline cannot forge a
log line. If auditing was requested and cannot be set up safely,
compartment-user and compartment-root refuse to run.

Earlier releases defaulted to `/var/tmp/compartment-audit-$UID/`. That
directory sits in a world-writable tree and the old code followed a
symlink planted at that path.

The log file is opened **before** Landlock is applied. The file descriptor
has `O_CLOEXEC`, so it does not leak to the exec'd child. This gives us:

```
1. audit_log_open()    ← opens fd (no restrictions yet)
2. audit_log()         ← writes COMPARTMENT_START event
3. apply_landlock()    ← from here, the log directory is inaccessible
4. apply_seccomp()
5. execv(child)        ← child inherits restrictions, fd is closed
```

The fd is closed across the exec, so the child cannot write to the open
log file.

**It does not follow that the child cannot reach the directory.** Landlock
is additive and only restricts the rights named in its handled mask:

* if the audit directory lies inside a path the profile grants (and the
  default `~/.local/state/compartment` lies inside the `rwx $HOME` rule
  the built-in `ai-agent` profile installs), the child can open, read and
  rewrite yesterday's log;
* even outside every rule, the handled mask carries no metadata-read
  right, so `stat()` and `access()` on the directory still succeed.

For tamper-evident logging, point `--audit-log` at a directory outside
every granted path — ideally one the sandboxed user cannot write at all,
such as a root-owned directory with `compartment-root` — or ship the
records off the host.

### File Permissions

- Directory: `0700` (only your user)
- Files: `0600` (only your user)
- Writes are `O_APPEND` (atomic for lines under 4096 bytes)

### Log Format

One line per event, structured for grep:

```
[2026-03-31 01:27:10] user=claude uid=1000 event=COMPARTMENT_START ppid_chain=1234->5678->1 cwd=/home/claude/project tty=/dev/pts/0 command=/bin/echo profile=ai-agent source=built-in landlock=1 seccomp=1 paths=14 blocked=43
```

Fields: timestamp, user, uid, event type, PPID chain (who launched us),
working directory, TTY, and event-specific detail.

### Rotation

No rotation logic needed — the date **is** the rotation. One file per day.
Clean up old logs with cron:

```bash
find "${XDG_STATE_HOME:-$HOME/.local/state}/compartment" -name '*.log' -mtime +30 -delete
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

`COMPARTMENT_SHELL_DIR` comes from the caller — in a login-shell
deployment, from the very user being confined — so it is honoured only
when it is an absolute path with no `..` component and both the directory
and the shell binary inside it are owned by root or by you and are
neither group- nor world-writable. Otherwise compartment-user prints a
warning and uses the compile-time `REAL_SHELL_DIR`.

**The sandbox is applied before the exec either way.** An accepted
`COMPARTMENT_SHELL_DIR` changes *which binary* runs, never *whether* it
is confined. For a hardened deployment, do not set the variable at all
and rely on `make hardened`.

In shell-replacement mode the profile is read from
`/etc/compartment/ai-agent.conf` or the compiled-in default;
`~/.config/compartment/` is never searched, and `--user-profiles` does
not apply.

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
