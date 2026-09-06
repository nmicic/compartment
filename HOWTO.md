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
4. **Built-in** — `ai-agent`, `strict` and `none` (compiled in)

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

# Filesystem (Landlock).  A rule may name a directory or a single file;
# a trailing '?' makes the rule optional instead of fatal when the path
# does not exist.
ro /usr
ro /lib
ro /lib64
ro /lib32?
ro /etc
ro /bin
ro /proc
ro /dev
rw /dev/null
rw /tmp
rwx $HOME

# Network (Landlock ABI v4 / Linux 6.7+, TCP only)
# net-connect 443
# net-default deny

# Syscall blocklist (seccomp)
block ptrace
block mount
block unshare
block bpf

# What a denied syscall does: errno (default), kill or log
# seccomp-default kill

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
audit-log /srv/audit/compartment

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

Filesystem and network — used by **both** tools (Landlock is on by default
for compartment-user and opt-in for compartment-root):

| Directive | Value | Example |
|-----------|-------|---------|
| `ro` | path (read + execute) | `ro /usr` |
| `rw` | path (read + write, no execute) | `rw /tmp` |
| `rwx` | path (read + write + execute) | `rwx $HOME` |
| `exec` | path (read + execute; on a **file**, a per-binary grant) | `exec /usr/bin/psql` |
| *(any of the above)* | a trailing `?` makes the rule optional | `ro /lib32?` |
| `workdir` | path (compartment-user; added as `rwx`, not the W^X `rw`) | `workdir $HOME/projects` |
| `landlock` | `on` only | `landlock on` |
| `net-bind` | TCP port 0-65535 (repeatable) | `net-bind 8080` |
| `net-connect` | TCP port 0-65535 (repeatable) | `net-connect 5432` |
| `net-default` | `deny` or `ignore` (default `ignore`) | `net-default deny` |

Three things about these rules are not obvious and will bite:

* **A rule may name a single file.** `rw /dev/null`, `ro /etc/resolv.conf`
  and `exec /usr/bin/psql` all work. Only the file-level rights apply to
  such a rule (execute, read, write, truncate, ioctl-dev); the
  directory-only rights are dropped.
* **A rule for a path that does not exist is fatal.** It would grant
  nothing, and a policy that believes it granted something is worse than one
  that refuses to start. Append `?` to the path for the entries that are
  genuinely conditional (`ro /lib32?`), and check with `--dry-run`, which
  marks a path that is not there.
* **Landlock is additive.** The rights of every rule matching an ancestor of
  the path being opened are unioned, so a narrower rule never restricts a
  wider one. `rw /work` together with `ro /work/secrets` leaves the secrets
  writable; both tools refuse that policy outright. Split the writable rules
  instead. (`exec` inside `rw` is allowed, because that one genuinely adds a
  right rather than pretending to remove one.)

Used by **both** tools:

| Directive | Value | Example |
|-----------|-------|---------|
| `block` | syscall name | `block ptrace` |
| `allow` | syscall name (switches to allow-list) | `allow read` |
| `seccomp-mode` | `allow`/`allowlist` or `deny`/`denylist`; **any other value is a fatal parse error** | `seccomp-mode allow` |
| `seccomp-default` | `errno`, `kill` or `log` (default `errno`) | `seccomp-default kill` |
| `env-deny` | variable name or `PREFIX*` | `env-deny LD_*` |
| `env-allow` | variable name or `PREFIX*` (switches to allow-list) | `env-allow PATH` |
| `env-mode` | `allow`/`allowlist` or `deny`/`denylist`; **any other value is a fatal parse error** | `env-mode allow` |
| `seccomp` | `on` only | `seccomp on` |
| `no-new-privs` | `on` only | `no-new-privs on` |
| `env-sanitize` | `on` only | `env-sanitize on` |
| `audit` | on/off | `audit on` |
| `audit-log` | directory path (outside every granted path) | `audit-log /srv/audit/compartment` |
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
| `uid-map` | `<container-start> <host-start> <count>` | `uid-map 0 100000 65536` | — (profile only) |
| `gid-map` | `<container-start> <host-start> <count>` | `gid-map 0 100000 65536` | — (profile only) |
| `rootdir-flags` | `ro`, `noexec` (comma-separated; `nosuid` and `nodev` are always applied and cannot be turned off) | `rootdir-flags ro,noexec` | — (profile only) |
| `mount-ro` | path inside the new root | `mount-ro /usr` | — (profile only) |
| `mount-noexec` | path inside the new root | `mount-noexec /tmp` | — (profile only) |
| `mount-nosuid` | path inside the new root | `mount-nosuid /home` | — (profile only) |
| `mount-nodev` | path inside the new root | `mount-nodev /home` | — (profile only) |

compartment-root also accepts `--landlock`, `--ro`, `--rw`, `--rwx` and
`--exec` on the command line; any of the four path options turns Landlock on
by itself.

`uid-map` and `gid-map` have no command-line equivalent; both default to
the identity map `0 0 65536`, which gives a capability boundary and no uid
isolation. See "Root-specific profile directives" below.

Note the one name that differs between the two spellings: the profile
directive is `cap-allow`, the command-line flag is `--cap-allowed`.
Writing `cap-allowed` in a profile is a **fatal parse error** from 1.4 —
before that it was a warning and the run continued with the capability
silently dropped.

Since 1.4 the parser distinguishes three cases, because they are three
different mistakes:

* An **unknown directive** — a typo, or a flag spelling where a directive
  was wanted — is a fatal parse error. A profile is policy; a line we
  cannot read means we do not know what the policy is.
* A directive belonging to **the other tool** is a warning that names the
  tool (`'cap-allow' is a compartment-root directive; compartment-user
  ignores it`) and the run continues. Sharing one file between the two is
  a legitimate shape; doing it silently is not.
* An **invalid value** for a directive that takes one — `seccomp-mode`,
  `env-mode`, `net-default`, `seccomp-default`, `audit` — is a fatal
  parse error naming the accepted values.

Keeping compartment-user and compartment-root policy in separate files is
still the recommendation; the warning tells you when you have not.

### `exec` on a file: a binary allow-list

A Landlock rule on a regular file grants `LANDLOCK_ACCESS_FS_EXECUTE` on
that one file. A policy that grants execute on individual files and on no
directory is therefore an allow-list of binaries:

```conf
landlock on
exec /usr/bin/exampled
exec /usr/bin/psql
ro   /usr/lib          # libraries: read is enough, see below
rw   /srv/exampled/data
```

Four facts decide whether this works for you, all verified against the
running kernel rather than inferred:

1. **The dynamic loader must be listed too.** `execve(2)` opens the ELF
   interpreter with `FMODE_EXEC`, and Landlock's `file_open` hook maps that
   to the execute right. Without `exec /lib64/ld-linux-x86-64.so.2` every
   dynamically linked binary fails with `EACCES` no matter what else is
   granted.
2. **Shared libraries do not.** `ld.so` opens a `.so` read-only and maps it
   `PROT_EXEC`; Landlock has no mmap hook, so `READ_FILE` on the library
   directory is all a library needs. `ro` or `rw` on `/usr/lib` is enough —
   and `rw` is the more honest choice in an allow-list, because `ro` grants
   execute on everything beneath it.
3. **`ro` on a directory grants execute.** No directory containing binaries
   may appear as `ro` in an allow-list policy, or the allow-list is a
   no-op. This is the single easiest way to get it wrong.
4. **The rule keys on the file, not on the name.** A busybox-style
   multi-call binary cannot be split into applets: allowing `/bin/sh`
   allows every applet, because they are all the same inode. Likewise a
   shell builtin is not an `execve` at all, so listing a shell in the
   allow-list gives away far more than the shell.

The allow-list is a property of the whole sandbox and not of a caller: it
cannot express "the supervisor may run psql but the request handler may
not", and it can only ever be narrowed by a child. That needs a BPF LSM.

### Landlock network rules

`net-bind PORT`, `net-connect PORT` and `net-default deny` build
`LANDLOCK_RULE_NET_PORT` rules. They need Landlock ABI v4 (Linux 6.7);
below that both tools print a loud warning and the port policy is **not**
active — the filesystem rules still are.

```conf
net-connect 443
net-connect 5432
net-default deny
```

`net-default deny` handles both TCP bind and connect, so with only connect
rules present every `bind(2)` is refused as well — including the explicit
`bind(port 0)` some clients make before connecting. Add `net-bind 0` if you
need that. Without `net-default deny`, naming any `net-*` rule still turns
the corresponding access on: `net-connect 443` alone means "connect to 443
and nothing else", while `bind` stays unrestricted.

What these rules cannot do, stated plainly:

* **TCP only.** No UDP, no unix sockets, no netlink, no raw sockets. A DNS
  query over UDP/53 is unaffected, and so is exfiltration over UDP.
* **Allow-list only.** There is no way to express "everything except port
  N". The shape available is `net-default deny` plus the ports you need.
* **Ports only.** No per-address rules: a rule for port 443 allows port 443
  on every address, IPv4 and IPv6 alike, and there is no way to allow v4
  while denying v6.
* **No `listen`/`accept` granularity.** `bind` is the only server-side
  operation covered.

A port deny-list, per-address rules and UDP all need a BPF LSM; they are
future work for a sibling tool, not something Landlock can be made to do.

### Environment name patterns

A trailing `*` in an `env-deny` or `env-allow` entry makes it a prefix
match; anything else is an exact variable name. `env-deny LD_*` covers
`LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, `LD_DEBUG`, `LD_PROFILE`,
`LD_ORIGIN_PATH` and whatever the loader grows next — which is the point,
because an exhaustive list of injection variables goes stale the moment
it is written. The built-in profile uses `LD_*`, `DYLD_*`, `BASH_FUNC_*`,
`PYTHON*`, `PERL5*` and `GIT_CONFIG_*` for exactly that reason.

### What the built-in profile does *not* strip

The `*_API_KEY` variables an agent authenticates its model provider with
are **deliberately left in place**. compartment-user exists to run those
agents; stripping the key the agent needs in order to start would make
the tool useless for its main job.

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
`inherit NAME` first looks for `NAME.conf` **in the directory holding the
profile doing the inheriting** — that is what makes `examples/strict.conf`'s
`inherit ai-agent` resolve to `examples/ai-agent.conf`. If there is no
sibling by that name it falls back to the same search order and the same
trust checks as `--profile`, so a system profile can never pull in a file
from `$HOME`. If the inherited profile exists but does not parse,
the whole load is rejected and nothing runs.

---

## Audit Logging

compartment-user logs events to stderr and to daily log files.

### Enable

```bash
# Stderr + default log dir (see "Log Location" below)
./compartment-user --audit -- claude

# Stderr + custom log dir
./compartment-user --audit-log /path/to/logs -- claude

# Via profile file
audit on
audit-log /srv/audit/compartment
```

### Log Location

The default must be somewhere the sandboxed process cannot rewrite, so
it is deliberately **not** under `$HOME`: the built-in `ai-agent` profile
grants the confined process read, write *and* execute there.

Without `--audit-log`, the directory is chosen in this order:

1. **`/var/lib/compartment/audit/<uid>/`** — used only if an
   administrator provisioned it. The parent must be root-owned and not
   group- or world-writable, and the per-uid directory must be a real
   directory owned by your real uid with mode `0700`:

   ```bash
   sudo install -d -m 0755 -o root -g root /var/lib/compartment/audit
   sudo install -d -m 0700 -o "$USER" "/var/lib/compartment/audit/$(id -u)"
   ```

   If the parent is writable by anyone but root, compartment-user says so
   and moves on to step 2 rather than trusting it.

2. **`/var/tmp/compartment-audit-<uid>/`** — created mode `0700`.
   `/var/tmp` is sticky and world-writable, so another user can create
   that name first. If the directory is found with a different owner or
   any mode other than `0700`, compartment-user **refuses to run** rather
   than appending to it:

   ```
   compartment: audit dir /var/tmp/compartment-audit-1000 is uid 1 mode 0777
   — expected uid 1000 mode 0700
   compartment: refusing to write the audit log to /var/tmp/compartment-audit-1000
   ```

Running as root short-circuits both of those: the default is
**`/var/log/compartment/`**, created mode `0700`, and steps 1 and 2 are
not consulted at all.

Whichever directory is used, it must be owned by the effective uid and
must not be group- or world-writable. It is opened with
`O_DIRECTORY` + `O_NOFOLLOW` and the daily file is created relative to
that descriptor with `O_NOFOLLOW`, so neither the directory nor the file
may be a symlink someone else controls. Every field written to a record
has control characters replaced with `_`, so a command path containing a
newline cannot forge a log line. If auditing was requested and cannot be
set up safely, compartment-user and compartment-root refuse to run.

Release 1.3.3 defaulted to `/var/tmp/compartment-audit-$UID/` with no
ownership or mode check at all, and followed a symlink planted at that
path.

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

Neither default is inside a path the built-in profiles grant for writing,
so the confined process cannot rewrite or delete its own trail. Verified:

```
$ compartment-user --audit -- /bin/sh -c ': > /var/tmp/compartment-audit-1000/2026-09-06.log'
/bin/sh: 1: cannot create …/2026-09-06.log: Permission denied
```

Two caveats, both about *reading* rather than writing:

* `/var/lib` is granted `ro` by the built-in `ai-agent` profile (dpkg,
  apt, node modules live there), so a log under
  `/var/lib/compartment/audit/` is **readable** from inside the sandbox.
  `/var/tmp` is covered by no rule at all, so a log there is not.
* the handled mask carries no metadata-read right, so `stat()` and
  `access()` on any path still succeed regardless.

**An operator-chosen `--audit-log` directory inside a granted `rw` or
`rwx` path is fully reachable by the sandboxed process** — it can read
the trail and rewrite it. `--audit-log /tmp/x`, for instance, sits inside
the `ai-agent` profile's `rw /tmp` rule. Pick a directory that no path
rule covers, or ship the records off the host.

### File Permissions

- Directory: `0700` (only your user)
- Files: `0600` (only your user)
- Writes are `O_APPEND` (atomic for lines under 4096 bytes)

### Log Format

One line per event, structured for grep:

```
[2026-03-31 01:27:10] user=dev uid=1000 event=COMPARTMENT_START ppid_chain=1234->5678->1 cwd=/home/dev/project tty=/dev/pts/0 command=/bin/echo profile=ai-agent source=built-in landlock=1 seccomp=1 paths=21 blocked=43
```

Fields: timestamp, user, uid, event type, PPID chain (who launched us),
working directory, TTY, and event-specific detail.

### Rotation

No rotation logic needed — the date **is** the rotation. One file per day.
Clean up old logs with cron:

```bash
find "/var/tmp/compartment-audit-$(id -u)" -name '*.log' -mtime +30 -delete
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
2. Resolve username to UID/GID (**host** `/etc/passwd`, before `clone()` —
   for a user that only exists inside the container, pass `--uid`/`--gid`)
3. Open audit log (host filesystem, before namespace setup)
4. Parent, still before `clone()`: validate `rootdir` ownership; clear the
   parent's own supplementary groups (once `/proc/<pid>/setgroups` is
   `deny` the child can no longer do it); and — when `netns` names one —
   join that network namespace, dropping `CLONE_NEWNET` so the child
   inherits it
5. `clone()` with new namespaces (UTS, mount, PID, IPC, net, user, cgroup)
6. Parent: write `deny` to `/proc/<pid>/setgroups`, then the UID/GID maps
   (identity `0 0 65536` unless `uid-map`/`gid-map` say otherwise), then
   cgroup assignment
6b. Child: become uid 0 *of the new namespace*, bind `rootdir` onto itself,
   remount it `nosuid,nodev` (plus anything `rootdir-flags` adds except
   `ro`), `pivot_root`
7. Child: mount `/proc`, mount read-only `/sys`, populate `/dev` with
   device nodes bind-mounted from the old root, mount a private `devpts` on
   `/dev/pts` and bind `/dev/ptmx` to it, mount a tmpfs `/dev/shm`, apply
   the `/proc` masks — **then** detach the old root (see "Why the order
   matters" below)
7b. Child: apply `mount-ro`/`mount-noexec`/`mount-nosuid`/`mount-nodev`,
   then `rootdir-flags ro` last of all — the tree has to be writable while
   the mount points above are being created
8. Child: Hostname isolation, optional loopback
8b. Child: Landlock, when `landlock on` (or any `--ro`/`--rw`/`--rwx`/
   `--exec`) is in the policy. Applied here because every mount is in place
   and the child still holds `CAP_SYS_ADMIN` in its own user namespace,
   which is what `landlock_restrict_self(2)` needs before `no_new_privs`
9. Child: Capability bounding-set drop (raw `prctl` — while still root)
10. Child: `PR_SET_KEEPCAPS` + privilege drop (`setgid`/`setuid`)
10b. Child: `capset()` — restore effective+permitted caps for service user
11. Child: `PR_SET_DUMPABLE(0)`, environment sanitize
12. Child: audit `CONTAINER_EXEC`, close inherited FDs
13. Child: `PR_SET_NO_NEW_PRIVS`, `PR_SET_PDEATHSIG`, fork under a PID 1
    reaper, seccomp BPF (raw, fatal on failure), resource limits,
    `exec` the command. The reaper installs the same filter whenever the
    policy permits `wait4`, `kill`, `rt_sigaction`, `rt_sigprocmask`,
    `rt_sigreturn`, `exit_group` and `write`; when it does not, PID 1 stays
    unfiltered and `--verbose` says so

### Why the order matters

Mounting a fresh `proc` or `sysfs` inside a user namespace is gated by the
kernel's `mount_too_revealing()` check: it only succeeds while a fully
visible mount of the same filesystem still exists in the current mount
namespace. Detaching the old root removes the last visible procfs, so the
old sequence (detach, then `mount proc`) failed with `EPERM` and
compartment-root could not start at all. The old root is also the only
source of real device nodes — `mknod(2)` checks `CAP_MKNOD` against the
*initial* user namespace and always fails here — so `/dev` is populated by
bind-mounting from `/.pivot_old/dev` before the detach.

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
| `uid-map` | `uid-map 0 100000 65536` | `<container-start> <host-start> <count>`; default is the identity map `0 0 65536` |
| `gid-map` | `gid-map 0 100000 65536` | Same, for gids |
| `rootdir-flags` | `rootdir-flags ro,noexec` | Extra mount flags on the rootdir bind. `nosuid` and `nodev` are always applied and cannot be turned off |
| `mount-ro` | `mount-ro /usr` | Bind a path inside the new root onto itself and remount it read-only (repeatable) |
| `mount-noexec` | `mount-noexec /tmp` | Same, `noexec` (repeatable) |
| `mount-nosuid` | `mount-nosuid /home` | Same, `nosuid` (repeatable) |
| `mount-nodev` | `mount-nodev /home` | Same, `nodev` (repeatable) |
| `landlock` | `landlock on` | Enforce Landlock inside the container. **Off by default** here, unlike compartment-user |

`cgroup` paths must resolve under `/sys/fs/cgroup/`.

**`rootdir` ownership is checked.** Under the default identity uid map the
directory must be owned by root; under a shifted `uid-map` it may instead be
owned by the host uid the container's root maps to. It must never be group-
or world-writable: whoever can write the container root chooses which
binaries exist inside it, and `nosuid,nodev` only takes the sharpest edge
off that. Note that a *root-owned* rootdir under a shifted map passes the
check but cannot actually be used — the container's root is then an
unprivileged host uid that cannot create the pivot point.

**Changing mount flags needs two calls.** A bind mount inherits the flags of
its source, and `mount(2)` ignores `MS_REC` on a remount, so each
`mount-*` directive does a `MS_BIND|MS_REC` self-bind followed by a
`MS_REMOUNT|MS_BIND|<flags>` pass — recursive via `mount_setattr(2)` where
the kernel has it (5.12+), top mount only otherwise. `rootdir-flags ro` is
deliberately **not** recursive: `/proc`, `/dev` and `/sys` are separate
mounts on top of the container root and have to stay writable. It is also
applied last, because those mount points must be created in a writable
tree first.

**`rootdir-flags noexec` disables the container.** Nothing inside the
container root can then be executed, including the target command. It is
only useful when the executables live on a separate mount.

### Landlock inside the container

`landlock on` runs the same ruleset builder compartment-user uses, so
`ro`/`rw`/`rwx`/`exec` and the `net-*` directives all mean what they mean
there. Two differences: Landlock is **off** by default (a profile written
before this release keeps its old behaviour), and a policy that carries path
rules without `landlock on` gets a warning rather than silence. `landlock on`
with no path rules is refused, because an empty ruleset with a non-empty
handled mask denies every filesystem access.

`exec /path/to/binary` is the reason to use it: see "`exec` on a file: a
binary allow-list" above, and `examples/restricted-root.conf` for a worked
profile. The one caveat specific to containers is the busybox one — a
single-binary rootdir cannot be split into applets, because an allow-list
keys on the inode.

**The default uid map gives no uid isolation.** `0 0 65536` maps container
uid 0 to host uid 0, so a process that regains uid 0 inside the container
is host root for DAC purposes on the files backing `rootdir`. The user
namespace still provides a capability boundary, which is the layer that
matters here — but if you want a uid boundary too, map onto a subuid range
with `uid-map`/`gid-map` and `chown` `rootdir` to the mapped host uid.

### Testing compartment-root

The rootless suite (`make test-integration`) cannot exercise any of this.
The root-only suites are run separately, as root:

```bash
sudo make test-root
```

`tests/scripts/root.d/compartment-root.sh` builds its own busybox rootdir
under `mktemp -d` and asserts against a real container (start-up, `/dev`,
seccomp, privilege drop, `/proc` and `/sys` masking, namespace isolation
and escape attempts, the init reaper, networking, uid mapping, cgroup
confinement, reporting), then removes everything it created on exit —
including on failure.
`tests/scripts/root.d/compartment-root-landlock.sh` does the same for the
Landlock exec allow-list, the `mount-*` and `rootdir-flags` hardening, the
`rootdir` ownership rules, the `--netns` join, devpts and `/dev/shm`, and
the TCP port rules. Green on kernel 6.8 (Ubuntu 24.04) and kernel 7.0
(Ubuntu 26.04). The runner prints the assertion totals it measured; they
move as suites are added, so read them from a run rather than from here.

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
README.md              — Overview, profile directive reference, file list
SECURITY.md            — Reporting policy and the known-limitation list
compartment-bpf/       — Optional BPF-LSM inode-sealing module
examples/              — 14 profiles and paranoid-ssh.sh; see README.md
                         for the full list and what each one is for
man/                   — compartment-user(1), compartment-root(8)
tools/                 — syscall.py profile generator and its guide
tests/                 — suites, fixtures and the two runners
extra/                 — optional egress-proxy helpers
scripts/               — timestamp.sh
archive/
  shell-guard/         — Archived shell-replacement tool (~2003, self-contained)
```
