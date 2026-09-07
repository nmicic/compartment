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
* it must not be group- or world-writable. Primary group membership is not
  recorded in the explicit member list returned by the group database, so
  an apparently empty group cannot safely be treated as private. Use
  `chmod go-w` on policy files and their containing directories;
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

Used by **compartment-user** only:

| Directive | Value | Example | CLI equivalent |
|-----------|-------|---------|----------------|
| `workdir` | path | `workdir $HOME/projects` | `--workdir` |
| `cap-drop` (alias `cap-bounding`) | capability name or number (repeatable) | `cap-drop CAP_SYS_MODULE` | `--cap-drop` |
| `mask` | path, `?` = optional (repeatable) | `mask /run/systemd/private` | `--mask` |

`cap-drop` and `mask` are the two directives a **root** subject needs and an
unprivileged one does not; both are no-ops for a caller with no privilege to
give up. They are compartment-user-only because compartment-root's nearest
equivalents are not the same thing: `cap-allow` is an allow-list over a set
compartment-root builds from scratch, and `mount-mask` names paths *inside
the new root* it is about to pivot into. Writing either of them in a
compartment-root profile gets the usual "belongs to the other tool" warning.

* **`cap-drop CAP`** removes `CAP` from the bounding set with
  `PR_CAPBSET_DROP`, clears the ambient and inheritable sets, and locks the
  securebits. For a uid-0 process exec'ing a file with no file capabilities
  the kernel recomputes permitted as *(full set ∩ bounding set)*, so what
  survives the exec is exactly the bounding set — which is why this, and not
  a `capset()` of the effective set, is the primitive that binds a root
  shell. It is one-way: nothing later in the session can put a dropped
  capability back. Check with `grep CapBnd /proc/self/status`.

  `SECBIT_NOROOT` is **not** set, deliberately. With it, the same exec
  computes permitted = 0 and the process gets no capabilities at all: right
  for an unprivileged sandbox, useless for an account that has to read a log
  or run `ip`. The trade-off is that a limited root keeps every capability
  the profile does not name.

* **`mask PATH`** covers `PATH` inside a private mount namespace — an empty
  read-only tmpfs over a directory, a bind of `/dev/null` over anything
  else. It needs `CAP_SYS_ADMIN` at setup time and nothing afterwards, so
  the capability can be dropped in the same run.

  It exists for the one surface Landlock has no right for: `connect(2)` to a
  unix socket named by a path is not a filesystem access, so a domain that
  denies `open()` on `/run/systemd/private` still lets the process drive
  systemd through it. Making the path not be there is the only answer short
  of a BPF socket hook.

  Two properties are easy to get wrong. The namespace is made
  `MS_PRIVATE|MS_REC` first — without it a cover mount propagates back to
  the host and hides the path from the whole machine, permanently, because
  `/` is `shared` on a systemd distribution. And a non-directory mask
  *neutralises* a write rather than refusing one: the open succeeds (Landlock
  keys on inodes and every usable profile grants `rw /dev/null`) and the
  bytes go nowhere. Use `mask` for a read or connect surface; use a path
  rule for a write surface, where Landlock refuses the open with `EACCES`.

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

**A login shell's `argv[0]` starts with a dash.** `login(1)` and `sshd`
hand a login shell `argv[0] = "-bash"`, and the dash is a convention that
tells the shell to read the login startup files — it is not part of the
program's name. compartment-user strips one leading `-` when it picks the
stash entry, and passes `argv` to the real shell unchanged so that the shell
still knows what it is. Without that, an interactive login looks for
`<stash>/-bash` and fails to exec; only `ssh host command` worked, because
sshd passes the bare basename there.

In shell-replacement mode the profile is resolved in this order, with the
same trust checks as `--profile` and with `~/.config/compartment/` never
searched:

1. `/etc/compartment/shell-replacement.conf`
2. `/etc/compartment/ai-agent.conf`, then the compiled-in `ai-agent` policy

`shell-replacement.conf` also changes the failure semantics. The agent
deployment degrades to a syslog warning and lets the login through, because
an unsandboxed agent beats a user locked out of `/bin/bash`. An operator who
writes `shell-replacement.conf` is confining an *account*, and for such an
account an unconfined uid-0 login **is** the failure — so with that file in
force a rejected profile, a failed mask, a failed capability policy or any
failed enforcement mechanism refuses the session with exit status 126.
Keep a second administrative account whose login shell is the stashed binary,
and console access, before you deploy it.

`mask` and `cap-drop` failures are fatal in *both* modes: nothing depends on
them degrading, and a mask that did not go on is a hole the profile says is
shut.

---

## Limited root over SSH

A uid-0 account that can administer the host but cannot switch off the
enforcement that confines it. The account logs in over the machine's own
sshd; its login shell is the compartment-user wrapper; everything descended
from that login inherits a Landlock domain, a seccomp filter, a reduced
capability bounding set and a private mount namespace. sshd, PID 1, cron and
the pinned `compartment-bpf` policy stay outside it.

Read the "what this does not guarantee" block at the top of
`examples/limited-root.conf` before deploying. The short version: this
confines a *session*; it does not create a uid boundary, and it does not
protect against a root process that was never in the session. That second
adversary is what the seal profile is for, and both halves are needed.

The complete list of what this deployment does **not** protect against is
§8 below. It is one list, deliberately, so that it can be read in full
before the first login rather than assembled from the profile comments.

### 1. The account

```bash
# A second name for uid 0.  -o allows the duplicate uid; the distinct name
# is what sshd, the audit trail and the seal profile key on.
useradd -o -u 0 -g 0 -m -d /home/radmin -s /bin/bash radmin
```

`-s /bin/bash` assumes the **shell-replacement deployment**: `/bin/bash` on
this host *is* the wrapper, and the real bash lives in the stash. That
confines every account whose shell is `/bin/bash`, including `root`, which
is usually what you want and is occasionally a surprise.

The alternative is to point only this account at the wrapper:

```bash
install -d -m 0755 /usr/local/lib/compartment/limited-root
ln -s /usr/local/bin/compartment-user /usr/local/lib/compartment/limited-root/bash
usermod -s /usr/local/lib/compartment/limited-root/bash radmin
```

Nothing else on the machine changes, and `root` keeps an unconfined shell —
which is either your recovery path or your escape route, depending on who
holds root's key. `tests/scripts/root.d/limited-root.sh` uses this form,
because a test must not replace `/bin/bash` on a host it does not own.

Either way the wrapper must be *invoked under a shell's name* — the symlink
is what puts it in shell-replacement mode. Setting the account's shell to
`/usr/local/bin/compartment-user` directly does not work.

### 2. The hardened stash

```bash
make hardened          # randomises REAL_SHELL_DIR; prints the path it chose
make install           # /usr/local/bin/compartment-user

install -d -m 0755 -o root -g root /bin/shells      # or the randomised path
install -m 0755 -o root -g root /bin/bash /bin/shells/bash
ln -sf /usr/local/bin/compartment-user /bin/bash    # shell-replacement form
```

The stash directory and the binary inside it must be owned by root and
neither group- nor world-writable, or the wrapper refuses to use them. Put
the stash somewhere a `ro` rule in the profile covers — under `/bin` or
`/usr` — or the confined shell cannot be exec'd.

### 3. The policy

```bash
install -d -m 0755 -o root -g root /etc/compartment
install -m 0644 -o root -g root examples/limited-root.conf /etc/compartment/
printf 'inherit limited-root\n' > /etc/compartment/shell-replacement.conf
chmod 0644 /etc/compartment/shell-replacement.conf
install -d -m 0700 -o root -g root /var/log/compartment
```

Both files must be root-owned and not group- or world-writable; the wrapper
refuses a policy anyone else could have written. Edit the `rw` rules to name
the paths this operator's limited root is actually supposed to manage — the
shipped list is an example, and a profile that grants more than the account
needs is the easiest way to undo everything below it.

Check the result before you rely on it:

```bash
compartment-user --profile limited-root --dry-run -- /bin/bash
```

### 4. sshd

Two settings, and neither is optional. Both defend against sshd doing
something on the account's behalf that the session itself cannot do.

```
# /etc/ssh/sshd_config.d/50-limited-root.conf
Match User radmin
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    PermitTunnel no
    X11Forwarding no
    PermitOpen none
    PermitListen none
```

`ssh -L /tmp/s:/run/systemd/private radmin@host` makes **sshd** — which is
outside the confinement — open the socket the profile masks. Forwarding has
to be off, and the seal on `sshd_config` is what keeps it off.

Keep the *external* sftp subsystem:

```
Subsystem sftp /usr/lib/openssh/sftp-server
```

OpenSSH runs a subsystem command through the user's login shell, so the
external `sftp-server` goes through the wrapper. `internal-sftp` runs
in-process in the sshd child and never execs a shell, so it bypasses the
confinement completely.

### 5. The seal profile

```bash
cd compartment-bpf
sysctl -w fs.protected_hardlinks=1
: > /etc/ld.so.preload                 # must exist before it can be sealed
export COMPARTMENT_BPF_PASSPHRASE='<high-entropy-string>'
sudo -E ./compartment-bpf --pin profiles/limited-root-authpath.conf
```

`--pin`, not a daemon. A daemon can be killed by any same-uid process, and
below Landlock ABI v6 the confined session can send that signal. `--pin`
leaves nothing to kill: the links live in the bpffs pin tree, which the
session cannot reach because no rule in `limited-root.conf` grants
`/sys/fs/bpf`.

Adjust the paths in that profile to your install before loading it — the
loader refuses the whole file if any path is missing or is a symlink at the
leaf. `--dry-run` names every one of them and touches no kernel state:

```bash
./compartment-bpf --dry-run profiles/limited-root-authpath.conf
# ... [dry-run] summary: N seals resolved, 2 actor groups, M errors
```

Fix the `M` before you `--pin`. Sealing pins the filesystem, so `--unpin` before a `dpkg` run that
rewrites a sealed file, before a kernel or grub upgrade, and before any
account maintenance: the account database is sealed shut, so `passwd(1)` and
`usermod(8)` do not work while the policy is loaded.

**Never seal a path the profile also masks.** compartment-bpf refuses a new
mount on or under a sealed path, so the mask fails — and a failed mask
refuses the login.

Consider adding `--self-protect` to that `--pin` line. Without it, anything
outside the session holding `CAP_BPF` owns the seals (§8, item 11); with it,
every map fd and the whole pin tree are behind the loader's own binary
identity. It is off by default because it changes the upgrade ceremony — a
rebuilt or upgraded loader is a different inode and cannot `--unpin` what
this one pinned unless it was named with `--authorize-loader` at pin time.
Read `compartment-bpf/HOWTO.md` §3.6 for that ceremony and the
self-protection section of `compartment-bpf/LIMITATIONS.md` for what the
flag still does not close, before turning it on.

### 6. Recommended one-way sysctls

```bash
sysctl -w kernel.modules_disabled=1        # irreversible until reboot
sysctl -w kernel.kexec_load_disabled=1     # irreversible until reboot
```

Both are genuinely one-way. `kernel.yama.ptrace_scope` is **not** — root can
lower it again from anything below 3 — so treat Yama as advisory and rely on
the `CAP_SYS_PTRACE` drop. Booting with `lockdown=integrity` closes
`/dev/mem`, unsigned module loading and `kexec` at the kernel level and is
worth doing, but it is a property of the host, not of this deployment.

`kernel.modules_disabled=1` must come after every module the host needs is
loaded.

### 7. Recovery

Everything here can lock the account out, on purpose:

* the wrapper refuses the session when a mask or the capability policy
  cannot be applied, or when `shell-replacement.conf` does not parse;
* a sealed `/etc/passwd` means the account's shell cannot be changed back
  while the policy is loaded;
* a stash that moves or loses its permissions makes the shell unexecutable.

So before enabling any of it, make sure you have **both** of:

1. a second administrative account whose login shell is the stashed binary
   (`/bin/shells/bash`, not `/bin/bash`), with its own key; and
2. console access — a serial console, the hypervisor console, or physical
   access.

To take the deployment apart, in this order:

```bash
compartment-bpf --unpin                  # needs the passphrase
rm /etc/compartment/shell-replacement.conf
usermod -s /bin/shells/bash radmin       # or ln -sf /bin/shells/bash /bin/bash
```

### 8. What limited root does not protect against

This is the whole list, in one place, so that anyone building a restricted
maintenance shell on top of this deployment can judge the fit without
reading the design notes. It is the reason this is a defence-in-depth layer
and not a boundary. Everything below was measured on kernel 6.8.0-139
(Landlock ABI 4) and on 7.0.0-31 (Landlock ABI 8).

**1. uid 0 is still uid 0.** Nothing here creates a uid boundary. The
account *is* uid 0, it keeps `CAP_DAC_OVERRIDE`, and DAC therefore
contributes nothing: the Landlock allow-list is the only thing between the
account and the filesystem. That makes **read** policy exactly as
load-bearing as write policy, which is the trap most easily walked into —
`ro /etc` is a comfortable-looking rule that hands over `/etc/shadow`,
every private key stored under `/etc`, and whatever else lives there. Name
the directories the account actually needs to read, the way the
`ro /sys/class`, `ro /sys/devices` lines in the shipped profile do, rather
than granting a tree and hoping.

**2. The `mask` list is an enumeration, not a boundary.** Landlock has no
access right covering `connect(2)` to a unix socket named by a path —
measured: under a domain that returned `EACCES` for `open()` on the socket
path, `connect()` to that same path still succeeded — and seccomp cannot
take up the slack, because that call's address family sits behind a pointer
a filter cannot dereference. So every privileged socket has to be named
individually, and a distribution that adds one adds a hole with no warning.
Re-run `find /run -type s` after every distribution upgrade and compare it
against the `mask` lines. Two things would end this, and neither is in
1.4.0: an **allow-list form of `mask`** — a tmpfs over `/run` with the
handful of paths an administrative session needs bound back — which needs a
survey of what such a session actually touches under `/run` before it can
ship; and a **BPF socket ACL**, which would let a policy allow a socket for
one operation instead of removing it from the namespace. Until one lands,
treat the list as something to re-check, not as a wall.

**3. A mask neutralises a write; it does not refuse one.** A mask over
anything that is not a directory is a bind of `/dev/null`, and Landlock
keys its rules on inodes, so the cover inherits the profile's
`rw /dev/null`: the open succeeds and the bytes go nowhere. Remounting the
bind read-only changes nothing either — the kernel's read-only-filesystem
check covers regular files, directories and symlinks, never device nodes.
Nothing leaks and nothing reaches the target, but the caller is told it
succeeded. **Use `mask` for read and connect surfaces, and a Landlock rule
for write surfaces**, where the open is refused outright. In the shipped
profile that is why `/proc/kcore`, `/dev/mem`, `/dev/kmem`, `/dev/port`,
`/sys/kernel/debug` and `/sys/kernel/tracing` are masked — all read
surfaces — while `/proc/sysrq-trigger` deliberately is not: `ro /proc`
already refuses that open, and a mask would have downgraded a refused
reboot trigger into an accepted one.

**4. A path cannot be both sealed and masked.** compartment-bpf refuses a
new mount on or under a sealed path, so the mask fails; and because masks
fail closed, a failed mask refuses the login. `/boot` is sealed and
deliberately not masked for this reason. Nothing in either tool catches the
conflict at load time — it surfaces at the next login — which is why the
two profiles have to be reviewed together.

**5. Below Landlock ABI v6 the session can signal processes outside its
domain.** There are no scoped rules before Linux 6.12, so on a 6.8 kernel
the confined account can signal anything its uid allows, which as uid 0 is
everything. It is a denial-of-service surface rather than an escape, and it
is the reason **`--pin` is mandatory** for the seal profile: a
`compartment-bpf` daemon is a process, a same-uid session can kill it, and
killing it takes enforcement with it. `--pin` leaves nothing to kill — the
links live in the bpffs pin tree, which no rule in `limited-root.conf`
grants. A `scope signal` directive would close this on kernels that have
the primitive (verified: a scoped ruleset makes `kill(1, 0)` return `EPERM`
on ABI 8, while on ABI 4 the extra ruleset attribute makes
`landlock_create_ruleset` fail `E2BIG`), and it was deliberately left out of
1.4.0 — a half-tested signal scope in an administrative shell is a good way
to break job control on the one kernel that supports it.

**6. sshd routes around the confinement two ways, and only configuration
closes them.** sshd is outside the session by design — it is what *creates*
the session — so anything it does on the account's behalf never enters the
domain:

* **stream-local forwarding.** `ssh -L /tmp/s:/run/systemd/private radmin@host`
  makes *sshd* open the socket the profile masks, and the account then
  talks to PID 1 through the forwarded fd;
* **`internal-sftp`**, which runs in-process in the sshd child and never
  execs a shell, so the wrapper is not on the path at all.

Both are closed by these lines and by nothing else — there is nothing to
implement, only something not to get wrong:

```
# /etc/ssh/sshd_config.d/50-limited-root.conf
Match User radmin
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    PermitTunnel no
    X11Forwarding no
    PermitOpen none
    PermitListen none
```

```
# and keep the EXTERNAL sftp subsystem, which OpenSSH runs through the
# login shell — never internal-sftp
Subsystem sftp /usr/lib/openssh/sftp-server
```

Both validation guests shipped the permissive forwarding default, so this
is a step the operator takes and not one the distribution takes for them.
The seal on `sshd_config` in the auth-path profile is what keeps the
setting from being edited back; configuration on its own would be a control
the adversary can write to.

**7. An `actor=` identity is forgeable from outside the session.** A seal
written `actor=NAME` decides who may write by resolving the caller's
`current->mm->exe_file`, and a process holding `CAP_SYS_RESOURCE` can point
that at another binary with `PR_SET_MM_EXE_FILE`. *Inside* the session this
is already closed: `cap-drop CAP_SYS_RESOURCE` is in the profile, and the
capability check runs before the mapping check, so the call returns `EPERM`
regardless of state (measured on both kernels). *Outside* it, an unconfined
root holding that capability can take on an actor identity its own binary
does not earn. compartment-bpf has the hook that stops it — `comp_task_prctl`
denies the whole `PR_SET_MM` family — but it is armed only under a
strict-launch policy, and the shipped auth-path profile uses plain
`actor=`. Three ways to close it, cheapest first:

1. **Do not put `actor=` on the path at all.** A seal with no actor is shut
   to everybody, forgery included. That is what the shipped auth-path
   profile already does for the account database, `sshd_config`, PAM and
   `ld.so.preload` — every path where the honest answer to "who may write
   this while the policy is loaded?" is "nobody". Prefer it wherever it
   fits: in the shipped profile the only `actor=` seal left is the audit
   log directory, which has to stay writable by the wrapper, so that is the
   whole blast radius of this residual there.
2. **A directive that arms the `PR_SET_MM` denial on its own** — not in
   1.4.0. The hook exists and the gate is the missing half: there is no way
   today to switch it on without adopting the whole strict-launch
   deployment.
3. **`actor-strict` plus a statically linked launcher**
   (`compartment-bpf/HOWTO.md` §2.3.x). This is the answer that ships
   today, and it is the largest change: the seal carries `strict-launch`,
   the identity moves from `mm->exe_file` to an in-kernel launch marker set
   at a committed exec of the declared launcher, and the launcher must be
   static and sealed `full` in the same profile. Whether this deployment
   should carry one is a decision to take once, together with the
   strict-launch work, rather than separately in each profile.

**8. Two things a Landlock domain cannot see.** An fd received over
`SCM_RIGHTS` from an unconfined process is not re-checked — there is no
hook, so a descriptor passed into the session carries whatever access it
was opened with. (The `compartment-bpf` seals are not fooled the same way:
`comp_file_permission` resolves the caller from `current->mm->exe_file`,
not from whoever opened the fd.) And `memfd` + `fexecve` runs code the
policy never named, because an anonymous file has no path for a rule to
match and Landlock has no mmap hook. That second one is bounded: the code
still runs inside the same Landlock domain, the same seccomp filter and the
same capability bounding set as everything else in the session.

**9. Service management is not available, on purpose.** The masks over
`/run/systemd/private` and `/run/dbus/system_bus_socket` are exactly what
make `systemctl`, `systemd-run` and every other bus client report
`Failed to connect to bus: Connection refused` inside the session. That is
the intended result — each of those is a way to ask an unconfined daemon to
do what the session may not — but it is a real cost and it should be priced
before deploying: this account cannot restart a unit, reload a daemon or
launch a transient one, and on systemd ≥ 257 the varlink interface to PID 1
is masked for the same reason. Reading is unaffected where it does not go
through PID 1 — `ro /var/log` keeps the log files readable. If the
account's job genuinely needs service management, the answer is not to drop
the masks, which gives back the entire surface, but one of the two
directions in item 2: a **broker** that accepts a fixed, audited set of
unit operations on the account's behalf, or the **BPF socket ACL**, which
could allow one socket for one operation. Neither is in 1.4.0.

**10. The account cannot run this project's own privileged tools.**
`cap-drop CAP_SYS_ADMIN` costs `mount`, `umount`, `setns`, `unshare`,
`pivot_root` and `nsenter`, and with them `compartment-root`, `sandbox.sh`
HARD mode and `sudo make test-root`. Worth recording loudly, because the
failure looks like a broken build rather than a policy decision: **a CI
runner must not be a limited root.**

**11. Anything holding `CAP_BPF` outside the session owns the seals, unless
self-protection is on.** This deployment makes `CAP_BPF` the only way to
reach the auth-path seals — `cap-drop CAP_BPF` takes it from the session,
seccomp blocks `bpf`, and no rule grants `/sys/fs/bpf` — but on its own it
does nothing to defend `CAP_BPF` itself. A uid-0 process that was never in
the session (cron, a unit, an sshd session for an account whose shell is
not the wrapper) and that holds the capability can unlink the pin tree,
delete `/run/compartment-bpf/unpin-sentinel` and take the legacy
no-passphrase unpin path, or rewrite the seal maps outright — freezing does
not stop that, because `bpf_map_freeze()` gates the syscall path and not the
program path. The answer ships in the same release and is opt-in: pin with
`--pin --self-protect`, which puts every map fd and the whole pin tree
behind the loader's own binary identity. **The two controls compose and
neither replaces the other**: this profile takes `CAP_BPF` away from the
account, self-protection answers everyone else. Read
`compartment-bpf/HOWTO.md` §3.6 for the upgrade ceremony it imposes and the
self-protection section of `compartment-bpf/LIMITATIONS.md` for the six
things it still does not close — turning the flag on without reading the
upgrade rule first is how a pin tree ends up stranded until a reboot.

**12. Some of what looks closed here is the host's doing, not this
deployment's.** Both validation guests boot with
`/sys/kernel/security/lockdown` at `integrity`, which pre-closes
`/dev/mem`, unsigned module loading and `kexec` at the kernel level. A
stock host does not. Do not read those results as properties of the
profile: `lockdown=integrity` is worth setting and it is a separate
decision. In the same class, `kernel.yama.ptrace_scope` is **not** one-way
below 3 — root lowered it from 2 back to 1 during validation — so Yama is
advisory here and the `CAP_SYS_PTRACE` drop is the real closure.

**13. One kernel divergence, recorded so it is not mistaken for flake.**
`/proc/1/environ` and `/proc/1/ns/*` are readable from the confined session
on 7.0.0-31 and denied on 6.8.0-139. The namespace fds are inert without
`setns`, which the `CAP_SYS_ADMIN` drop and the seccomp block both remove.
`/proc/1/root` is refused on both kernels, by Landlock's own
`ptrace_access_check` rather than by the `/proc` rule — with and without
`ro /proc`, while `/proc/self/root` opens.


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
