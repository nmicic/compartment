# shell-guard

Shell replacement that intercepts every shell invocation on a Linux box,
logs it to syslog, and optionally enforces a compile-time security policy.

Originally written ~2003 as a stop-gap for servers where kernel-level
MAC (LIDS/lidsadm) could not be deployed. The core idea — intercept
shell exec, walk the PPID chain, check parent names/paths/sockets,
allow or deny — needed nothing beyond `/proc` and standard libc.
seccomp filtering and the YAML/Python config generator were added later.

Most of its functionality has since been folded into
`compartment-user` in the parent project, but shell-guard remains
useful on legacy boxes that lack modern kernel namespaces, seccomp,
or LSM support.

## Status

**Archived.** This code is preserved for historical reference and for
use on legacy systems. Active development has moved to the
`compartment-user` / `compartment-root` tools in the parent directory.

## How it works

1. The real shell (e.g. `/bin/bash`) is moved to `/bin/shells/bash`.
2. shell-guard is compiled and symlinked in its place (`/bin/bash`).
3. Every process that exec's a shell now runs shell-guard first.
4. shell-guard logs the invocation (user, PID, PPID chain, CWD, TTY,
   args, network sockets) to syslog under the `shell-guard` ident.
5. In enforcement mode it checks the call against a compiled-in policy
   and calls `deny_execution()` if any check fails.
6. If allowed (or in monitoring mode), it `execv`'s the real shell.

## Modes

| Mode | Behaviour | Build |
|------|-----------|-------|
| **Monitoring** (default) | Log only, never block | `#define MONITORING` (already set) |
| **Enforcement** | Log + block policy violations | Comment out `#define MONITORING` in `shell-guard.c` |

## Policy checks (enforcement mode)

Original checks (no dependencies beyond libc + `/proc`):
- PPID chain — walk every ancestor, verify executable path and CWD against allow-lists
- Network socket audit — enumerate `/proc/<pid>/fd` for open sockets, check against allowed CIDR ranges
- UID / GID allow-list
- Forbidden environment variables (`LD_PRELOAD`, etc.) rejected; env sanitised to an allow-list before exec
- Argument length and character validation

Added later (requires libseccomp):
- seccomp filter — only listed syscalls are permitted after exec

## Configure

Policy is defined in YAML, then compiled into C arrays via a Python
code generator. This two-step approach lets you edit a readable YAML
file and get a compile-time policy with zero runtime parsing overhead.

```
config.yaml  →  config.py  →  config.h  →  gcc compiles into shell-guard
 (human)         (codegen)     (C arrays)    (binary with baked-in policy)
```

### config.yaml

Edit `config.yaml` to define your policy:

```yaml
shell_guard:
  allowed_uids: [0, 1000]           # which UIDs may run shells
  allowed_gids: [0, 1000]           # which GIDs may run shells
  allowed_cwds: ["/home", "/tmp"]   # CWDs that pass validation
  allowed_executables:               # parent processes that may spawn shells
    - "/usr/sbin/sshd"
    - "/usr/bin/sudo"
  seccomp_allowed_syscalls:          # enforcement mode: syscall allow-list
    - read
    - write
    - execve
    # ... (see config.yaml for the full default list)

# Shared settings (used by shell-guard and compartment-root)
forbidden_env_vars: ["LD_PRELOAD", "LD_LIBRARY_PATH"]
allowed_env_vars: ["PATH", "HOME", "USER", "SHELL", "TERM", "LANG"]
allowed_network_ranges: ["127.0.0.0/8", "10.0.0.0/8"]
```

### Generate config.h

```bash
pip install pyyaml             # one-time dependency
python3 config.py              # reads config.yaml, writes config.h
```

This produces `config.h` containing static C arrays (`allowed_uids[]`,
`allowed_network_ranges[]`, `seccomp_allowed_syscalls[]`, etc.) that
shell-guard.c `#include`s at compile time. You must re-run `config.py`
and recompile whenever you change the policy.

## Compile

Monitoring mode (log only — requires `config.h` but not libseccomp):

```bash
python3 config.py             # generates config.h
gcc -O2 -Wall -o shell-guard shell-guard.c
```

Enforcement mode (requires `config.h` + `libseccomp-dev`):

```bash
# first comment out "#define MONITORING" in shell-guard.c
apt install libseccomp-dev    # or yum install libseccomp-devel
python3 config.py             # generates config.h
gcc -O2 -Wall -o shell-guard shell-guard.c -lseccomp
```

On very old boxes without libseccomp you can still use enforcement mode
by commenting out the seccomp code — the PPID/socket/env checks work
standalone.

## Install

> **Warning:** Always keep an open root shell while installing.
> If the policy is wrong you can restore `/bin/shells/bash` to `/bin/bash`.

```bash
sudo mkdir -p /bin/shells
sudo mv /bin/bash /bin/shells/bash    # preserve the real shell
sudo cp shell-guard /bin/bash
sudo chmod 755 /bin/bash
```

Verify — open a **new** terminal, then:

```bash
grep shell-guard /var/log/auth.log
```

## Protecting the logs

shell-guard is only as good as the log trail it produces. If an attacker
gets root they can truncate syslog and erase all evidence. On the
original deployments this was paired with LIDS (`lidsadm`) to make log
files append-only at the kernel level — even root could not truncate them
without sealing/unsealing LIDS.

Without LIDS you can still harden the logs:

```bash
# ext2/3/4 append-only attribute — root can write but not truncate/delete
chattr +a /var/log/auth.log
chattr +a /var/log/syslog
```

This survives reboots but a root attacker can `chattr -a` to undo it.
For stronger guarantees, forward syslog to a remote host or use a
write-once/append-only storage backend.

## Uninstall

```bash
sudo mv /bin/shells/bash /bin/bash
```

## Files

| File | Purpose |
|------|---------|
| `shell-guard.c` | Main source — shell replacement with logging and policy enforcement |
| `config.yaml` | Human-editable policy (UIDs, GIDs, allowed paths, network ranges, syscalls) |
| `config.py` | Generates `config.h` from `config.yaml` (requires Python 3 + PyYAML) |

Note: `config.py` also generates `compartment-root-config.h` for the
parent project's `compartment-root` tool. This output is unused by
shell-guard itself.

## Requirements

- Linux with `/proc` filesystem
- Python 3 + PyYAML (config generation — needed before any compilation)
- libseccomp-dev (enforcement mode only, not needed for monitoring)
- gcc
