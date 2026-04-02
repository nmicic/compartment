<!-- Copyright (c) 2026 Nenad Mićić <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# HOWTO: Syscall Profiling with syscall.py

Generate compartment-user security profiles by observing what a
program actually needs at runtime.

## Quick Start

```bash
cd extra/

# 1. Check: is the default ai-agent profile safe for your program?
python3 syscall.py check --profile ai-agent -- ./my-program

# 2. If safe: done, use the default
compartment-user -- ./my-program

# 3. If not safe: generate a custom profile
python3 syscall.py profile -o my-program.conf -- ./my-program
compartment-user --profile my-program.conf -- ./my-program
```

## Two Modes: Deny vs Allow

### Deny-list (default — safe, won't break program)

Blocks dangerous syscalls (ptrace, mount, reboot, etc.) that the
program does NOT use. Everything else is allowed.

```bash
python3 syscall.py profile -- ls /tmp
```

Output:
```conf
inherit ai-agent
block acct
block bpf
block chroot
block mount
block ptrace
# ... (only dangerous syscalls the program never called)
```

**When to use:** general-purpose sandboxing. Low risk of breakage.

### Allow-list (strict — may break program)

ONLY permits the exact syscalls observed during profiling. Everything
else returns EPERM.

```bash
python3 syscall.py profile --seccomp-mode allow -- ls /tmp
```

Output:
```conf
seccomp-mode allowlist
allow 0   # read
allow 1   # write
allow 2   # open
allow 3   # close
# ... (only syscalls actually observed)
```

**When to use:** high-security isolation where you've profiled all
code paths. Beware: rare paths (error handling, signal handling,
timezone reload) may use syscalls not seen during profiling.

### With environment allow-list

Strip all env vars except those the program actually needs:

```bash
python3 syscall.py profile --seccomp-mode allow --with-env -- ./my-program
```

Adds to the profile:
```conf
env-mode allowlist
env-allow PATH
env-allow HOME
env-allow TERM
# ...
```

## Workflow: Profiling a Long-Running Program

AI agents run for hours. Use `--duration` to capture a representative sample:

```bash
# Profile for 5 minutes, following child processes
python3 syscall.py profile --seccomp-mode allow --duration 300 \
    -o claude.conf -- claude --model claude-opus-4-6

# Review what was observed
python3 syscall.py trace --duration 300 -- claude --model claude-opus-4-6

# Check if the ai-agent default would have been fine
python3 syscall.py check --profile ai-agent --duration 300 -- claude
```

**Tip:** Run the profile step multiple times with different workloads
(coding task, file search, web fetch) and merge the results. A syscall
used in ANY run should be in the allow-list.

## Workflow: Static + Dynamic Combined

Static analysis finds syscalls in the binary without running it.
Dynamic analysis finds what actually gets called at runtime.
Use both:

```bash
# Static: finds syscalls in the ELF binary (fast, incomplete)
python3 syscall.py static /usr/bin/ls

# Dynamic: finds actual runtime syscalls (complete, slower)
python3 syscall.py trace -- ls /tmp

# Static misses libc wrappers (open → openat etc.)
# Dynamic misses rare code paths
# Combine both for best coverage
```

## Workflow: Checking Before Deploying

Before running a program under compartment-user in production:

```bash
# Step 1: Will the default profile break anything?
python3 syscall.py check --profile ai-agent -- ./my-program
# Output: "OK" or "BROKEN: 2 syscall(s) would be blocked"

# Step 2: If broken, generate a custom profile
python3 syscall.py profile -o custom.conf -- ./my-program

# Step 3: Install the profile
mkdir -p ~/.config/compartment
cp custom.conf ~/.config/compartment/my-program.conf

# Step 4: Use it
compartment-user --profile my-program -- ./my-program
```

## Deploying Profiles

Profiles are searched in order:
1. `~/.config/compartment/<name>.conf` (user override)
2. `/etc/compartment/<name>.conf` (system default)

```bash
# User profile
mkdir -p ~/.config/compartment
python3 syscall.py profile -m allow --with-env \
    -o ~/.config/compartment/claude.conf -- claude

# System profile (as root)
python3 syscall.py profile -m allow --with-env \
    -o /etc/compartment/claude.conf -- claude

# Use by name (no path needed)
compartment-user --profile claude -- claude
```

## Profile Inheritance

Custom profiles can inherit from base profiles:

```conf
# ~/.config/compartment/my-agent.conf
inherit ai-agent          # start with ai-agent defaults
rw /data/my-project       # add access to project data
block ptrace              # extra: block ptrace too
env-deny GITHUB_TOKEN     # strip token from env
```

For allow-list mode, don't inherit (it would add deny-list rules that
conflict with the allow-list):

```conf
# Full allow-list profile (no inherit)
seccomp-mode allowlist
allow 0   # read
allow 1   # write
...

env-mode allowlist
env-allow PATH
env-allow HOME
...

rw /data/my-project
ro /usr
ro /lib
```

## Comparing Deny vs Allow

```bash
# Generate both, compare
python3 syscall.py profile -- ls /tmp > deny.conf
python3 syscall.py profile --seccomp-mode allow -- ls /tmp > allow.conf

# deny.conf: blocks 37 dangerous syscalls (inherits ai-agent)
# allow.conf: permits only 23 observed syscalls (everything else denied)
#
# allow.conf blocks ~277 more syscalls than deny.conf
# but may break if a rare code path uses an unobserved syscall
```

## Troubleshooting

### Program crashes under allow-list profile

A syscall used in a rare code path wasn't observed during profiling.

```bash
# Run under strace to find the missing syscall
strace -f ./my-program 2>&1 | grep EPERM
# or
strace -c -f ./my-program   # shows summary of all syscalls

# Add the missing syscall to the profile
echo "allow 435  # clone3" >> ~/.config/compartment/my-program.conf
```

### "unknown syscall" in profile

syscall.py emits numeric IDs (`allow 59  # execve`).
compartment-user accepts both names (135 entries covering all
common and dangerous syscalls) and numbers. If you see "unknown
syscall", the value is neither a known name nor a valid number.

### strace not available

```bash
apt install strace    # Debian/Ubuntu
yum install strace    # RHEL/CentOS
```

For static analysis (no strace needed):
```bash
pip install pyelftools capstone
python3 syscall.py static /path/to/binary
```
