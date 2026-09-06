<!-- Copyright (c) 2026 Nenad Mićić <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# HOWTO: Syscall Profiling with syscall.py

Generate compartment-user security profiles by observing what a
program actually needs at runtime.

## Quick Start

```bash
# 1. Check: is the default ai-agent profile safe for your program?
python3 tools/syscall.py check --profile ai-agent -- ./my-program

# 2. If safe: done, use the default
./compartment-user -- ./my-program

# 3. If not safe: generate a custom profile
python3 tools/syscall.py profile -o my-program.conf -- ./my-program
./compartment-user --profile ./my-program.conf -- ./my-program
```

A profile argument without a `/` is treated as a *name* and gets `.conf`
appended, so pass `./my-program.conf` (or an absolute path) when you mean a
file in the current directory.

Generated profiles are self-contained: they carry their own Landlock path
rules, syscall rules and env rules, and load without any other file being
present. Read one before you use it — profiling only sees the code paths
that actually ran.

## Two Modes: Deny vs Allow

### Deny-list (default — safe, won't break program)

Blocks dangerous syscalls (ptrace, mount, reboot, etc.) that the
program never used successfully. Everything else is allowed.

```bash
python3 syscall.py profile -- ls /tmp
```

Output:
```conf
ro /etc
ro /usr/bin
ro /usr/lib
block acct
block bpf
block chroot
block mount
block ptrace
# ... (only dangerous syscalls the program never called successfully)
```

"Successfully" matters. A dangerous syscall the program *attempted* and that
failed with `EPERM` is still blocked, and the profile records why:

```conf
# Attempted but never succeeded — blocked anyway, since
# a call that already fails loses nothing by being denied:
#   mount (1 attempts, 0 succeeded)
```

Anything the program really does use is left open, and named:

```conf
# NEEDED (not blocked — the program really uses these):
#   unshare (3 successful calls)
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
allow read
allow write
allow openat
allow close
# ... (only syscalls actually observed)
```

Syscalls are emitted by name whenever `compartment.h`'s `syscall_table[]`
knows the name, because names are portable across architectures. Anything
the table does not name falls back to a raw number with the name in a
trailing comment (`allow 435  # clone3`); those numbers are valid only on
the architecture the profile was generated on, and the profile says so.

**When to use:** high-security isolation where you've profiled all
code paths. Beware: rare paths (error handling, signal handling,
timezone reload) may use syscalls not seen during profiling.

### With environment allow-list

Add a conservative env-allow list to the profile:

```bash
python3 tools/syscall.py profile --seccomp-mode allow --with-env -- ./my-program
```

Adds to the profile:
```conf
env-mode allowlist
env-allow PATH
env-allow HOME
env-allow TERM
# ...
```

> **Note:** `--with-env` generates a conservative default list (PATH,
> HOME, TERM, LANG, XDG vars, plus any proxy variables currently set).
> It does NOT dynamically discover which env vars the program reads —
> `getenv(3)` makes no syscall, so there is nothing to trace. Review and
> trim the list for your deployment.
>
> It never emits an `env-allow` line for a variable whose name looks like a
> credential (`*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, ...). An
> `env-allow` line re-admits a variable into a sandbox whose whole job is
> to strip it, so if your program genuinely needs one, add it by hand and
> take the decision consciously.

## Workflow: Profiling a Long-Running Program

AI agents run for hours. Use `--duration` to capture a representative sample:

```bash
# Profile for 5 minutes, following child processes
python3 syscall.py profile --seccomp-mode allow --duration 300 \
    -o my-agent.conf -- my-agent --model some-model

# Review what was observed
python3 syscall.py trace --duration 300 -- my-agent --model some-model

# Check if the ai-agent default would have been fine
python3 syscall.py check --profile ai-agent --duration 300 -- my-agent
```

> **Important:** A single profiling run will miss rare code paths.
> Run the profile step multiple times with different workloads
> (coding task, file search, web fetch, error conditions, network
> timeouts) and merge the results. A syscall used in ANY run must
> be in the allow-list. This is the same lesson from years of
> manual strace work: rare paths only appear under specific
> conditions, and a profile that misses them will break in
> production at the worst possible time.

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

A `--profile` argument containing a `/` is loaded directly as a file. A
bare name is searched for in order:
1. `~/.config/compartment/<name>.conf` (user override)
2. `/etc/compartment/<name>.conf` (system default)

```bash
# User profile
mkdir -p ~/.config/compartment
python3 syscall.py profile -m allow --with-env \
    -o ~/.config/compartment/my-agent.conf -- my-agent

# System profile (as root)
python3 syscall.py profile -m allow --with-env \
    -o /etc/compartment/my-agent.conf -- my-agent

# Use by name (no path needed)
compartment-user --profile my-agent -- my-agent
```

## Profile Inheritance

Custom profiles can inherit from base profiles. `inherit NAME` resolves to
a *file*: first `NAME.conf` beside the inheriting profile, then the standard
search paths. It never resolves to compartment-user's compiled-in `ai-agent`
policy, so `inherit ai-agent` only works when an `ai-agent.conf` file exists
in one of those places (`examples/ai-agent.conf` is such a file, but
`make install` does not deploy it). Generated profiles are self-contained
for exactly this reason.

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
allow read
allow write
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

# deny.conf: blocks the dangerous syscalls the program never used
# allow.conf: permits only the syscalls actually observed
#
# allow.conf denies far more than deny.conf, but breaks if a rare code
# path uses a syscall that profiling never saw.
#
# Both carry the same Landlock path rules, derived from the paths the
# program opened during the trace.
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
echo "allow clone3" >> ~/.config/compartment/my-program.conf
```

### "unknown syscall" in profile

compartment-user accepts both names and numbers. The names it knows are
the ones in `compartment.h`'s `syscall_table[]` — `compartment-user
--verify` prints the current count. syscall.py reads that same table and
emits a name when there is one, a number when there is not. If you see
"unknown syscall", the value is neither a known name nor a valid number.

Note that no inline comment is allowed after a *name*: the parser takes
everything after the directive as the value, so `block ptrace  # why`
looks for a syscall literally called `ptrace  # why`. Numbers are the one
exception (`allow 435  # clone3` parses). Put comments on their own line.

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
