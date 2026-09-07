<!-- Copyright (c) 2026 Nenad Micic <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.4.x   | Yes       |
| 1.3.x   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in Compartment, please report
it responsibly:

1. **Email:** nenad@micic.be
2. **Subject:** `[SECURITY] compartment: <brief description>`
3. **Include:** steps to reproduce, affected version, potential impact

Please do **not** open a public GitHub issue for security vulnerabilities.

## Response

- Acknowledgment within 72 hours
- Fix or mitigation within 30 days for confirmed vulnerabilities
- Credit in release notes (unless you prefer anonymity)

## Scope

In scope:
- Sandbox escapes (Landlock, seccomp, namespace bypasses)
- Privilege escalation via compartment-user or compartment-root
- Environment variable injection past the sanitize filter
- Profile parsing bugs that weaken the intended policy
- Shell-replacement mode bypasses

Out of scope:
- Bugs in the Linux kernel itself (report to kernel security team)
- Attacks requiring pre-existing root access on the host
- Denial of service against the sandboxed process (not a goal)

## Known Limitations

See the [README](README.md) disclaimer and [DESIGN.md](DESIGN.md) for
documented limitations, including:

- No formal verification or professional penetration testing
- Network egress bypass testing not yet automated for sandbox.sh HARD mode
- compartment-root is tested under real root by
  `tests/scripts/root.d/compartment-root.sh`, run together with the other
  root-only suites by `sudo make test-root`. It covers container start-up,
  `/dev` device nodes, the default seccomp deny-list, the capability and
  privilege drop, `no-new-privs`, `/proc` and `/sys` masking, namespace
  isolation and escape attempts (host mounts visible in the container,
  `/proc/1/root`, a pre-opened host directory fd, a setuid-root binary
  inside `rootdir`), the PID 1 reaper and signal handling, the network
  namespace, uid/gid mapping, cgroup path confinement and policy reporting
  — 101 assertions in 1.4.0, all passing on Ubuntu 24.04
  (kernel 6.8.0, gcc 13.3) and Ubuntu 26.04 (kernel 7.0.0, gcc 15.2).
  `tests/scripts/root.d/compartment-root-landlock.sh` adds 78 more for
  Landlock inside the container, the `exec` binary allow-list, the mount
  hardening (including the recursion difference between `rootdir-flags ro`
  and `mount-ro`), `rootdir` ownership, the `--netns` join and
  devpts/`/dev/shm`;
  `tests/scripts/root.d/limited-root.sh` adds 70 for the limited-root
  deployment over a real sshd login;
  `tests/scripts/root.d/profile-trust-root.sh` adds 48 for profile trust
  under root; `tests/scripts/root.d/sandbox-hard.sh` adds 10; 312 in total
  with the discovery smoke suite. Those counts
  move as suites are added: what is covered is whatever
  `tests/scripts/root.d/` contains, and the runner prints the totals it
  measured — run it rather than trusting this paragraph. The
  root suites are not part of `make test`, which stays rootless, and they
  are run by the `root-tests` CI job rather than by `make test-integration`
- The uid/gid map defaults to the identity map, so the user namespace
  provides a capability boundary but no uid isolation unless `uid-map` /
  `gid-map` are set (see HOWTO.md)
- **The limited-root deployment confines a *session*, not a uid.** Everything
  `examples/limited-root.conf` installs is per-task kernel state on the login,
  so it says nothing about a uid-0 process that was never in the session —
  that is what the auth-path seal profile is for — and it creates no uid
  boundary at all. The complete list of what it does not protect against is
  HOWTO.md, "Limited root over SSH" §8, which is the authoritative copy;
  condensed, it is:
  - uid 0 is still uid 0. The Landlock allow-list is the only thing between
    the account and the filesystem and DAC contributes nothing, so read policy
    is as load-bearing as write policy: `ro /etc` hands over `/etc/shadow`
  - the `mask` list is an enumeration of privileged unix sockets, and a
    distribution that adds one adds a hole. Landlock has no access right
    covering `connect(2)` to a pathname socket and seccomp cannot filter that
    call's address family (it is behind a pointer). The two real fixes — an
    allow-list `mask` (tmpfs over `/run`, needed paths bound back) and a BPF
    socket ACL — are both future work
  - a mask **neutralises** a write rather than refusing one: a non-directory
    mask is a `/dev/null` bind that inherits the profile's `rw /dev/null`, and
    a read-only remount does not cover device nodes. Mask read and connect
    surfaces; use a Landlock rule for write surfaces
  - a path cannot be both sealed and masked — the mask fails, and a failed
    mask refuses the login
  - below Landlock ABI v6 the session can signal processes outside its domain.
    A denial-of-service surface, not an escape, and the reason the seal
    profile must be loaded with `--pin` rather than run as a killable daemon
  - sshd stream-local forwarding and `internal-sftp` route around a
    login-shell confinement. Closed by a `Match User` block in `sshd_config`
    plus keeping the external `Subsystem sftp`, and by the seal that stops the
    setting being edited back — that is, by configuration and a seal, not by
    enforcement
  - an `actor=` identity is forgeable by an unconfined `CAP_SYS_RESOURCE` root
    (`PR_SET_MM_EXE_FILE`); it is closed inside the session by the capability
    drop. Outside it, close it with a no-actor seal where the path needs no
    writer, a future directive that arms the `PR_SET_MM` denial on its own, or
    `actor-strict` plus a static launcher
  - fds received over `SCM_RIGHTS` are not re-checked (no hook), and
    `memfd` + `fexecve` runs unnamed code — bounded, because it runs inside
    the same domain, filter and capability set
  - service management is unavailable while systemd's private socket and the
    system bus are masked. That is the point of the masks, and it is a real
    cost; a broker or the BPF socket ACL are the directions that would give it
    back safely
  - the account cannot run `compartment-root`, `sandbox.sh` HARD mode or this
    project's root suites, because `CAP_SYS_ADMIN` is dropped. A CI runner
    must not be a limited root
  - anything holding `CAP_BPF` outside the session owns the seals unless the
    policy was pinned with `--pin --self-protect`. The two controls compose
    and neither replaces the other
  - `lockdown=integrity` on the validation guests pre-closes `/dev/mem`,
    unsigned module loading and `kexec`; a stock host does not. Yama's
    `ptrace_scope` is not one-way below 3. And `/proc/1/environ` and
    `/proc/1/ns/*` are readable on 7.0 while denied on 6.8 — a kernel
    divergence, recorded so it is not mistaken for flake
- `compartment-root --netns NAME` joins the target namespace in the parent,
  before `clone()`, and drops `CLONE_NEWNET` so the container inherits it.
  One consequence: a network namespace owned by the initial user namespace
  cannot have a fresh `sysfs` mounted over it from inside the container, so
  `/sys` falls back to an empty read-only tmpfs. `--verbose` reports that
- The audit log is a record, not a restriction, and its confidentiality
  depends on where it is kept. The defaults are outside every path rule the
  built-in profiles grant, so a sandboxed process can neither read nor
  rewrite its own trail — except for the admin-provisioned
  `/var/lib/compartment/audit/<uid>` location, which the built-in `ai-agent`
  profile covers with `ro /var/lib` and is therefore *readable* (not
  writable or removable) from inside the sandbox. An operator-chosen
  `--audit-log` directory inside a granted `rw`/`rwx` path (for example
  `--audit-log /tmp/x` under `rw /tmp`) is fully reachable by the confined
  process. Both tools now print a warning when the audit directory resolves
  inside a granted `rw`/`rwx` rule, but it is a warning and not a refusal —
  the run continues
- **Landlock is additive.** The rights of every rule matching an ancestor of
  the path being opened are unioned, so a narrower rule never restricts a
  wider one. A `ro` rule inside a `rw`/`rwx` rule is now refused outright
  rather than silently doing nothing, but the underlying limitation stands:
  there is no way to carve an exception out of a granted subtree. Split the
  writable rules instead
- **Landlock network rules are TCP-only and allow-list-only.** `net-bind`,
  `net-connect` and `net-default deny` cover `bind(2)` and `connect(2)` on
  TCP and nothing else. UDP, unix sockets, netlink and raw sockets are
  untouched — a DNS query over UDP/53 works, and so would exfiltration over
  UDP. There is no `listen`/`accept` granularity and no per-address rule: a
  rule for port 443 allows port 443 on every address, IPv4 and IPv6 alike.
  There is no way to express "everything except port N"; a port deny-list,
  per-address rules and UDP all need a BPF LSM. Below Landlock ABI v4
  (Linux 6.7) both tools warn loudly and the port policy is **not** active
  while the filesystem rules still are
- **Landlock in compartment-root is opt-in.** It is off unless the policy
  says `landlock on` (or a `--ro`/`--rw`/`--rwx`/`--exec` flag is given), so
  a profile written for an earlier release keeps its previous behaviour and
  gets no filesystem confinement inside the container. A policy that carries
  path rules without turning Landlock on produces a warning, not an error
- **An `exec` allow-list is a property of the sandbox, not of a caller.**
  `exec /usr/bin/psql` restricts what may be executed anywhere in the
  sandbox, including by uid 0 inside it, but it cannot express "the
  supervisor may run psql and the request handler may not". It also keys on
  the file rather than the name, so a busybox-style multi-call binary cannot
  be split into applets, and it says nothing about shell builtins, which are
  not `execve` at all. The dynamic loader must be listed alongside the
  binaries — `execve(2)` opens the ELF interpreter with `FMODE_EXEC` —
  while shared libraries need only read access, because `ld.so` opens them
  read-only and Landlock has no mmap hook
- **An `exec` allow-list that lists the loader is a hardening layer, not an
  exec-target boundary.** Listing the dynamic loader is required for any
  dynamically linked policy (above), and it is also the way out of the
  allow-list: `/lib64/ld-linux-x86-64.so.2 /path/to/readable.elf` starts
  that file with no `execve(2)` of it and therefore no execute check on it.
  The loader opens the target `O_RDONLY` and maps it `PROT_EXEC`, and
  Landlock has no mmap hook — the same mechanism that lets a shared library
  load on read access alone. A compatible loadable ELF the sandbox can read
  is one it can run. Since `rw` grants read, any location that is both
  readable and writable — a data directory, `$HOME`, `/tmp` — is somewhere
  the sandbox can write an ELF and then start it, and any readable unlisted
  system binary can be started without writing anything. Measured on
  6.8.0-139 (ABI v4) and 7.0.0-31 (ABI v8), rootless and inside a
  `compartment-root` container: the direct `execve` returns `EACCES` and the
  loader runs the same file. Two shapes close the direct-loader bypass —
  static-link the allowed binaries and do not list the loader (an unlisted
  loader cannot be executed either, and a dynamically linked payload then
  cannot start at all), or grant no location that is both readable and
  writable and leave no readable ELF you did not intend to allow. A `noexec`
  mount over the writable areas (`mount-noexec` in a compartment-root
  profile) closes the writable-payload half of the bypass and only that
  half, measured on both kernels — the loader maps its target `PROT_EXEC`
  and the kernel refuses that on `MNT_NOEXEC` — while a readable unlisted
  ELF elsewhere is untouched by it. Closing the bypass buys an exec-target
  boundary and never a code-execution boundary: an allowed program that is
  compromised can still interpret a script, JIT, `dlopen` or
  `mmap(PROT_EXEC)` code of its own, none of which is an `execve` or an
  `open` for execute. A kernel-side exec confinement that checks the program
  actually being started, and so does not need the loader listed, is
  designed and not shipped. `HOWTO.md`, "`exec` on a file: a binary
  allow-list", fact 5, is the full statement;
  `rootless.d/landlock-rules.sh` and `root.d/compartment-root-landlock.sh`
  re-measure it on every run
- **`ro` on a directory grants execute on every file beneath it.** A
  directory rule is not a data grant: `ro /usr/lib` in an `exec` allow-list
  makes `/usr/lib/klibc/bin/true` — and every other executable a
  distribution leaves under `/usr/lib` — an `execve` target that no `exec`
  rule names. `examples/restricted-root.conf` grants the library and
  read-only-data directories with `rw` for exactly this reason: `rw` is read
  plus write and carries no execute right. What makes that write right inert
  is a `mount-ro` directive on each of those directories: `rootdir-flags ro`
  is applied **non-recursively**, on purpose, so that `/proc`, `/dev` and
  `/sys` stay usable, and a writable submount under a `rw` rule would
  otherwise stay writable. `mount-ro` remounts the subtree read-only through
  `mount_setattr(2)` with `AT_RECURSIVE` and covers the submounts too.
  `HOWTO.md` facts 2 and 3 state the rule; both Landlock suites witness it,
  and the root suite witnesses the recursion difference in both directions
- **A Landlock rule for a path that does not exist grants nothing.** That is
  now a fatal error rather than a silent no-op; a trailing `?` on the path
  marks a rule optional. `--verbose` reports the number of rules actually
  installed, and `--dry-run` marks a path that is absent
- **The seccomp allow-list default action is `ERRNO(EPERM)`.** A denied
  syscall returns an error the program may mishandle rather than terminating
  it, and an attacker can probe the filter one call at a time because every
  denial returns cleanly. `seccomp-default kill` changes that to
  `SECCOMP_RET_KILL_PROCESS`; the default stays `errno` for compatibility
- **`compartment-bpf`: `bpf_map_freeze()` is not map integrity, and
  `CAP_BPF` is the boundary.** Corrected in v0.8.0 — the previous text
  claimed the frozen seal maps were immune to mutation, and that was wrong
  in the reassuring direction. Freezing strips `FMODE_CAN_WRITE` on the
  **syscall** path only; it does not gate the **program** path. Measured on
  6.8.0-139 and 7.0.0-31: a caller holding `CAP_BPF` that obtains any fd to
  a frozen map — `BPF_MAP_GET_FD_BY_ID` with `BPF_F_RDONLY` is enough — can
  splice it into a BPF program of its own and update or delete entries from
  program context. Every compartment map is reachable that way, and wiping
  the seal entries removes policy with no unlink, no umount and **no audit
  event at all**. The load-bearing control is keeping `CAP_BPF` (and
  `CAP_SYS_ADMIN`) off every workload and every root login — systemd
  `CapabilityBoundingSet=`, or the limited-root deployment above — plus
  ingesting the `audit_event` ringbuf and alerting on enforcement stopping.
  `tests/bypass/26-frozen-map-honesty.sh` re-measures the gap on every run,
  so it cannot quietly return to prose
- **`compartment-bpf --pin --self-protect` closes that at the kernel, opt-in.**
  The flag gates `bpf_map_new_fd()` and the pin tree so only an authorised
  loader image can obtain a map fd — read-only included, because a read-only
  fd is a complete attack — unlink or rename a pin, over-mount the pin tree,
  or unmount the bpffs holding it. Measured on 6.8.0-139 and 7.0.0-31. It is
  off by default for three costs: it changes the upgrade ceremony (a successor
  loader at a different inode cannot `--unpin` what this one pinned unless it
  was named with `--authorize-loader` at pin time, and a stranded tree costs a
  reboot); a host-wide `bpftool map show` aborts at the first compartment map
  while it is on; and the gate costs of order 100–250 ns per map-fd creation,
  where the default build costs nothing. Six residuals with the flag on — a
  reboot with `lsm=` changed or a `kexec`; a map fd stolen from a *running*
  loader via `pidfd_getfd(2)`/`SCM_RIGHTS`, which never calls
  `bpf_map_new_fd()`; a stranded pin tree; the `bpftool map show` listing; an
  operator in a mount namespace that cannot see the pin tree; and `CAP_BPF`
  itself, which is the limited-root profile's job. Two adjacent upstream gaps
  sit beside them: `mount --move` of the pin bpffs has no LSM hook and orphans
  the pins while enforcement stays live, and the ED-11 unpin sentinel lives on
  `/run` rather than bpffs, so deleting it downgrades `--unpin` to the legacy
  path without removing enforcement. **The two controls compose and neither
  replaces the other.** `compartment-bpf/HOWTO.md` §3.6 is the operator path;
  the self-protection section of `compartment-bpf/LIMITATIONS.md` carries the
  full table
