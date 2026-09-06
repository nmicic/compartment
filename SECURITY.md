<!-- Copyright (c) 2026 Nenad Micic <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.3.x   | Yes       |

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
  — 59 assertions when this was written, all passing on Ubuntu 24.04
  (kernel 6.8.0, gcc 13.3) and Ubuntu 26.04 (kernel 7.0.0, gcc 15.2).
  `tests/scripts/root.d/profile-trust-root.sh` adds 32 more for profile
  trust under root. Those counts move as suites are added: what is covered
  is whatever `tests/scripts/root.d/` contains, and the runner prints the
  totals it measured — run it rather than trusting this paragraph. The
  root suites are not part of `make test`, which stays rootless, and they
  are run by the `root-tests` CI job rather than by `make test-integration`
- The uid/gid map defaults to the identity map, so the user namespace
  provides a capability boundary but no uid isolation unless `uid-map` /
  `gid-map` are set (see HOWTO.md)
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
- **A Landlock rule for a path that does not exist grants nothing.** That is
  now a fatal error rather than a silent no-op; a trailing `?` on the path
  marks a rule optional. `--verbose` reports the number of rules actually
  installed, and `--dry-run` marks a path that is absent
- **The seccomp allow-list default action is `ERRNO(EPERM)`.** A denied
  syscall returns an error the program may mishandle rather than terminating
  it, and an attacker can probe the filter one call at a time because every
  denial returns cleanly. `seccomp-default kill` changes that to
  `SECCOMP_RET_KILL_PROCESS`; the default stays `errno` for compatibility
