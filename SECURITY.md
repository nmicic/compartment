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
