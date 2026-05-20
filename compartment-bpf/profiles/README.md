<!-- Copyright (c) 2026 Nenad Micic -->
<!-- SPDX-License-Identifier: NONE -->

# Top-10 daemon hardening profiles

POC `compartment-bpf` profiles for the ten most security-relevant
default-installed daemons on Ubuntu 26.04 LTS (Resolute) server.

This is **interpretation A** — binary + config integrity using existing
seal flags (`no-unlink`, `no-rename`, `no-write`, `no-chmod`). Exec-domain
blocking (per-cgroup `SEAL_NO_EXEC`) is **interpretation B**, tracked in
Out of scope here.

The actor-allowlist profiles (AIDE, postgres) under
`profiles/aide.conf` and `profiles/postgres.conf` are a different
class of profile — they pair the seal flags above with an
`actor=NAME` clause (ABI v0.3). See
`HOWTO.md` §2 for the operator-facing walkthrough.

## Reference Environment

- **Ubuntu image:** 26.04 LTS (Resolute)
- **Kernel:** 7.0.0-15-generic
- **LSM state:** `bpf` present in `/sys/kernel/security/lsm`

## Selection

Daemon scoring axes:

1. **(D)** part of the default Ubuntu server install
2. **(R)** actively running on stock Resolute (no extra packages installed)
3. **(A)** high attack surface — network-facing, privileged, IPC-exposed,
   or with a CVE history that would benefit from binary + config integrity
   protection.

The brief's initial guess listed `NetworkManager`, `snapd`, and
`accounts-daemon`. Reality on a fresh Resolute server image:
**NetworkManager is not installed** (Resolute server uses
`systemd-networkd`); **snapd has only oneshot units active**
(`snapd.apparmor`, `snapd.seeded`) — the long-running `snapd.service` is
not enabled by default on this minimal image; **accounts-daemon is not
installed**. Substituted with three running, network-exposed,
default-installed alternatives: `systemd-networkd`, `systemd-resolved`,
`chronyd`. `udisks2` was dropped in favor of `systemd-logind` — both run,
but `systemd-logind` is closer to PAM and session-state surface, which is
a higher-value integrity target.

| #  | Daemon              | Unit                   | D | R | A | Why                                   |
|----|---------------------|------------------------|---|---|---|---------------------------------------|
|  1 | `sshd`              | `ssh.service`          | ✓ | ✓ | H | network-facing, root login            |
|  2 | `systemd-journald`  | `systemd-journald`     | ✓ | ✓ | H | central logging integrity             |
|  3 | `dbus-daemon`       | `dbus.service`         | ✓ | ✓ | H | system message bus, IPC pivot         |
|  4 | `polkitd`           | `polkit.service`       | ✓ | ✓ | H | auth arbiter (PwnKit lineage)         |
|  5 | `cron`              | `cron.service`         | ✓ | ✓ | M | runs scheduled jobs as root           |
|  6 | `rsyslogd`          | `rsyslog.service`      | ✓ | ✓ | M | log ingestion, remote-syslog surface  |
|  7 | `systemd-networkd`  | `systemd-networkd`     | ✓ | ✓ | M | privileged network management         |
|  8 | `systemd-resolved`  | `systemd-resolved`     | ✓ | ✓ | M | DNS surface, parses untrusted RRs     |
|  9 | `systemd-logind`    | `systemd-logind`       | ✓ | ✓ | M | session/seat manager, PAM-adjacent    |
| 10 | `chronyd`           | `chrony.service`       | ✓ | ✓ | M | NTP/NTS network surface               |

## Cocktail rule

Default seals applied per profile:

- **Daemon binary:** `no-unlink no-rename no-write no-chmod`
  → blocks the four common tamper paths an attacker uses to substitute
    a malicious binary or strip caps from the existing one.
- **Main config file/dir:** `no-unlink no-rename no-write no-chmod`
  → blocks silent policy edits. Where a daemon writes runtime state under
    its config directory, only the leaf config files are sealed, not the
    directory.
- **Runtime state files** (logs, sockets, runtime dirs in `/run`,
  `/var/lib/<daemon>`): NOT sealed. Documented per profile.

## Profile files

Each `profiles/<daemon>.conf` carries a manifest header:

- daemon name + version on Resolute
- systemd unit + ExecStart binary
- main config path(s)
- runtime state path(s) — what is intentionally NOT sealed and why
- liveness check command — minimum signal that the daemon is operational
  under enforcement

## Smoke runners

Two runners live under `tests/`. Both run on the Resolute VM in
`/root/compartment-bpf-profiles` and require root:

### Per-profile gate — `tests/profile-smoke.sh`

```sh
# on the VM, from /root/compartment-bpf-profiles
sudo bash tests/profile-smoke.sh
```

For each profile, it:

1. restarts the daemon to a known baseline,
2. loads the profile via `./compartment-bpf --pin profiles/<daemon>.conf`,
3. waits up to 10 s for `[run] compartment-bpf live`,
4. restarts the daemon under enforcement,
5. runs the liveness check after a 3-second settle,
6. positive control: confirms a write to a sealed *config* file is
   denied at the LSM layer (we use a config file rather than the running
   binary because the kernel already rejects writes to a live binary
   with `ETXTBSY` *before* the LSM hook fires — we record `ETXTBSY` on
   the binary as defence-in-depth, not as the LSM probe),
7. scans the audit ringbuf for any unexpected DENY events,
8. SIGINTs `compartment-bpf`, removes pinned links, restarts the daemon
   to a clean state.

Output: `tests/profile-smoke-results-<TS>.csv`.

PASS bar: 10/10 profiles keep the daemon operational, 10/10 deny the
positive control via LSM, and 0 unexpected DENY events.

### Aggregate gate — `tests/aggregate-smoke.sh`

```sh
sudo bash tests/aggregate-smoke.sh
```

Loads `profiles/all-daemons.conf` (concatenation of all 10 profiles —
48 seal directives) and asserts every daemon stays operational
*simultaneously*. This is the production-like run.

Output: `tests/aggregate-smoke-results-<TS>.csv`.

`profiles/all-daemons.conf` is regenerated from the per-daemon files by
`tests/build-all-daemons-conf.sh`. Re-run that after editing any
per-daemon profile to keep the aggregate in sync (the parser supports
only the `seal` directive — there is no `include`).

## Results

Reference runs from RUN 20260430-profiles-top10:

- `tests/profile-smoke-results-20260430T044525Z.csv` — 10/10 PASS
  per-profile, 0/10 unexpected denies, 10/10 binaries ETXTBSY-locked.
- `tests/aggregate-smoke-results-20260430T044629Z.csv` — 10/10 PASS
  under aggregate enforcement, 0 unexpected denies.

One recurring lesson from these profiles: when sealing a systemd unit's
`.conf`, also seal the parallel `/usr/lib/systemd/<x>.conf.d/` vendor
drop-in dir — not just `/etc/systemd/<x>.conf.d/`.

## Actor-bound profiles (ABI v0.3, exec-domain)

Two shipped examples pair the v0 seal flags with the exec-domain
actor allowlist:

- **`profiles/aide.conf`** — `actor aide = /usr/sbin/aide` plus
  `actor=aide` clauses on `/var/lib/aide/aide.db{,.new}`. `aide
  --check` and `aide --update` continue to work; root with any
  other binary cannot rewrite the baseline. Regression witness:
  `tests/profile-e2e/aide.sh` (ED-9).
- **`profiles/postgres.conf`** — `actor postgres = /usr/lib/postgresql/
  18/bin/postgres` plus `actor=postgres` on the data dir and
  PG_VERSION sentinel. Substitutes for the SPEC's oracle example


  `tests/profile-e2e/postgres.sh` (ED-10).

The actor= clause is parser-checked at load time
(`COMPARTMENT_MAX_ACTORS_PER_SEAL = 4`, no forward references,
strict mode requires every actor binary to be `full`-sealed at its
declared path). See HOWTO.md §2 for the syntax reference and worked
examples.

## Limits

- **Does not block exec.** A malicious binary placed *somewhere else*
  on disk, then exec'd in place of the daemon, is out of scope. That
  needs `SEAL_NO_EXEC` + per-cgroup scoping (interpretation B).
- **Single-host POC.** No fleet rollout, no monitoring integration.
- **Resolute-specific paths.** Path layout is from a Resolute cloud
  image; older releases may diverge (e.g. `dbus-daemon` lived in
  `/usr/lib` on some derivatives).
