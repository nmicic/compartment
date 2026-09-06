# Running the compartment-bpf test suites

<!-- SPDX-License-Identifier: Apache-2.0 -->

Every suite follows the same PASS / FAIL / SKIP convention and the same
exit-code convention: **0** all executed witnesses passed, **1** at least
one failed, **77** the environment cannot host the suite (a clean skip).

Everything below assumes a guest with `bpf` in
`/sys/kernel/security/lsm`, root, and a built tree
(`make vmlinux.h && make`). Run remote commands through a login shell
(`ssh <vm> "bash -lc '...'"`) — a non-login, non-interactive shell does
not read `/etc/profile.d`, and `sudo` replaces `PATH` with its
`secure_path`.

## The two entry points

| command | what it is | on a dev host |
|---|---|---|
| `sudo make check` | every gate; developer-friendly | suites needing root/BPF SKIP cleanly, exit 0 |
| `sudo make check-release` | the release gate | FAILS if the host cannot exercise enforcement, and FAILS on any SKIP that is not in `tests/release-skip-allowlist.txt` |

## Per-suite invocation

| suite | command | expected (identical on 6.8.0-139 and 7.0.0-31) |
|---|---|---|
| static coverage | `make check-coverage-static` | selftest 11/11, then "every surface is witnessed or explicitly exempted" |
| smoke | `sudo make smoke` | `smoke ok` |
| mesh | `sudo tests/mesh/run-mesh.sh` | 3284 trials: 3277 PASS / 0 FAIL / 0 KNOWN-GAP / 7 SKIP |
| bypass (in place) | `sudo tests/bypass/run-local.sh` | `44 PASS / 0 FAIL / 0 SKIP over 44 scripts` |
| bypass (host driver) | `tests/bypass/run-all.sh` | see below — it is NOT an in-guest command |
| strict-launch | `sudo tests/strict-launch/run.sh` | `PASS=17 FAIL=0` |
| observe | `sudo tests/observe/run.sh` | `PASS=21 FAIL=0 SKIP=1` (T12: AIDE absent) |
| dir matrix | `sudo make check-dir-matrix` | `40/40 PASS` |
| actor wrapper | `sudo make check-wrapper` | `Total PASS=21 FAIL=0` |
| stability (quick) | `sudo make check-stability-quick` | `stability summary: pass=8 fail=0 skip=0` |
| stability (full) | `sudo make check-stability` | 1024 cycles, ~45-60 min |
| bpf(2) overhead | `sudo make bench-bpf-syscall` | three legs (no policy / `--pin` / `--pin --self-protect`); flag off within noise of baseline, flag on ~+130-145 ns per `BPF_MAP_GET_FD_BY_ID` |

### `tests/bypass/run-all.sh` is a host-side driver

It sources `tests/lib.sh` (`VM_HOST`, `VM_USER=root`,
`VM_WORKDIR=/root/compartment-bpf`), rsyncs the tree to that host and
ssh-runs every witness there. Its `VM_HOST` default points at one
specific lab VM, so an un-overridden run from a different guest silently
targets the wrong machine.

```sh
tests/bypass/run-all.sh --help    # every knob and precondition
tests/bypass/run-all.sh --check   # preflight only
tests/bypass/run-all.sh --local   # run the same witnesses HERE
```

Driver preconditions, all checked up front with a precise error:

1. `ssh $VM_USER@$VM_HOST` works non-interactively (key auth, BatchMode).
   Inside a guest that means root ssh-to-self, which no image ships:

   ```sh
   sudo ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519
   sudo sh -c 'cat /root/.ssh/id_ed25519.pub >> /root/.ssh/authorized_keys'
   ```

2. `$VM_WORKDIR` is a real directory, **not** the tree being synced from
   and **not** a symlink into it — `vm_sync_repo` runs
   `rsync -az --delete`, which would delete the sources mid-copy:

   ```sh
   sudo cp -a ~/compartment-bpf /root/compartment-bpf
   ```

3. The VM can build (`make vmlinux.h && make && make test-tools`).

### `tests/mesh/run-mesh.sh` standalone

The harness chowns `tests/mesh/sequences` to root itself (ME-21 refuses
to source a `.seq` file that is not root-owned) and builds the eight mesh
stubs if they are missing. Both used to be the caller's job, known only
to the `check-mesh` Makefile target, so a direct `sudo
tests/mesh/run-mesh.sh` on a freshly rsync'd tree either FATAL'd every
sequence or died with a bare "missing stub".

## Skip vocabulary

`make check-release` FAILS on any SKIP line that does not match an entry
in `tests/release-skip-allowlist.txt`. That file is the authoritative
list; the categories are:

* **tallies** — `SKIP: 7`, `... 0 SKIP over 44 scripts`, `Summary:
  PASS=.. SKIP=..`. Counts, not verdicts; the lines they summarise are
  scanned individually.
* **optional packages** — `aide not installed`, `pg_lsclusters not
  present`, `AIDE not present`. Installing `aide` and
  `postgresql-common` in the guest closes all four.
* **documented out-of-scope** — `ME-22 btrfs/overlay SKIP: anon_bdev`
  (refused by the HIGH-1 loader gate by design), `ME-22 nfs SKIP:
  out-of-scope for v0`.
* **image-dependent fixtures** — `missing fixture:
  /etc/chrony/chrony.conf` (Noble uses systemd-timesyncd).

Anything else is a failure. `needs root`, `bpf not in active LSM`,
`daemon not built`, `sealprobe not built`, `bpftool not available`,
`fixtures missing`, or any wording nobody has written down, all fail the
release gate — including the two skips that used to hide dead witnesses:

```
SKIP BX-11-ld-preload-strict: spike fixtures missing (...)
SKIP BX-12-abi-size-gate: bpftool map create failed (rc=255; ...)
```

## Fixtures: never `/usr/bin/true`

`tests/lib-realbin.sh` provides `realbin_noop` / `realbin_false`, which
build a minimal static ELF and hand back its path. Use them anywhere a
test needs "a small binary": on distros shipping uutils coreutils
(Ubuntu 26.04) `/usr/bin/true` is a symlink, the loader refuses a
symlink leaf, and `readlink -f` lands on the shared multi-call binary —
so sealing it would seal every coreutils applet on the box.
