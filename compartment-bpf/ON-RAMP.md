# compartment-bpf — outside-operator on-ramp

If you are reading this in a fresh clone and want to confirm that
`compartment-bpf` builds, loads, and seals files on your machine,
pick one of the three paths below. They differ in fidelity, setup
cost, and what they prove.

For the design rationale, start with `README.md` and `HOWTO.md`.

## Path A — full-fidelity KVM VM (production-grade)

`kvm/ubuntu-resolute.sh` autoinstalls an Ubuntu 26.04 LTS (Resolute)
KVM VM with the BPF LSM activated at boot and the build toolchain
preinstalled. After it finishes, the VM has a persistent IP and you
can `ssh` in and run `sudo make check` against a clone of the repo
inside the guest. (`make smoke` is a faster subset but does not
exercise chmod / the legacy `inode_setattr` path, so the runbooks
gate on `make check`.) Long-lived; autostarts.

This is the path cited by V-1 / V-2 / V-3 / V-4 / V-4b / V-7 evidence
chains. If you need the fidelity that those tags claim, use this
path.

Costs: ~10 min first run (cloud-image download, autoinstall, reboot
for LSM cmdline). About 16 GiB disk for the qcow2 plus base image.

## Path B — virtme-ng kernel matrix (fast iteration)

`kvm/quickstart-vng.md` shows how to boot a chosen mainline kernel
under virtme-ng with `bpf` added to the active LSM list via
`--append lsm=…,bpf`. Use it for kernel-version sweeps and for
isolating "is the LSM hook even present on this kernel" questions.

Costs: ~150 MB cached per kernel version; sub-minute boots once
cached.

Caveats: virtme-ng exposes the host filesystem via 9p. `(dev, ino)`
keys are 9p-virtualized, so smoke results that depend on real on-disk
inode behavior should be re-confirmed under Path A or Path C. The
sibling project (`~/compartment`) found that some Landlock filesystem
tests are not faithful through 9p; the same class of caveat applies
to compartment-bpf's seal-path tests.

## Path C — Vagrant + libvirt quickstart (SELF-TESTED, warm-cache 126 s)

`kvm/quickstart-vagrant/` packages the same upstream Resolute cloud
image as a vagrant-libvirt box and gives you `vagrant up` plus
`vagrant reload --provision` to land in the same `make check` gate. Use it
when you want the production-grade kernel but do not want to manage
a long-lived libvirt domain.

Costs: ~820 MiB cloud-image download (cached) and a one-time
`build-local-box.sh` that runs `virt-customize` to add the
`vagrant` user, SSH key, sudo NOPASSWD, a systemd-networkd DHCP
drop-in, and a cloud-init datasource-disable. Total bootstrap is
about 25 s of host time once the image is cached.

Caveats: Requires a Linux libvirt host (macOS is not supported);
needs `vagrant-libvirt` 0.12+, `libguestfs-tools`, and one-time
operator setup documented in `kvm/quickstart-vagrant/README.md`.

**Current status:** Path C is tested end-to-end on Ubuntu 24.04 Noble.
Warm-cache measurement: **126 s** (`vagrant up` start → `make smoke`
exit 0), under the 300 s budget by 174 s.

## Running the suites on a fresh VM

These are the exact commands a clean bring-up needs, in order, with the
tallies to expect as of this branch (measured on Ubuntu 24.04, kernel
6.8.0-139-generic, 2 vCPU / 8 GiB).

```sh
# 0. On the HOST: check the bring-up prerequisites without touching anything
bash kvm/ubuntu-noble.sh --check        # or ubuntu-resolute.sh --check
bash kvm/ubuntu-noble.sh                # real bring-up; ~10 min, reboots once

# 1. Copy the tree in. Exclude .git; the guest only needs the sources.
rsync -a --exclude=.git/ <checkout>/compartment-bpf/ <user>@<vm>:~/compartment-bpf/

# 2. Build. Run every remote command through a login shell so PATH is sane.
ssh <user>@<vm> "bash -lc 'cd ~/compartment-bpf && make vmlinux.h && make'"

# 3. The gates.
ssh <user>@<vm> "bash -lc 'cd ~/compartment-bpf && sudo make smoke'"
ssh <user>@<vm> "bash -lc 'cd ~/compartment-bpf && sudo make check'"
ssh <user>@<vm> "bash -lc 'cd ~/compartment-bpf && sudo make check-release'"
ssh <user>@<vm> "bash -lc 'cd ~/compartment-bpf && sudo make check-stability-quick'"
```

| command | wall time | expected |
|---|---|---|
| `make vmlinux.h && make` | ~5 s | exit 0, zero warnings |
| `sudo make smoke` | ~10 s | `smoke ok` |
| `sudo make check` | 3-6 min | exit 0; see the per-target tallies below |
| `sudo make check-release` | 3-6 min (it re-runs the whole of `make check`) | `[check-release] PASS ...` |
| `sudo make check-stability-quick` | ~2 min | `stability summary: pass=8 fail=0 skip=0` |

Headline tallies inside `make check`:

| target | expected |
|---|---|
| `check-coverage-static` | selftest 11/11, then "every surface is witnessed or explicitly exempted" |
| `check-mesh` | 3284 trials: 3277 PASS / 0 FAIL / 0 KNOWN-GAP / 7 SKIP |
| `check-bypass` | 44 PASS / 0 FAIL / 0 SKIP over 44 scripts |
| `check-strict-launch` | PASS=17 FAIL=0 |
| `check-observe` | PASS=26 FAIL=0 SKIP=0 with AIDE installed; PASS=21 FAIL=0 SKIP=1 without (T12) |
| `check-dir-matrix` | 40/40 PASS |
| `check-wrapper` | PASS=21 FAIL=0 |
| `check-profiles` | 20/20 profiles parsed cleanly |
| `check-profile-e2e` | 2 SKIP (aide, postgres not installed) |

Two suites are NOT part of `make check` and have preconditions of their
own:

* `tests/bypass/run-all.sh` is a **host-side driver** — it rsyncs to a VM
  and ssh-runs each witness there. Inside a guest use
  `tests/bypass/run-all.sh --local` (or just `make check-bypass`, which
  calls `run-local.sh`). `--check` validates the driver's preconditions
  and `--help` documents every environment knob.
* `make check-stability-quick` needs the mesh stubs and test tools; the
  target now builds them. It drives `tests/mesh/run-mesh.sh` concurrently
  with 64 pin/unpin cycles, so both take the PIN_ROOT test mutex
  (`tests/lib-pinlock.sh`).

### Skip vocabulary

`make check` is developer-friendly and skips suites the host cannot run.
`make check-release` is the release gate: it FAILS on any SKIP line that
does not match a documented entry in `tests/release-skip-allowlist.txt`.
An unrecognised skip is a failure, because that is exactly how two
permanently-dead bypass witnesses read as green for several releases.

The skips a fully provisioned VM still legitimately produces:

| skip | why |
|---|---|
| `SKIP aide-e2e: aide not installed` | `aide` is not in the kvm scripts' package list |
| `SKIP postgres-e2e: pg_lsclusters not present ...` | `postgresql-common` likewise |
| `SKIP  T12: AIDE not present ...` | same, observe suite |
| `[mesh] ME-22 btrfs/overlay SKIP: anon_bdev ...` | refused by the HIGH-1 loader gate on purpose; see LIMITATIONS.md |
| `[mesh] ME-22 nfs SKIP: out-of-scope for v0` | documented scope |
| `missing fixture: /etc/chrony/chrony.conf` | Noble's cloud image uses systemd-timesyncd |

Everything else — `needs root`, `bpf not in active LSM`, `daemon not
built`, `sealprobe not built`, `bpftool not available`, `fixtures
missing`, or any wording nobody has written down — fails
`make check-release`. Installing `aide` and `postgresql-common` in the
guest closes the four package-driven skips.

## Choosing a path

| You want                                              | Use      |
|-------------------------------------------------------|----------|
| Anchor evidence for a release claim                   | Path A   |
| Sweep kernel versions, isolate LSM activation         | Path B   |
| Reproduce the `make check` gate without managing a KVM VM | Path C   |
| Run on macOS                                          | None of the above. compartment-bpf needs a Linux host kernel with `CONFIG_BPF_LSM=y` to load BPF LSM hooks; use a remote Linux libvirt host. |
