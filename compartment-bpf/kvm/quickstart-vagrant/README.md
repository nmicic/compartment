# compartment-bpf — Path C quickstart (Vagrant + libvirt)

> **Status:** Path C is self-tested end-to-end on a reference Ubuntu
> 24.04 libvirt host. A representative warm-cache run measured 126 s
> from `vagrant up` start to `make smoke` exit 0, comfortably under the
> 300 s gate. Treat that number as indicative rather than guaranteed:
> local storage, CPU, and image cache state still matter.


This is the outside-operator on-ramp for `compartment-bpf`'s v0 smoke
gate. It stands up an Ubuntu 26.04 LTS (Resolute) VM via Vagrant
(libvirt provider), enables the BPF LSM in the guest's kernel cmdline,
and runs `sudo make smoke` against the synced repo.

Two friction-relevant facts up front:

- Docker is **not** an option for BPF LSM smoke. BPF LSM activation is
  a host-kernel boot property (`lsm=` cmdline), not a container
  capability.
- The Resolute cloud image used here matches what `kvm/ubuntu-resolute.sh`
  (Path A) bootstraps from. Path A is the production-grade fidelity
  path; this Path C exists for outside reviewers who just want
  "checkout repo, run vagrant up, see smoke pass".

For the higher-fidelity host-managed VM, see `kvm/ubuntu-resolute.sh`
(Path A). For a per-kernel virtme-ng matrix, see `kvm/quickstart-vng.md`
(Path B).

## The on-ramp at a glance

| # | Step | What it does |
|---|------|--------------|
| 0 | [Prerequisites](#prerequisites-one-time-on-the-operators-linux-host) | One-time host setup: apt deps, vagrant-libvirt plugin, libvirt group, pre-flight check. |
| 1 | [Step 0 — bootstrap](#step-0--one-time-bootstrap) | `./build-local-box.sh` (downloads + customises the Resolute cloud image; idempotent). |
| 2 | [Step 1 — first boot](#step-1--first-boot) | `vagrant up` (first provisioning pass writes the LSM cmdline drop-in; exits 99 by design). |
| 3 | [Step 2 — reload](#step-2--reload-to-pick-up-the-lsm-cmdline) | `vagrant reload --provision` (reboots, verifies `bpf` in `/sys/kernel/security/lsm`, runs `make smoke`). |

Each step has its own section below; the table is the canonical
headline and the sections are the detailed expansion.

## Prerequisites (one-time, on the operator's Linux host)

```
sudo apt install libvirt-daemon-system qemu-utils vagrant ovmf
sudo apt install libvirt-dev krb5-multidev build-essential ruby-dev
vagrant plugin install vagrant-libvirt        # builds the gem; needs the apt deps above
sudo adduser "$USER" libvirt                  # or rely on the libvirt-sock world-rw default
```

Then log out + back in (or run `newgrp libvirt`) so the new group
membership takes effect for the operator's shell — `vagrant up` will
otherwise fail to talk to `/var/run/libvirt/libvirt-sock`.

Known-good combination on Ubuntu 26.04 LTS for the reference run:
vagrant 2.4.9 + vagrant-libvirt 0.12.2 + libvirt 10.x.

Pre-flight readiness check (run before `build-local-box.sh`):

```
kvm-ok                                                       # CPU virt + KVM kernel module
test -r /usr/share/OVMF/OVMF_CODE_4M.ms.fd && echo OVMF ok   # apt: ovmf
virsh -c qemu:///system list --all                           # libvirt RPC socket reachable
```

All three must succeed. If `OVMF_CODE_4M.ms.fd` is missing, libvirt
emits a cryptic XML validation error rather than a friendly
prerequisite message.

This quickstart uses the **system-wide** libvirt storage pool named
`images` (default `/var/lib/libvirt/images/`). Volumes are allocated
by `libvirtd` running as root via the libvirt RPC socket; the
operator's user only needs access to that socket (granted by the
`libvirt` group, or the world-rw `libvirt-sock` default on
Ubuntu 24.04). No write access to `/var/lib/libvirt/images/` from
the operator's user is required. Set
`COMPARTMENT_BPF_VAGRANT_POOL=<name>` if a non-default pool is wanted.
(V-5b's earlier "user-owned pool" approach was retired by V-5c: the
captured-NVRAM-in-home-dir path landed outside libvirt-qemu's
AppArmor whitelist; the system pool sidesteps that class of bug.)

The quickstart needs roughly 8 GiB of free disk for the box plus the
working overlay.

## Step 0 — one-time bootstrap

```
cd kvm/quickstart-vagrant
./build-local-box.sh
```

`build-local-box.sh` downloads the upstream Resolute cloud image
(`resolute-server-cloudimg-amd64.img`, ≈ 820 MiB), verifies its SHA256
against the upstream `SHA256SUMS` published next to the image, packages
it as a vagrant-libvirt box named `compartment/resolute`, and ensures
the user-owned libvirt pool exists. Re-running with the same image is
a no-op.

See `INVENTORY.md` for the exact box source, packages installed by
provisioning, and the configuration the provisioner writes.

## Step 1 — first boot

```
cd kvm/quickstart-vagrant
vagrant up
```

The first `vagrant up` boots the guest, runs `provision.sh`, writes the
GRUB drop-in that adds `bpf` to the active LSM list, and **exits
non-zero** with a `BPF LSM not yet in /sys/kernel/security/lsm` message.
This is expected: the running kernel has not seen the new cmdline yet.
`provision.sh` prints a distinctive "FIRST-PASS provisioning" banner
at the top of the first pass to make this visually obvious — if you
see that banner followed by exit 99, you are on the happy path.

## Step 2 — reload to pick up the LSM cmdline

```
vagrant reload --provision
```

The reload reboots the guest. The second provisioning pass verifies
that `/sys/kernel/security/lsm` now contains `bpf`, copies the synced
repo into a build directory inside the guest, and runs `make smoke`.
The end of provisioning prints `[provision] smoke OK`.

If the second pass still does not see `bpf` in
`/sys/kernel/security/lsm`, the provisioner fails loudly rather than
silently continuing.

## Timing

`build-local-box.sh` is one-time and **not part of the timing gate**:
the upstream image is ≈ 820 MiB so download time dominates and is
network-dependent.

Two timings matter for V-5 evidence:

- **Cold cache** — fresh clone, no cached box, no cached image. Runs
  the bootstrap plus the first two steps. Includes the image download.
  Several hundred seconds is normal; this is not a gate.
- **Warm cache** — box already added, image already cached. Run with
  `vagrant destroy -f` first to clear the working VM, then time
  end-to-end:

  ```
  vagrant destroy -f
  time (vagrant up && vagrant reload --provision)
  ```

  V-5's science gate is **warm-cache ≤ 300 s** from the start of the
  `vagrant up` to the `make smoke` exit-0 inside the second
  provisioning pass.

Reference transcripts live under
`tests/results/v5-on-ramp-20260512T192129Z-fabe97a/path-c/`. Run
`ls tests/results/` if the tree contains a newer on-ramp capture.

## Failure remediation

### "this box is corrupted" / partial download mid-fetch

If `build-local-box.sh` is interrupted mid-download, or if the box
itself is reported corrupted by `vagrant up`, the supported remediation
is:

```
vagrant box remove --force compartment/resolute
./build-local-box.sh
```

**Do not** hand-edit `/var/lib/libvirt/images/` or the user-owned pool
directory to salvage partial files. Vagrant's internal box metadata
desynchronizes from a hand-edited libvirt pool and produces a
"this box is corrupted" loop that wastes thirty minutes of debugging.
Clean removal plus re-fetch is the only supported path.

### `vagrant up` fails with "Connection to libvirt failed"

Check that the libvirt daemon is running and that
`/var/run/libvirt/libvirt-sock` exists. Either add yourself to the
`libvirt` group or rely on the world-rw default permissions. Run
`virsh -c qemu:///system list --all` as your user — if that fails, the
quickstart cannot start.

### `vagrant up` complains about the storage pool

The Vagrantfile (`Vagrantfile:209`) targets the system-default libvirt
pool `images` (`/var/lib/libvirt/images/`). It is allocated by
`libvirtd` and managed by the `libvirt-daemon-system` package; the
operator's user does not own it. First verify it exists and is
running:

```
virsh -c qemu:///system pool-list --all
virsh -c qemu:///system pool-info images
```

If the pool is missing or inactive, ask your distro's libvirt
maintainer how to (re)create the system `images` pool — do NOT
`pool-destroy` it; other libvirt VMs on this host share it. Override
the target pool name with `COMPARTMENT_BPF_VAGRANT_POOL=<name>` if a
dedicated pool is desired. (V-5b's retired user-owned-pool variant
was named `compartment-bpf-vagrant` and lived at
`~/.vagrant-libvirt-pool/`; V-5c moved to the system pool to sidestep
an AppArmor whitelist issue.)

### Provisioning exits with code 99

That is the expected first-pass exit (see Step 1). Run
`vagrant reload --provision`.

### `bpf` not in `/sys/kernel/security/lsm` after reload

Check the guest's kernel cmdline (`vagrant ssh -c 'cat /proc/cmdline'`).
If the `lsm=` argument is missing, the GRUB drop-in was not picked up
by `update-grub` — re-run `vagrant provision` (which is idempotent) and
then `vagrant reload --provision` again. If the problem persists, fall
back to Path A.

## Tearing down

```
vagrant destroy -f
```

To fully clean up, also remove the box and the per-VM volumes that
`vagrant up` allocated inside the system `images` pool:

```
vagrant box remove --force compartment/resolute
# Optional, only if you are the sole user of the system images pool:
#   virsh -c qemu:///system vol-list  images
#   virsh -c qemu:///system vol-delete --pool images <volume-name>
rm -rf ~/.cache/compartment-bpf-vagrant
```

Do NOT `virsh pool-destroy images` — the system `images` pool is
shared with other libvirt VMs on this host. (V-5b's retired
user-owned-pool variant was named `compartment-bpf-vagrant` and lived
at `~/.vagrant-libvirt-pool/`; if a legacy variant is present, that
pool may still be safely undefined.)

## When to prefer Path A instead

Path A (`kvm/ubuntu-resolute.sh`) is the fidelity fallback. Prefer it
when:

- You are not on a Linux libvirt host (Path C cannot run from macOS).
- You need the long-lived VM that Path A provisions
  (autostart, dedicated MAC and IP, coexists with sibling VMs).
- A reproducibility transcript from Path A is the one cited by the
  V-1 / V-7 evidence chain.
