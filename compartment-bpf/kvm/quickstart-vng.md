# compartment-bpf — Path B quickstart (virtme-ng)

This is the lightweight kernel-matrix path: boot a chosen mainline
kernel inside a virtme-ng (vng) VM, with the BPF LSM activated, and
exercise compartment-bpf against the live kernel.

Path B is the fastest way to answer questions of the shape "does the
loader still attach on kernel X" or "is `/sys/kernel/security/lsm` what
we think it is on this build". It is not a full-fidelity stand-in for
the smoke gate — see "9p caveats" below.

For the full smoke gate, see `kvm/ubuntu-resolute.sh` (Path A) or
`kvm/quickstart-vagrant/README.md` (Path C).

## Prerequisites

- `virtme-ng` ≥ 1.40 (`pip install virtme-ng` or `apt install virtme-ng`).
- Read access to a kernel image. The first `vng --run v6.8` downloads
  a pre-built mainline kernel into `~/.cache/virtme-ng/` (~150 MB);
  subsequent runs reuse the cache.
- `/dev/kvm` writable for fast boots; without it, vng falls back to
  TCG emulation (slower but functional).

If `/dev/kvm` is not writable, `vng` either errors out or runs with
`--disable-kvm`. The commands below stay correct either way.

## Boot Resolute-style kernel with BPF LSM active

vng kernels boot with the distro's default `lsm=` cmdline, which does
**not** include `bpf`. Append it explicitly:

```
vng --run v6.8 \
    --append "lsm=lockdown,capability,landlock,yama,apparmor,bpf" \
    --exec 'cat /sys/kernel/security/lsm'
```

Expected output: a single line containing the LSMs in load order,
ending in `bpf`. That confirms the kernel has `CONFIG_BPF_LSM=y` and
the BPF LSM hook is wired up. The mainline v6.8 kernel bundled with
vng has `CONFIG_BPF_LSM=y` and was used to capture the self-test
transcript shipped with this V-5 evidence
(`tests/results/v5-on-ramp-20260512T192129Z-fabe97a/path-b/` — run
`ls tests/results/` to find the most recent on-ramp directory if
this one has been rotated out).

To verify a different version, replace `v6.8` with one of the cached
versions in `~/.cache/virtme-ng/` or any version `vng` can resolve.

## Build + smoke (with 9p caveats)

**Install build deps on the host first.** vng's `/usr` overlay is
ephemeral; you cannot `apt install` inside the guest and expect it to
persist. Run on the host before invoking `vng --run`:

```
sudo apt install clang libbpf-dev linux-tools-generic build-essential make
```

The host repo is then exposed to the vng guest at
`/home/$USER/<repo>` via 9p, so `make` runs unchanged inside the
guest. Build artifacts land back in the host working tree because the
overlay is read-write.

```
vng --run v6.8 \
    --append "lsm=lockdown,capability,landlock,yama,apparmor,bpf" \
    --rw --pwd \
    --exec 'make compartment-bpf && sudo make smoke'
```

If you skipped the host-side apt install step above, the in-guest
`make compartment-bpf` step will fail with a missing-`clang` /
missing-`bpf/bpf.h` error rather than a friendly prerequisite
message.

## 9p caveats

These are inherent to the virtme-ng host-filesystem-via-9p model.
Each one matters for what `make smoke` actually proves under Path B:

- **`(dev, ino)` keys are 9p-virtualized.** compartment-bpf's policy
  map is keyed by `(dev, ino)`. Under 9p, the inode numbers the guest
  sees are mapped from the host's inodes through the 9p server, with
  no guarantee that they remain stable across reboots or across
  `--run` invocations. A seal loaded against one boot's inode keys
  may not match the same files on the next boot. For correctness
  testing this is fine (the policy load reads the *current* inode);
  for soak/persistence testing it is not.

- **Rename and link semantics travel through 9p.** Rename-across-dir
  and hardlink tests rely on the kernel's directory operations
  reaching the underlying filesystem. Under 9p, those operations are
  forwarded over the 9p protocol; if the 9p server squashes a class
  of operation, the kernel-level LSM hook may not see it. The sibling
  project (`~/compartment`) found that Landlock filesystem rules
  cannot be exercised through 9p for this reason. compartment-bpf's
  BPF LSM hooks tend to fire correctly on 9p-presented files because
  they hook the kernel-side syscall path, not the storage layer — but
  the same class of risk applies. Treat any "smoke PASS" obtained
  under vng as evidence the loader is wired up, not as proof that
  end-to-end seal enforcement matches a real disk.

- **Truncate (kernel ≥ 6.5) and ioctl (kernel ≥ 6.8) hooks need their
  LSM hook present.** The hook-availability probe inside the loader
  uses uname-based hints in the loader itself. vng
  reports the exact mainline version, so a probe under `--run v5.15`
  will fail loudly if compartment-bpf is asking for a hook that does
  not exist in that kernel.

- **`sudo` requires the host user to be a sudoer.** vng inherits the
  host's identity through its overlay; if the host user cannot
  `sudo`, neither can the guest. For the smoke gate this means either
  use a sudo-enabled host user or invoke vng with `--user root`.

## When to prefer Path A or Path C

- **Path A (`kvm/ubuntu-resolute.sh`)** if the question is "does the
  daemon hold up against a real disk, real cloud-init, real boot
  order, real Resolute kernel". The transcripts cited by V-1 / V-7
  came from Path A.
- **Path C (`kvm/quickstart-vagrant/`)** if you are an outside
  operator who just wants `vagrant up && sudo make smoke` against a
  Resolute guest without managing a long-lived KVM domain.
- **Path B (this doc)** for fast kernel-version sweeps, for
  reproducing kernel-cmdline edge cases, and for verifying the LSM
  activation step in isolation.

## Self-test transcript

A reference self-test transcript lives at
`tests/results/v5-on-ramp-20260512T192129Z-fabe97a/path-b/` (run
`ls tests/results/` to find the most recent on-ramp directory if the
tree contains a newer one). It exercises the
`/sys/kernel/security/lsm` activation under `--append lsm=…,bpf` on
vng's v6.8 kernel and captures the `/proc/cmdline` proving the boot
arg was honored. It does not run `make smoke` end-to-end because the
host where it was captured did not have the C-side toolchain
installed (clang / libbpf-dev). An operator with the toolchain
installed can run the
`make smoke` invocation above directly.
