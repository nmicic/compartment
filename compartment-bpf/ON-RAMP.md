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

## Choosing a path

| You want                                              | Use      |
|-------------------------------------------------------|----------|
| Anchor evidence for a release claim                   | Path A   |
| Sweep kernel versions, isolate LSM activation         | Path B   |
| Reproduce the `make check` gate without managing a KVM VM | Path C   |
| Run on macOS                                          | None of the above. compartment-bpf needs a Linux host kernel with `CONFIG_BPF_LSM=y` to load BPF LSM hooks; use a remote Linux libvirt host. |
