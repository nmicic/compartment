# Path C inventory

Every change the quickstart makes, with rationale. The point of this
file is that a reviewer can decide "is anything happening that I would
not want?" without having to chase commands across the box-build
script, the Vagrantfile, and the in-guest provisioner.

> **Status:** Path C is self-tested end-to-end. A representative
> warm-cache run measured **126 s** from `vagrant up` start to
> `make smoke` exit 0, under the 300 s budget by 174 s.

## Box source

| Field           | Value |
|-----------------|-------|
| Vagrant box name      | `compartment/resolute` |
| Provider              | `libvirt` |
| Upstream image URL    | `https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-amd64.img` |
| Upstream SHA256 source| `https://cloud-images.ubuntu.com/resolute/current/SHA256SUMS` |
| Format                | qcow2 |
| Ubuntu release        | 26.04 LTS (Resolute) |
| Guest arch            | amd64 |

Canonical's `current/` symlink rolls forward when a new build of the
26.04 cloud image is published. `build-local-box.sh` fetches the
matching `SHA256SUMS` at the same moment as the image, so the resulting
local box is bit-identical to whatever upstream advertised at build
time. To pin to a date-stamped build, edit `CLOUD_IMG_URL` and
`SHA256SUMS_URL` in `build-local-box.sh` to the `releases/<release>/`
path.

The SHA observed when this quickstart was written (kept here for
audit, not as a pin):

```
8ed228c9f08a50122fa72307623d9f88d9209ba26e7e849edd584fa675e34863  resolute-server-cloudimg-amd64.img
```

## Host artifacts created by `build-local-box.sh`

| Path                                | Purpose |
|-------------------------------------|---------|
| `~/.cache/compartment-bpf-vagrant/` | Cached image, SHA256SUMS, staging dir, packaged `.box` tarball, plus throwaway-VM qcow2 overlays produced by `bootstrap-nvram.sh`. Safe to delete; rebuild on next run. |
| `~/.config/libvirt/qemu/nvram/`     | User-mode libvirt session URI's nvram dir, where `bootstrap-nvram.sh`'s throwaway VM writes its per-VM OVMF varstore. Cleaned up on script exit. |
| libvirt system pool `images`        | **The pool the Vagrantfile uses (V-5c canonical).** Default `/var/lib/libvirt/images/`. `vagrant box add` uploads the customised box.img here; `vagrant up` snapshots it as the per-VM disk. Operator access is via the libvirt RPC socket, not direct filesystem writes. Override the pool name with `COMPARTMENT_BPF_VAGRANT_POOL`. (V-5b's user-owned-pool variant was retired — see README "Prerequisites" for rationale.) |
| `~/.vagrant.d/boxes/compartment-VAGRANTSLASH-resolute/` | Vagrant box store, populated by `vagrant box add`. |
| `kvm/quickstart-vagrant/resolute-nvram-template.fd` | OVMF NVRAM template captured by `bootstrap-nvram.sh` (intermediate artefact from the V-5b approach). **No longer load-bearing under V-5c:** the Vagrantfile NVRAM template is now the stock SecureBoot-enrolled OVMF varstore (next row). The captured-template path is retained as a fingerprint witness for the M4 box-staleness check; pool upload happens for historical/diagnostic reasons. Not committed to git. |
| `/var/lib/libvirt/images/compartment-bpf-resolute-nvram-template.fd` | Pool-resident copy of the captured OVMF NVRAM template, uploaded by `bootstrap-nvram.sh` via `virsh vol-upload`. **Not** the path the Vagrantfile references — that role is now held by `/usr/share/OVMF/OVMF_VARS_4M.ms.fd` (next row), per the V-5c pivot. Kept as the M4 build-rebuild trigger: its presence is the host-side witness that bootstrap-nvram.sh has run successfully for this box version, and `build-local-box.sh` re-runs bootstrap-nvram when this volume is absent. |
| `/usr/share/OVMF/OVMF_VARS_4M.ms.fd` (Vagrantfile `NVRAM_TEMPLATE`) | **Load-bearing under V-5c.** Stock SecureBoot-enrolled OVMF varstore shipped by the host's `ovmf` package, referenced by the Vagrantfile as `<nvram template='…'>` via a monkey-patch on `to_xml`. Combined with a `<boot order='1'/>` injection on the disk, this gets QEMU to forward a bootindex hint that lets OVMF synthesise a Boot#### for the cloud image's `\EFI\BOOT\fbx64.efi` → shim → grub → kernel chain on first boot. Warm-cache reboots then land directly on the registered `Boot0002 'Ubuntu'` entry. |

## Box Staleness Fingerprint

`build-local-box.sh` early-exits if the named box `compartment/resolute`
is already registered with the libvirt provider — but only after the
box passes a V-5c fingerprint check. The check guards against a
pre-V-5c stale box silently surviving a quickstart refresh.

| Check | Source of truth | Pass condition |
|-------|-----------------|----------------|
| `metadata.json` parseable as JSON | `~/.vagrant.d/boxes/compartment-VAGRANTSLASH-resolute/<version>/<provider>/metadata.json` | `json.load()` succeeds; `virtual_size` key is present and integer. |
| Disk virtual size ≥ 3 GiB | Same `metadata.json` `virtual_size` field. V-5c builds at 8 GiB; pre-V-5c JSON-parser bug wrote `virtual_size: 1`. | `virtual_size ≥ 3` (generous floor — anything ≤ 2 GiB cannot host the Resolute cloud image's `\EFI\BOOT\BOOTX64.EFI` past byte offset 1.03 GiB). |

If either check fails, `build-local-box.sh` does
`vagrant box remove --force --provider libvirt compartment/resolute`
and falls through to the full rebuild path (image download
verification, virt-resize, virt-customize, repackage, re-add). The
removal is intentional: keeping the broken box around would let a
later `vagrant up` boot a 1 GiB-truncated disk and reproduce V-5's
"BdsDxe: No bootable option" failure.

## Image customisations applied by `build-local-box.sh` (one-time, on the host)

The Resolute upstream cloud image is not a vagrant-libvirt box out of
the box — it has no `vagrant` user, no SSH key, no working DHCP path
without a cloud-init datasource that vagrant-libvirt does not inject.
`build-local-box.sh` calls `virt-customize` on the staged image with
the following ordered changes:

| Step                        | What it does | Why |
|-----------------------------|--------------|-----|
| `useradd vagrant -G sudo`   | Adds `vagrant` user to sudo group. | Vagrant SSH expects `vagrant@guest`. |
| `--ssh-inject vagrant:…/vagrant.pub.rsa` | Authorises the standard vagrant insecure public key. | Standard vagrant insecure-keypair flow. |
| `/etc/sudoers.d/vagrant`    | `vagrant ALL=(ALL) NOPASSWD:ALL`, mode 0440. | Provisioner runs `sudo` without prompt. |
| `systemctl enable ssh.service` | Make sure SSH is up after boot. | Resolute image enables it already; idempotent. |
| `/etc/systemd/network/01-compartment-bpf-dhcp.network` | DHCP on any `e*` interface. | Cloud-init's network module is disabled (next row); systemd-networkd consumes the `.network` directly. |
| `/etc/cloud/cloud.cfg.d/99-compartment-bpf.cfg` | `datasource_list: [ None ]`, `network: {config: disabled}`. | Stops cloud-init from spending tens of seconds probing for a datasource that vagrant-libvirt does not provide. |
| `systemctl mask cloud-init-*.service` | Belt-and-braces on top of the `cloud-init.disabled` file. | Some Ubuntu builds re-enable cloud-init from drop-ins. |
| `truncate /etc/machine-id` + remove `/var/lib/dbus/machine-id` | Force a fresh machine-id on first boot. | Cloud-image hygiene — the upstream baked machine-id otherwise collides between multiple guests. |

## Guest packages installed by `provision.sh`

| Package              | Why |
|----------------------|-----|
| `clang`              | Compiles the BPF program in the loader. |
| `libbpf-dev`         | Headers + library for `bpf_object__open_skeleton` etc. |
| `linux-tools-generic`| Provides `bpftool` on Resolute. |
| `make`               | Drives `make smoke`. |
| `build-essential`    | gcc + headers for the user-space loader. |
| `bpftool`            | Pinned dependency for some smoke probes. (Most Resolute images already include it via `linux-tools-generic`; named explicitly so a future minimal image still pulls it.) |

The provisioner uses `dpkg-query -W` to check for each package before
calling `apt-get install`, so re-running provision is cheap on a
warm guest.

## Guest configuration written by `provision.sh`

### `/etc/default/grub.d/99-compartment-bpf.cfg`

```
GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lsm=lockdown,capability,landlock,yama,apparmor,bpf"
```

Adds `bpf` to the active LSM list. Matches the
`LSM_LIST` value in `kvm/ubuntu-resolute.sh` so Path A and Path C
produce the same `/sys/kernel/security/lsm` content. The provisioner
calls `update-grub` after writing the drop-in and exits with code 99
on the first pass to surface the `vagrant reload --provision` step
explicitly rather than relying on Vagrant magic.

### Build directory `/root/compartment-bpf/`

The synced `/repo` mount is rsynced read-only by convention; the
provisioner copies it under `/root/compartment-bpf/` before running
`make smoke` so the synced source on the host stays untouched.

## What the Vagrantfile asks libvirt for

| Setting               | Value | Why |
|-----------------------|-------|-----|
| `lv.driver`           | `kvm` | Hardware acceleration; matches Path A. |
| `lv.memory`           | 4096  | Smoke build is light; 4 GiB keeps kernel headers + BTF + clang happy. Override via `COMPARTMENT_BPF_VAGRANT_MEM`. |
| `lv.cpus`             | 4     | Override via `COMPARTMENT_BPF_VAGRANT_CPUS`. |
| `lv.cpu_mode`         | `host-passthrough` | Surface every host CPU feature; matches Path A. |
| `lv.storage_pool_name`| `images` | System-default libvirt pool (`/var/lib/libvirt/images/`), allocated by `libvirtd` as root; the operator's user only needs access to the libvirt RPC socket. Override with `COMPARTMENT_BPF_VAGRANT_POOL`. (V-5b's retired user-owned-pool variant was named `compartment-bpf-vagrant`.) |
| `lv.qemu_use_session` | `false` | System URI; matches the pool URI. |

Default synced folder (`/vagrant`) is disabled because the Vagrantfile
mounts the host repo at `/repo` via rsync — the synced-folder default
would otherwise pin `/vagrant` to the `kvm/quickstart-vagrant/`
subdirectory, which is the wrong root.

## What this quickstart deliberately does NOT do

- It does **not** modify `kvm/ubuntu-resolute*.sh`. Those are the
  Path A scripts; this quickstart treats them as separate host-managed
  helpers.
- It does **not** pre-bake the GRUB drop-in into the box image.
  Provisioning explicitly demonstrates the LSM activation step so the
  reviewer sees the kernel cmdline change rather than having to trust
  a pre-built image.
- It does **not** install Docker or any container runtime. BPF LSM
  testing is a host-kernel-boot property; containerization is out of
  scope.
- It does **not** expose ports out of the guest. The smoke gate is
  self-contained in the provisioner.
