#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# bootstrap-nvram.sh — one-time generation of resolute-nvram-template.fd
#
# STATUS: drafted under V-5b's E.6 direction; the captured NVRAM file is
# produced cleanly (this script runs end-to-end, captures
# /home/$USER/.config/libvirt/qemu/nvram/<throwaway>_VARS.fd into
# the OUT_TEMPLATE path), BUT using that NVRAM as the template= for
# the real Path C `vagrant up` still leaves OVMF at "BdsDxe: No
# bootable option or device was found" on first boot. The captured
# Boot0002 'Ubuntu' entry written by fbx64 inside the throwaway VM is
# apparently not equivalent to what the real Path C VM needs — root
# cause still being investigated, see V-5c follow-up sidebar.
#
# Why this exists in concept: Ubuntu Noble's OVMF Edk2 BdsDxe build
# does not perform the removable-media fallback to
# \EFI\BOOT\BOOTX64.EFI when the NVRAM varstore has no Boot#### entries
# (verified on `ovmf 2024.02-2ubuntu0.8`). Path A boots only because
# its first boot ran the cloud
# image's `\EFI\BOOT\fbx64.efi` fallback installer which wrote the Boot
# entry into NVRAM. This script tries to replicate that bootstrap inside
# a disposable libvirt domain whose PCI topology exactly matches what
# vagrant-libvirt generates for `kvm/quickstart-vagrant/`.
#
# Inputs:
#   $1 — path to the customised box.img produced by build-local-box.sh
#   $2 — output path for the captured NVRAM template
#
# Implementation: uses qemu:///session (user-mode libvirt) so the
# per-VM NVRAM lands in ~/.config/libvirt/qemu/nvram/ where the caller
# can read it without sudo. The system-URI nvram dir is mode 0755
# owned by libvirt-qemu with new files at 0600, which would require
# sudo or operator-side chmod to read.
#
# Requires:
#   * `virsh`, `qemu-img`, `qemu-system-x86_64` in PATH.
#   * `/usr/share/OVMF/OVMF_CODE_4M.ms.fd` and
#     `/usr/share/OVMF/OVMF_VARS_4M.ms.fd` (ovmf package).
#   * Read access to the BOX_IMG path (caller's responsibility — if
#     the box is under /var/lib/libvirt/images/ as managed by
#     vagrant-libvirt, the caller must be in the kvm group AND the
#     image file must be group-readable; chmod g+r applied by the
#     operator works).
#
# Exit status: 0 on success (NVRAM captured), non-zero on failure.

set -euo pipefail

BOX_IMG="${1:?box.img path required}"
OUT_TEMPLATE="${2:?output template path required}"

OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.ms.fd"
OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
[ -r "${OVMF_CODE}" ] && [ -r "${OVMF_VARS}" ] \
  || { echo "bootstrap-nvram: stock OVMF files not readable (need ovmf package)" >&2; exit 1; }

# Use qemu:///session (user-mode libvirt) so the per-VM NVRAM lands in
# ~/.config/libvirt/qemu/nvram/ where the caller can read it without
# sudo. The system URI's nvram dir is mode 0755 owned by libvirt-qemu
# with new files at 0600 — unreadable to the caller. virt-aa-helper
# AppArmor rules are also skipped in session mode, simplifying the
# disk-source plumbing.
URI='qemu:///session'

VM_NAME="compartment-bpf-vagrant-nvramboot-$$"
OVERLAY_DIR="${HOME}/.cache/compartment-bpf-vagrant"
OVERLAY="${OVERLAY_DIR}/${VM_NAME}.qcow2"
mkdir -p "${OVERLAY_DIR}"
LIBVIRT_NVRAM="${HOME}/.config/libvirt/qemu/nvram/${VM_NAME}_VARS.fd"
mkdir -p "$(dirname "${LIBVIRT_NVRAM}")"

log() { printf '[bootstrap-nvram] %s\n' "$*" >&2; }

cleanup() {
  rc=$?
  log "cleanup (rc=${rc}): tearing down ${VM_NAME}"
  virsh -c "${URI}" destroy        "${VM_NAME}" >/dev/null 2>&1 || true
  virsh -c "${URI}" undefine --nvram "${VM_NAME}" >/dev/null 2>&1 || true
  rm -f "${OVERLAY}" "${LIBVIRT_NVRAM}" 2>/dev/null || true
  exit $rc
}
trap cleanup EXIT

log "creating overlay ${OVERLAY} backed by ${BOX_IMG}"
qemu-img create -f qcow2 -F qcow2 -b "${BOX_IMG}" "${OVERLAY}" >/dev/null

cat > "/tmp/${VM_NAME}.xml" <<EOF
<domain type='kvm'>
  <name>${VM_NAME}</name>
  <memory unit='MiB'>2048</memory>
  <vcpu placement='static'>2</vcpu>
  <os>
    <type arch='x86_64' machine='pc-q35-noble'>hvm</type>
    <loader readonly='yes' secure='yes' type='pflash'>${OVMF_CODE}</loader>
    <nvram template='${OVMF_VARS}'>${LIBVIRT_NVRAM}</nvram>
    <bootmenu enable='no'/>
  </os>
  <features>
    <acpi/>
    <apic/>
    <smm state='on'/>
  </features>
  <cpu mode='host-passthrough'/>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <!--
      pcie-root-port chassis/port/address triples are chosen to match
      precisely what vagrant-libvirt emits for the real Path C domain
      (verified via virsh dumpxml quickstart-vagrant_default). UEFI
      device paths in NVRAM Boot#### entries encode the PCI hop using
      Pci(slot,func) of each parent bridge — making slot/func match
      here is what ensures the captured NVRAM's device paths resolve
      against the real Path C VM later.
    -->
    <controller type='pci' index='0' model='pcie-root'/>
    <controller type='pci' index='1' model='pcie-root-port'>
      <target chassis='1' port='0x10'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0' multifunction='on'/>
    </controller>
    <controller type='pci' index='2' model='pcie-root-port'>
      <target chassis='2' port='0x11'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x1'/>
    </controller>
    <controller type='pci' index='3' model='pcie-root-port'>
      <target chassis='3' port='0x12'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x2'/>
    </controller>
    <controller type='pci' index='4' model='pcie-root-port'>
      <target chassis='4' port='0x13'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x3'/>
    </controller>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='${OVERLAY}'/>
      <target dev='vda' bus='virtio'/>
      <address type='pci' domain='0x0000' bus='0x02' slot='0x00' function='0x0'/>
      <boot order='1'/>
    </disk>
    <serial type='pty'><target type='isa-serial' port='0'/></serial>
    <console type='pty'><target type='serial' port='0'/></console>
    <graphics type='vnc' port='-1' listen='127.0.0.1'/>
    <video><model type='cirrus'/></video>
  </devices>
</domain>
EOF

log "defining and starting ${VM_NAME}"
virsh -c "${URI}" define "/tmp/${VM_NAME}.xml" >/dev/null
rm -f "/tmp/${VM_NAME}.xml"
virsh -c "${URI}" start "${VM_NAME}" >/dev/null

# Wait long enough for the first-boot dance to complete:
#   1. OVMF tries QEMU bootindex-1 device → loads \EFI\BOOT\BOOTX64.EFI
#   2. Shim sees no Boot#### entry for itself, loads fbx64.efi
#   3. fbx64 reads \EFI\<*>\BOOTX64.CSV, writes Boot#### + BootOrder,
#      calls ResetSystem
#   4. Second boot: OVMF finds the new Boot####, loads shim → grub →
#      kernel → systemd start
#   5. Cloud-init is disabled in our box, so systemd just settles and
#      waits. The NVRAM is fully written by the time fbx64 finishes
#      step 3; everything after that is decoration. 45 s is plenty.
log "waiting 45 s for fbx64 + first-boot NVRAM write"
sleep 45

log "shutting down ${VM_NAME}"
virsh -c "${URI}" destroy "${VM_NAME}" >/dev/null 2>&1 || true

# libvirt holds an exclusive write handle to the NVRAM file while the
# domain is running; once destroyed and the qemu process exits the file
# is closed and the contents are durable.
sleep 2

if [ ! -r "${LIBVIRT_NVRAM}" ]; then
  echo "[bootstrap-nvram] cannot read ${LIBVIRT_NVRAM} — session-URI libvirt should have written it user-owned; this is unexpected." >&2
  exit 2
fi

log "captured NVRAM (${LIBVIRT_NVRAM}) → ${OUT_TEMPLATE}"
cp "${LIBVIRT_NVRAM}" "${OUT_TEMPLATE}"
chmod 0644 "${OUT_TEMPLATE}"
log "captured to ${OUT_TEMPLATE} ($(wc -c < "${OUT_TEMPLATE}") bytes)"

# Upload into the libvirt `images` system pool so the libvirt-qemu
# AppArmor abstraction's `/var/lib/libvirt/images/** rwk` rule applies
# to the template (V-5c finding: libvirtd silently falls back to seeding
# from the stock OVMF_VARS_4M template when the operator's template=
# path is outside that whitelist, e.g. anywhere under /home/<operator>/,
# producing an empty-looking varstore at boot and OVMF's "No bootable
# option" panic). qemu:///system + vol-upload routes the write through
# libvirtd as root, so the operator doesn't need direct write to
# /var/lib/libvirt/images/.
POOL="${COMPARTMENT_BPF_VAGRANT_POOL:-images}"
VOL_NAME="compartment-bpf-resolute-nvram-template.fd"
log "uploading template into libvirt pool '${POOL}' as ${VOL_NAME}"
# Re-create the volume so we always have a fresh copy. vol-create-as
# tolerates an existing volume of matching size; we delete first to
# avoid stale-content edge cases.
virsh -c qemu:///system vol-delete --pool "${POOL}" "${VOL_NAME}" >/dev/null 2>&1 || true
TPL_SIZE=$(stat -c%s "${OUT_TEMPLATE}")
virsh -c qemu:///system vol-create-as --pool "${POOL}" --name "${VOL_NAME}" --capacity "${TPL_SIZE}" --format raw >/dev/null
virsh -c qemu:///system vol-upload --pool "${POOL}" "${VOL_NAME}" "${OUT_TEMPLATE}"
POOL_PATH=$(virsh -c qemu:///system vol-path --pool "${POOL}" "${VOL_NAME}")
log "template now resident at ${POOL_PATH} (libvirt-readable)"
log "done"
