#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# One-time bootstrap for compartment-bpf's Path C quickstart.
#
# Packages the upstream Ubuntu Resolute (26.04 LTS) cloud image as a
# vagrant-libvirt box under the name `compartment/resolute`, and
# ensures a user-owned libvirt storage pool exists so `vagrant up` does
# not need write access to /var/lib/libvirt/images/.
#
# Idempotent: re-running with the same checksum is a no-op.

set -euo pipefail

BOX_NAME="${BOX_NAME:-compartment/resolute}"
WORK_DIR="${WORK_DIR:-${HOME}/.cache/compartment-bpf-vagrant}"

CLOUD_IMG_URL="https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-amd64.img"
SHA256SUMS_URL="https://cloud-images.ubuntu.com/resolute/current/SHA256SUMS"
CLOUD_IMG_FILE="resolute-server-cloudimg-amd64.img"

# Bootstrap NVRAM template — see Vagrantfile's NVRAM_TEMPLATE comment
# for the rationale. The companion bootstrap-nvram.sh script populates
# this file by booting a throwaway libvirt domain that lets the cloud
# image's \EFI\BOOT\fbx64.efi fallback register a proper Boot####
# entry into a fresh OVMF varstore. V-5b ships this plumbing but does
# NOT yet measure warm-cache — bootstrap-nvram.sh produces a captured
# NVRAM that does not currently cause the real Path C VM to boot
# (root cause under investigation in V-5c). Outside operators who
# need a working Path C today should follow V-5c's follow-up notes.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NVRAM_TEMPLATE="${SCRIPT_DIR}/resolute-nvram-template.fd"
BOOTSTRAP_NVRAM_SH="${SCRIPT_DIR}/bootstrap-nvram.sh"

log() { printf '[build-local-box] %s\n' "$*"; }
die() { printf '[build-local-box] ERROR: %s\n' "$*" >&2; exit 1; }

command -v vagrant        >/dev/null || die "vagrant not found in PATH"
command -v qemu-img       >/dev/null || die "qemu-img not found in PATH (apt install qemu-utils)"
command -v curl           >/dev/null || die "curl not found in PATH"
command -v sha256sum      >/dev/null || die "sha256sum not found in PATH"
command -v tar            >/dev/null || die "tar not found in PATH"
command -v virt-customize >/dev/null || die "virt-customize not found in PATH (apt install libguestfs-tools)"

vagrant plugin list 2>/dev/null | grep -q '^vagrant-libvirt ' \
  || die "vagrant-libvirt plugin not installed (vagrant plugin install vagrant-libvirt)"

# NVRAM template is produced by bootstrap-nvram.sh at the end of this
# script (after the box is added). Vagrantfile references the template
# unconditionally; if it's missing on a fresh checkout, fall through —
# the user's first `vagrant up` will surface a clearer "file not found"
# error than digging into vagrant-libvirt internals.
if [ ! -r "${NVRAM_TEMPLATE}" ]; then
  log "OVMF NVRAM template not yet present at ${NVRAM_TEMPLATE} — will be bootstrapped at the end of this run"
fi

# vagrant ships an insecure keypair used by every vanilla box; we inject
# the public half into the box so vagrant-libvirt's SSH probe lands.
# Default to the HashiCorp /opt/vagrant install layout (gem path versioned
# by the installed vagrant). Apt-installed vagrant ships the same key at
# /usr/share/vagrant/gems/gems/vagrant-<ver>/keys/vagrant.pub.rsa — fall
# back to a glob if the primary path is missing. Override with VAGRANT_PUB.
if [ -z "${VAGRANT_PUB:-}" ]; then
  vagrant_ver="$(vagrant --version 2>/dev/null | awk '{print $2}')"
  for candidate in \
    "/opt/vagrant/embedded/gems/gems/vagrant-${vagrant_ver}/keys/vagrant.pub.rsa" \
    "/usr/share/vagrant/gems/gems/vagrant-${vagrant_ver}/keys/vagrant.pub.rsa" \
    /opt/vagrant/embedded/gems/gems/vagrant-*/keys/vagrant.pub.rsa \
    /usr/share/vagrant/gems/gems/vagrant-*/keys/vagrant.pub.rsa; do
    if [ -r "${candidate}" ]; then
      VAGRANT_PUB="${candidate}"
      break
    fi
  done
fi
[ -n "${VAGRANT_PUB:-}" ] && [ -r "${VAGRANT_PUB}" ] \
  || die "vagrant insecure public key not found (tried /opt/vagrant and /usr/share/vagrant for vagrant-${vagrant_ver:-?}); set VAGRANT_PUB env"

mkdir -p "${WORK_DIR}"

# Staleness fingerprint check: an older build from
# before the JSON-parser fix wrote `"virtual_size":1` into the box's
# metadata.json, which made every per-VM disk a 1 GiB COW snapshot of
# the 3.5 GiB box image and truncated the ESP at byte offset ~1.03 GiB
# off the visible disk. virt-resize at build time now expands the
# cloud image's root past 3 GiB, so any stored box whose metadata
# reports virtual_size < 3 (or whose metadata cannot be parsed at all)
# was built by the buggy pre-V-5c path and must be force-rebuilt.
# INVENTORY.md documents this fingerprint in the "host artifacts" table.
V5C_MIN_VIRTUAL_SIZE_GIB=3
box_v5c_fingerprint_ok() {
  local store
  store="${HOME}/.vagrant.d/boxes/${BOX_NAME//\//-VAGRANTSLASH-}"
  local meta
  meta="$(find "${store}" -type f -name metadata.json 2>/dev/null | head -n 1)"
  [ -n "${meta}" ] && [ -r "${meta}" ] || {
    log "stored box has no readable metadata.json under ${store} — failing V-5c fingerprint"
    return 1
  }
  local vsize
  vsize="$(python3 -c "import json,sys;d=json.load(open('${meta}'));print(d.get('virtual_size', 0))" 2>/dev/null)" || {
    log "stored box metadata.json unparseable (${meta}) — failing V-5c fingerprint"
    return 1
  }
  if [ "${vsize}" -lt "${V5C_MIN_VIRTUAL_SIZE_GIB}" ]; then
    log "stored box reports virtual_size=${vsize} GiB, below V-5c floor ${V5C_MIN_VIRTUAL_SIZE_GIB} GiB — failing V-5c fingerprint"
    return 1
  fi
  return 0
}

if vagrant box list 2>/dev/null | grep -qE "^${BOX_NAME//\//\\/} +\(libvirt,"; then
  if box_v5c_fingerprint_ok; then
    log "vagrant box ${BOX_NAME} already added for libvirt and passes V-5c fingerprint — nothing to do"
    exit 0
  fi
  log "vagrant box ${BOX_NAME} present but stale (pre-V-5c) — removing and rebuilding"
  vagrant box remove --force --provider libvirt "${BOX_NAME}" \
    || die "could not remove stale ${BOX_NAME} box for V-5c rebuild"
fi

# Fetch upstream SHA256SUMS, pin the row for our image
log "fetching upstream SHA256SUMS"
sums="${WORK_DIR}/SHA256SUMS"
curl -sSL --fail --max-time 60 "${SHA256SUMS_URL}" -o "${sums}"
expected_sha="$(awk -v f="*${CLOUD_IMG_FILE}" '$2 == f {print $1}' "${sums}")"
[ -n "${expected_sha}" ] || die "no SHA row for ${CLOUD_IMG_FILE} in ${SHA256SUMS_URL}"
log "expected SHA256 ${expected_sha} (${CLOUD_IMG_FILE})"

# Cache the cloud image; re-verify each time so a corrupted partial download
# does not silently survive a re-run.
img="${WORK_DIR}/${CLOUD_IMG_FILE}"
if [ -f "${img}" ]; then
  log "verifying cached ${CLOUD_IMG_FILE}"
  actual_sha="$(sha256sum "${img}" | awk '{print $1}')"
  if [ "${actual_sha}" != "${expected_sha}" ]; then
    log "cached image SHA mismatch — re-downloading"
    rm -f "${img}"
  fi
fi

if [ ! -f "${img}" ]; then
  log "downloading ${CLOUD_IMG_URL}"
  curl -L --fail --max-time 1200 "${CLOUD_IMG_URL}" -o "${img}.part"
  mv "${img}.part" "${img}"
  actual_sha="$(sha256sum "${img}" | awk '{print $1}')"
  [ "${actual_sha}" = "${expected_sha}" ] || die "SHA256 mismatch after download: expected ${expected_sha}, got ${actual_sha}"
fi

# Assemble vagrant-libvirt box layout:
#   metadata.json   provider=libvirt, format=qcow2
#   Vagrantfile     box-default stub
#   box.img         the upstream Resolute cloud image, customised below
stage="${WORK_DIR}/stage"
rm -rf "${stage}"
mkdir -p "${stage}"
cp "${img}" "${stage}/box.img"

# The upstream cloud image is not a Vagrant box: it has no `vagrant`
# user, no SSH key authorised for it, no sudo NOPASSWD, and cloud-init
# expects a datasource (NoCloud seed, etc.) that vagrant-libvirt does
# not provide. We add the bits a vagrant-libvirt box needs so that
# the first `vagrant up` reaches SSH on standard timing.
log "growing box.img: 3.5 GiB → 8 GiB (V-5c apt-cache headroom)"
# F3 attempt was to pre-bake clang+libbpf-dev+linux-tools-generic at
# box-build time so the provisioner's apt step is a no-op. That hit a
# wall: libguestfs's supermin appliance has no working DNS resolution,
# so `virt-customize --install` (and equivalent `--run-command "apt
# install"`) fail with "Temporary failure resolving
# archive.ubuntu.com" → "Package clang has no installation candidate".
# Static `/etc/resolv.conf` injection didn't fix it (8.8.8.8 not
# reachable through the appliance's network stack here either).
#
# Pivoted to F1: expand the box image's root partition before
# packaging, so the provisioner's runtime apt install has the
# ~600 MiB of /var/cache/apt headroom it needs. virt-resize only
# uses libguestfs's offline path (no network), so it works inside
# this environment. Net cost: build-local-box.sh is ~10-15 s slower
# the first time; every operator's first `vagrant up` then pays the
# apt-install cost once, and every subsequent warm-cache `vagrant up`
# is a dpkg-query no-op.
expanded="${WORK_DIR}/box.img.expanded"
rm -f "${expanded}"
qemu-img create -f qcow2 "${expanded}" 8G >/dev/null
virt-resize --quiet --expand /dev/sda1 "${stage}/box.img" "${expanded}"
mv "${expanded}" "${stage}/box.img"

log "customising box.img: vagrant user + insecure SSH key + NOPASSWD"
virt-customize -a "${stage}/box.img" \
  --run-command 'useradd -m -s /bin/bash -G sudo vagrant || true' \
  --run-command 'install -d -m 0700 -o vagrant -g vagrant /home/vagrant/.ssh' \
  --ssh-inject "vagrant:file:${VAGRANT_PUB}" \
  --run-command 'chmod 0600 /home/vagrant/.ssh/authorized_keys && chown vagrant:vagrant /home/vagrant/.ssh/authorized_keys' \
  --write '/etc/sudoers.d/vagrant:vagrant ALL=(ALL) NOPASSWD:ALL
' \
  --run-command 'chmod 0440 /etc/sudoers.d/vagrant' \
  --run-command 'systemctl enable ssh.service' \
  --run-command 'ssh-keygen -A' \
  --write '/etc/systemd/network/01-compartment-bpf-dhcp.network:[Match]
Name=e*

[Network]
DHCP=yes
' \
  --write '/etc/cloud/cloud.cfg.d/99-compartment-bpf.cfg:datasource_list: [ None ]
network: {config: disabled}
' \
  --run-command 'systemctl mask cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service 2>/dev/null || true' \
  --run-command 'systemctl enable systemd-networkd-wait-online.service 2>/dev/null || true' \
  --truncate /etc/machine-id \
  --run-command 'rm -f /var/lib/dbus/machine-id || true'

# qemu-img info --output=json emits NESTED "virtual-size" keys under
# children[].info — and the file-format (nested) entry shows the
# qcow2's on-disk byte length (~822 MiB for the Resolute cloud image),
# not the underlying virtual disk size. An awk-based first-match
# extractor reads the wrong one, sees ~822 MiB, rounds up to 1 GiB,
# writes `virtual_size: 1` into metadata.json — and vagrant-libvirt
# then creates each per-VM disk as a 1 GiB qcow2 COW snapshot of the
# 3.5 GiB box image, truncating /dev/sda14 + /dev/sda15 (which include
# the ESP at byte offset ~1.03 GiB). OVMF on that truncated disk
# cannot find `\EFI\BOOT\BOOTX64.EFI` and lands at the BdsDxe "No
# bootable option" panic. The fix is to parse the JSON correctly and
# pick the *top-level* virtual-size field.
virtual_size_bytes="$(qemu-img info --output=json "${stage}/box.img" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["virtual-size"])')"
virtual_size_gib=$(( (virtual_size_bytes + (1<<30) - 1) >> 30 ))
[ "${virtual_size_gib}" -ge 1 ] || virtual_size_gib=1
log "box virtual disk size: ${virtual_size_bytes} bytes → ${virtual_size_gib} GiB (must be ≥ ESP partition end ≈ 1.13 GiB on Resolute cloud image)"

cat > "${stage}/metadata.json" <<EOF
{"provider":"libvirt","format":"qcow2","virtual_size":${virtual_size_gib}}
EOF

cat > "${stage}/Vagrantfile" <<'EOF'
Vagrant.configure("2") do |config|
  config.vm.synced_folder ".", "/vagrant", disabled: true
end
EOF

box_tar="${WORK_DIR}/compartment-resolute.box"
log "packaging box → ${box_tar}"
# Plain tar (no gzip) — the qcow2 inside is already compressed, so an
# extra gzip pass only burns CPU; vagrant-libvirt accepts both.
tar -C "${stage}" -cf "${box_tar}" metadata.json Vagrantfile box.img

log "adding box ${BOX_NAME} (provider libvirt)"
vagrant box add --name "${BOX_NAME}" --provider libvirt "${box_tar}"

# The pool-resident copy of the captured NVRAM template is what the
# Vagrantfile actually references — see Vagrantfile's
# `NVRAM_TEMPLATE_POOL_PATH` comment for the why. `bootstrap-nvram.sh`
# now uploads the captured varstore into the libvirt `images` pool as
# `compartment-bpf-resolute-nvram-template.fd`. We treat the pool
# volume as the source of truth and only rerun bootstrap when it's
# absent.
NVRAM_TEMPLATE_VOL="compartment-bpf-resolute-nvram-template.fd"
POOL_TEMPLATE_PATH="/var/lib/libvirt/images/${NVRAM_TEMPLATE_VOL}"

template_in_pool() {
  virsh -c qemu:///system vol-list --pool images 2>/dev/null \
    | awk -v v="${NVRAM_TEMPLATE_VOL}" '$1 == v {found=1} END {exit found?0:1}'
}

if ! template_in_pool; then
  pool_box_img="$(virsh -c qemu:///system vol-list --pool images 2>/dev/null \
    | awk '/compartment-VAGRANTSLASH-resolute_vagrant_box_image_/ {print $2; exit}')"
  if [ -n "${pool_box_img}" ] && [ -r "${pool_box_img}" ]; then
    log "bootstrapping OVMF NVRAM template into libvirt pool (V-5c gate)"
    bash "${BOOTSTRAP_NVRAM_SH}" "${pool_box_img}" "${NVRAM_TEMPLATE}" \
      || die "bootstrap-nvram.sh failed; vagrant up will not boot. See kvm/quickstart-vagrant/README.md"
  else
    die "cannot resolve libvirt-pool box.img path for bootstrap-nvram step. Rerun build-local-box.sh after the box image is in the system pool."
  fi
else
  log "OVMF NVRAM template already in libvirt pool at ${POOL_TEMPLATE_PATH} (re-bootstrap not needed)"
fi

log "done. Try: cd kvm/quickstart-vagrant && vagrant up"
