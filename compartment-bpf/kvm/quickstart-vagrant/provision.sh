#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# compartment-bpf Path C in-guest provisioner.
#
# First pass:  install toolchain, write GRUB drop-in adding `bpf` to the
#              active LSM list, exit non-zero with a clear message that
#              tells the operator to run `vagrant reload --provision`.
# Second pass: verify `bpf` in /sys/kernel/security/lsm. Build + smoke.

set -euo pipefail

LSM_LIST="lockdown,capability,landlock,yama,apparmor,bpf"
GRUB_DROPIN="/etc/default/grub.d/99-compartment-bpf.cfg"
REPO_GUEST="/repo"

log() { printf '[provision] %s\n' "$*"; }

# Distinctive first-pass banner — visually separates the expected exit-99
# stop after writing the GRUB drop-in from a real failure. README's
# "Step 1 — first boot" section documents this; the banner is the in-VM
# echo of that note so a copy-paster sees it even without reading docs.
if ! grep -qwE 'bpf' /sys/kernel/security/lsm 2>/dev/null; then
  cat <<'EOM'
================================================================
  [provision] FIRST-PASS provisioning (this VM will exit non-zero
  on purpose; that is NOT a failure). The pass writes the GRUB
  drop-in that adds `bpf` to the active LSM list, then asks you to
  run `vagrant reload --provision` so the new cmdline takes effect.
  Second pass picks up automatically and runs `make smoke`.
================================================================
EOM
fi

log "kernel: $(uname -r)   /sys/kernel/security/lsm: $(cat /sys/kernel/security/lsm 2>/dev/null || echo MISSING)"

# Toolchain (idempotent — dpkg-query first, only install missing).
need=()
for pkg in clang libbpf-dev libsodium-dev linux-tools-generic make build-essential bpftool; do
  dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q "install ok installed" || need+=("${pkg}")
done
if [ "${#need[@]}" -gt 0 ]; then
  log "apt-get install: ${need[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${need[@]}"
fi

# GRUB drop-in (idempotent — content compared before write).
new_grub="GRUB_CMDLINE_LINUX_DEFAULT=\"\$GRUB_CMDLINE_LINUX_DEFAULT lsm=${LSM_LIST}\""
if ! [ -f "${GRUB_DROPIN}" ] || ! grep -qxF "${new_grub}" "${GRUB_DROPIN}"; then
  log "writing ${GRUB_DROPIN}"
  printf '%s\n' "${new_grub}" > "${GRUB_DROPIN}"
  update-grub
fi

if grep -qwE 'bpf' /sys/kernel/security/lsm; then
  log "BPF LSM active — proceeding to build + smoke"
else
  cat <<'EOM'
[provision] BPF LSM not yet in /sys/kernel/security/lsm.
[provision] The GRUB drop-in is in place but the running kernel has not seen it.
[provision]
[provision] From the host repo root:
[provision]   cd kvm/quickstart-vagrant
[provision]   vagrant reload --provision
[provision]
[provision] After reload, /sys/kernel/security/lsm must contain `bpf` or this
[provision] provisioner will fail loudly.
EOM
  exit 99
fi

# Build + smoke. The synced repo is read-only-by-convention; copy into the
# guest so make can write its build artifacts without touching the host tree.
build_dir="/root/compartment-bpf"
rm -rf "${build_dir}"
cp -a "${REPO_GUEST}" "${build_dir}"
cd "${build_dir}"

log "make smoke"
make smoke
log "smoke OK"
