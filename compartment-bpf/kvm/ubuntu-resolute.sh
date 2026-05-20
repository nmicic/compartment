#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Ubuntu 26.04 LTS (Resolute) cloud-image KVM VM for the
# `compartment-bpf` smoke gate.
#
# Re-running tears down the VM and rebuilds. The defaults assume the
# libvirt `virbr0` NAT bridge; override the variables below if your host
# uses a different lab layout.

set -euo pipefail

# ===== USER CONFIG =====
VM_NAME="${VM_NAME:-compartment-bpf-resolute}"

# Host networking — override to fit your local bridge/NAT layout.
BRIDGE_NAME="${BRIDGE_NAME:-virbr0}"
HOST_IP="${HOST_IP:-192.168.122.1}"
VM_IP="${VM_IP:-192.168.122.253}"
NETMASK="${NETMASK:-255.255.255.0}"
GATEWAY="${GATEWAY:-192.168.122.1}"
DNS_SERVERS="${DNS_SERVERS:-8.8.8.8 1.1.1.1}"
TIMEZONE="${TIMEZONE:-UTC}"

# Resources — modest; smoke is light, but kernel headers/BTF want room.
RAM="${RAM:-8192}"     # MiB
CPUS="${CPUS:-2}"

# Disks/paths
IMAGES_DIR="${IMAGES_DIR:-/var/lib/libvirt/images}"
BASE_IMG_URL="${BASE_IMG_URL:-https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-amd64.img}"
BASE_IMG="${BASE_IMG:-${IMAGES_DIR}/resolute-server-cloudimg-amd64.img}"
VM_DISK="${VM_DISK:-${IMAGES_DIR}/${VM_NAME}.qcow2}"
VM_DISK_SIZE="${VM_DISK_SIZE:-16G}"
SEED_ISO="${SEED_ISO:-${IMAGES_DIR}/${VM_NAME}-seed.iso}"

# Guest user. The same SSH keys are injected for both this user and
# root. By default the script scans `~/.ssh/*.pub`; override with
# SSH_AUTH_KEYS_FILE=/path/to/authorized_keys.pub for deterministic runs.
USERNAME="${USERNAME:-compartment}"
SSH_AUTH_KEYS_FILE="${SSH_AUTH_KEYS_FILE:-}"

# Stable local MAC so repeated rebuilds keep the same guest identity.
MAC_ADDR="${MAC_ADDR:-52:54:00:7a:11:43}"

# LSM list to bake into the kernel cmdline. Ordering does not matter for
# correctness — every LSM sees every hook and earlier denies are preserved
# by the conventional `if (ret != 0) return ret;` guard.
LSM_LIST="${LSM_LIST:-lockdown,capability,landlock,yama,apparmor,bpf}"

# ===== Helpers =====
mask2cidr() {
  local IFS=. oct cidr=0
  for oct in $1; do
    case $oct in
      255) cidr=$((cidr+8));;
      254) cidr=$((cidr+7));;
      252) cidr=$((cidr+6));;
      248) cidr=$((cidr+5));;
      240) cidr=$((cidr+4));;
      224) cidr=$((cidr+3));;
      192) cidr=$((cidr+2));;
      128) cidr=$((cidr+1));;
      0) ;;
      *) echo "Invalid NETMASK: $1" >&2; exit 1;;
    esac
  done
  echo "$cidr"
}

ensure_pkg() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Installing host packages..."
    sudo apt-get update -y
    sudo apt-get install -y qemu-kvm libvirt-daemon-system virtinst cloud-image-utils genisoimage bridge-utils iptables curl
  }
}

iptables_append_once() {
  local table="$1"; shift
  local -a rule=( "$@" )
  if ! sudo iptables -t "$table" -C "${rule[@]}" 2>/dev/null; then
    sudo iptables -t "$table" -A "${rule[@]}"
  fi
}

collect_ssh_keys() {
  local -a candidates=()
  local file line
  local -i count=0
  declare -A seen=()

  if [[ -n "$SSH_AUTH_KEYS_FILE" ]]; then
    candidates+=( "$SSH_AUTH_KEYS_FILE" )
  else
    shopt -s nullglob
    candidates=( "${HOME}/.ssh/"*.pub )
    shopt -u nullglob
  fi

  for file in "${candidates[@]}"; do
    [[ -r "$file" ]] || continue
    while IFS= read -r line; do
      case "$line" in
        ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*\ *)
          if [[ -z "${seen[$line]:-}" ]]; then
            printf '%s\n' "$line"
            seen["$line"]=1
            count+=1
          fi
          ;;
      esac
    done <"$file"
  done

  return $((count == 0))
}

# ===== Preflight =====
ensure_pkg virt-install
ensure_pkg cloud-localds
AUTHORIZED_KEYS="$(collect_ssh_keys)" || {
  echo "No SSH public keys found." >&2
  echo "Set SSH_AUTH_KEYS_FILE=/path/to/authorized_keys.pub or place at least one *.pub file under ~/.ssh/." >&2
  exit 1
}
AUTHORIZED_KEYS_YAML="$(printf '%s\n' "$AUTHORIZED_KEYS" | sed 's/^/      - /')"
sudo mkdir -p "$IMAGES_DIR"

# Download base image once
if [[ ! -f "$BASE_IMG" ]]; then
  echo "Downloading Ubuntu Resolute (26.04 LTS) cloud image..."
  sudo curl -L "$BASE_IMG_URL" -o "$BASE_IMG".tmp
  sudo qemu-img convert -O qcow2 "$BASE_IMG".tmp "$BASE_IMG"
  sudo rm -f "$BASE_IMG".tmp
fi

# ===== Tear down any existing VM (always fresh) =====
if sudo virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
  echo "Destroying existing VM ${VM_NAME}..."
  sudo virsh destroy "$VM_NAME" 2>/dev/null || true
  sudo virsh undefine "$VM_NAME" --nvram 2>/dev/null || sudo virsh undefine "$VM_NAME" 2>/dev/null || true
fi
sudo rm -f "$VM_DISK" "$SEED_ISO"

# Create fresh overlay/root disk
echo "Creating overlay root disk..."
sudo qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMG" "$VM_DISK"
sudo qemu-img resize "$VM_DISK" "$VM_DISK_SIZE"

# ===== Host bridge + NAT (idempotent) =====
echo "Ensuring bridge $BRIDGE_NAME exists..."
if ! ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
  sudo brctl addbr "$BRIDGE_NAME"
  sudo ip addr add "$HOST_IP"/"$(mask2cidr "$NETMASK")" dev "$BRIDGE_NAME"
  sudo ip link set "$BRIDGE_NAME" up
fi
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
EXT_IF=$(ip route | awk '/^default/ {print $5; exit}')
iptables_append_once nat POSTROUTING -o "$EXT_IF" -j MASQUERADE
iptables_append_once filter FORWARD -i "$BRIDGE_NAME" -j ACCEPT
iptables_append_once filter FORWARD -o "$BRIDGE_NAME" -m state --state RELATED,ESTABLISHED -j ACCEPT

# ===== cloud-init seed =====
CIDR=$(mask2cidr "$NETMASK")
DNS_YAML=$(printf '%s\n' "$DNS_SERVERS" | awk '{for(i=1;i<=NF;i++) printf (i==NF?"%s": "%s, "), $i}')

SEED_DIR=$(mktemp -d)
trap 'rm -rf "$SEED_DIR"' EXIT

# user-data:
#   1. install BPF LSM toolchain
#   2. edit /etc/default/grub to put `bpf` in the active LSM list
#   3. update-grub
#   4. reboot once at end of first-boot so the new cmdline takes effect
cat >"$SEED_DIR/user-data" <<EOF
#cloud-config
preserve_hostname: false
hostname: ${VM_NAME}
manage_etc_hosts: true
timezone: ${TIMEZONE}

ssh_pwauth: false
disable_root: false

users:
  - default
  - name: ${USERNAME}
    lock_passwd: true
    shell: /bin/bash
    ssh_authorized_keys:
${AUTHORIZED_KEYS_YAML}
    sudo: ALL=(ALL) NOPASSWD:ALL
  - name: root
    lock_passwd: true
    ssh_authorized_keys:
${AUTHORIZED_KEYS_YAML}

package_update: true
package_upgrade: false
packages:
  - qemu-guest-agent
  - tmux
  - curl
  - jq
  - nano
  - sudo
  - util-linux
  - ca-certificates
  - wget
  - git
  - iproute2
  - iptables
  - net-tools
  - tcpdump
  - dnsutils
  # compartment-bpf build/test toolchain
  - clang
  - lld
  - llvm
  - libbpf-dev
  - libsodium-dev
  - libelf-dev
  - zlib1g-dev
  - linux-libc-dev
  - linux-headers-generic
  - linux-tools-generic
  - linux-tools-common
  - make
  - build-essential
  - pkg-config

write_files:
  - path: /etc/ssh/sshd_config.d/99-allow-root.conf
    permissions: "0644"
    owner: root:root
    content: |
      PermitRootLogin prohibit-password
      PasswordAuthentication no

  # Drop-in for setting the active LSM list. We use a drop-in file rather
  # than sed-editing /etc/default/grub so a re-run doesn't double-append.
  # update-grub reads /etc/default/grub.d/*.cfg after the main file.
  - path: /etc/default/grub.d/99-compartment-bpf-lsm.cfg
    permissions: "0644"
    owner: root:root
    content: |
      # Set by ubuntu-resolute.sh — activates BPF LSM for compartment-bpf.
      GRUB_CMDLINE_LINUX_DEFAULT="\${GRUB_CMDLINE_LINUX_DEFAULT} lsm=${LSM_LIST}"

  - path: /etc/profile.d/compartment-bpf.sh
    permissions: "0644"
    owner: root:root
    content: |
      # Convenience for the test loop. bpftool ships under linux-tools-<ver>
      # and is not always on PATH for non-root.
      if [ -d /usr/lib/linux-tools/\$(uname -r) ]; then
        export PATH=\$PATH:/usr/lib/linux-tools/\$(uname -r)
      fi

runcmd:
  - systemctl enable --now qemu-guest-agent || true
  - systemctl restart sshd
  # Wire BPF LSM into the kernel cmdline. Takes effect on next boot.
  - update-grub
  # Touch a marker so the operator can confirm cloud-init reached this step.
  - install -d -m 0755 /var/lib/${VM_NAME}
  - date -Iseconds > /var/lib/${VM_NAME}/cloud-init-done.stamp

# Reboot once at the end so lsm=...,bpf takes effect.
power_state:
  mode: reboot
  timeout: 30
  condition: True
  message: "Rebooting to activate BPF LSM"
EOF

# meta-data
cat >"$SEED_DIR/meta-data" <<EOF
instance-id: ${VM_NAME}-01
local-hostname: ${VM_NAME}
EOF

# network-config (v2), match by MAC
cat >"$SEED_DIR/network-config" <<EOF
version: 2
ethernets:
  nic0:
    match:
      macaddress: ${MAC_ADDR}
    set-name: ens3
    dhcp4: false
    addresses: [${VM_IP}/${CIDR}]
    gateway4: ${GATEWAY}
    nameservers:
      addresses: [${DNS_YAML}]
renderer: networkd
EOF

echo "Building NoCloud seed ISO..."
sudo cloud-localds -v --network-config="$SEED_DIR/network-config" "$SEED_ISO" "$SEED_DIR/user-data" "$SEED_DIR/meta-data"

# os-variant: libosinfo on the host may not yet know ubuntu26.04. Pick the
# closest known value; this only affects performance/feature hints, not
# correctness, since we're using virtio everywhere.
OS_VARIANT="ubuntu24.04"
if osinfo-query os 2>/dev/null | awk '{print $1}' | grep -qx ubuntu26.04; then
  OS_VARIANT="ubuntu26.04"
fi
echo "Using --os-variant ${OS_VARIANT}"

echo "Starting VM ${VM_NAME}..."
sudo virt-install \
  --name "${VM_NAME}" \
  --memory "${RAM}" \
  --vcpus "${CPUS}" \
  --machine q35 --cpu host \
  --disk "path=${VM_DISK},format=qcow2,bus=virtio" \
  --disk "path=${SEED_ISO},device=cdrom" \
  --network "bridge=${BRIDGE_NAME},model=virtio,mac=${MAC_ADDR}" \
  --os-variant "${OS_VARIANT}" \
  --graphics none \
  --console pty,target_type=serial \
  --import \
  --noautoconsole \
  --autostart \
  --boot uefi

cat <<EOF

VM ${VM_NAME} is booting. cloud-init will:
  1. install clang / libbpf-dev / libsodium-dev / linux-tools / kernel headers
  2. add 'bpf' to the active LSM list via /etc/default/grub.d/
  3. update-grub
  4. reboot once at the end (look for power_state in cloud-init log)

After that reboot, validate from the host:

  ssh ${USERNAME}@${VM_IP} 'cat /sys/kernel/security/lsm'
  # must include 'bpf'

Then sync the compartment-bpf source and run the smoke gate:

  rsync -a --exclude=.git/ ~/compartment-bpf/ ${USERNAME}@${VM_IP}:~/compartment-bpf/
  ssh ${USERNAME}@${VM_IP} 'cd compartment-bpf && make vmlinux.h && make && sudo make smoke'

Expected output: 'smoke ok'.

This VM is key-only by default. Set SSH_AUTH_KEYS_FILE to control which
public keys are injected into ${USERNAME} and root.

Re-run this script to bring back a fresh VM with the same IP/MAC.
EOF
