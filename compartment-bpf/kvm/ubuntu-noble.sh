#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Ubuntu 24.04 LTS (Noble) cloud-image KVM VM for the `compartment-bpf`
# smoke gate.
#
# Noble ships the 6.8 kernel — the *previous* LTS relative to Resolute (26.04 /
# 7.0). It is the lowest kernel we target for production: many deployed servers
# still run Noble, so compartment-bpf is validated here before the newer Resolute
# matrix. (The prior-prior LTS, Jammy 22.04 / 5.15, is a separate, later check —
# 5.15 does not carry 'bpf' in the default LSM set and needs its own bring-up.)
#
# Re-running tears down the VM and rebuilds. The defaults assume the libvirt
# `virbr0` NAT bridge; override the variables below if your host uses a
# different lab layout.

# usage: ubuntu-noble.sh [--check]
#
#   (no args)  tear down any existing VM and bring up a fresh one
#   --check    preflight only: report host prerequisites, the NAT plan, the
#              console log path and the cloud-image state, then exit WITHOUT
#              touching the VM, the disks, iptables or the network
#
# Every knob is an environment variable with a default; see USER CONFIG below.
# END-USAGE
set -euo pipefail

# ===== Argument handling =====
CHECK_ONLY=0
for arg in "${@:-}"; do
  case "$arg" in
    "") ;;
    --check) CHECK_ONLY=1 ;;
    -h|--help)
      sed -n '/^# usage:/,/^# END-USAGE$/p' "$0" | sed '$d; s/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown argument '$arg' (try --help)" >&2; exit 2 ;;
  esac
done

# ===== USER CONFIG =====
VM_NAME="${VM_NAME:-compartment-bpf-noble}"

# Host networking — override to fit your local bridge/NAT layout.
# .252 = Noble; .253 = Resolute; .254 = webhook-lab (jammy). Distinct IP + MAC
# so all three can coexist on virbr0 at once.
BRIDGE_NAME="${BRIDGE_NAME:-virbr0}"
HOST_IP="${HOST_IP:-192.168.122.1}"
VM_IP="${VM_IP:-192.168.122.252}"
NETMASK="${NETMASK:-255.255.255.0}"
GATEWAY="${GATEWAY:-192.168.122.1}"
DNS_SERVERS="${DNS_SERVERS:-8.8.8.8 1.1.1.1}"
TIMEZONE="${TIMEZONE:-UTC}"

# Resources — modest; smoke is light, but kernel headers/BTF want room.
RAM="${RAM:-8192}"     # MiB
CPUS="${CPUS:-2}"

# Disks/paths
IMAGES_DIR="${IMAGES_DIR:-/var/lib/libvirt/images}"
BASE_IMG_URL="${BASE_IMG_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
BASE_IMG="${BASE_IMG:-${IMAGES_DIR}/noble-server-cloudimg-amd64.img}"
VM_DISK="${VM_DISK:-${IMAGES_DIR}/${VM_NAME}.qcow2}"
VM_DISK_SIZE="${VM_DISK_SIZE:-16G}"
SEED_ISO="${SEED_ISO:-${IMAGES_DIR}/${VM_NAME}-seed.iso}"

# First-boot serial console. With `--console pty,target_type=serial` plus
# `--noautoconsole` the entire first boot goes nowhere retrievable: if
# cloud-init fails you have no log at all, which makes an automated bring-up
# undebuggable. Default to a file so `--check`/CI runs leave evidence. libvirt
# will not accept a pty and a file on serial port 0 at the same time, so
# setting CONSOLE_LOG="" restores the interactive `virsh console <vm>` pty.
CONSOLE_LOG="${CONSOLE_LOG-${IMAGES_DIR}/${VM_NAME}-console.log}"

# Guest user. The same SSH keys are injected for both this user and
# root. By default the script scans `~/.ssh/*.pub`; override with
# SSH_AUTH_KEYS_FILE=/path/to/authorized_keys.pub for deterministic runs.
USERNAME="${USERNAME:-compartment}"
SSH_AUTH_KEYS_FILE="${SSH_AUTH_KEYS_FILE:-}"

# Stable local MAC so repeated rebuilds keep the same guest identity.
# Differs from the Resolute VM's MAC (…:7a:11:43) by the last octet so both
# VMs can be defined simultaneously.
MAC_ADDR="${MAC_ADDR:-52:54:00:7a:11:41}"

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

# Host packages. `virt-install`/`cloud-localds` used to be the only two probed,
# so a host that happened to have those skipped the whole install and a missing
# ovmf surfaced much later as an opaque virt-install error. Probe EVERY binary
# this script executes, plus the UEFI firmware `--boot uefi` needs.
#
# Every package HOST_TOOLS names has to appear in HOST_PKGS as well, or the
# probe reports a package the installer never installs and the run dies on the
# re-probe with "Still missing after apt-get install". iproute2 (`ip`) did
# exactly that, and `sysctl` — run unconditionally to set ip_forward — was not
# probed at all, so a host without procps failed at the call site with 127.
HOST_PKGS=(
  qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients virtinst
  cloud-image-utils genisoimage bridge-utils iptables curl
  libosinfo-bin ovmf iproute2 procps
)

# tool:apt-package pairs for every external command used below.
HOST_TOOLS=(
  "virt-install:virtinst"
  "virsh:libvirt-clients"
  "qemu-img:qemu-utils"
  "cloud-localds:cloud-image-utils"
  "genisoimage:genisoimage"
  "brctl:bridge-utils"
  "iptables:iptables"
  "curl:curl"
  "ip:iproute2"
  "osinfo-query:libosinfo-bin"
  "sysctl:procps"
)

# ovmf ships firmware blobs, not a binary; --boot uefi fails without them.
ovmf_present() {
  local f
  for f in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd \
           /usr/share/OVMF/OVMF_CODE.secboot.fd /usr/share/ovmf/OVMF.fd; do
    [[ -r "$f" ]] && return 0
  done
  return 1
}

# missing_host_tools -> prints "tool (apt: pkg)" lines for whatever is absent.
missing_host_tools() {
  local pair tool pkg
  for pair in "${HOST_TOOLS[@]}"; do
    tool="${pair%%:*}"; pkg="${pair#*:}"
    command -v "$tool" >/dev/null 2>&1 || printf '%s (apt: %s)\n' "$tool" "$pkg"
  done
  ovmf_present || printf 'OVMF firmware for --boot uefi (apt: ovmf)\n'
}

ensure_host_packages() {
  local missing
  missing="$(missing_host_tools)"
  [[ -z "$missing" ]] && return 0
  echo "Missing host prerequisites:"
  printf '%s\n' "$missing" | sed 's/^/  /'
  echo "Installing host packages: ${HOST_PKGS[*]}"
  sudo apt-get update -y
  sudo apt-get install -y "${HOST_PKGS[@]}"
  missing="$(missing_host_tools)"
  if [[ -n "$missing" ]]; then
    echo "Still missing after apt-get install:" >&2
    printf '%s\n' "$missing" | sed 's/^/  /' >&2
    exit 1
  fi
}

iptables_append_once() {
  local table="$1"; shift
  local -a rule=( "$@" )
  if ! sudo iptables -t "$table" -C "${rule[@]}" 2>/dev/null; then
    sudo iptables -t "$table" -A "${rule[@]}"
  fi
}

# net_prefix <ip> <netmask> -> network address (e.g. 192.168.122.0)
net_prefix() {
  local ip="$1" mask="$2"
  local IFS=.
  # shellcheck disable=SC2206
  local -a i=( $ip ) m=( $mask )
  echo "$(( i[0] & m[0] )).$(( i[1] & m[1] )).$(( i[2] & m[2] )).$(( i[3] & m[3] ))"
}

# libvirt_nat_network_for <bridge> -> name of the libvirt network that owns
# this bridge AND is in forward mode 'nat', or empty. libvirt installs its own
# correctly scoped LIBVIRT_PRT MASQUERADE for such a network, so ours would be
# redundant.
libvirt_nat_network_for() {
  local bridge="$1" net br
  command -v virsh >/dev/null 2>&1 || return 0
  for net in $(sudo virsh net-list --name 2>/dev/null); do
    br="$(sudo virsh net-info "$net" 2>/dev/null | awk '/^Bridge:/ {print $2}')"
    [[ "$br" == "$bridge" ]] || continue
    if sudo virsh net-dumpxml "$net" 2>/dev/null | grep -q "forward mode='nat'"; then
      echo "$net"
      return 0
    fi
  done
  return 0
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
CIDR="$(mask2cidr "$NETMASK")"
GUEST_SUBNET="${GUEST_SUBNET:-$(net_prefix "$VM_IP" "$NETMASK")/${CIDR}}"

if [[ -n "$CONSOLE_LOG" ]]; then
  CONSOLE_ARGS=( --serial "file,path=${CONSOLE_LOG}" )
else
  CONSOLE_ARGS=( --console "pty,target_type=serial" )
fi

if (( CHECK_ONLY )); then
  echo "=== ${VM_NAME}: preflight (--check; nothing will be created or changed) ==="
  miss="$(missing_host_tools)"
  if [[ -n "$miss" ]]; then
    echo "host packages MISSING:"
    printf '%s\n' "$miss" | sed 's/^/  /'
  else
    echo "host packages: OK (all probed binaries + OVMF firmware present)"
  fi
  if keys="$(collect_ssh_keys)"; then
    echo "ssh keys: $(printf '%s\n' "$keys" | grep -c .) key(s) would be injected"
  else
    echo "ssh keys: NONE FOUND — set SSH_AUTH_KEYS_FILE or add a *.pub under ~/.ssh/"
  fi
  echo "guest:    ${VM_NAME} ${VM_IP}/${CIDR} via ${GATEWAY} mac ${MAC_ADDR}"
  echo "bridge:   ${BRIDGE_NAME}"
  net="$(libvirt_nat_network_for "$BRIDGE_NAME")"
  if [[ -n "$net" ]]; then
    echo "NAT:      libvirt network '${net}' already masquerades ${GUEST_SUBNET}; no iptables rule needed"
  else
    echo "NAT:      would add  iptables -t nat -A POSTROUTING -s ${GUEST_SUBNET} ! -d ${GUEST_SUBNET} -o <default-if> -j MASQUERADE"
  fi
  echo "console:  ${CONSOLE_LOG:-pty (virsh console ${VM_NAME})}"
  echo "base img: ${BASE_IMG}$( [[ -f "$BASE_IMG" ]] && echo ' (present)' || echo " (would download from ${BASE_IMG_URL})" )"
  echo "disks:    ${VM_DISK} (${VM_DISK_SIZE}), ${SEED_ISO}"
  if sudo virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
    echo "existing: domain ${VM_NAME} EXISTS — a real run would destroy and undefine it"
  else
    echo "existing: no domain named ${VM_NAME}"
  fi
  [[ -n "$miss" ]] && exit 1
  exit 0
fi

ensure_host_packages
AUTHORIZED_KEYS="$(collect_ssh_keys)" || {
  echo "No SSH public keys found." >&2
  echo "Set SSH_AUTH_KEYS_FILE=/path/to/authorized_keys.pub or place at least one *.pub file under ~/.ssh/." >&2
  exit 1
}
AUTHORIZED_KEYS_YAML="$(printf '%s\n' "$AUTHORIZED_KEYS" | sed 's/^/      - /')"
sudo mkdir -p "$IMAGES_DIR"

# Download base image once
if [[ ! -f "$BASE_IMG" ]]; then
  echo "Downloading Ubuntu Noble (24.04 LTS) cloud image..."
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

# NAT for the guest subnet ONLY. The rule used to be an unscoped
#   iptables -t nat -A POSTROUTING -o $EXT_IF -j MASQUERADE
# which, on any host that already forwards other traffic (docker, WireGuard,
# a second libvirt network), NATs EVERYTHING leaving the default-route
# interface. And when the bridge belongs to a libvirt NAT network it is
# redundant: libvirt's LIBVIRT_PRT chain already masquerades this subnet
# correctly. Skip it in that case, scope it otherwise.
LIBVIRT_NET="$(libvirt_nat_network_for "$BRIDGE_NAME")"
if [[ -n "$LIBVIRT_NET" ]]; then
  echo "Bridge ${BRIDGE_NAME} belongs to libvirt NAT network '${LIBVIRT_NET}'; it already"
  echo "masquerades ${GUEST_SUBNET} (LIBVIRT_PRT). Not adding a second MASQUERADE rule."
else
  iptables_append_once nat POSTROUTING -s "$GUEST_SUBNET" ! -d "$GUEST_SUBNET" -o "$EXT_IF" -j MASQUERADE
  iptables_append_once filter FORWARD -i "$BRIDGE_NAME" -j ACCEPT
  iptables_append_once filter FORWARD -o "$BRIDGE_NAME" -m state --state RELATED,ESTABLISHED -j ACCEPT
fi

# ===== cloud-init seed =====
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
    # NOPASSWD sudo is intentional for this disposable test VM (the suite
    # needs passwordless root). Do NOT expose this VM to untrusted networks.
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
  # Daemons the profile-e2e and observe witnesses need. Without them
  # tests/profile-e2e/aide.sh, tests/profile-e2e/postgres.sh and observe
  # T12 SKIP, and each skip had to be carried in
  # tests/release-skip-allowlist.txt — four allow-listed skips on every
  # release, for three packages. postgresql (not just -common) is needed
  # because postgres.sh asserts against a live, online cluster.
  - aide
  - postgresql-common
  - postgresql

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
      # Set by ubuntu-noble.sh — activates BPF LSM for compartment-bpf.
      GRUB_CMDLINE_LINUX_DEFAULT="\${GRUB_CMDLINE_LINUX_DEFAULT} lsm=${LSM_LIST}"

runcmd:
  - systemctl enable --now qemu-guest-agent || true
  - systemctl restart sshd
  # bpftool on PATH for BOTH ways the suites are actually invoked.
  #
  # This used to be an /etc/profile.d snippet appending
  # /usr/lib/linux-tools/\$(uname -r) to PATH. A non-interactive, non-login
  # "ssh host 'make'" never sources /etc/profile.d, and sudo replaces PATH
  # with its compiled-in secure_path, so the snippet could not help either
  # of the two ways the suites are run. On both of these images it was moot
  # anyway: linux-tools-common ships /usr/sbin/bpftool, which is already on
  # the default PATH for root and for the guest user.
  #
  # Symlink into /usr/local/sbin instead — that directory IS in the default
  # PATH and IS in sudo's secure_path — and only when bpftool is genuinely
  # not resolvable.
  - >
    command -v bpftool >/dev/null 2>&1 ||
    { [ -x "/usr/lib/linux-tools/\$(uname -r)/bpftool" ] &&
      ln -sf "/usr/lib/linux-tools/\$(uname -r)/bpftool" /usr/local/sbin/bpftool; } ||
    true
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
    # netplan v2 default route. \`gateway4:\` is deprecated — cloud-init on
    # 24.04 and 26.04 both log
    #   WARNING: \`gateway4\` has been deprecated, use default routes instead.
    # and it will eventually stop working.
    routes:
      - to: default
        via: ${GATEWAY}
    nameservers:
      addresses: [${DNS_YAML}]
renderer: networkd
EOF

echo "Building NoCloud seed ISO..."
sudo cloud-localds -v --network-config="$SEED_DIR/network-config" "$SEED_ISO" "$SEED_DIR/user-data" "$SEED_DIR/meta-data"

# os-variant: Noble (ubuntu24.04) is well-known to libosinfo. Fall back to a
# generic value if this host's osinfo db predates it.
OS_VARIANT="ubuntu24.04"
if ! osinfo-query os 2>/dev/null | awk '{print $1}' | grep -qx ubuntu24.04; then
  OS_VARIANT="ubuntu22.04"
  echo "NOTE: this host's osinfo-db does not know ubuntu24.04; falling back to"
  echo "      --os-variant ${OS_VARIANT}. The guest is therefore DESCRIBED to libvirt"
  echo "      as 22.04. Harmless here (virtio everywhere, and the variant only"
  echo "      feeds device/feature hints), but it is what \`virsh dominfo\` will"
  echo "      report. Install a newer osinfo-db to remove the discrepancy."
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
  "${CONSOLE_ARGS[@]}" \
  --import \
  --noautoconsole \
  --autostart \
  --boot uefi

cat <<EOF

VM ${VM_NAME} is booting (Noble 24.04, kernel 6.8). cloud-init will:
  1. install clang / libbpf-dev / libsodium-dev / linux-tools / kernel headers
  2. add 'bpf' to the active LSM list via /etc/default/grub.d/
  3. update-grub
  4. reboot once at the end (look for power_state in cloud-init log)

After that reboot, validate from the host:

  ssh ${USERNAME}@${VM_IP} 'cat /sys/kernel/security/lsm'
  # must include 'bpf'

Then sync the compartment-bpf source and run the smoke gate:

  rsync -a --exclude=.git/ <checkout>/compartment-bpf/ ${USERNAME}@${VM_IP}:~/compartment-bpf/
  ssh ${USERNAME}@${VM_IP} "bash -lc 'cd ~/compartment-bpf && make vmlinux.h && make && sudo make check'"

\`make check\` runs every gate and prints a per-target transcript; the last
lines are the howto-examples tally, and the run is green when it exits 0.
\`sudo make smoke\` on its own is the one that prints 'smoke ok'. For the
strict gate — where an unrecognised SKIP is a failure — use:

  ssh ${USERNAME}@${VM_IP} "bash -lc 'cd ~/compartment-bpf && sudo make check-release'"
  # ends with: [check-release] PASS ...

Boot/console log for this VM: ${CONSOLE_LOG:-<pty; use \`virsh console ${VM_NAME}\`>}

This VM is key-only by default. Set SSH_AUTH_KEYS_FILE to control which
public keys are injected into ${USERNAME} and root.

Re-run this script to bring back a fresh VM with the same IP/MAC.
EOF
