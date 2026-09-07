#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# 24-bpffs-umount.sh — detaching or shadowing the bpffs that holds the pins.
#
# Measured on stock v0.8, both kernels:
#   * `umount /sys/fs/bpf` and `umount -l /sys/fs/bpf` both succeed. On a box
#     where nothing else holds that superblock, enforcement is gone within 6s:
#     the lazy unmount does NOT leave a usefully long-lived superblock.
#   * On a box where another mount namespace holds a peer mount of the same
#     bpffs — observed on 7.0.0-31, polkitd runs with a read-only /sys/fs/bpf
#     of its own — the host-side umount instead ORPHANS the policy: the pins
#     are invisible from the host, enforcement stays live, and `--unpin`
#     reports "does not exist; nothing to do" and exits 0. The tree can then
#     only be cleared by entering that namespace or rebooting.
#   * `mount -t bpf bpf /sys/fs/bpf` over the live bpffs shadows the pin tree
#     with the same consequences and no unmount at all.
# Both outcomes are bad and both are denied here.
#
# Witnesses (policy pinned with --self-protect, daemon left running):
#   C   an unrelated tmpfs still unmounts cleanly (over-deny guard, first)
#   W1  umount /sys/fs/bpf        -> DENY
#   W2  umount -l /sys/fs/bpf     -> DENY
#   W3  mount -t bpf over it      -> DENY
#   S   /sys/fs/bpf is still mounted, the pins are still visible, the seal is
#       still enforced
#   A   DENY_UMOUNT / DENY_PIN_TAMPER audit lines present
set -u
# shellcheck disable=SC2034  # read by lib-bypass.sh after sourcing
BYPASS_NAME="24-bpffs-umount"
. "$(dirname "$0")/lib-bypass.sh"
. "$(dirname "$0")/lib-self-protect.sh"
sp_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
CTL="$TMP/ctl"
mkdir -p "$CTL"
# shellcheck disable=SC2034  # read by sp_teardown in lib-self-protect.sh
SP_MOUNTS="$CTL"
trap 'sp_teardown' EXIT INT TERM

# C first: a box that cannot mount at all must SKIP, not false-pass.
mount -t tmpfs -o size=1M tmpfs "$CTL" 2>/dev/null \
	|| bypass_skip "control tmpfs mount failed (need privileged mount)"
umount "$CTL" 2>/dev/null \
	|| bypass_skip "control tmpfs umount failed (need privileged mount)"

TARGET="$TMP/target"
echo content > "$TARGET"
printf 'seal %s full\n' "$TARGET" > "$TMP/policy.conf"
"$DAEMON" --dry-run "$TMP/policy.conf" >"$TMP/dry.log" 2>&1 \
	|| { cat "$TMP/dry.log" >&2; bypass_fail "baseline --dry-run failed"; }

SP_OWNER="$TMP/loader"
sp_install "$SP_OWNER"
sp_pin "$SP_OWNER" "$TMP/policy.conf" "$TMP/daemon.err"
before=$(sp_npins)

# W1
if umount /sys/fs/bpf 2>/dev/null; then
	# Put it back before failing so the box is not left without a bpffs.
	mountpoint -q /sys/fs/bpf || mount -t bpf -o mode=700 bpf /sys/fs/bpf 2>/dev/null
	bypass_fail "W1 BYPASS: umount of the bpffs holding the pins succeeded"
fi
# W2
if umount -l /sys/fs/bpf 2>/dev/null; then
	mountpoint -q /sys/fs/bpf || mount -t bpf -o mode=700 bpf /sys/fs/bpf 2>/dev/null
	bypass_fail "W2 BYPASS: umount -l (MNT_DETACH) of the pin bpffs succeeded"
fi
# W3
if mount -t bpf -o mode=700 bpf /sys/fs/bpf 2>/dev/null; then
	umount /sys/fs/bpf 2>/dev/null
	bypass_fail "W3 BYPASS: a second bpffs was mounted over the pin tree, shadowing it"
fi

# S
mountpoint -q /sys/fs/bpf || bypass_fail "S: /sys/fs/bpf is no longer mounted"
[ "$(sp_npins)" -eq "$before" ] \
	|| bypass_fail "S: pin count changed from $before to $(sp_npins) during the detach attempts"
if { echo tampered > "$TARGET"; } 2>/dev/null; then
	bypass_fail "S: the sealed file became writable after the detach attempts"
fi

# C again, with the policy live: an unrelated filesystem must still unmount.
mount -t tmpfs -o size=1M tmpfs "$CTL" 2>/dev/null \
	|| bypass_fail "C OVER-DENY: could not mount an unrelated tmpfs while a self-protected policy was live"
umount "$CTL" 2>/dev/null \
	|| bypass_fail "C OVER-DENY: an unrelated tmpfs became unmountable while a self-protected policy was live"

# A: the umount denies emit DENY_UMOUNT (shared with the sealed-filesystem
# gate, deliberately — see the comment on deny_umount_of_sealed_dev), the
# over-mount emits DENY_PIN_TAMPER.
sp_audit_wait "$TMP/daemon.err" 'DENY_UMOUNT' \
	|| bypass_fail "A: no DENY_UMOUNT audit line for the denied bpffs detaches"
sp_audit_wait "$TMP/daemon.err" 'DENY_PIN_TAMPER' \
	|| bypass_fail "A: no DENY_PIN_TAMPER audit line for the denied over-mount"

bypass_pass "umount (W1), umount -l (W2) and over-mounting a second bpffs (W3) on the filesystem holding the pins are all denied and audited (A); the pin tree, the mount and the seal all survived (S); an unrelated tmpfs still mounts and unmounts (C)"
