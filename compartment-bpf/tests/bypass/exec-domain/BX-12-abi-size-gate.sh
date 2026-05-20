#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-12-abi-size-gate.sh
# M-22: check_pinned_seal_map_shapes() rejects a pre-existing pinned seal
# map with the wrong value_size (simulating a v0 deployment that left a
# __u32-valued sealed_inodes map under PIN_ROOT).
#
# Mechanism: use bpftool to create a hash map with key_size=16 (matching
# struct inode_key) but value_size=4 (wrong; struct seal_value is 96 bytes
# in v0.5). Pin it at PIN_ROOT/maps/sealed_inodes. Run the loader with
# --parse-only (which triggers check_pinned_seal_map_shapes before the
# parse-only fork). Assert the loader refuses with the "pin-shape: refusing"
# diagnostic.
#
# Guard: skip if bpftool is unavailable or if PIN_ROOT/maps/sealed_inodes
# already exists from a running deployment (to avoid corrupting production).
set -u
BYPASS_NAME="BX-12-abi-size-gate"
. "$(dirname "$0")/../lib-bypass.sh"

bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)

if ! command -v bpftool >/dev/null 2>&1; then
	bypass_skip "bpftool not available"
fi

PIN_MAPS="/sys/fs/bpf/compartment/maps"
FAKE_INODE="$PIN_MAPS/sealed_inodes"

# Guard: do not clobber a real deployment.
if [ -e "$FAKE_INODE" ]; then
	bypass_skip "PIN_ROOT/maps/sealed_inodes already exists (live deployment?); skipping to avoid interference"
fi

# Create the directory structure on bpffs.
mkdir -p "$PIN_MAPS" 2>/dev/null || {
	bypass_skip "cannot create $PIN_MAPS (bpffs not mounted or no permission)"
}

# Create a hash map with correct key_size=16 but wrong value_size=4.
bpftool map create pinned "$FAKE_INODE" name sealed_inodes \
	type hash key 16 value 4 entries 256 flags 0 2>/dev/null
bpf_rc=$?
if [ "$bpf_rc" -ne 0 ]; then
	bypass_skip "bpftool map create failed (rc=$bpf_rc; bpffs or CAP_BPF issue)"
fi

# Minimal policy file (parse-only won't resolve paths).
echo "# abi-size-gate synthetic test" > "$TMP/policy.conf"

# Run the loader with --parse-only; check_pinned_seal_map_shapes fires
# before the parse-only branch and must reject the wrong-sized map.
OUT="$TMP/loader.err"
"$DAEMON" --parse-only "$TMP/policy.conf" >"$OUT" 2>&1
lrc=$?

# Clean up the fake pinned map regardless of outcome.
rm -f "$FAKE_INODE" 2>/dev/null || true

if [ "$lrc" -eq 0 ]; then
	bypass_fail "loader --parse-only succeeded with wrong-sized sealed_inodes map (ABI size gate did not fire)"
elif grep -q "pin-shape: refusing" "$OUT" 2>/dev/null; then
	bypass_pass "ABI size-gate: wrong sealed_inodes value_size=4 rejected by check_pinned_seal_map_shapes (M-22)"
else
	# Loader failed but not with the expected diagnostic.
	cat "$OUT" >&2
	bypass_fail "loader exited $lrc but 'pin-shape: refusing' not in output (unexpected failure mode)"
fi
