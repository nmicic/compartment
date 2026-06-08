#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/map-freeze-witness.sh — regression test for Codex finding 5.
#
# Pre-fix the sealed_inodes / sealed_dirs maps were left writable after
# the daemon went live. Root with CAP_BPF could BPF_MAP_UPDATE_ELEM /
# BPF_MAP_DELETE_ELEM to weaken or remove seals without crashing the
# daemon -- silent policy bypass.
#
# Post-fix the daemon calls bpf_map_freeze() on both maps after policy
# load. Update / delete then return EPERM. Lookups (LSM hot path) are
# unaffected.
#
# Witness: launch daemon, find map IDs via bpftool, attempt update,
# assert it fails with EPERM. Repeat for both maps.
set -u

REPO=${REPO:-/root/compartment-bpf}
DAEMON="$REPO/compartment-bpf"

[ "$(id -u)" -eq 0 ] || { echo "SKIP map-freeze-witness: needs root" >&2; exit 77; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| { echo "SKIP map-freeze-witness: bpf not in active LSM" >&2; exit 77; }
[ -x "$DAEMON" ] || { echo "SKIP map-freeze-witness: daemon not built" >&2; exit 77; }
command -v bpftool >/dev/null 2>&1 \
	|| { echo "SKIP map-freeze-witness: bpftool not available" >&2; exit 77; }

TMP=$(mktemp -d /tmp/freeze.XXXXXX)
TARGET="$TMP/file"
PROFILE="$TMP/policy.conf"
LOG="$TMP/daemon.err"
echo content > "$TARGET"
printf 'seal %s no-write\n' "$TARGET" > "$PROFILE"

cleanup() {
	if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
		kill "$PID" 2>/dev/null || true
		wait "$PID" 2>/dev/null || true
	fi
	rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

"$DAEMON" "$PROFILE" >"$LOG" 2>&1 &
PID=$!
for _ in $(seq 1 100); do
	grep -q '\[run\] compartment-bpf live' "$LOG" 2>/dev/null && break
	kill -0 "$PID" 2>/dev/null \
		|| { echo "FAIL map-freeze-witness: daemon died during attach"; cat "$LOG" >&2; exit 1; }
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$LOG" 2>/dev/null \
	|| { echo "FAIL map-freeze-witness: daemon did not go live"; cat "$LOG" >&2; exit 1; }

# Find map IDs. bpftool prints lines like:
#   <id>: hash  name sealed_inodes  flags ...
# We grep both names and yank the leading id.
sealed_inodes_id=$(bpftool map show 2>/dev/null \
	| awk '/name sealed_inodes/ { sub(":",""); print $1; exit }')
sealed_dirs_id=$(bpftool map show 2>/dev/null \
	| awk '/name sealed_dirs/ { sub(":",""); print $1; exit }')

if [ -z "$sealed_inodes_id" ] || [ -z "$sealed_dirs_id" ]; then
	echo "FAIL map-freeze-witness: could not find map IDs (inodes='$sealed_inodes_id' dirs='$sealed_dirs_id')"
	bpftool map show >&2 || true
	exit 1
fi

# Try to update each map. Both maps are hash with key=struct inode_key
# (16 bytes: dev __u64 + ino __u64) and value=struct seal_value (96 bytes,
# ABI v0.6). The original draft of this test used a 4-byte value=__u32;
# because the witness was orphaned (never wired into a gate) that size
# silently drifted as seal_value grew, and bpftool rejected the update on
# SIZE ("value expected 96 bytes got 4") BEFORE the kernel freeze check could
# return EPERM — masking exactly what this test claims to prove. Provide a
# correctly-sized value so the update reaches the frozen map and the EPERM is
# the genuine freeze rejection. 2026-06-08 coverage audit.
key_hex='0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0'
val_hex="$(for _ in $(seq 1 96); do printf '0 '; done)"

assert_eperm() {
	id=$1; name=$2
	out=$(bpftool map update id "$id" key hex $key_hex value hex $val_hex 2>&1)
	rc=$?
	if [ "$rc" -eq 0 ]; then
		echo "FAIL map-freeze-witness: update on $name (id=$id) succeeded; map not frozen"
		echo "$out" >&2
		return 1
	fi
	# bpftool surfaces errno via strerror; EPERM message is
	# "Operation not permitted" on glibc. Be lenient and accept either
	# substring.
	case "$out" in
		*"Operation not permitted"*|*EPERM*|*"errno 1"*) return 0 ;;
		*) echo "FAIL map-freeze-witness: update on $name failed with non-EPERM: $out"
		   return 1 ;;
	esac
}

if ! assert_eperm "$sealed_inodes_id" sealed_inodes; then exit 1; fi
if ! assert_eperm "$sealed_dirs_id" sealed_dirs; then exit 1; fi

# Sanity: lookups still work. We don't have a known key in dirs (no dir
# was sealed), but sealed_inodes has $TARGET's (dev, ino). Just dump.
bpftool map dump id "$sealed_inodes_id" >/dev/null 2>&1 \
	|| { echo "FAIL map-freeze-witness: lookup on frozen sealed_inodes failed"; exit 1; }

echo "PASS map-freeze-witness: sealed_inodes (id=$sealed_inodes_id) and sealed_dirs (id=$sealed_dirs_id) reject update with EPERM"
exit 0
