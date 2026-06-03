#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/duplicate-seal-merge.sh — regression test for Codex finding 1.
#
# A profile listing the same path twice with different flags must leave
# BOTH flags active. Pre-fix `seal_path` used `bpf_map_update_elem(...,
# BPF_ANY)` unconditionally, so the second update overwrote the first and
# only the most-recent flag bit was honored.
#
# Profile under test:
#   seal $TARGET no-write
#   seal $TARGET no-unlink
# Expected post-fix: open-write DENY *and* unlink DENY.
# Pre-fix: open-write would ALLOW (no-write dropped), unlink DENY.
#
# Runs on the VM. Defaults to VM workdir /root/compartment-bpf;
# override with REPO=/elsewhere.
set -u

REPO=${REPO:-/root/compartment-bpf}
DAEMON="$REPO/compartment-bpf"
SEALPROBE="$REPO/tests/sealprobe"

[ "$(id -u)" -eq 0 ] || { echo "SKIP duplicate-seal-merge: needs root" >&2; exit 77; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| { echo "SKIP duplicate-seal-merge: bpf not in active LSM" >&2; exit 77; }
[ -x "$DAEMON" ]    || { echo "SKIP duplicate-seal-merge: daemon not built" >&2; exit 77; }
[ -x "$SEALPROBE" ] || { echo "SKIP duplicate-seal-merge: sealprobe not built" >&2; exit 77; }

TMP=$(mktemp -d /tmp/dup-seal.XXXXXX)
TARGET="$TMP/file"
PROFILE="$TMP/policy.conf"
LOG="$TMP/daemon.err"
echo content > "$TARGET"

cat > "$PROFILE" <<EOF
seal $TARGET no-write
seal $TARGET no-unlink
EOF

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
		|| { echo "FAIL duplicate-seal-merge: daemon died during attach"; cat "$LOG" >&2; exit 1; }
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$LOG" 2>/dev/null \
	|| { echo "FAIL duplicate-seal-merge: daemon did not go live"; cat "$LOG" >&2; exit 1; }

# Daemon should print the merged flags. SEAL_NO_WRITE=0x4, SEAL_NO_UNLINK=0x1.
# Merged: 0x5. Pre-fix would print 0x1 on the SECOND seal line, which is
# the only line that reached the map. Use this as a fast secondary signal.
flags_line=$(grep "ino=.* flags=" "$LOG" | tail -1 || true)
case "$flags_line" in
	*flags=0x5*) ;;
	*) echo "FAIL duplicate-seal-merge: expected merged flags=0x5 in '$flags_line'"; exit 1 ;;
esac

# Primary check: actual deny behavior for both flags.
"$SEALPROBE" open-write "$TARGET" >/dev/null 2>&1; rc_w=$?
"$SEALPROBE" unlink "$TARGET" >/dev/null 2>&1; rc_u=$?

if [ "$rc_w" -eq 1 ] && [ "$rc_u" -eq 1 ]; then
	echo "PASS duplicate-seal-merge: both no-write (rc=$rc_w) and no-unlink (rc=$rc_u) honored"
	exit 0
fi
echo "FAIL duplicate-seal-merge: open-write rc=$rc_w (want 1), unlink rc=$rc_u (want 1)"
exit 1
