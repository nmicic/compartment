#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Bypass class: mount --bind a decoy file over the sealed path. The path
# now resolves to a different inode; documented behavior is that path
# protection moves with the inode, so the original (dev, ino) is still
# sealed but the path is no longer protected.
#
# This test verifies the documented split:
#   - writes via the bind-mounted PATH succeed (the path now points to decoy)
#   - operations on the original inode (reached via a saved hardlink)
#     remain denied
# Either result deviating from the above is a behavior change worth noting.
# Suggestion ID: 4.2g
set -u
BYPASS_NAME="07-mount-bind-decoy"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
TARGET="$TMP/target"
DECOY="$TMP/decoy"
SAFE_HARDLINK="$TMP/saved-hardlink"
echo original > "$TARGET"
echo decoy_payload > "$DECOY"
ln "$TARGET" "$SAFE_HARDLINK"  # alternate path to the same inode

echo "seal $TARGET no-write,no-unlink" > "$TMP/policy.conf"
DAEMON_LOG="$TMP/daemon.err"
"$DAEMON" "$TMP/policy.conf" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
trap '
	mount | grep -q " on $TARGET " 2>/dev/null && umount "$TARGET" 2>/dev/null
	[ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null
	rm -rf "$TMP"
' EXIT INT TERM
for _ in $(seq 1 100); do
	grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null && break
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null \
	|| { echo "FAIL ${BYPASS_NAME}: daemon did not go live" >&2; exit 1; }

mount --bind "$DECOY" "$TARGET" || bypass_skip "bind-mount failed (need privileged mount)"

# Path now points at decoy: writes via TARGET should succeed (documented).
if "$SEALPROBE" open-write "$TARGET" >/dev/null 2>&1; then
	path_unprotected=1
else
	path_unprotected=0
fi

# Original inode (via saved hardlink) must remain protected.
"$SEALPROBE" open-write "$SAFE_HARDLINK" >/dev/null 2>&1; rc=$?

umount "$TARGET" 2>/dev/null || true

if [ "$path_unprotected" = 1 ] && [ "$rc" -eq 1 ]; then
	bypass_pass "bind-mount over path: path unprotected (documented), original inode still sealed"
else
	bypass_fail "unexpected: path_unprotected=$path_unprotected, hardlink_rc=$rc (expected path=1 hardlink=DENY)"
fi
