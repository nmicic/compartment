#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Bypass class: mount --bind a decoy file over the sealed path so the path
# resolves to a different, unsealed inode.
#
# Pre-v0.8 this was a documented GAP: the bind succeeded, writes via the
# path hit the decoy, and only the original inode (reached via a saved
# hardlink) stayed protected. v0.8 attaches lsm/sb_mount + lsm/move_mount:
# attaching a mount ON a sealed inode (or anywhere inside a sealed subtree)
# is denied with ACTION_DENY_MOUNT. This witness asserts:
#   C   bind-mount over an UNSEALED sibling still works (hook is targeted,
#       and the host can bind-mount at all — otherwise SKIP);
#   W1  bind-mount over the sealed file FAILS;
#   W2  open-write via the path still hits the sealed inode → DENY;
#   W3  the saved hardlink is still DENY (inode seal intact);
#   A   the daemon logged DENY_MOUNT.
# A bind that succeeds is a regression → FAIL.
# Suggestion ID: 4.2g
set -u
BYPASS_NAME="07-mount-bind-decoy"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
TARGET="$TMP/target"
DECOY="$TMP/decoy"
CONTROL="$TMP/control"
SAFE_HARDLINK="$TMP/saved-hardlink"
echo original > "$TARGET"
echo decoy_payload > "$DECOY"
echo control > "$CONTROL"
ln "$TARGET" "$SAFE_HARDLINK"  # alternate path to the same inode

echo "seal $TARGET no-write,no-unlink" > "$TMP/policy.conf"
DAEMON_LOG="$TMP/daemon.err"
"$DAEMON" "$TMP/policy.conf" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
trap '
	umount "$TARGET" 2>/dev/null
	umount "$CONTROL" 2>/dev/null
	[ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null
	rm -rf "$TMP"
' EXIT INT TERM
for _ in $(seq 1 100); do
	grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null && break
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null \
	|| { echo "FAIL ${BYPASS_NAME}: daemon did not go live" >&2; exit 1; }

# C: control bind over an unsealed sibling.
mount --bind "$DECOY" "$CONTROL" 2>/dev/null \
	|| bypass_skip "control bind-mount failed (need privileged mount)"
umount "$CONTROL" 2>/dev/null || true

# W1: bind over the sealed file must be denied.
if mount --bind "$DECOY" "$TARGET" 2>/dev/null; then
	umount "$TARGET" 2>/dev/null || true
	bypass_fail "BYPASS: bind-mount over sealed path succeeded (comp_sb_mount did not deny)"
fi

# W2: path still resolves to the sealed inode.
"$SEALPROBE" open-write "$TARGET" >/dev/null 2>&1; rc_path=$?
# W3: saved hardlink still denied.
"$SEALPROBE" open-write "$SAFE_HARDLINK" >/dev/null 2>&1; rc_link=$?

# A: audit witness. The ringbuf consumer prints asynchronously; poll.
audit_ok=0
for _ in $(seq 1 20); do
	grep -q 'DENY_MOUNT' "$DAEMON_LOG" 2>/dev/null && { audit_ok=1; break; }
	sleep 0.1
done

if [ "$rc_path" -eq 1 ] && [ "$rc_link" -eq 1 ] && [ "$audit_ok" -eq 1 ]; then
	bypass_pass "bind-mount over sealed path denied (DENY_MOUNT audited); path and hardlink both still DENY; control mount on unsealed sibling allowed"
else
	bypass_fail "unexpected: path_rc=$rc_path hardlink_rc=$rc_link audit=$audit_ok (want 1/1/1)"
fi
