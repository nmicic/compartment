#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/17-mount-inside-sealed-dir.sh
#
# Bypass class: attach a mount INSIDE a recursively sealed directory (or on
# the sealed directory itself). The nested mount's dentry tree never reaches
# the sealed ancestor, so writes under the mountpoint were unenforced
# (pre-v0.8 LIMITATIONS "Mount-inside-sealed-subtree bypass").
#
# v0.8 attaches lsm/sb_mount + lsm/move_mount. Witnesses (DIR sealed
# `no-write`, recursive):
#   C   tmpfs mount on an unrelated dir works (host can mount; else SKIP)
#   W1  tmpfs mount ON the sealed dir                   → DENY
#   W2  tmpfs mount on DIR/sub  (depth 1 inside)        → DENY
#   W3  bind mount  on DIR/sub/deep (depth 2 inside)    → DENY
#   W4  mount --move of a tmpfs onto DIR/sub inside a private mount
#       namespace (MS_MOVE / move_mount(2))             → DENY
#   G   bind-mount FROM the sealed dir to an outside alias → ALLOW, and
#       create-in through the alias → DENY (aliasing must keep working;
#       the seal follows the shared dentries — guards against over-deny)
#   A   DENY_MOUNT audit line present
set -u
BYPASS_NAME="17-mount-inside-sealed-dir"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
DIR="$TMP/sealed"
OUT="$TMP/outside"
SRC="$TMP/srcdir"
ALIAS="$TMP/alias"
mkdir -p "$DIR/sub/deep" "$OUT" "$SRC" "$ALIAS"
echo content > "$DIR/sub/file"

printf 'seal %s no-write\n' "$DIR" > "$TMP/policy.conf"
DAEMON_LOG="$TMP/daemon.err"
"$DAEMON" "$TMP/policy.conf" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
trap '
	for m in "$ALIAS" "$OUT" "$DIR/sub/deep" "$DIR/sub" "$DIR"; do
		umount "$m" 2>/dev/null
	done
	[ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null
	rm -rf "$TMP"
' EXIT INT TERM
for _ in $(seq 1 100); do
	grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null && break
	kill -0 "$DAEMON_PID" 2>/dev/null || { cat "$DAEMON_LOG" >&2; bypass_die "daemon died during attach"; }
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null \
	|| { cat "$DAEMON_LOG" >&2; bypass_die "daemon did not go live"; }

# C: control mount outside the sealed tree.
mount -t tmpfs -o size=1M tmpfs "$OUT" 2>/dev/null \
	|| bypass_skip "control tmpfs mount failed (need privileged mount)"
umount "$OUT" 2>/dev/null || true

# W1: mount ON the sealed directory.
if mount -t tmpfs -o size=1M tmpfs "$DIR" 2>/dev/null; then
	umount "$DIR" 2>/dev/null || true
	bypass_fail "W1 BYPASS: tmpfs mounted ON sealed dir (comp_sb_mount did not deny)"
fi
# W2: mount one level inside.
if mount -t tmpfs -o size=1M tmpfs "$DIR/sub" 2>/dev/null; then
	umount "$DIR/sub" 2>/dev/null || true
	bypass_fail "W2 BYPASS: tmpfs mounted inside sealed subtree at depth 1"
fi
# W3: bind mount two levels inside.
if mount --bind "$SRC" "$DIR/sub/deep" 2>/dev/null; then
	umount "$DIR/sub/deep" 2>/dev/null || true
	bypass_fail "W3 BYPASS: bind mount inside sealed subtree at depth 2"
fi

# W4: MS_MOVE / move_mount(2). Done in a private mount namespace so the
# move is legal (moving a mount that lives under a shared mount is EINVAL
# on systemd hosts) and so nothing leaks past the subshell.
#   exit 77 = setup problem (skip this sub-witness)
#   exit 1  = move denied (expected)   exit 0 = move succeeded (bypass)
w4=77
if command -v unshare >/dev/null 2>&1; then
	unshare -m --propagation private sh -c "
		mount -t tmpfs -o size=1M tmpfs '$OUT' || exit 77
		if mount --move '$OUT' '$DIR/sub' 2>/dev/null; then exit 0; fi
		exit 1
	" >/dev/null 2>&1
	w4=$?
fi
case "$w4" in
	1|77) ;;
	0) bypass_fail "W4 BYPASS: mount --move onto a path inside the sealed subtree succeeded" ;;
	*) bypass_fail "W4 unexpected rc=$w4" ;;
esac

# G: aliasing FROM the sealed dir must still be allowed and still sealed.
mount --bind "$DIR" "$ALIAS" 2>/dev/null \
	|| bypass_fail "G: bind-mount FROM sealed dir to outside alias was denied — hook is over-denying (source is not a mountpoint under a seal)"
"$SEALPROBE" create-in "$ALIAS/sub" >/dev/null 2>&1; rc_alias=$?
umount "$ALIAS" 2>/dev/null || true
[ "$rc_alias" -eq 1 ] \
	|| bypass_fail "G: create-in through the alias rc=$rc_alias (want 1=DENY — seal must follow shared dentries)"

# A: audit witness (asynchronous ringbuf consumer; poll).
audit_ok=0
for _ in $(seq 1 20); do
	grep -q 'DENY_MOUNT' "$DAEMON_LOG" 2>/dev/null && { audit_ok=1; break; }
	sleep 0.1
done
[ "$audit_ok" -eq 1 ] || bypass_fail "A: no DENY_MOUNT audit line for the mount denies"

w4msg="move denied"; [ "$w4" -eq 77 ] && w4msg="move sub-witness skipped (unshare/tmpfs setup)"
bypass_pass "mounts on/inside sealed dir denied (W1-W3), $w4msg (W4), alias from sealed dir allowed and still enforced (G), DENY_MOUNT audited"
