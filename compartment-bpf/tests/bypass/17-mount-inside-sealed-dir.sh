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
#       namespace (MS_MOVE, dispatched by sb_mount)     → DENY
#   W5  raw mount(2) with MS_BIND|MS_PRIVATE onto DIR/sub → DENY.
#       path_mount() tests MS_BIND *before* the propagation bits, so a gate
#       that exempts on any propagation bit is defeated by one extra flag.
#       mount(8) cannot emit this single-syscall shape; helpers/mount_witness.c
#       does.
#   W6  open_tree(OPEN_TREE_CLONE) + move_mount(2) onto DIR/sub → DENY.
#       This is the only witness that reaches security_move_mount() without
#       first passing security_sb_mount(): `mount --move` runs
#       do_move_mount_old(), which never calls the move_mount hook. Without
#       W6, comp_move_mount could be entirely broken and W1-W5 would still
#       pass.
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

# W5/W6: raw-syscall shapes that mount(8) cannot express. Build the helper
# once; if there is no compiler, both sub-witnesses skip (they never turn the
# script's single label into a SKIP — the script still PASSes on W1-W4).
MW="$TMP/mount_witness"
w5=77; w6=77
if cc -O2 -Wall "$(dirname "$0")/helpers/mount_witness.c" -o "$MW" >"$TMP/mw-build.log" 2>&1; then
	# W5: MS_BIND|MS_PRIVATE — the propagation-exemption bypass.
	"$MW" bind-private "$SRC" "$DIR/sub" >>"$DAEMON_LOG" 2>&1
	w5=$?
	[ "$w5" -eq 0 ] && umount "$DIR/sub" 2>/dev/null
	# W6: new mount API. open_tree needs something to clone; $OUT is a plain
	# directory on the same fs, which open_tree(OPEN_TREE_CLONE) accepts.
	"$MW" opentree-move "$OUT" "$DIR/sub" >>"$DAEMON_LOG" 2>&1
	w6=$?
	[ "$w6" -eq 0 ] && umount "$DIR/sub" 2>/dev/null
fi
case "$w5" in
	1|77) ;;
	0) bypass_fail "W5 BYPASS: mount(2) MS_BIND|MS_PRIVATE attached inside the sealed subtree (comp_sb_mount exempts on a propagation bit — path_mount() dispatches MS_BIND first)" ;;
	*) bypass_fail "W5 unexpected rc=$w5 (see $DAEMON_LOG)" ;;
esac
case "$w6" in
	1|77) ;;
	0) bypass_fail "W6 BYPASS: open_tree(OPEN_TREE_CLONE)+move_mount(2) attached inside the sealed subtree (comp_move_mount did not deny)" ;;
	*) bypass_fail "W6 unexpected rc=$w6 (see $DAEMON_LOG)" ;;
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
w5msg="bind|private denied"; [ "$w5" -eq 77 ] && w5msg="bind|private sub-witness skipped (no compiler)"
w6msg="open_tree+move_mount denied"; [ "$w6" -eq 77 ] && w6msg="open_tree+move_mount sub-witness skipped (syscall/compiler unavailable)"
bypass_pass "mounts on/inside sealed dir denied (W1-W3), $w4msg (W4), $w5msg (W5), $w6msg (W6), alias from sealed dir allowed and still enforced (G), DENY_MOUNT audited"
