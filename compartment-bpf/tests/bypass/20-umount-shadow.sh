#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/20-umount-shadow.sh
#
# Bypass class: path shadowing by DETACHING the filesystem instead of
# mounting over it. v0.8's sb_mount / move_mount gate covers the mount
# DESTINATION, so `mount -t tmpfs none /sealed` is denied — but nothing
# stopped `umount -l /data` first. Once the filesystem is detached the
# sealed path resolves to the mountpoint dentry in the PARENT filesystem,
# which carries no seal, and the follow-up mount sails straight through the
# destination gate. The sealed inodes are untouched and completely
# unreachable; every sealed path now reads attacker content.
#
# In daemon mode the loader's held O_PATH fds make a plain umount EBUSY, but
# that is an implementation accident, not a control: `umount -l` detaches
# regardless, and in daemonless `--pin` mode the fds died with the loader.
#
# v0.8 closes it with lsm/sb_umount plus a loader-populated sealed_devs
# (s_dev) map, denying with ACTION_DENY_UMOUNT.
#
# Witnesses (a tmpfs mounted at $MNT, one file on it sealed no-write):
#   C   an UNRELATED tmpfs mount must still umount cleanly (over-deny guard,
#       run first so a host that cannot mount SKIPs instead of false-passing)
#   W1  umount $MNT                    -> DENY
#   W2  umount -l $MNT (MNT_DETACH)    -> DENY
#   W3  move_mount(2) of $MNT elsewhere -> DENY (via helpers/mount_witness.c).
#       Deliberately NOT `mount --move`: mount(2) with MS_MOVE runs
#       do_move_mount_old(), which calls do_move_mount() directly and never
#       security_move_mount(), so a shell `mount --move` probe cannot tell our
#       deny apart from the EINVAL a shared-propagation parent returns — it
#       would be a false pass. The MS_MOVE-from-side residual is documented in
#       LIMITATIONS.md; move_mount(2) is the shape this hook can actually see.
#   S   the sealed file is still there and still enforced afterwards
#   G   umount of a BIND mount of a subdirectory of the sealed fs is
#       ALLOWED — the filesystem is not detached by it, and denying it
#       would make every bind mount of a root-fs directory unmountable on
#       any host that seals a single file on /
#   A   DENY_UMOUNT audit line present
set -u
BYPASS_NAME="20-umount-shadow"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
MNT="$TMP/fs"
CTRL="$TMP/ctrl"
MOVED="$TMP/moved"
BINDSRC_MP="$TMP/bind"
mkdir -p "$MNT" "$CTRL" "$MOVED" "$BINDSRC_MP"

# Teardown order matters here: the daemon must die BEFORE the umounts,
# because while it is live comp_sb_umount denies exactly the umount this
# cleanup needs to do — which would leave a stray tmpfs mount and make
# bypass_teardown's `rm -rf` fail with EBUSY. Kill first, then unmount, then
# let bypass_teardown remove the tree.
_u20_cleanup() {
	if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
		kill "$DAEMON_PID" 2>/dev/null || true
		wait "$DAEMON_PID" 2>/dev/null || true
		DAEMON_PID=""
	fi
	for m in "$BINDSRC_MP" "$MOVED" "$MNT" "$CTRL"; do
		umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null || true
	done
	bypass_teardown
}
trap '_u20_cleanup' EXIT INT TERM

# C: control mount, before the daemon exists. Proves this host can mount and
# umount at all; a host that cannot SKIPs here rather than passing W1-W3
# vacuously.
mount -t tmpfs -o size=1M tmpfs "$CTRL" 2>/dev/null \
	|| bypass_skip "control tmpfs mount failed (need privileged mount)"
umount "$CTRL" 2>/dev/null \
	|| bypass_skip "control tmpfs umount failed (need privileged mount)"

mount -t tmpfs -o size=1M tmpfs "$MNT" 2>/dev/null \
	|| bypass_skip "tmpfs mount for the sealed filesystem failed"
mkdir -p "$MNT/sub"
TARGET="$MNT/target"
echo content > "$TARGET"

printf 'seal %s no-write\n' "$TARGET" > "$TMP/policy.conf"
DAEMON_LOG="$TMP/daemon.err"
"$DAEMON" "$TMP/policy.conf" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do
	grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null && break
	kill -0 "$DAEMON_PID" 2>/dev/null || { cat "$DAEMON_LOG" >&2; bypass_die "daemon died during attach"; }
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null \
	|| { cat "$DAEMON_LOG" >&2; bypass_die "daemon did not go live"; }

# W1: plain umount.
if umount "$MNT" 2>/dev/null; then
	bypass_fail "W1 BYPASS: umount of the filesystem hosting a sealed inode succeeded (comp_sb_umount did not deny)"
fi
# W2: lazy umount. This is the one the held-fd EBUSY never covered.
if umount -l "$MNT" 2>/dev/null; then
	bypass_fail "W2 BYPASS: umount -l (MNT_DETACH) of the sealed filesystem succeeded"
fi
# W3: move the filesystem away from under the sealed path, through
# move_mount(2) — the only spelling security_move_mount() sees.
MW="$TMP/mount_witness"
w3=77
if cc -O2 -Wall "$(dirname "$0")/helpers/mount_witness.c" -o "$MW" >"$TMP/mw-build.log" 2>&1; then
	"$MW" move-fs "$MNT" "$MOVED" >>"$DAEMON_LOG" 2>&1
	w3=$?
	if [ "$w3" -eq 0 ]; then
		umount "$MOVED" 2>/dev/null || true
		bypass_fail "W3 BYPASS: move_mount(2) moved the sealed filesystem away from its mountpoint (comp_move_mount from-side gate missing)"
	fi
	[ "$w3" -eq 1 ] || bypass_fail "W3 unexpected rc=$w3 from move_mount(2) (want 1=DENY; see $DAEMON_LOG)"
fi

# S: the seal is still in force and the path still resolves to it.
[ -f "$TARGET" ] || bypass_fail "S: sealed file vanished after the denied detaches"
"$SEALPROBE" open-write "$TARGET" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 1 ] \
	|| bypass_fail "S: write to the sealed file rc=$rc (want 1=DENY) — enforcement lost after the umount attempts"

# G: over-deny guard. A bind mount of a SUBDIRECTORY of the sealed
# filesystem shares its s_dev, but unmounting it detaches nothing: the
# filesystem stays mounted at $MNT and every path into it still resolves.
# Denying this shape would make every bind mount of a root-fs directory
# unmountable on a host that seals one file on /.
if mount --bind "$MNT/sub" "$BINDSRC_MP" 2>/dev/null; then
	umount "$BINDSRC_MP" 2>/dev/null \
		|| bypass_fail "G OVER-DENY: umount of a bind mount of a subdirectory of the sealed filesystem was denied; comp_sb_umount must require mnt_root == s_root"
	g_msg="bind-mount umount still allowed"
else
	g_msg="bind-mount over-deny guard skipped (bind mount unavailable)"
fi

# A: audit witness (asynchronous ringbuf consumer; poll).
audit_ok=0
for _ in $(seq 1 20); do
	grep -q 'DENY_UMOUNT' "$DAEMON_LOG" 2>/dev/null && { audit_ok=1; break; }
	sleep 0.1
done
[ "$audit_ok" -eq 1 ] || bypass_fail "A: no DENY_UMOUNT audit line for the detach denies"

w3msg="move_mount(2) denied"
[ "$w3" -eq 77 ] && w3msg="move_mount(2) sub-witness skipped (no compiler)"
bypass_pass "umount (W1) and umount -l (W2) of the filesystem hosting a sealed inode denied with DENY_UMOUNT, $w3msg (W3); seal still enforced afterwards (S); $g_msg (G)"
