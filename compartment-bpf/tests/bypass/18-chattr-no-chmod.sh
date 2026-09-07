#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/18-chattr-no-chmod.sh
#
# Bypass class: inode flag ioctls on a `no-chmod` sealed file. chattr(1)
# uses FS_IOC_SETFLAGS, which changes inode metadata via ->fileattr_set and
# never passes inode_setattr or any xattr hook. Pre-v0.8 nothing in
# compartment-bpf saw it: root could set +i (wedging an actor that must
# write the file) or +a on a sealed inode. v0.8 attaches lsm/file_ioctl and
# gates FS_IOC_SETFLAGS / FS_IOC32_SETFLAGS / FS_IOC_FSSETXATTR /
# FS_IOC_SETVERSION under SEAL_NO_CHMOD.
#
# Witnesses:
#   P   pick a base dir whose filesystem supports FS_IOC_SETFLAGS (tmpfs
#       returns EOPNOTSUPP); /tmp then /var/tmp; else SKIP
#   W1  chattr +i on sealed target → DENY, lsattr shows no 'i'
#   W2  chattr +a on sealed target → DENY, lsattr shows no 'a'
#   W3  32-bit (i386) FS_IOC32_SETFLAGS on sealed target → DENY. A compat
#       process enters COMPAT_SYSCALL_DEFINE3(ioctl), which calls
#       security_file_ioctl_compat() and never security_file_ioctl(), so
#       lsm/file_ioctl alone does not see it. This is the only witness for
#       the lsm/file_ioctl_compat program. Skipped (not failed) when
#       gcc-multilib is absent — the script still emits one label.
#   C   chattr +a / -a on an unsealed sibling → ALLOW
#   A   DENY_CHMOD audit line present
set -u
BYPASS_NAME="18-chattr-no-chmod"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env
command -v chattr >/dev/null 2>&1 || bypass_skip "chattr not installed (e2fsprogs)"
command -v lsattr >/dev/null 2>&1 || bypass_skip "lsattr not installed (e2fsprogs)"

# P: substrate probe.
BASE=""
for d in /tmp /var/tmp; do
	[ -d "$d" ] || continue
	probe=$(mktemp "$d/bypass-chattr.XXXXXX" 2>/dev/null) || continue
	if chattr +a "$probe" 2>/dev/null; then
		chattr -a "$probe" 2>/dev/null || true
		rm -f "$probe"
		BASE=$d
		break
	fi
	rm -f "$probe"
done
[ -n "$BASE" ] || bypass_skip "no filesystem with FS_IOC_SETFLAGS support under /tmp or /var/tmp"

TMP=$(mktemp -d "$BASE/bypass.XXXXXX")
TARGET="$TMP/target"
CONTROL="$TMP/control"
echo content > "$TARGET"
echo content > "$CONTROL"
# Never leave immutable/append-only bits behind: teardown's rm -rf would
# fail with EPERM. The sealed target must never gain them; clear the
# control defensively.
trap 'chattr -i -a "$CONTROL" "$TARGET" 2>/dev/null; bypass_teardown' EXIT INT TERM

printf 'seal %s no-chmod\n' "$TARGET" > "$TMP/policy.conf"
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

flags_of() { lsattr -d "$1" 2>/dev/null | cut -d' ' -f1; }

# W1: immutable.
if chattr +i "$TARGET" 2>/dev/null; then
	chattr -i "$TARGET" 2>/dev/null || true
	bypass_fail "W1 BYPASS: chattr +i succeeded on no-chmod sealed file (file_ioctl gate missing)"
fi
case "$(flags_of "$TARGET")" in *i*) bypass_fail "W1: 'i' flag present after denied chattr" ;; esac

# W2: append-only.
if chattr +a "$TARGET" 2>/dev/null; then
	chattr -a "$TARGET" 2>/dev/null || true
	bypass_fail "W2 BYPASS: chattr +a succeeded on no-chmod sealed file (file_ioctl gate missing)"
fi
case "$(flags_of "$TARGET")" in *a*) bypass_fail "W2: 'a' flag present after denied chattr" ;; esac

# W3: 32-bit compat ioctl. Needs a multilib toolchain; without one the
# sub-witness reports "skipped" inside the PASS line rather than turning the
# whole script into a SKIP (W1/W2 still prove the native gate).
w3=77
if command -v gcc >/dev/null 2>&1 &&
   gcc -m32 -O2 -Wall "$(dirname "$0")/helpers/ioctl32_setflags.c" \
       -o "$TMP/ioctl32" >"$TMP/m32-build.log" 2>&1; then
	"$TMP/ioctl32" "$TARGET" >>"$DAEMON_LOG" 2>&1
	w3=$?
	[ "$w3" -eq 0 ] && chattr -i "$TARGET" 2>/dev/null
fi
case "$w3" in
	1|77) ;;
	0) bypass_fail "W3 BYPASS: 32-bit FS_IOC32_SETFLAGS set +i on a no-chmod sealed file (lsm/file_ioctl_compat not attached)" ;;
	*) bypass_fail "W3 unexpected rc=$w3 (see $DAEMON_LOG and $TMP/m32-build.log)" ;;
esac
case "$(flags_of "$TARGET")" in *i*) bypass_fail "W3: 'i' flag present after the 32-bit ioctl" ;; esac

# C: unsealed sibling still accepts flag changes.
chattr +a "$CONTROL" 2>/dev/null \
	|| bypass_fail "C: chattr +a on UNSEALED control failed — file_ioctl hook is over-denying"
chattr -a "$CONTROL" 2>/dev/null \
	|| bypass_fail "C: chattr -a on UNSEALED control failed"

# A: audit witness (asynchronous ringbuf consumer; poll).
audit_ok=0
for _ in $(seq 1 20); do
	grep -q 'DENY_CHMOD' "$DAEMON_LOG" 2>/dev/null && { audit_ok=1; break; }
	sleep 0.1
done
[ "$audit_ok" -eq 1 ] || bypass_fail "A: no DENY_CHMOD audit line for the ioctl denies"

w3msg="32-bit compat ioctl denied"
[ "$w3" -eq 77 ] && w3msg="32-bit compat sub-witness skipped (no gcc-multilib)"
bypass_pass "chattr +i/+a denied on no-chmod seal (flags unchanged, DENY_CHMOD audited); $w3msg (W3); control file still accepts chattr"
