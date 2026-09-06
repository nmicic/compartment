#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/19-utimes-no-chmod.sh
#
# Class: timestamp forgery on a directly sealed `no-chmod` file. Pre-v0.8
# the per-inode inode_setattr path only classified ATTR_MODE/UID/GID as
# chmod-class, so `touch -d` / utimensat(2) could rewrite atime/mtime on a
# sealed file (anti-forensics against an integrity baseline) while the
# parent-dir rule (v0.5) already treated every non-size attribute as
# chmod-class. v0.8 aligns the per-inode rule: ATTR_ATIME|ATTR_MTIME
# without ATTR_SIZE is chmod-class. Truncation (ATTR_SIZE + times) stays
# write-class — a `no-chmod`-only seal must NOT block it.
#
# Witnesses:
#   W1  touch -d <past> on sealed target (ATTR_*_SET) → DENY, mtime intact
#   W2  touch           on sealed target (ATTR_TOUCH) → DENY, mtime intact
#   W3  sealprobe chmod on sealed target → DENY (pre-existing behaviour)
#   R   sealprobe truncate on a second `no-chmod`-only file → ALLOW
#       (regression guard for the ATTR_SIZE exclusion)
#   C   touch -d on an unsealed sibling → ALLOW
#   A   DENY_CHMOD audit line present
set -u
BYPASS_NAME="19-utimes-no-chmod"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
TARGET="$TMP/target"
TRUNC="$TMP/trunc"
CONTROL="$TMP/control"
echo content > "$TARGET"
echo content > "$TRUNC"
echo content > "$CONTROL"

{
	printf 'seal %s no-chmod\n' "$TARGET"
	printf 'seal %s no-chmod\n' "$TRUNC"
} > "$TMP/policy.conf"
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

mtime_before=$(stat -c %Y "$TARGET")

# W1: explicit timestamp.
if touch -d '2001-02-03 04:05:06' "$TARGET" 2>/dev/null; then
	bypass_fail "W1 BYPASS: touch -d succeeded on no-chmod sealed file"
fi
# W2: touch-to-now (ATTR_TOUCH). Sleep so a successful touch would change
# the second-resolution mtime we compare below.
sleep 1
if touch "$TARGET" 2>/dev/null; then
	bypass_fail "W2 BYPASS: touch succeeded on no-chmod sealed file"
fi
mtime_after=$(stat -c %Y "$TARGET")
[ "$mtime_before" = "$mtime_after" ] \
	|| bypass_fail "mtime changed despite denies ($mtime_before -> $mtime_after)"

# W3: chmod still denied.
"$SEALPROBE" chmod "$TARGET" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 1 ] || bypass_fail "W3: chmod rc=$rc (want 1=DENY)"

# R: truncate on a no-chmod-only seal must remain ALLOW.
"$SEALPROBE" truncate "$TRUNC" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 0 ] || bypass_fail "R REGRESSION: truncate on no-chmod-only seal rc=$rc (want 0=ALLOW; ATTR_SIZE must stay write-class)"

# C: unsealed sibling.
touch -d '2001-02-03 04:05:06' "$CONTROL" 2>/dev/null \
	|| bypass_fail "C: touch -d on UNSEALED control failed — over-deny"

# A: audit witness (asynchronous ringbuf consumer; poll).
audit_ok=0
for _ in $(seq 1 20); do
	grep -q 'DENY_CHMOD' "$DAEMON_LOG" 2>/dev/null && { audit_ok=1; break; }
	sleep 0.1
done
[ "$audit_ok" -eq 1 ] || bypass_fail "A: no DENY_CHMOD audit line for the utimes denies"

bypass_pass "touch/touch -d denied on no-chmod seal (mtime intact, DENY_CHMOD audited); truncate on no-chmod-only seal still allowed; control file touchable"
