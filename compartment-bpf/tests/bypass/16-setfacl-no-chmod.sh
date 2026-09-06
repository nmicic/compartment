#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/16-setfacl-no-chmod.sh
#
# Bypass class: POSIX ACL write on a `no-chmod` sealed file. Since Linux
# 6.2, setxattr(2)/removexattr(2) on system.posix_acl_access are routed to
# vfs_set_acl()/vfs_remove_acl(), which call the inode_set_acl /
# inode_remove_acl LSM hooks and NOT inode_setxattr / inode_removexattr.
# Pre-v0.8 compartment-bpf hooked only the xattr pair, so `setfacl` could
# rewrite the effective permission bits of a sealed file (the ACL mask is
# mirrored into the group bits) while a plain `chmod` was denied.
#
# v0.8 attaches comp_inode_set_acl / comp_inode_remove_acl. Witnesses:
#   W1  setfacl -m (modify entry → set_acl)      on sealed target → DENY
#   W2  setfacl -x (drop entry   → set_acl)      on sealed target → DENY
#   W3  setfacl -b (strip all    → remove_acl)   on sealed target → DENY
#   U   getfacl output identical before/after W1..W3
#   C   setfacl -m on an unsealed sibling → ALLOW (hook is targeted)
#   A   DENY_CHMOD audit line present
set -u
BYPASS_NAME="16-setfacl-no-chmod"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env
command -v setfacl >/dev/null 2>&1 || bypass_skip "setfacl not installed (apt install acl)"
command -v getfacl >/dev/null 2>&1 || bypass_skip "getfacl not installed (apt install acl)"

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
TARGET="$TMP/target"
CONTROL="$TMP/control"
echo content > "$TARGET"
echo content > "$CONTROL"

# Stage an ACL on the target BEFORE policy load so -x / -b have something
# to remove, and prove the filesystem supports ACLs at all.
setfacl -m u:65534:rw "$TARGET" 2>/dev/null \
	|| bypass_skip "filesystem under $TMP does not support POSIX ACLs"
before=$(getfacl -n -p --omit-header "$TARGET" 2>/dev/null) \
	|| bypass_die "getfacl on staged target failed"
printf '%s\n' "$before" | grep -q '^user:65534:rw-' \
	|| bypass_die "staged ACL entry not visible in getfacl output"

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

# W1: modify → set_acl.
if setfacl -m u:65534:rwx "$TARGET" 2>/dev/null; then
	bypass_fail "W1 BYPASS: setfacl -m succeeded on no-chmod sealed file (inode_set_acl not enforced)"
fi
# W2: drop one entry → set_acl with a reduced ACL.
if setfacl -x u:65534 "$TARGET" 2>/dev/null; then
	bypass_fail "W2 BYPASS: setfacl -x succeeded on no-chmod sealed file (inode_set_acl not enforced)"
fi
# W3: strip all extended entries → remove_acl.
if setfacl -b "$TARGET" 2>/dev/null; then
	bypass_fail "W3 BYPASS: setfacl -b succeeded on no-chmod sealed file (inode_remove_acl not enforced)"
fi

# U: the ACL must be byte-identical to the staged one.
after=$(getfacl -n -p --omit-header "$TARGET" 2>/dev/null)
[ "$before" = "$after" ] \
	|| bypass_fail "U: ACL changed despite denies. before=[$before] after=[$after]"

# C: unsealed sibling still accepts ACL writes.
setfacl -m u:65534:rw "$CONTROL" 2>/dev/null \
	|| bypass_fail "C: setfacl on UNSEALED control file failed — hook is over-denying"

# A: audit witness (asynchronous ringbuf consumer; poll).
audit_ok=0
for _ in $(seq 1 20); do
	grep -q 'DENY_CHMOD' "$DAEMON_LOG" 2>/dev/null && { audit_ok=1; break; }
	sleep 0.1
done
[ "$audit_ok" -eq 1 ] || bypass_fail "A: no DENY_CHMOD audit line for the ACL denies"

bypass_pass "setfacl -m/-x/-b denied on no-chmod seal (ACL unchanged, DENY_CHMOD audited); control file still accepts ACL writes"
