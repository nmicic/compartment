#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Bypass class (Codex finding 3): rename a payload INTO a no-write dir.
# Pre-fix: comp_inode_rename only AND-masked SEAL_NO_RENAME on both
# old_dir and new_dir. `seal /etc no-write` left `mv payload /etc/payload`
# unblocked, even though `inode_create` would have stopped a fresh write.
# Post-fix: new_dir flags AND-mask {SEAL_NO_RENAME, SEAL_NO_WRITE}, so
# rename-into-no-write is denied and emits ACTION_DENY_WRITE.
set -u
BYPASS_NAME="11-rename-into-no-write-dir"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env

# We seal a DIR with no-write, not the file itself. bypass_setup seals a
# file by default; sub in a dir-targeted profile manually.
TMP=$(mktemp -d /tmp/bypass.XXXXXX)
SEALED_DIR="$TMP/sealed"
mkdir "$SEALED_DIR"
PAYLOAD="$TMP/payload"
echo content > "$PAYLOAD"

PROFILE="$TMP/policy.conf"
cat > "$PROFILE" <<EOF
seal $SEALED_DIR no-write
EOF

DAEMON_LOG="$TMP/daemon.err"
"$DAEMON" "$PROFILE" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
trap 'kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; rm -rf "$TMP"' EXIT INT TERM

for _ in $(seq 1 100); do
	grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null && break
	kill -0 "$DAEMON_PID" 2>/dev/null \
		|| { cat "$DAEMON_LOG" >&2; bypass_die "daemon died during attach"; }
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null \
	|| { cat "$DAEMON_LOG" >&2; bypass_die "daemon did not go live"; }

# Attempt: rename payload INTO the sealed dir.
"$SEALPROBE" rename "$PAYLOAD" "$SEALED_DIR/payload" >/dev/null 2>&1; rc=$?
case $rc in
	1) ;;  # DENY — good
	0) bypass_fail "BYPASS: rename into no-write dir succeeded" ;;
	*) bypass_fail "unexpected rc=$rc" ;;
esac

# Verify the audit emitted ACTION_DENY_WRITE_PARENT_DIR, NOT ACTION_DENY_RENAME.
# v0.6: rename INTO a no-write dir is denied via deny_dentry_parent_dir_action()
# on new_dentry, so the emitted action is DENY_WRITE_PARENT_DIR (the parent dir
# carries the seal, not the inode being created). A regression that flips the
# emitted action back to DENY_RENAME would still block the rename (rc check above
# passes), but the audit semantics would be wrong. Hard-assert the action name.
sleep 0.3   # ringbuf drain
if grep -q 'DENY_RENAME' "$DAEMON_LOG" && ! grep -q 'DENY_WRITE_PARENT_DIR' "$DAEMON_LOG"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "audit emitted DENY_RENAME but expected DENY_WRITE_PARENT_DIR on no-write new_dir"
fi
if ! grep -q 'DENY_WRITE_PARENT_DIR' "$DAEMON_LOG"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "expected DENY_WRITE_PARENT_DIR audit line on rename into no-write dir"
fi

bypass_pass "rename-into-no-write-dir denied (rc=DENY) and audit emitted DENY_WRITE_PARENT_DIR"
