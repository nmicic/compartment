#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/15-runtime-subtree-alias-invariants.sh — BX-23
#
# Runtime companion to the loader's recursive subtree alias invariants.
# Once a recursive no-write seal is live, an allowed actor must NOT be
# able to:
#   (1) create a symlink under the sealed subtree;
#   (2) create a hardlink into the sealed subtree;
#   (3) create a hardlink out of the sealed subtree;
#   (4) rename a symlink or hardlinked file into the sealed subtree; or
#   (5) import/deepen a directory in ways the kernel cannot prove safe
#       without a subtree walk.
set -u
BYPASS_NAME="15-runtime-subtree-alias-invariants"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env

command -v cc >/dev/null 2>&1 || bypass_skip "no C compiler for actor helper"

audit_count() {
	count=$(grep -cE "$1" "$DAEMON_LOG" 2>/dev/null || true)
	[ -n "$count" ] || count=0
	printf '%s\n' "$count"
}

wait_for_audit_bump() {
	pattern=$1
	before=$2
	for _ in $(seq 1 30); do
		now=$(audit_count "$pattern")
		if [ "$now" -gt "$before" ]; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
ROOT="$TMP/root"
OUTSIDE="$TMP/outside"
ACTOR_BIN="$TMP/depth-actor"
mkdir -p "$ROOT/deepen/a/b" "$OUTSIDE"
mkdir -p "$ROOT/shallow-dir" "$OUTSIDE/import-dir"
: > "$ROOT/pinned.txt"
: > "$ROOT/shallow-dir/leaf.txt"
: > "$OUTSIDE/leaf.txt"
: > "$OUTSIDE/alias-target.txt"
: > "$OUTSIDE/import-dir/leaf.txt"
ln -s "$OUTSIDE" "$OUTSIDE/incoming-sym"
ln "$OUTSIDE/alias-target.txt" "$OUTSIDE/incoming-hard"

if ! cc -O2 -Wall "$(dirname "$0")/helpers/depth_actor.c" -o "$ACTOR_BIN" >/tmp/depth-actor-build.log 2>&1; then
	cat /tmp/depth-actor-build.log >&2 || true
	rm -f /tmp/depth-actor-build.log
	bypass_skip "failed to build depth actor helper"
fi
rm -f /tmp/depth-actor-build.log
chmod 0755 "$ACTOR_BIN"

PROFILE="$TMP/policy.conf"
cat > "$PROFILE" <<EOF
actor grow = $ACTOR_BIN

seal $ACTOR_BIN full
seal $ROOT no-write actor=grow
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

# Phase A: symlink creation inside the sealed subtree must fail closed.
before_create=$(audit_count '\[audit\] DENY_CREATE')
set +e
"$ACTOR_BIN" symlink "$OUTSIDE" "$ROOT/inside-symlink" >/dev/null 2>&1
rc_sym_create=$?
set -e
case $rc_sym_create in
	0) bypass_fail "actor-created symlink under recursive sealed root succeeded" ;;
esac
[ ! -e "$ROOT/inside-symlink" ] || bypass_fail "symlink unexpectedly created under sealed subtree"
if ! wait_for_audit_bump '\[audit\] DENY_CREATE' "$before_create"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "symlink-in-subtree deny lacked DENY_CREATE audit witness"
fi

# Phase B: hardlink creation into the sealed subtree must fail closed.
before_create=$(audit_count '\[audit\] DENY_CREATE')
set +e
"$ACTOR_BIN" link "$OUTSIDE/leaf.txt" "$ROOT/imported-hard" >/dev/null 2>&1
rc_link_in=$?
set -e
case $rc_link_in in
	0) bypass_fail "hardlink into recursive sealed root succeeded" ;;
esac
[ ! -e "$ROOT/imported-hard" ] || bypass_fail "hardlink unexpectedly created inside sealed subtree"
if ! wait_for_audit_bump '\[audit\] DENY_CREATE' "$before_create"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "hardlink-into-subtree deny lacked DENY_CREATE audit witness"
fi

# Phase C: hardlink creation out of the sealed subtree must fail closed.
before_write_parent=$(audit_count '\[audit\] DENY_WRITE_PARENT_DIR')
set +e
"$ACTOR_BIN" link "$ROOT/pinned.txt" "$OUTSIDE/exported-hard" >/dev/null 2>&1
rc_link_out=$?
set -e
case $rc_link_out in
	0) bypass_fail "hardlink out of recursive sealed root succeeded" ;;
esac
[ ! -e "$OUTSIDE/exported-hard" ] || bypass_fail "hardlink unexpectedly created outside from sealed subtree"
if ! wait_for_audit_bump '\[audit\] DENY_WRITE_PARENT_DIR' "$before_write_parent"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "hardlink-out-of-subtree deny lacked DENY_WRITE_PARENT_DIR audit witness"
fi

# Phase D: rename-import of a symlink must fail closed.
# Under a `seal $ROOT no-write` profile the destination-parent directory is
# covered by parent-dir no-write, so the DENY_WRITE_PARENT_DIR check in
# comp_inode_rename typically fires before the alias-invariant DENY_RENAME
# branch is reached. Either witness is correct evidence of fail-closed;
# the test asserts the security property (deny + audit), not which branch fired.
RENAME_AUDIT='\[audit\] DENY_(RENAME|WRITE_PARENT_DIR)'
before_rename=$(audit_count "$RENAME_AUDIT")
set +e
"$ACTOR_BIN" rename "$OUTSIDE/incoming-sym" "$ROOT/incoming-sym" >/dev/null 2>&1
rc_mv_sym=$?
set -e
case $rc_mv_sym in
	0) bypass_fail "rename-import of symlink into recursive sealed root succeeded" ;;
esac
[ -L "$OUTSIDE/incoming-sym" ] || bypass_fail "symlink source disappeared after denied rename-import"
[ ! -e "$ROOT/incoming-sym" ] || bypass_fail "symlink destination exists after denied rename-import"
if ! wait_for_audit_bump "$RENAME_AUDIT" "$before_rename"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "symlink rename-import deny lacked DENY_RENAME|DENY_WRITE_PARENT_DIR audit witness"
fi

# Phase E: rename-import of a hardlinked file must fail closed.
before_rename=$(audit_count "$RENAME_AUDIT")
set +e
"$ACTOR_BIN" rename "$OUTSIDE/incoming-hard" "$ROOT/incoming-hard" >/dev/null 2>&1
rc_mv_hard=$?
set -e
case $rc_mv_hard in
	0) bypass_fail "rename-import of hardlinked file into recursive sealed root succeeded" ;;
esac
[ -e "$OUTSIDE/incoming-hard" ] || bypass_fail "hardlink source disappeared after denied rename-import"
[ ! -e "$ROOT/incoming-hard" ] || bypass_fail "hardlink destination exists after denied rename-import"
if ! wait_for_audit_bump "$RENAME_AUDIT" "$before_rename"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "hardlink rename-import deny lacked DENY_RENAME|DENY_WRITE_PARENT_DIR audit witness"
fi

# Phase F: importing a file-only directory from outside must fail closed.
before_rename=$(audit_count "$RENAME_AUDIT")
set +e
"$ACTOR_BIN" rename "$OUTSIDE/import-dir" "$ROOT/import-dir" >/dev/null 2>&1
rc_mv_import_dir=$?
set -e
case $rc_mv_import_dir in
	0) bypass_fail "outside directory import into recursive sealed root succeeded" ;;
esac
[ -d "$OUTSIDE/import-dir" ] || bypass_fail "directory import source disappeared after denied rename"
[ ! -e "$ROOT/import-dir" ] || bypass_fail "directory import destination exists after denied rename"
if ! wait_for_audit_bump "$RENAME_AUDIT" "$before_rename"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "outside directory import deny lacked DENY_RENAME|DENY_WRITE_PARENT_DIR audit witness"
fi

# Phase G: same-seal deepening rename of a file-only directory must also
# fail closed; this locks the portable rule that no runtime path depends
# on filesystem-specific i_nlink directory semantics.
#
# Note: under this fixture (`seal $ROOT no-write` recursive), the
# destination-parent directory is also covered by parent-dir no-write, so
# the deny may come from `deny_dentry_parent_dir_action`
# (DENY_WRITE_PARENT_DIR at comp_inode_rename:~1099) before reaching the
# depth-cap guard `deny_dir_rename_subtree_depth_cap` (DENY_RENAME at ~1114).
# Either branch is a correct fail-closed outcome; this test proves the
# end-to-end property (rename denied + audited), not which guard fired.
# Isolating the depth-cap branch specifically would require a fixture
# where the destination parent is NOT covered by SEAL_NO_WRITE. That
# targeted witness is deferred.
before_rename=$(audit_count "$RENAME_AUDIT")
set +e
"$ACTOR_BIN" rename "$ROOT/shallow-dir" "$ROOT/deepen/a/b/shallow-dir-moved" >/dev/null 2>&1
rc_mv_deepen=$?
set -e
case $rc_mv_deepen in
	0) bypass_fail "same-seal deepening rename of file-only directory succeeded" ;;
esac
[ -d "$ROOT/shallow-dir" ] || bypass_fail "same-seal source directory disappeared after denied deepening rename"
[ ! -e "$ROOT/deepen/a/b/shallow-dir-moved" ] || bypass_fail "same-seal deepening destination exists after denied rename"
if ! wait_for_audit_bump "$RENAME_AUDIT" "$before_rename"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "same-seal deepening rename deny lacked DENY_RENAME|DENY_WRITE_PARENT_DIR audit witness"
fi

bypass_pass "runtime recursive subtree alias invariants held: symlink create, hardlink in/out, symlink+hardlink rename-import, outside dir import, and same-seal deepening rename all denied (deny branch may be parent-dir DENY_WRITE_PARENT_DIR or depth-cap DENY_RENAME — both correct outcomes)"
