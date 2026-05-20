#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/14-runtime-subtree-depth-cap.sh — BX-22
#
# Runtime companion to BX-20's attach-time depth-cap witness.
# Once a recursive no-write seal is live, an allowed actor must NOT be
# able to grow the protected subtree past COMPARTMENT_MAX_DIR_ANCESTORS
# by:
#   (1) mkdir at the boundary, or
#   (2) renaming a directory-with-subdirs deeper inside the same subtree.
set -u
BYPASS_NAME="14-runtime-subtree-depth-cap"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env

command -v cc >/dev/null 2>&1 || bypass_skip "no C compiler for actor helper"

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
ROOT="$TMP/root"
BOUNDARY_PARENT="$ROOT/d1/d2/d3/d4/d5/d6/d7"
SRC_DIR="$ROOT/src"
DEST_PARENT="$ROOT/d1/d2/d3/d4/d5"
IMPORT_DIR="$TMP/import-dir"
ACTOR_BIN="$TMP/depth-actor"
mkdir -p "$BOUNDARY_PARENT"
mkdir -p "$SRC_DIR/a/b"
mkdir -p "$DEST_PARENT"
mkdir -p "$IMPORT_DIR/sub"

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

# Phase A: actor-allowed mkdir at the boundary must fail closed.
set +e
"$ACTOR_BIN" mkdir "$BOUNDARY_PARENT/d8" >/dev/null 2>&1
rc_mkdir=$?
set -e
case $rc_mkdir in
	0) bypass_fail "actor mkdir created a level-cap directory under recursive sealed root" ;;
esac
[ ! -d "$BOUNDARY_PARENT/d8" ] || bypass_fail "boundary mkdir unexpectedly created $BOUNDARY_PARENT/d8"
sleep 0.3
if ! grep -q '\[audit\] DENY_CREATE' "$DAEMON_LOG"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "boundary mkdir deny lacked DENY_CREATE audit witness"
fi

# Phase B: same-root deepening rename of a directory that already has
# subdirectories must fail closed.
set +e
"$ACTOR_BIN" rename "$SRC_DIR" "$DEST_PARENT/src-moved" >/dev/null 2>&1
rc_mv_same=$?
set -e
case $rc_mv_same in
	0) bypass_fail "deepening rename within sealed subtree succeeded for directory-with-subdirs" ;;
esac
[ -d "$SRC_DIR" ] || bypass_fail "source subtree disappeared after denied deepening rename"
[ ! -e "$DEST_PARENT/src-moved" ] || bypass_fail "destination path exists after denied deepening rename"
sleep 0.3
if ! grep -q '\[audit\] DENY_RENAME' "$DAEMON_LOG"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "deepening rename deny lacked DENY_RENAME audit witness"
fi

# Phase C: importing a directory-with-subdirs from outside the sealed
# tree must also fail closed because the kernel-side hook cannot cheaply
# prove the imported subtree's max descendant depth in-hook.
set +e
"$ACTOR_BIN" rename "$IMPORT_DIR" "$ROOT/d1/d2/imported" >/dev/null 2>&1
rc_mv_import=$?
set -e
case $rc_mv_import in
	0) bypass_fail "imported directory-with-subdirs succeeded into sealed subtree despite unknown depth budget" ;;
esac
[ -d "$IMPORT_DIR" ] || bypass_fail "import source disappeared after denied import rename"
[ ! -e "$ROOT/d1/d2/imported" ] || bypass_fail "import destination exists after denied import rename"

bypass_pass "runtime depth-cap guard denied boundary mkdir (rc=$rc_mkdir), deepening same-root rename (rc=$rc_mv_same), and imported-subtree rename (rc=$rc_mv_import)"
