#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/13-deep-rename-into-sealed.sh — BX-21 (V-7 P1-D)
#
# Witness comp_inode_rename's ancestor walk past depth-1 (the regression
# class behind BX-11 was a depth-1-only fix; v0.6 recursive subtree
# protection extends to depth ≤ 8 but no test exercised depth ≥ 2).
#
# Setup:
#   $SEALED_DIR/d1/d2/                                   (depth-2 subdir of sealed dir)
#   $TMP/outside_payload                                  (file outside the sealed tree)
#   $SEALED_DIR/d1/d2/inside_payload                      (file already inside sealed tree)
#
# Assertions:
#   rename(outside → $SEALED_DIR/d1/d2/x)      → DENY  (new_parent ancestor walk: d2 → d1 → sealed)
#   rename($SEALED_DIR/d1/d2/inside_payload → $TMP/x)  → DENY  (old_parent ancestor walk)
set -u
BYPASS_NAME="13-deep-rename-into-sealed"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
SEALED_DIR="$TMP/sealed"
mkdir -p "$SEALED_DIR/d1/d2"
OUT_PAYLOAD="$TMP/outside_payload"
IN_PAYLOAD="$SEALED_DIR/d1/d2/inside_payload"
echo outside > "$OUT_PAYLOAD"
echo inside  > "$IN_PAYLOAD"

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

# 1) rename INTO depth-2 inside sealed tree must DENY.
"$SEALPROBE" rename "$OUT_PAYLOAD" "$SEALED_DIR/d1/d2/from_outside" >/dev/null 2>&1; rc_in=$?
case $rc_in in
	1) ;;  # DENY
	0) bypass_fail "BYPASS: rename INTO depth-2 sealed subtree succeeded (ancestor walk regressed at depth>=2)" ;;
	*) bypass_fail "unexpected rc=$rc_in on rename into sealed subtree" ;;
esac

# 2) rename OUT of depth-2 inside sealed tree must DENY.
#    (old_parent ancestor walk must also fire — `mv sealed/d1/d2/x /tmp/x`
#    is a structural mutation against the sealed subtree from the source side.)
"$SEALPROBE" rename "$IN_PAYLOAD" "$TMP/escaped_payload" >/dev/null 2>&1; rc_out=$?
case $rc_out in
	1) ;;  # DENY
	0) bypass_fail "BYPASS: rename OUT of depth-2 sealed subtree succeeded (old_parent ancestor walk regressed)" ;;
	*) bypass_fail "unexpected rc=$rc_out on rename out of sealed subtree" ;;
esac

# Verify audit emitted a deny line for both renames. The exact action
# (DENY_RENAME vs DENY_WRITE_PARENT_DIR) depends on which seal flag mask
# fires first; both are acceptable so long as the seal is reported.
# Poll for the audit row (10 × 0.1s) instead of a fixed sleep; tolerates
# ringbuf flush jitter under load. (P2-5)
for _ in $(seq 1 10); do
	grep -qE 'DENY_(RENAME|WRITE_PARENT_DIR|UNLINK)' "$DAEMON_LOG" 2>/dev/null && break
	sleep 0.1
done
if ! grep -qE 'DENY_(RENAME|WRITE_PARENT_DIR|UNLINK)' "$DAEMON_LOG"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "no DENY audit line emitted for depth-2 rename in/out"
fi

bypass_pass "deep-rename depth-2: into DENY (rc=$rc_in) + out DENY (rc=$rc_out)"
