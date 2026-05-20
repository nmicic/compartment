#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/12-deep-subtree-write.sh — BX-20 (V-7 P1-C)
#
# Witness the default COMPARTMENT_MAX_DIR_ANCESTORS=8 boundary directly.
# Without this test the verifier-friendly cap is unexercised: an
# off-by-one shift or a compile-time bump to a smaller value (e.g.
# the operator-driven 64→8 reduction) would not surface in CI.
#
# Phase A layout (in range):
#   $OK_DIR                                             seal full
#   $OK_DIR/d1/d2/d3/d4/d5/d6/d7/payload8               file at depth 8; parent walk finds seal at iter 7
#
# Phase B layout (too deep):
#   $DEEP_DIR                                           seal full
#   $DEEP_DIR/d1/d2/d3/d4/d5/d6/d7/d8/                  directory at level 8 from sealed root (dir-branch)
#   $DEEP_DIR/d1/d2/d3/d4/d5/d6/d7/d8/d9                file at level 9 from sealed root (non-dir-branch)
#
# Assertions:
#   phase A: in-range open-write → DENY  + DENY_WRITE* audit witness (V-7 P1-α)
#   phase B: over-deep subtree   → loader FAIL-CLOSED before attach (compiled-cap invariant)
#            rejection message MUST cite COMPARTMENT_MAX_DIR_ANCESTORS=<cap> so an operator
#            who tunes the cap via `make COMPARTMENT_MAX_DIR_ANCESTORS=N` sees the right
#            number — text-lock guard against the diagnostic going generic. (P2-3)
set -u
BYPASS_NAME="12-deep-subtree-write"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
OK_DIR="$TMP/in_range"
DEEP_DIR="$TMP/too_deep"
mkdir -p "$OK_DIR/d1/d2/d3/d4/d5/d6/d7"
mkdir -p "$DEEP_DIR/d1/d2/d3/d4/d5/d6/d7/d8"
# d9: regular file at level 9 from sealed root, exercising the non-dir
# branch (level > cap) of validate_recursive_dir_seal. Symmetric to the
# d8 directory at level 8 which exercises the dir branch (level >= cap).
: > "$DEEP_DIR/d1/d2/d3/d4/d5/d6/d7/d8/d9"
PAYLOAD8="$OK_DIR/d1/d2/d3/d4/d5/d6/d7/payload8"
: > "$PAYLOAD8"

PROFILE_OK="$TMP/policy-ok.conf"
cat > "$PROFILE_OK" <<PROF
seal $OK_DIR full
PROF

DAEMON_LOG_OK="$TMP/daemon-ok.err"
"$DAEMON" "$PROFILE_OK" >"$DAEMON_LOG_OK" 2>&1 &
DAEMON_PID=$!
trap 'if [ -n "${DAEMON_PID:-}" ]; then kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; fi; rm -rf "$TMP"' EXIT INT TERM

for _ in $(seq 1 100); do
	grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG_OK" 2>/dev/null && break
	kill -0 "$DAEMON_PID" 2>/dev/null \
		|| { cat "$DAEMON_LOG_OK" >&2; bypass_die "daemon died during attach (phase A)"; }
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG_OK" 2>/dev/null \
	|| { cat "$DAEMON_LOG_OK" >&2; bypass_die "phase A daemon did not go live"; }

# Phase A: in-range write must DENY.
"$SEALPROBE" open-write "$PAYLOAD8" >/dev/null 2>&1; rc8=$?
case $rc8 in
	1) ;;  # DENY — good
	0) bypass_fail "BYPASS: in-range depth-8 open-write succeeded under sealed root (recursive subtree walk regressed below cap)" ;;
	*) bypass_fail "unexpected rc=$rc8 on in-range depth-8 open-write" ;;
esac

# V-7 re-run #1 P1-α: rc=1 alone could be any EACCES; require an audit line.
# Poll for the audit row (10 × 0.1s) instead of fixed sleep; matches the
# pattern used elsewhere in the bypass suite and tolerates ringbuf flush
# jitter on busy VMs. (P2-4)
for _ in $(seq 1 10); do
	grep -qE '\[audit\] DENY_(WRITE|WRITE_PARENT_DIR)\b' "$DAEMON_LOG_OK" 2>/dev/null && break
	sleep 0.1
done
if ! grep -qE '\[audit\] DENY_(WRITE|WRITE_PARENT_DIR)\b' "$DAEMON_LOG_OK"; then
	cat "$DAEMON_LOG_OK" >&2
	bypass_fail "BX-20: depth-8 DENY fired but no DENY_WRITE* audit line"
fi

kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=

# Phase B: loader must REFUSE the over-deep subtree before going live.
# `validate_recursive_dir_seal` walks every sealed directory and rejects
# any descendant at depth >= COMPARTMENT_MAX_DIR_ANCESTORS (for dirs) or
# > cap (for non-dirs). Sealing $DEEP_DIR (which contains a level-8 dir)
# MUST trip this gate; if the daemon stays alive, the compiled-cap
# invariant has regressed.
PROFILE_DEEP="$TMP/policy-too-deep.conf"
cat > "$PROFILE_DEEP" <<PROF
seal $DEEP_DIR full
PROF

DAEMON_LOG_DEEP="$TMP/daemon-too-deep.err"
set +e
timeout --kill-after=1s 3s "$DAEMON" "$PROFILE_DEEP" >"$DAEMON_LOG_DEEP" 2>&1
rc_deep=$?
set -e
case $rc_deep in
	0)        cat "$DAEMON_LOG_DEEP" >&2; bypass_fail "UNEXPECTED-CLEAN-EXIT: loader returned 0 for over-deep subtree (rejection path may not have fired)" ;;
	124|137)  cat "$DAEMON_LOG_DEEP" >&2; bypass_fail "loader did NOT fail closed on over-deep subtree (timed out instead — compile-cap invariant regressed)" ;;
esac
if ! grep -q 'exceeds the compiled depth cap' "$DAEMON_LOG_DEEP"; then
	cat "$DAEMON_LOG_DEEP" >&2
	bypass_fail "loader rejected over-deep subtree without the expected depth-cap diagnostic"
fi
# P2-3 text-lock: the rejection diagnostic must cite the compiled cap value
# so a build with `make COMPARTMENT_MAX_DIR_ANCESTORS=N` surfaces N to the
# operator. Without this assertion the diagnostic could drift to a generic
# "subtree too deep" and the cap-tuning workflow would silently break.
if ! grep -q 'COMPARTMENT_MAX_DIR_ANCESTORS=8' "$DAEMON_LOG_DEEP" 2>/dev/null; then
	cat "$DAEMON_LOG_DEEP" >&2
	bypass_fail "phase-B rejection message did not cite COMPARTMENT_MAX_DIR_ANCESTORS=8"
fi

bypass_pass "deep subtree boundary: in-range depth-8 DENY + DENY_WRITE* audit witness; over-deep subtree rejected (rc=$rc_deep) with COMPARTMENT_MAX_DIR_ANCESTORS=8 diagnostic"
