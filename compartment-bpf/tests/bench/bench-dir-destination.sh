#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# tests/bench/bench-dir-destination.sh — v0.6 subtree write-path overhead benchmark.
#
# Four scenarios (each N=10000 open+write+close iterations):
#   1. File write with no matching seal (baseline)
#   2. File write with direct inode seal (actor=bench-actor, caller=actor)
#   3. File write with parent directory destination seal (actor=bench-actor, caller=actor)
#   4. File write with parent directory destination seal, no matching actor (outsider)
#
# Reports:
#   - Absolute ns/iter for all four scenarios
#   - Incremental overhead of scenario 3 vs scenario 2 (dir-dest vs inode seal)
#
# Halt/review gate: >5% incremental overhead on scenario 3 vs scenario 2.
set -euo pipefail

: "${REPO:=$(realpath "$(dirname "$0")/../..")}"
DAEMON="$REPO/compartment-bpf"
ACTOR="$REPO/tests/mesh/build/mesh_actor_a1"
OUTSIDER="$REPO/tests/mesh/build/mesh_outsider_b1"

if [ "$(id -u)" -ne 0 ]; then
	echo "[bench] SKIP: needs root" >&2; exit 77
fi
if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
	echo "[bench] SKIP: bpf LSM not active" >&2; exit 77
fi
[ -x "$DAEMON" ]  || { echo "[bench] FAIL: $DAEMON not found" >&2; exit 1; }
[ -x "$ACTOR" ]   || { echo "[bench] FAIL: $ACTOR not found" >&2; exit 1; }
[ -x "$OUTSIDER" ] || { echo "[bench] FAIL: $OUTSIDER not found" >&2; exit 1; }

N=10000
TMP=$(mktemp -d /tmp/bench-dd.XXXXXX)
chmod 700 "$TMP"
cleanup() {
	if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
		kill -INT "$DAEMON_PID" 2>/dev/null || true
		for _ in $(seq 1 20); do
			kill -0 "$DAEMON_PID" 2>/dev/null || break
			sleep 0.1
		done
		kill -KILL "$DAEMON_PID" 2>/dev/null || true
		wait "$DAEMON_PID" 2>/dev/null || true
	fi
	rm -rf "$TMP" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Copy actor/outsider binaries to a root-owned 700 dir so the loader's
# parent-dir world/group-writable check does not reject them.
BENCH_BIN="$TMP/bin"
mkdir -p "$BENCH_BIN"
chmod 700 "$BENCH_BIN"
cp "$ACTOR"   "$BENCH_BIN/bench_actor"
cp "$OUTSIDER" "$BENCH_BIN/bench_outsider"
chmod 755 "$BENCH_BIN/bench_actor" "$BENCH_BIN/bench_outsider"
ACTOR="$BENCH_BIN/bench_actor"
OUTSIDER="$BENCH_BIN/bench_outsider"

# Fixture layout:
#   $TMP/baseline/leaf      — no seal
#   $TMP/inode-seal/leaf    — inode seal no-write actor=bench-actor
#   $TMP/dir-dest/leaf      — dir seal no-write actor=bench-actor (direct child)
#   $TMP/dir-dest-out/leaf  — dir seal no-write actor=bench-actor (outsider caller)
mkdir -p "$TMP/baseline" "$TMP/inode-seal" "$TMP/dir-dest" "$TMP/dir-dest-out"
chmod 700 "$TMP/baseline" "$TMP/inode-seal" "$TMP/dir-dest" "$TMP/dir-dest-out"
: > "$TMP/baseline/leaf"
: > "$TMP/inode-seal/leaf"
: > "$TMP/dir-dest/leaf"
: > "$TMP/dir-dest-out/leaf"

{
	echo "actor bench-actor = $ACTOR"
	echo "seal $ACTOR full"
	echo "seal $TMP/inode-seal/leaf no-write actor=bench-actor"
	echo "seal $TMP/dir-dest        no-write actor=bench-actor"
	echo "seal $TMP/dir-dest-out    no-write actor=bench-actor"
} > "$TMP/policy.conf"

"$DAEMON" "$TMP/policy.conf" >"$TMP/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 60); do
	grep -q '\[run\] compartment-bpf live' "$TMP/daemon.log" 2>/dev/null && break
	kill -0 "$DAEMON_PID" 2>/dev/null || { cat "$TMP/daemon.log" >&2; echo "[bench] FAIL: daemon died" >&2; exit 1; }
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$TMP/daemon.log" 2>/dev/null \
	|| { cat "$TMP/daemon.log" >&2; echo "[bench] FAIL: daemon not live" >&2; exit 1; }

# run_scenario <stub> <file> <label>
# Returns: elapsed nanoseconds for N iterations to stdout.
run_scenario() {
	local stub="$1" target="$2" label="$3"
	local t0 t1 elapsed ns_per
	t0=$(date +%s%N)
	for _ in $(seq 1 "$N"); do
		"$stub" write "$target" >/dev/null 2>&1 || true
	done
	t1=$(date +%s%N)
	elapsed=$(( t1 - t0 ))
	ns_per=$(( elapsed / N ))
	echo "$ns_per"
}

echo "[bench] warming up..."
for _ in $(seq 1 100); do
	"$ACTOR"   write "$TMP/baseline/leaf" >/dev/null 2>&1 || true
	"$ACTOR"   write "$TMP/inode-seal/leaf" >/dev/null 2>&1 || true
	"$ACTOR"   write "$TMP/dir-dest/leaf" >/dev/null 2>&1 || true
	"$OUTSIDER" write "$TMP/dir-dest-out/leaf" >/dev/null 2>&1 || true
done

echo "[bench] scenario 1: baseline (no seal) ..."
S1=$(run_scenario "$ACTOR"    "$TMP/baseline/leaf"    "baseline")
echo "[bench] scenario 2: inode seal + actor match ..."
S2=$(run_scenario "$ACTOR"    "$TMP/inode-seal/leaf"  "inode-seal-actor")
echo "[bench] scenario 3: dir-dest seal + actor match ..."
S3=$(run_scenario "$ACTOR"    "$TMP/dir-dest/leaf"    "dir-dest-actor")
echo "[bench] scenario 4: dir-dest seal + outsider (DENY path) ..."
S4=$(run_scenario "$OUTSIDER" "$TMP/dir-dest-out/leaf" "dir-dest-outsider")

# Incremental overhead: (S3 - S2) / S2 * 100
if [ "$S2" -gt 0 ]; then
	INCR_NUM=$(( (S3 - S2) * 1000 / S2 ))
	INCR_INT=$(( INCR_NUM / 10 ))
	INCR_FRAC=$(( INCR_NUM % 10 ))
	INCR_PCT="${INCR_INT}.${INCR_FRAC}%"
else
	INCR_PCT="N/A"
fi

echo ""
echo "=== bench-dir-destination results (N=$N) ==="
echo "  S1 baseline (no seal):               ${S1} ns/iter"
echo "  S2 inode seal + actor match (ALLOW): ${S2} ns/iter"
echo "  S3 dir-dest seal + actor match:      ${S3} ns/iter"
echo "  S4 dir-dest seal + outsider (DENY):  ${S4} ns/iter"
echo "  Incremental overhead S3 vs S2:       ${INCR_PCT}"
echo ""

# Halt gate: >5% incremental overhead
if [ "$S2" -gt 0 ] && [ $(( (S3 - S2) * 100 )) -gt $(( S2 * 5 )) ]; then
	echo "[bench] HALT: incremental overhead ${INCR_PCT} exceeds 5% gate (SPEC §9)" >&2
	exit 2
fi

echo "[bench] PASS: incremental overhead ${INCR_PCT} within 5% gate"
exit 0
