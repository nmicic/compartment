#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# tests/limit-stress.sh
#
# "Test to the failure": deliberately push the loader toward its scale limits
# with large fan-out trees and over-capacity profiles, and assert it behaves
# FAIL-CLOSED at the boundary rather than hanging or silently truncating
# (silent truncation of seals past a map cap = fail-OPEN).
#
# Real caps (compartment.bpf.c): sealed_inodes = 65536, sealed_dirs = 8192.
# NB a *recursive* directory seal is ONE map entry; the caps are reached by many
# *individual* seal lines. The recursive-subtree VALIDATION walk size is a
# separate scale axis (nftw over the whole subtree at load).
#
# Part A (no root): big clean fan-out tree, recursive seal via --dry-run — the
#   nftw walk must complete (no hang/OOM) and resolve the single seal.
# Part B (root + BPF LSM): a profile with > sealed_dirs seals — real load must
#   fail closed (never reach "live", non-zero exit), NOT go live with a silently
#   truncated seal set.
#
# Tunables: STRESS_FANOUT (dirs per level, default 64 -> ~64*64 nodes),
#           STRESS_DIR_SEALS (default 8200, just over the 8192 cap).
# Exit: 0 pass, 1 fail, 77 skip.
set -u
cd "$(dirname "$0")/.."
BIN="./compartment-bpf"
FANOUT=${STRESS_FANOUT:-64}
DIR_SEALS=${STRESS_DIR_SEALS:-8200}
SEALED_DIRS_CAP=8192

[ -x "$BIN" ] || { echo "SKIP limit-stress: $BIN not built"; exit 77; }

TMP=$(mktemp -d /tmp/limit-stress.XXXXXX)
cleanup() { pkill -9 -x compartment-bpf 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT INT TERM
pass=0; fail=0

# ---------------------------------------------------------------------------
# Part A — recursive-validation scale (no root; --dry-run)
# ---------------------------------------------------------------------------
echo "== Part A: fan-out validation scale (${FANOUT}x${FANOUT} nodes, --dry-run) =="
root="$TMP/fanout"; mkdir -p "$root"
# Brace-free, batched mkdir so arbitrary FANOUT works without huge argv.
for a in $(seq 1 "$FANOUT"); do
	mkdir -p "$root/d$a"
	for b in $(seq 1 "$FANOUT"); do mkdir -p "$root/d$a/s$b"; done
done
nodes=$(find "$root" -type d | wc -l)
printf 'seal %s no-write\n' "$root" > "$TMP/fanout.conf"
# 60s outer cap: a hang/OOM in the nftw walk would trip this (fail), a healthy
# walk over a few thousand nodes completes in well under a second.
outA=$(timeout 60 "$BIN" --dry-run "$TMP/fanout.conf" 2>&1); rcA=$?
if [ "$rcA" -eq 124 ]; then
	echo "FAIL part-A: validation walk TIMED OUT over $nodes nodes (hang/OOM)"; fail=$((fail+1))
elif printf '%s' "$outA" | grep -qF "1 seal resolved" && printf '%s' "$outA" | grep -qF "0 errors"; then
	echo "PASS part-A: clean $nodes-node subtree validated + resolved (no hang)"; pass=$((pass+1))
elif printf '%s' "$outA" | grep -qiE 'pin-shape:.*(permission denied|operation not permitted)'; then
	# Non-root + root-only bpffs: --dry-run can't reach validation. Not a logic
	# failure — SKIP Part A (run as root to exercise it).
	echo "SKIP part-A: --dry-run cannot reach validation here (bpffs pin-shape probe needs root)"
else
	echo "FAIL part-A: clean $nodes-node subtree did not resolve cleanly"
	printf '%s\n' "$outA" | tail -3 | sed 's/^/    /'; fail=$((fail+1))
fi

# ---------------------------------------------------------------------------
# Part B — map-capacity fail-closed (root + BPF LSM)
# ---------------------------------------------------------------------------
echo "== Part B: > sealed_dirs cap ($DIR_SEALS > $SEALED_DIRS_CAP) must fail closed =="
if [ "$(id -u)" -ne 0 ]; then
	echo "SKIP part-B: needs root + BPF LSM"
elif ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
	echo "SKIP part-B: bpf not in active LSM"
else
	# DIR_SEALS empty dirs (each validates clean -> lands in sealed_dirs as one
	# entry). Profile seals each with no-unlink (structural dir seal).
	od="$TMP/manydirs"; mkdir -p "$od"
	: > "$TMP/many.conf"
	for n in $(seq 1 "$DIR_SEALS"); do
		mkdir -p "$od/d$n"
		printf 'seal %s/d%s no-unlink\n' "$od" "$n" >> "$TMP/many.conf"
	done
	log="$TMP/manyload.log"
	timeout 90 "$BIN" "$TMP/many.conf" >"$log" 2>&1 &
	pid=$!
	live=0; gone=0
	for _ in $(seq 1 120); do
		grep -q '\[run\].*live' "$log" 2>/dev/null && { live=1; break; }
		kill -0 "$pid" 2>/dev/null || { gone=1; break; }
		sleep 0.5
	done
	if [ "$live" -eq 1 ]; then
		# Went live with > cap seals -> silent truncation -> FAIL-OPEN.
		echo "FAIL part-B: daemon went LIVE with $DIR_SEALS > $SEALED_DIRS_CAP dir seals (silent truncation = fail-open)"
		kill -9 "$pid" 2>/dev/null; fail=$((fail+1))
	else
		wait "$pid" 2>/dev/null; rcB=$?
		if [ "$rcB" -ne 0 ]; then
			echo "PASS part-B: over-cap load failed closed (exit=$rcB, never live)"
			# bonus: confirm the diagnostic points at the seal/map, not a crash
			if grep -qiE 'seal|map|update|E2BIG|too many|capacity|No space' "$log"; then
				echo "       (diagnostic references the seal/map limit)"
			else
				echo "       NOTE: exit was clean-closed but diagnostic is generic:"
				tail -2 "$log" | sed 's/^/         /'
			fi
			pass=$((pass+1))
		else
			echo "FAIL part-B: daemon exited 0 without going live (ambiguous)"; fail=$((fail+1))
		fi
	fi
fi

echo "[limit-stress] $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ] || exit 1
exit 0
