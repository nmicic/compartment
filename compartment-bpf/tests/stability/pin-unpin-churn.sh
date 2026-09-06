#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/stability/pin-unpin-churn.sh — kernel stability stress harness.
#
# Loop A (background): pin/unpin churn for $STAB_CYCLES iterations.
# Loop B (foreground): mesh trials, repeated until Loop A signals done.
#
# Usage:
#   [STAB_CYCLES=64] [DUAL_PROFILE=1] [STAB_PROFILE=path] \
#       bash tests/stability/pin-unpin-churn.sh
#
# Exit codes (PASS/FAIL/SKIP project convention):
#   0   PASS — all T-STAB-1..6 cleared
#   1   FAIL — at least one T-STAB-* check failed; evidence in $STAB_DIR
#   77  SKIP — environment cannot host the harness (no root, no daemon, ...)
#
# Why a stress harness exists at all: synthetic-reviewer cohorts (Claude
# Opus) validate policy correctness but cannot exercise sustained kernel-
# state lifecycle stress in a review pass. Kernel races, memory leaks and
# lifecycle bugs only manifest under high-frequency real BPF substrate
# operation.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
export REPO

. "$SCRIPT_DIR/lib-stability.sh"

# --- Phase 0: Preflight -----------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
	stab_skip "pin-unpin-churn requires root (CAP_BPF/CAP_SYS_ADMIN for --pin/--unpin)"
	stab_summary || true
	exit 77
fi

DAEMON="$REPO/compartment-bpf"
MESH="$REPO/tests/mesh/run-mesh.sh"

if [ ! -x "$DAEMON" ]; then
	stab_skip "compartment-bpf binary missing at $DAEMON"
	stab_summary || true
	exit 77
fi
if [ ! -r "$MESH" ]; then
	stab_skip "mesh runner missing at $MESH"
	stab_summary || true
	exit 77
fi
if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
	stab_skip "bpf not in active LSM list"
	stab_summary || true
	exit 77
fi

UTC=$(date -u +%Y%m%dT%H%M%SZ)
STAB_DIR="${STAB_DIR:-$SCRIPT_DIR/results/$UTC}"
export STAB_DIR
mkdir -p "$STAB_DIR"

# The shipped profiles are templates (@STAB_ACTOR@ / @STAB_ACTOR_B@);
# stab_profile renders them against a real regular-file ELF fixture. See
# tests/lib-realbin.sh for why /usr/bin/true is no longer usable.
PROFILE_A=$(stab_profile "${STAB_PROFILE:-$SCRIPT_DIR/baseline-profile.conf}")
PROFILE_B=$(stab_profile "$SCRIPT_DIR/baseline-profile-b.conf")
if grep -q '@STAB_ACTOR' "$PROFILE_A" 2>/dev/null; then
	stab_skip "no real (non-symlink) ELF actor fixture could be produced; install a C compiler or set REALBIN_CACHE to a prebuilt one"
	stab_summary || true
	exit 77
fi
DUAL_PROFILE="${DUAL_PROFILE:-0}"
STAB_CYCLES="${STAB_CYCLES:-64}"

stab_log "==== pin-unpin-churn start ===="
stab_log "STAB_DIR=$STAB_DIR"
stab_log "STAB_CYCLES=$STAB_CYCLES DUAL_PROFILE=$DUAL_PROFILE"
stab_log "profile_a=$PROFILE_A"
[ "$DUAL_PROFILE" = "1" ] && stab_log "profile_b=$PROFILE_B"

# Create the synthetic paths the profile references. The loader stat()s
# every sealed path, so absence would fail-closed at pin time before we
# get the first churn cycle.
mkdir -p /tmp/stab-datadir
[ -e /tmp/stab-file ] || : > /tmp/stab-file
if [ "$DUAL_PROFILE" = "1" ]; then
	mkdir -p /tmp/stab-datadir-b
	[ -e /tmp/stab-file-b ] || : > /tmp/stab-file-b
fi

# Pre-run sanitiser: if a previous failed run left state under PIN_ROOT,
# tear it down so the baseline snapshot reflects a clean kernel. We do
# not FAIL the run on pre-existing residue (it is not our fault); we
# only want T-STAB-3 to be measuring our run, not someone else's.
"$DAEMON" --unpin >/dev/null 2>&1 || true

LOOP_A_DONE="/tmp/stab-loop-a-done.$$"
LOOP_A_FAIL="/tmp/stab-loop-a-fail.$$"
LOOP_A_PINNED="/tmp/stab-loop-a-pinned.$$"
rm -f "$LOOP_A_DONE" "$LOOP_A_FAIL" "$LOOP_A_PINNED"

cleanup() {
	# Loop A may still be running on early exit (Loop B mesh fail). Kill
	# its process group so any pending compartment-bpf --pin in flight is
	# torn down before we attempt the final --unpin.
	if [ -n "${LOOP_A_PID:-}" ] && kill -0 "$LOOP_A_PID" 2>/dev/null; then
		kill -TERM "$LOOP_A_PID" 2>/dev/null || true
		# Best-effort wait, then SIGKILL.
		i=0
		while kill -0 "$LOOP_A_PID" 2>/dev/null && [ "$i" -lt 30 ]; do
			sleep 0.1; i=$((i+1))
		done
		kill -KILL "$LOOP_A_PID" 2>/dev/null || true
	fi
	# Final --unpin so the host bpffs is clean regardless of where we
	# exited. Failure here is informational; T-STAB-3 records the truth.
	"$DAEMON" --unpin >>"$STAB_DIR/cleanup-unpin.log" 2>&1 || true
	rm -f "$LOOP_A_DONE" "$LOOP_A_FAIL" "$LOOP_A_PINNED"
	# Don't remove /tmp/stab-* paths — they're cheap to recreate and
	# leaving them lets a re-run skip the mkdir+touch.
}
trap cleanup EXIT INT TERM

stab_snapshot_baseline
START_TS=$(date +%s)

# --- Phase 1: Loop A (background, pin/unpin churn) --------------------------

(
	i=0
	pinned_cycles=0
	deferred_total=0
	while [ "$i" -lt "$STAB_CYCLES" ]; do
		if [ "$DUAL_PROFILE" = "1" ] && [ $((i % 2)) -eq 0 ]; then
			PROF="$PROFILE_B"
		else
			PROF="$PROFILE_A"
		fi

		echo "=== cycle $i: pin $PROF ===" >> "$STAB_DIR/loop-a.log"
		PIN_START=$(date +%s%3N 2>/dev/null || date +%s)

		# PIN_ROOT is a single global namespace and Loop B's mesh runner
		# owns it for its own ME-10 --pin'd counter phase. Take the
		# harness mutex for the whole pin->unpin transaction so this
		# loop's --unpin can never delete the counter maps ME-10 is
		# measuring (tests/lib-pinlock.sh). The lock is released
		# implicitly if this subshell dies, so a crash cannot wedge
		# the mesh runner.
		if ! pinlock_acquire 120; then
			echo "LOOP_A_PINLOCK_TIMEOUT cycle=$i (waited 120s for $COMPARTMENT_TEST_PINLOCK)" >> "$STAB_DIR/loop-a.log"
			touch "$LOOP_A_FAIL"
			touch "$LOOP_A_DONE"
			exit 1
		fi

		# Belt and braces: even holding the mutex, never pin over and
		# never --unpin a tree we did not create.
		DEFER=0
		while : ; do
			FOREIGN=$(stab_count_pins links)
			if [ "${FOREIGN:-0}" -eq 0 ]; then
				stab_pin_once "$DAEMON" "$PROF" "$STAB_DIR/loop-a.log" 100
				PIN_RC=$?
				# rc=1 with a tree now present means the other owner
				# pinned inside our check->pin window. That is a
				# deferral, not a silent no-op — retry.
				if [ "$PIN_RC" -ne 1 ]; then
					break
				fi
				FOREIGN=$(stab_count_pins links)
				if [ "${FOREIGN:-0}" -eq 0 ]; then
					break
				fi
			else
				PIN_RC=1
			fi
			DEFER=$((DEFER + 1))
			deferred_total=$((deferred_total + 1))
			if [ "$DEFER" -gt 300 ]; then
				echo "LOOP_A_PIN_STARVED cycle=$i (PIN_ROOT held by another owner for >30s)" >> "$STAB_DIR/loop-a.log"
				touch "$LOOP_A_FAIL"
				touch "$LOOP_A_DONE"
				exit 1
			fi
			sleep 0.1
		done

		PIN_END=$(date +%s%3N 2>/dev/null || date +%s)
		echo "cycle $i pin rc=$PIN_RC links=${STAB_PIN_LINKS:-0} defer=$DEFER start=$PIN_START end=$PIN_END" >> "$STAB_DIR/loop-a.log"

		if [ "$PIN_RC" -eq 2 ]; then
			# stab_pin_once already captured the stack.
			echo "LOOP_A_HANG_PIN cycle=$i" >> "$STAB_DIR/loop-a.log"
			touch "$LOOP_A_FAIL"
			touch "$LOOP_A_DONE"
			exit 1
		fi
		# T-STAB-7: a cycle that pins nothing is a SILENT NO-OP, and the
		# whole point of this loop is the churn. Before this assertion a
		# profile whose actor path failed to resolve (the /usr/bin/true
		# symlink case) produced 64 cycles of "pin rc=1 / 0 pins removed"
		# and the run still reported the churn as healthy.
		if [ "$PIN_RC" -ne 0 ] || [ "${STAB_PIN_LINKS:-0}" -le 0 ]; then
			echo "LOOP_A_PIN_NOOP cycle=$i rc=$PIN_RC links=${STAB_PIN_LINKS:-0} (pin produced no pinned links)" >> "$STAB_DIR/loop-a.log"
			touch "$LOOP_A_FAIL"
			touch "$LOOP_A_DONE"
			exit 1
		fi
		pinned_cycles=$((pinned_cycles + 1))

		# Random 10-100ms jitter so pin/unpin don't synchronise with mesh.
		sleep 0.0$(( (RANDOM % 9) + 1 ))

		echo "=== cycle $i: unpin ===" >> "$STAB_DIR/loop-a.log"
		UNPIN_START=$(date +%s%3N 2>/dev/null || date +%s)
		"$DAEMON" --unpin >> "$STAB_DIR/loop-a.log" 2>&1
		UNPIN_RC=$?
		UNPIN_END=$(date +%s%3N 2>/dev/null || date +%s)
		RESIDUE=$(stab_count_pins)
		echo "cycle $i unpin rc=$UNPIN_RC residue=$RESIDUE start=$UNPIN_START end=$UNPIN_END" >> "$STAB_DIR/loop-a.log"
		pinlock_release

		sleep 0.0$(( (RANDOM % 9) + 1 ))

		i=$((i + 1))
		echo "cycle $i/$STAB_CYCLES complete" >> "$STAB_DIR/loop-a.log"
	done
	echo "loop-a: pinned_cycles=$pinned_cycles/$STAB_CYCLES deferrals=$deferred_total" >> "$STAB_DIR/loop-a.log"
	echo "$pinned_cycles" > "$LOOP_A_PINNED"
	touch "$LOOP_A_DONE"
) &
LOOP_A_PID=$!
stab_log "Loop A started (pid=$LOOP_A_PID)"

# --- Phase 2: Loop B (foreground, mesh trials) ------------------------------

MESH_ITER=0
MESH_TOTAL_PASS=0
MESH_TOTAL_FAIL=0
MESH_TIMEOUTS=0

while ! [ -f "$LOOP_A_DONE" ]; do
	MESH_ITER=$((MESH_ITER + 1))
	stab_log "mesh iteration $MESH_ITER starting"

	# Run the mesh harness once. The mesh runner itself runs ~30s on the
	# Resolute VM. A 120s timeout is 4x normal — anything beyond that is
	# almost certainly a kernel-level wedge (D-state, ringbuf consumer
	# stuck), not honest slowness.
	timeout 120 bash "$MESH" >> "$STAB_DIR/mesh-iter-$MESH_ITER.log" 2>&1
	MESH_RC=$?

	if [ "$MESH_RC" -eq 124 ]; then
		MESH_TIMEOUTS=$((MESH_TIMEOUTS + 1))
		stab_fail "T-STAB-6 mesh iteration $MESH_ITER timed out (>120s) — possible kernel hang"
		break
	fi

	# Mesh harness-level errors (run-mesh.sh exit codes: 2 missing daemon
	# or stub, 3 inode collision, 4/5 daemon attach) mean the iteration
	# ran NO trials. Without this guard the loop spun on an unbuildable
	# mesh several hundred times in five seconds, tallied pass=0 fail=0
	# every time, and the run then SKIPped T-STAB-4 for "no mesh
	# iterations completed" instead of reporting the real cause.
	case "$MESH_RC" in
	0|6|7)
		: ;;
	77)
		stab_skip "mesh iteration $MESH_ITER SKIPped (rc=77, env unsupported); stopping Loop B"
		break ;;
	*)
		stab_fail "T-STAB-4 mesh iteration $MESH_ITER: harness error rc=$MESH_RC (no trials ran); see $STAB_DIR/mesh-iter-$MESH_ITER.log"
		break ;;
	esac

	# Pass-rate accounting. The mesh runner emits "ENFORCED PASS"/
	# "ENFORCED FAIL" rows + a final summary; we count the per-trial
	# verdict lines, not the header banner. `grep | wc -l` is robust
	# to zero-match (grep -c emits "0" + exit 1, which when paired with
	# `|| echo 0` produces a two-line string that breaks arithmetic).
	# The mesh runner emits a final summary line
	#   "ENFORCED: <N> PASS, <M> FAIL"
	# (with literal commas) plus per-block "[mesh] ME-NN ...: P PASS / F FAIL"
	# rows. Parse the ENFORCED total when present; fall back to summing
	# per-block rows. `awk` end-of-stream output keeps the value a single
	# integer regardless of match count.
	MESH_LOG="$STAB_DIR/mesh-iter-$MESH_ITER.log"
	MESH_PASS=$(awk '/^[[:space:]]*ENFORCED:/ {for(i=1;i<=NF;i++) if($i=="PASS,") {gsub(",","",$(i-1)); print $(i-1); exit}}' "$MESH_LOG" 2>/dev/null)
	MESH_FAIL=$(awk '/^[[:space:]]*ENFORCED:/ {for(i=1;i<=NF;i++) if($i=="FAIL")  {print $(i-1); exit}}' "$MESH_LOG" 2>/dev/null)
	if [ -z "$MESH_PASS" ]; then
		MESH_PASS=$(awk '/\[mesh\].*[0-9]+ PASS \/ [0-9]+ FAIL/ {for(i=1;i<=NF;i++) if($i=="PASS") s+=$(i-1)} END{print s+0}' "$MESH_LOG" 2>/dev/null)
		MESH_FAIL=$(awk '/\[mesh\].*[0-9]+ PASS \/ [0-9]+ FAIL/ {for(i=1;i<=NF;i++) if($i=="FAIL") s+=$(i-1)} END{print s+0}' "$MESH_LOG" 2>/dev/null)
	fi
	MESH_PASS=${MESH_PASS:-0}
	MESH_FAIL=${MESH_FAIL:-0}
	MESH_TOTAL_PASS=$((MESH_TOTAL_PASS + MESH_PASS))
	MESH_TOTAL_FAIL=$((MESH_TOTAL_FAIL + MESH_FAIL))
	stab_log "mesh iteration $MESH_ITER: rc=$MESH_RC pass=$MESH_PASS fail=$MESH_FAIL"

	if [ "$MESH_FAIL" -gt 0 ]; then
		stab_fail "T-STAB-4 mesh iteration $MESH_ITER had $MESH_FAIL FAIL row(s) during churn"
	fi

	# If Loop A failed early, exit promptly.
	if [ -f "$LOOP_A_FAIL" ]; then
		stab_fail "T-STAB-6 Loop A reported a hang/failure — see loop-a.log"
		break
	fi
done

# Wait for Loop A to settle. If it set LOOP_A_FAIL but did not also create
# LOOP_A_DONE in time, the wait still terminates because the subshell exits.
wait "$LOOP_A_PID" 2>/dev/null
LOOP_A_RC=$?
if [ "$LOOP_A_RC" -ne 0 ]; then
	stab_fail "Loop A exited rc=$LOOP_A_RC"
fi

# T-STAB-7: the churn must actually have churned. Loop A records the number
# of cycles in which a pin was OBSERVED on bpffs (link-pin count > 0); a run
# where every cycle pinned nothing used to pass every other check precisely
# BECAUSE nothing was ever pinned (T-STAB-3 "0 pinned objects" is trivially
# satisfied by a no-op).
LOOP_A_PINNED_N=0
[ -r "$LOOP_A_PINNED" ] && LOOP_A_PINNED_N=$(cat "$LOOP_A_PINNED" 2>/dev/null || echo 0)
LOOP_A_PINNED_N=${LOOP_A_PINNED_N:-0}
if [ "$LOOP_A_PINNED_N" -eq "$STAB_CYCLES" ]; then
	stab_pass "T-STAB-7 pin witness: $LOOP_A_PINNED_N/$STAB_CYCLES cycles observed a live pin under $STAB_PIN_ROOT/links"
else
	stab_fail "T-STAB-7 pin witness: only $LOOP_A_PINNED_N/$STAB_CYCLES cycles observed a live pin — the churn was (partly) a no-op; see $STAB_DIR/loop-a.log"
fi

END_TS=$(date +%s)
DURATION=$((END_TS - START_TS))
stab_log "Loop A+B complete: duration=${DURATION}s mesh_iters=$MESH_ITER pass=$MESH_TOTAL_PASS fail=$MESH_TOTAL_FAIL timeouts=$MESH_TIMEOUTS"

# Drain any residual pinned state before T-STAB-3 measures bpffs. This is
# distinct from the trap-on-EXIT --unpin: we want the post-run snapshot
# to reflect the operator's bpffs hygiene contract, not their later trap
# cleanup. If --unpin here fails, T-STAB-3 will still surface the residue
# as a FAIL — which is the correct outcome.
"$DAEMON" --unpin >>"$STAB_DIR/final-unpin.log" 2>&1 || true

# --- Phase 3: Post-run checks -----------------------------------------------

stab_check_dmesg
stab_check_taint
stab_check_bpffs_clean
stab_check_memory_growth
stab_check_bpf_count_consistency

# T-STAB-4 aggregate pass-rate gate (>=99% across all iterations).
if [ "$MESH_TOTAL_PASS" -gt 0 ]; then
	denom=$((MESH_TOTAL_PASS + MESH_TOTAL_FAIL))
	# integer percentage * 100 so we can compare without floats
	pct100=$(( (MESH_TOTAL_PASS * 10000) / denom ))
	# 99% → 9900
	if [ "$pct100" -ge 9900 ]; then
		stab_pass "T-STAB-4 mesh aggregate: $MESH_TOTAL_PASS/$denom (pct100=$pct100, ≥99%)"
	else
		stab_fail "T-STAB-4 mesh aggregate: $MESH_TOTAL_PASS/$denom (pct100=$pct100, <99%)"
	fi
elif [ "$MESH_TIMEOUTS" -gt 0 ]; then
	stab_fail "T-STAB-4 mesh aggregate: no PASS rows + $MESH_TIMEOUTS timeout(s)"
else
	stab_skip "T-STAB-4 mesh aggregate: no mesh iterations completed (cycles too short?)"
fi

# T-STAB-6 stuck-state surface: any process still in D-state?
if command -v ps >/dev/null 2>&1; then
	dstate=$(ps -eo stat,pid,comm | awk '$1 ~ /^D/ {print}' || true)
	if [ -n "$dstate" ]; then
		stab_fail "T-STAB-6 D-state process(es) present after run:"
		echo "$dstate" | tee "$STAB_DIR/dstate.txt"
	else
		stab_pass "T-STAB-6 no D-state processes after run"
	fi
fi

# Write RESULTS.md for this run.
{
	echo "# Stability run — $UTC"
	echo
	echo "- duration: ${DURATION}s"
	echo "- cycles: $STAB_CYCLES"
	echo "- dual_profile: $DUAL_PROFILE"
	echo "- mesh iterations: $MESH_ITER"
	echo "- mesh aggregate pass/fail: $MESH_TOTAL_PASS / $MESH_TOTAL_FAIL"
	echo "- mesh timeouts (>120s): $MESH_TIMEOUTS"
	echo
	echo "## Summary"
	echo "- PASS: $STAB_PASS"
	echo "- FAIL: $STAB_FAIL"
	echo "- SKIP: $STAB_SKIP"
	echo
	if [ "$STAB_FAIL" -eq 0 ]; then
		echo "**Overall: PASS**"
	else
		echo "**Overall: FAIL** — see $STAB_DIR/{loop-a.log,dmesg-new.txt,bpffs-residue.txt,dstate.txt}"
	fi
} > "$STAB_DIR/RESULTS.md"

stab_summary
RC=$?
if [ "$RC" -eq 0 ]; then
	exit 0
else
	exit 1
fi
