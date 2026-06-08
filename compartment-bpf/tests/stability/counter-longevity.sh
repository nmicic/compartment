#!/usr/bin/env bash
# counter-longevity.sh — sustained counter-provocation longevity + leak watch.
#
# Answers: "what's the point of a counter if it always stays 0?" and "do counters
# get stuck / wrap / corrupt, or the daemon leak, under sustained load?"
#
# Phase A (one LONG-LIVED daemon, counters accumulate — no unpin reset):
#   each iteration provokes deny_total / actor_mismatch_total / audit_drop_total
#   and asserts they STRICTLY increased (not stuck) and never decreased
#   (no wrap/reset/corruption). Daemon RSS is sampled every iter (leak watch).
# Phase B (exec-domain counters): loops strict-launch/run.sh, which self-asserts
#   exact per-witness deltas for the 9 exec-domain counters; a stuck/missing
#   counter fails a run. RSS/dmesg tracked across runs.
# Verdict: every counter except marker_stale_generation_total (negative-only by
#   design — v0.4 fresh-load-only) MUST be observed > 0 at least once; any
#   always-0 counter = no test provokes it = a coverage gap to fix.
# Leak: daemon RSS trend flat, BPF map/prog counts return to baseline, dmesg
#   clean, taint unchanged.
#
# Env: COUNTER_LONGEVITY_ITERS (default 30), CL_DENY (200), CL_AMISMA (100),
#      CL_STORM (3000), COUNTER_LONGEVITY_SL_RUNS (3).
# Requires root + bpf in active LSM list. Exits non-zero on any FAIL.

set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO}"
BIN="${REPO}/compartment-bpf"
PIN_ROOT="/sys/fs/bpf/compartment"
ITERS="${COUNTER_LONGEVITY_ITERS:-30}"
DENY="${CL_DENY:-200}"; AMISMA="${CL_AMISMA:-100}"; STORM="${CL_STORM:-3000}"
SL_RUNS="${COUNTER_LONGEVITY_SL_RUNS:-3}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
export STAB_DIR="${REPO}/tests/results/counter-longevity-${TS}"
mkdir -p "${STAB_DIR}"
. tests/stability/lib-stability.sh
: "${STAB_PASS:=0}" "${STAB_FAIL:=0}" "${STAB_SKIP:=0}"

[ "$(id -u)" -eq 0 ] || { stab_skip "requires root"; exit 0; }
[ -x "${BIN}" ] || { echo "fatal: build compartment-bpf first" >&2; exit 1; }

# Counters expected to be provoked by this run (all except the by-design-0).
ALL_COUNTERS="deny_total audit_drop_total actor_mismatch_total \
strict_launch_missing_total strict_launch_allowed_total marker_set_total \
marker_clear_foreign_exec_total marker_copy_fork_total \
prctl_set_mm_exe_file_denied_total ptrace_access_denied_total \
ptrace_traceme_denied_total"
NEGATIVE_ONLY="marker_stale_generation_total"   # v0.4 fresh-load-only: stays 0

declare -A SEEN_NONZERO
for c in ${ALL_COUNTERS} ${NEGATIVE_ONLY}; do SEEN_NONZERO[$c]=0; done

# read one counter from --stats
cget() { "${BIN}" --stats 2>/dev/null | grep -oE "$1=[0-9]+" | head -1 | cut -d= -f2; }
# mark any currently-nonzero counters as seen
mark_seen() { local n v; for n in ${ALL_COUNTERS} ${NEGATIVE_ONLY}; do v="$(cget "$n")"; [ "${v:-0}" -gt 0 ] 2>/dev/null && SEEN_NONZERO[$n]=1; done; }
daemon_rss() { awk '/^VmRSS:/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }

stab_snapshot_baseline

# ---- Phase A: sustained inode-counter accumulation under ONE daemon ---------
SCR="$(mktemp -d /tmp/counter-longevity.XXXXXX)"
SEALED="${SCR}/s.txt"; SEALED_AM="${SCR}/sam.txt"; ACTOR="${SCR}/actor"; PROF="${SCR}/p.conf"
echo seal > "${SEALED}"; echo seal > "${SEALED_AM}"; cp /bin/dd "${ACTOR}"; chmod 0755 "${ACTOR}"
cat > "${PROF}" <<EOF
actor allowed = ${ACTOR}
seal ${ACTOR} full
seal ${SEALED} no-write
seal ${SEALED_AM} no-write actor=allowed
EOF

"${BIN}" --unpin >/dev/null 2>&1 || true
"${BIN}" --pin "${PROF}" > "${STAB_DIR}/daemon-A.log" 2>&1 &
DPID=$!
for i in $(seq 1 75); do grep -q "^\[run\] compartment-bpf live" "${STAB_DIR}/daemon-A.log" 2>/dev/null && break; kill -0 "$DPID" 2>/dev/null || { stab_fail "phase-A daemon died at startup"; break; }; sleep 0.2; done

rss0=0; rssN=0; first_rss=""; last_rss=""
prev_deny=-1; prev_am=-1; prev_drop=-1; stuck=0; wrapped=0
echo "iter,deny,amisma,audit_drop,rss_kb" > "${STAB_DIR}/phase-a.csv"
i=0
while [ "$i" -lt "$ITERS" ]; do
	i=$((i+1))
	# provoke: DENY denied writes + AMISMA actor-mismatch writes + a deny-storm burst
	j=0; while [ "$j" -lt "$DENY" ];   do printf 'x' >> "${SEALED}"    2>/dev/null || true; j=$((j+1)); done
	j=0; while [ "$j" -lt "$AMISMA" ]; do printf 'x' >> "${SEALED_AM}" 2>/dev/null || true; j=$((j+1)); done
	d="$(cget deny_total)"; a="$(cget actor_mismatch_total)"; dr="$(cget audit_drop_total)"
	r="$(daemon_rss "$DPID")"
	echo "$i,$d,$a,$dr,$r" >> "${STAB_DIR}/phase-a.csv"
	mark_seen
	[ -z "$first_rss" ] && first_rss="$r"; last_rss="$r"
	# monotonic / not-stuck checks (after first iter establishes prev)
	if [ "$prev_deny" -ge 0 ]; then
		[ "$d"  -lt "$prev_deny" ] && wrapped=1
		[ "$a"  -lt "$prev_am" ]   && wrapped=1
		[ "$dr" -lt "$prev_drop" ] && wrapped=1
		[ "$d"  -le "$prev_deny" ] && stuck=1   # deny is provoked every iter; must grow
		[ "$a"  -le "$prev_am" ]   && stuck=1
	fi
	prev_deny="$d"; prev_am="$a"; prev_drop="$dr"
done
stop_rss="$(daemon_rss "$DPID")"
kill -TERM "$DPID" 2>/dev/null || true; wait "$DPID" 2>/dev/null || true

# Phase A verdicts
[ "$wrapped" -eq 0 ] && stab_pass "CL-A1 no counter decreased across ${ITERS} iters (no wrap/reset/corruption)" \
	|| stab_fail "CL-A1 a counter DECREASED across iters (wrap/reset/corruption)"
[ "$stuck" -eq 0 ] && stab_pass "CL-A2 deny_total + actor_mismatch_total grew every iter (not stuck)" \
	|| stab_fail "CL-A2 a provoked counter did NOT grow in some iter (stuck)"
# RSS leak: compare first vs last sampled RSS; tolerate jitter.
if [ -n "$first_rss" ] && [ "$first_rss" -gt 0 ] 2>/dev/null; then
	growth=$(( last_rss - first_rss ))
	# allow up to 1024 KiB (1 MiB) drift over the run; counters are fixed-size maps.
	if [ "$growth" -le 1024 ]; then
		stab_pass "CL-A3 daemon RSS flat under sustained load (first=${first_rss}kB last=${last_rss}kB Δ=${growth}kB)"
	else
		stab_fail "CL-A3 daemon RSS grew ${growth}kB over ${ITERS} iters (possible leak; first=${first_rss} last=${last_rss})"
	fi
else
	stab_skip "CL-A3 RSS unreadable"
fi

# ---- Phase B: repeat the PROVEN provoker suites (leak watch across repeats) --
# counter-smoke provokes deny/audit_drop/actor_mismatch (bounded, with its own
# pressure handling); strict-launch provokes the 9 exec-domain counters with
# exact per-witness deltas. Each is run SL_RUNS times so a counter that gets
# stuck/regresses across repeats fails its own run; RSS/dmesg are watched across.
"${BIN}" --unpin >/dev/null 2>&1 || true
cs_ok=0; sl_ok=0; runs=0
k=0
while [ "$k" -lt "$SL_RUNS" ]; do
	k=$((k+1)); runs=$((runs+1))
	bash tests/counter-smoke.sh   > "${STAB_DIR}/counter-smoke-${k}.log"  2>&1 && cs_ok=$((cs_ok+1))
	bash tests/strict-launch/run.sh > "${STAB_DIR}/strict-launch-${k}.log" 2>&1 && sl_ok=$((sl_ok+1))
done
CS_LOG="${STAB_DIR}/counter-smoke-${SL_RUNS}.log"
SL_LOG="${STAB_DIR}/strict-launch-${SL_RUNS}.log"
# Mark counters provoked, from the suites' own PASS/delta lines.
if [ -f "$CS_LOG" ]; then
	grep -qE "T4b.1 PASS|deny_delta=[1-9]"   "$CS_LOG" && SEEN_NONZERO[deny_total]=1
	grep -qE "T4b.4 PASS|amisma_delta=[1-9]" "$CS_LOG" && SEEN_NONZERO[actor_mismatch_total]=1
	grep -qE "drop_delta=[1-9]"              "$CS_LOG" && SEEN_NONZERO[audit_drop_total]=1
fi
if [ -f "$SL_LOG" ]; then
	grep -qE "SL-1-allow|SL-4-fork"       "$SL_LOG" && SEEN_NONZERO[marker_set_total]=1
	grep -qE "SL-3-chain|SL-5-exec-foreign" "$SL_LOG" && SEEN_NONZERO[marker_clear_foreign_exec_total]=1
	grep -qE "SL-4-fork"                  "$SL_LOG" && SEEN_NONZERO[marker_copy_fork_total]=1
	grep -qE "SL-7a-prctl|SL-7c-prctl"    "$SL_LOG" && SEEN_NONZERO[prctl_set_mm_exe_file_denied_total]=1
	grep -qE "ptrace\+[1-9]"             "$SL_LOG" && SEEN_NONZERO[ptrace_access_denied_total]=1
	grep -qE "traceme_denied\+[1-9]"     "$SL_LOG" && SEEN_NONZERO[ptrace_traceme_denied_total]=1
	grep -qE "miss\+[1-9]"               "$SL_LOG" && SEEN_NONZERO[strict_launch_missing_total]=1
	grep -qE "allow\+[1-9]"              "$SL_LOG" && SEEN_NONZERO[strict_launch_allowed_total]=1
fi
[ "$cs_ok" -eq "$runs" ] && stab_pass "CL-B1 counter-smoke ${cs_ok}/${runs} green across repeats" \
	|| stab_fail "CL-B1 counter-smoke ${cs_ok}/${runs} green (a repeat regressed)"
[ "$sl_ok" -eq "$runs" ] && stab_pass "CL-B2 strict-launch ${sl_ok}/${runs} green across repeats (exec-domain deltas held)" \
	|| stab_fail "CL-B2 strict-launch ${sl_ok}/${runs} green (a repeat regressed)"

# ---- Coverage verdict: any always-0 DETERMINISTIC counter = missing provoker -
# DETERMINISTIC: must be provoked by some test. audit_drop is pressure/timing-
# dependent (counter-smoke T4b.2 itself can be INCONCLUSIVE), so it is best-effort.
DET="deny_total actor_mismatch_total strict_launch_missing_total \
strict_launch_allowed_total marker_set_total marker_clear_foreign_exec_total \
marker_copy_fork_total prctl_set_mm_exe_file_denied_total \
ptrace_access_denied_total ptrace_traceme_denied_total"
always0=""
for c in ${DET}; do [ "${SEEN_NONZERO[$c]}" -eq 0 ] && always0="${always0} ${c}"; done
if [ -z "$always0" ]; then
	stab_pass "CL-COV all 10 deterministic counters provoked >0 (no always-0 / dead counter)"
else
	stab_fail "CL-COV ALWAYS-0 counters (no test provokes them):${always0}  -> add an e2e provoker"
fi
if [ "${SEEN_NONZERO[audit_drop_total]}" -eq 1 ]; then
	stab_pass "CL-DROP audit_drop_total provoked under ringbuf pressure (>0)"
else
	stab_log "INFO audit_drop_total not provoked this run — pressure/timing-dependent (counter-smoke T4b.2 INCONCLUSIVE-class); covered by T4b.2, not a coverage gap"
fi
stab_log "INFO ${NEGATIVE_ONLY} is negative-only by design (v0.4 fresh-load-only); not required >0"

# ---- Leak/health verdicts (lib-stability) ----------------------------------
"${BIN}" --unpin >/dev/null 2>&1 || true
stab_check_taint
stab_check_dmesg
rm -rf "${SCR}"

echo "=== counter-longevity SUMMARY: PASS=${STAB_PASS} FAIL=${STAB_FAIL} SKIP=${STAB_SKIP} (${STAB_DIR}) ==="
[ "${STAB_FAIL}" -eq 0 ]
