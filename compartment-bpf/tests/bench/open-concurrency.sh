#!/usr/bin/env bash
# open-concurrency.sh — resolve the "concurrency cliff" cleanly.
#
# Runs the threaded C open() microbenchmark (open-concurrency.c — pure file_open,
# NO shell fork/exec) at a thread sweep, WITHOUT compartment then WITH compartment
# enforcing (daemon pinned, workload file UNSEALED -> ALLOW hot path). If the
# shell-observed cliff was real (a serializing lock on file_open) it shows here as
# WITH-daemon wall-time exploding with thread count; if it was the exec/fork
# artifact it does NOT reproduce (open/close stays flat vs baseline).
#
# Env: OC_THREADS ("1 2 4 8 16"), OC_ITERS (200000), OC_MAXPCT (60 soft gate on
#      the worst per-thread-count WITH-vs-WITHOUT overhead).
# Requires root + a built ./compartment-bpf.

set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO}"
BIN="${REPO}/compartment-bpf"
BENCHBIN="${REPO}/tests/bench/open-concurrency"
SRC="${REPO}/tests/bench/open-concurrency.c"
PIN_ROOT="/sys/fs/bpf/compartment"
THREADS="${OC_THREADS:-1 2 4 8 16}"
ITERS="${OC_ITERS:-200000}"
MAXPCT="${OC_MAXPCT:-60}"

[ "$(id -u)" -eq 0 ] || { echo "open-concurrency: needs root" >&2; exit 2; }
[ -x "${BIN}" ] || { echo "open-concurrency: build compartment-bpf first" >&2; exit 2; }
cc -O2 -pthread -o "${BENCHBIN}" "${SRC}" || { echo "open-concurrency: cc failed" >&2; exit 2; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS="${REPO}/tests/results/open-concurrency-${TS}"
mkdir -p "${RESULTS}"
CSV="${RESULTS}/open-concurrency.csv"
echo "mode,threads,total_ops,errs,wall_ms,ops_sec,ns_op" > "${CSV}"

SCR="$(mktemp -d /tmp/open-conc.XXXXXX)"
WL="${SCR}/workload-file"; echo x > "${WL}"          # unsealed -> ALLOW hot path
DUMMY="${SCR}/sealed-dummy"; echo d > "${DUMMY}"
PROFILE="${SCR}/p.conf"; echo "seal ${DUMMY} no-write" > "${PROFILE}"

DAEMON_PID=""
cleanup() {
	[ -n "${DAEMON_PID}" ] && kill -0 "${DAEMON_PID}" 2>/dev/null && \
		{ kill -TERM "${DAEMON_PID}" 2>/dev/null || true; wait "${DAEMON_PID}" 2>/dev/null || true; }
	"${BIN}" --unpin >/dev/null 2>&1 || true
	rm -rf "${SCR}"
}
trap cleanup EXIT INT TERM

REPS="${OC_REPS:-3}"   # reps per (mode,thread); keep the MIN wall to de-noise (P2-c)
run_sweep() {  # $1=mode label
	local mode="$1" line t
	for t in ${THREADS}; do
		# Reject any non-numeric token: THREADS comes from OC_THREADS (env),
		# and t flows into process args / variable names below — a non-numeric
		# token is meaningless for a thread count AND a code-injection vector
		# in a root script. Fail-closed: skip it loudly.
		case "$t" in ''|*[!0-9]*) echo "[${mode}] skip non-numeric thread token '$t'" >&2; continue;; esac
		t=$((10#$t))   # normalize leading zeros (P2-b): bash arith below + the C
		               # benchmark must agree on base-10 ('08' is not octal here).
		local rep wall errs best="" timedout=0
		for rep in $(seq 1 "${REPS}"); do
			# 120s wall guard: a real cliff (the >100s shell timeout) trips this.
			line="$(timeout 120 "${BENCHBIN}" "$t" "${ITERS}" "${WL}" 2>&1)"
			if [ $? -ne 0 ]; then
				echo "[${mode}] threads=$t rep${rep} TIMEOUT/ERROR (>120s) -> ${line}"
				echo "${mode},${t},NA,NA,TIMEOUT,NA,NA" >> "${CSV}"
				timedout=1; break
			fi
			echo "[${mode}] rep${rep} ${line}"
			wall="$(echo "$line" | sed -n 's/.*wall_ms=\([0-9.]*\).*/\1/p')"
			errs="$(echo "$line" | sed -n 's/.*errs=\([0-9]*\).*/\1/p')"
			ERRS_TOTAL=$(( ERRS_TOTAL + ${errs:-0} ))
			# keep the MIN wall across reps (least-contended run = truest hot-path)
			if [ -z "$best" ] || awk "BEGIN{exit !(${wall:-0} < ${best})}"; then best="${wall:-0}"; fi
		done
		# A timeout in ANY rep is a failed measurement for this thread count: leave
		# WALL_* unset so the summary records it MISSING and the gate FAILs.
		[ "$timedout" -eq 1 ] && continue
		local total=$(( t * ITERS ))
		echo "${mode},${t},${total},min-of-${REPS},${best},,," >> "${CSV}"
		# No eval: t is validated+normalized numeric; printf -v keeps it data-safe.
		printf -v "WALL_${mode}_${t}" '%s' "${best:-0}"
		MEASURED=$(( MEASURED + 1 ))
	done
}
ERRS_TOTAL=0
MEASURED=0

echo "=== WITHOUT compartment (no daemon, no hooks) ==="
"${BIN}" --unpin >/dev/null 2>&1 || true
run_sweep OFF

echo "=== WITH compartment (daemon pinned, ALLOW hot path) ==="
"${BIN}" --pin "${PROFILE}" > "${RESULTS}/daemon.log" 2>&1 &
DAEMON_PID=$!
live=0
for i in $(seq 1 75); do
	if grep -q "^\[run\] compartment-bpf live" "${RESULTS}/daemon.log" 2>/dev/null; then live=1; break; fi
	kill -0 "$DAEMON_PID" 2>/dev/null || { echo "daemon died" >&2; cat "${RESULTS}/daemon.log" >&2; exit 1; }
	sleep 0.2
done
# P2-d: do NOT proceed to the ON sweep unless the daemon actually reached live —
# otherwise "ON" would measure the no-enforcement path and the comparison is bogus.
if [ "$live" -ne 1 ]; then
	echo "[open-conc] FAIL — daemon did not reach live state in 15s; ON sweep would be meaningless" >&2
	cat "${RESULTS}/daemon.log" >&2
	exit 1
fi
run_sweep ON
kill -TERM "$DAEMON_PID" 2>/dev/null || true; wait "$DAEMON_PID" 2>/dev/null || true; DAEMON_PID=""
"${BIN}" --unpin >/dev/null 2>&1 || true

echo "=== summary (ALLOW path: ON vs OFF per thread count) ==="
# NB: compute `worst`/`bad_rows` in THIS shell, NOT inside a `... | tee` block —
# a pipe runs the block in a subshell and every update would be lost (the parent
# would keep worst=0 and PASS unconditionally). Write the table to the file with
# a plain redirect and echo each row.
worst=0
bad_rows=0
SUMMARY="${RESULTS}/summary.txt"
hdr="$(printf "%-8s %-12s %-12s %-10s" "threads" "OFF_wall_ms" "ON_wall_ms" "overhead%")"
echo "$hdr" | tee "${SUMMARY}"
for t in ${THREADS}; do
	# Mirror run_sweep's guard + leading-zero normalize so the WALL_* var names
	# match what run_sweep set (P2-3 + P2-b).
	case "$t" in ''|*[!0-9]*) continue;; esac
	t=$((10#$t))
	local_off="WALL_OFF_${t}"; local_on="WALL_ON_${t}"
	off="${!local_off:-}"; on="${!local_on:-}"
	pct="NA"
	if [ -z "$off" ] || [ -z "$on" ]; then
		# A timed-out / errored / missing row never set its WALL_* var. That is
		# a failed measurement, not a 0% pass.
		pct="MISSING"; bad_rows=$((bad_rows+1))
	elif awk "BEGIN{exit !($off>0)}"; then
		pct="$(awk "BEGIN{printf \"%d\", ($on-$off)*100/$off}")"
		[ "$pct" -gt "$worst" ] && worst="$pct"
	else
		pct="NA(off=0)"; bad_rows=$((bad_rows+1))
	fi
	printf "%-8s %-12s %-12s %-10s\n" "$t" "${off:-NA}" "${on:-NA}" "$pct" | tee -a "${SUMMARY}"
done

# P2-a: an all-invalid OC_THREADS (e.g. "abc") skips every token in BOTH sweeps →
# zero rows → worst stays 0 → would PASS vacuously. A run that measured NOTHING is
# not a pass.
if [ "${MEASURED:-0}" -eq 0 ]; then
	echo "[open-conc] FAIL — no valid thread count was measured (check OC_THREADS='${THREADS}'); nothing benchmarked"
	exit 1
fi
echo "[open-conc] worst ON-vs-OFF overhead=${worst}% (soft gate ${MAXPCT}%); CSV ${CSV}"
echo "[open-conc] interpretation: flat/low overhead => no file_open concurrency cliff"
echo "[open-conc]   (the shell 'cliff' was exec/fork hook serialization, not file_open)."
# The workload file is UNSEALED → every open() must succeed (ALLOW path). Any
# errs means a broken benchmark (bad path / wrong mode), so the % overhead is
# measuring nothing — fail loudly instead of reporting a flattering 0%.
if [ "${ERRS_TOTAL:-0}" -ne 0 ]; then
	echo "[open-conc] FAIL — ${ERRS_TOTAL} open() error(s) across sweeps: benchmark is not measuring the ALLOW path (check WL path / mode); result is meaningless"
	exit 1
fi
if [ "${bad_rows}" -ne 0 ]; then
	echo "[open-conc] FAIL — ${bad_rows} row(s) missing/timed-out/invalid: the sweep did not produce a complete measurement (result is not a pass)"
	exit 1
fi
if [ "$worst" -le "$MAXPCT" ]; then
	echo "[open-conc] PASS — no file_open concurrency cliff (overhead ${worst}% <= ${MAXPCT}%)"
	exit 0
else
	echo "[open-conc] FAIL — overhead ${worst}% > ${MAXPCT}% soft gate: real file_open scaling cost, investigate with perf"
	exit 1
fi
