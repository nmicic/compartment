#!/usr/bin/env bash
# actor-overhead.sh — quantify compartment's exec-domain enforcement overhead.
#
# Answers "how much does running compartment cost?" with a single % number:
# a representative actor-like workload (file open/read + process exec — the
# operations compartment's LSM hooks intercept) is timed WITH compartment
# enforcing (daemon pinned, hooks active on the ALLOW hot path) vs WITHOUT
# (no daemon, no hooks). Median of REPS reps; reports baseline / compartment /
# delta / overhead %. The A-vs-B delta isolates the per-syscall LSM-hook cost
# (shell overhead cancels — both modes run the identical workload).
#
# This is the headline complement to bench-runner.sh's per-op MODE-A/MODE-B rows.
#
# Env: BENCH_OVERHEAD_REPS (7), BENCH_OVERHEAD_OPS (4000 open cycles/rep),
#      BENCH_OVERHEAD_EXECS (400 execs/rep), BENCH_OVERHEAD_MAXPCT (60 soft gate).
# Requires root (CAP_BPF + bpffs) and a built ./compartment-bpf.

set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO}"
BIN="${REPO}/compartment-bpf"
PIN_ROOT="/sys/fs/bpf/compartment"
REPS="${BENCH_OVERHEAD_REPS:-7}"
OPS="${BENCH_OVERHEAD_OPS:-4000}"
EXECS="${BENCH_OVERHEAD_EXECS:-400}"
MAXPCT="${BENCH_OVERHEAD_MAXPCT:-60}"

[ "$(id -u)" -eq 0 ] || { echo "actor-overhead: needs root" >&2; exit 2; }
[ -x "${BIN}" ] || { echo "actor-overhead: build compartment-bpf first" >&2; exit 2; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS="${REPO}/tests/results/actor-overhead-${TS}"
mkdir -p "${RESULTS}"
CSV="${RESULTS}/actor-overhead.csv"
echo "mode,rep,ms" > "${CSV}"

SCR="$(mktemp -d /tmp/actor-overhead.XXXXXX)"
WL="${SCR}/wl"; mkdir -p "${WL}"
PROFILE="${SCR}/p.conf"
DUMMY="${SCR}/sealed-dummy"
echo dummy > "${DUMMY}"
# A minimal seal just to make the daemon active (hooks attach globally once pinned;
# the workload's own files are unsealed → they hit the hook's ALLOW hot path).
echo "seal ${DUMMY} no-write" > "${PROFILE}"

# Pre-create the rotating file set so the loop is pure open/read (no create churn).
for n in $(seq 0 63); do echo x > "${WL}/f${n}"; done

DAEMON_PID=""
cleanup() {
	[ -n "${DAEMON_PID}" ] && kill -0 "${DAEMON_PID}" 2>/dev/null && \
		{ kill -TERM "${DAEMON_PID}" 2>/dev/null || true; wait "${DAEMON_PID}" 2>/dev/null || true; }
	"${BIN}" --unpin >/dev/null 2>&1 || true
	rm -rf "${SCR}"
}
trap cleanup EXIT INT TERM

# Representative workload: OPS open(write)+open(read) cycles (file_open /
# file_permission hooks, builtins → no exec noise) + EXECS /bin/true (exec hook).
workload() {
	local i=0
	while [ "$i" -lt "$OPS" ]; do
		local f="${WL}/f$((i & 63))"
		printf 'x' > "$f" 2>/dev/null || true      # open(O_WRONLY|CREAT|TRUNC) -> hook
		read -r _ < "$f" 2>/dev/null || true        # open(O_RDONLY)            -> hook
		i=$((i+1))
	done
	i=0
	while [ "$i" -lt "$EXECS" ]; do /bin/true; i=$((i+1)); done   # exec -> bprm hook
}
time_ms() { local t0 t1; t0=$(date +%s%N); workload; t1=$(date +%s%N); echo $(( (t1 - t0) / 1000000 )); }
median() { printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }

# ---- Mode A: WITHOUT compartment (no daemon, no LSM hooks) ------------------
"${BIN}" --unpin >/dev/null 2>&1 || true
time_ms >/dev/null   # warmup (page cache, shell)
A=()
for r in $(seq 1 "$REPS"); do m="$(time_ms)"; A+=("$m"); echo "A,$r,$m" >> "${CSV}"; done
mode_a="$(median "${A[@]}")"

# ---- Mode B: WITH compartment (daemon pinned, hooks active) -----------------
"${BIN}" --pin "${PROFILE}" > "${RESULTS}/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 75); do grep -q "^\[run\] compartment-bpf live" "${RESULTS}/daemon.log" 2>/dev/null && break; kill -0 "$DAEMON_PID" 2>/dev/null || { echo "daemon died" >&2; cat "${RESULTS}/daemon.log" >&2; exit 1; }; sleep 0.2; done
time_ms >/dev/null   # warmup
B=()
for r in $(seq 1 "$REPS"); do m="$(time_ms)"; B+=("$m"); echo "B,$r,$m" >> "${CSV}"; done
mode_b="$(median "${B[@]}")"
kill -TERM "$DAEMON_PID" 2>/dev/null || true; wait "$DAEMON_PID" 2>/dev/null || true; DAEMON_PID=""
"${BIN}" --unpin >/dev/null 2>&1 || true

# ---- Report -----------------------------------------------------------------
delta=$(( mode_b - mode_a ))
if [ "$mode_a" -gt 0 ]; then pct=$(( delta * 100 / mode_a )); else pct=0; fi
{
	echo "workload: ${OPS} open(write)+open(read) cycles + ${EXECS} exec /bin/true, median of ${REPS} reps"
	echo "baseline (no compartment):   ${mode_a} ms"
	echo "with compartment (enforcing): ${mode_b} ms"
	echo "delta:                        ${delta} ms"
	echo "overhead:                     ${pct} %"
} | tee "${RESULTS}/summary.txt"

echo "[overhead] baseline=${mode_a}ms compartment=${mode_b}ms delta=${delta}ms overhead=${pct}% (CSV ${CSV})"
if [ "$pct" -le "$MAXPCT" ]; then
	echo "[overhead] PASS (overhead ${pct}% <= ${MAXPCT}% soft gate)"
	exit 0
else
	echo "[overhead] FAIL (overhead ${pct}% > ${MAXPCT}% soft gate — investigate)"
	exit 1
fi
