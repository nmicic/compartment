#!/usr/bin/env bash
# telemetry-smoke.sh — bulletproof the minimal-overhead telemetry/stats surface.
#
# Complements counter-smoke.sh (which checks exact accuracy of 3 counters). This
# harness makes the *whole* `--stats` telemetry surface robust + drift-proof, so a
# poller (operator / monitoring) gets correct, minimal-overhead stats:
#
#   TM-1 PARITY/DRIFT-GUARD : every pinned `*_total` counter map is surfaced by
#        `--stats` (and vice-versa) — a new counter that forgets the --stats table,
#        or a stale table entry, FAILS here. Closes the monitoring blind-spot.
#   TM-2 TYPE              : every surfaced counter map is a PERCPU_ARRAY (the
#        always-on, lossless, contention-free counter shape) — if bpftool present.
#   TM-3 AT-REST STABILITY : with no enforcement activity, repeated `--stats` reads
#        are identical for ALL counters (read-only, no drift).
#   TM-4 MINIMAL-OVERHEAD POLLING : under a deny workload, polling `--stats` is
#        non-perturbing (counts stay exact across reads) and cheap (out-of-band,
#        read-only) — this is the "minimal telemetry by polling" property.
#   TM-5 CATALOGUE         : every pinned counter is documented in COUNTERS.md, so
#        the catalogue can't silently drift from the implementation.
#
# Zero data-plane change: read-only over the existing counters. Exits non-zero on
# any failure. Requires root (CAP_BPF + bpffs) and a built ./compartment-bpf.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"

if [ -z "${RESULTS:-}" ]; then
	DATE="$(date -u +%Y%m%dT%H%M%SZ)"
	RESULTS="${REPO}/tests/results/telemetry-smoke-${DATE}"
fi
mkdir -p "${RESULTS}"
CSV="${RESULTS}/telemetry-smoke.csv"
echo "test,outcome,detail" > "${CSV}"

BIN="${REPO}/compartment-bpf"
PIN_ROOT="/sys/fs/bpf/compartment"
COUNTERS_DOC="${REPO}/COUNTERS.md"
LOG="${RESULTS}/telemetry-smoke.log"

[ -x "${BIN}" ] || { echo "fatal: ${BIN} not built (run make)" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "fatal: requires root" >&2; exit 1; }

SCRATCH="$(mktemp -d /tmp/telemetry-smoke.XXXXXX)"
SEALED="${SCRATCH}/sealed.txt"
PROFILE="${SCRATCH}/profile.conf"
echo "stay-sealed" > "${SEALED}"
echo "seal ${SEALED} no-write" > "${PROFILE}"

DAEMON_PID=""
cleanup() {
	local rc=$?
	[ -n "${DAEMON_PID}" ] && kill -0 "${DAEMON_PID}" 2>/dev/null && \
		{ kill -TERM "${DAEMON_PID}" 2>/dev/null || true; wait "${DAEMON_PID}" 2>/dev/null || true; }
	"${BIN}" --unpin >/dev/null 2>&1 || true
	rm -rf "${SCRATCH}"
	exit $rc
}
trap cleanup EXIT INT TERM

record() { echo "$1,$2,$3" >> "${CSV}"; echo "[$1] $2  $3" >&2; }
failed=0; passed=0
ok()   { record "$1" PASS "$2"; passed=$((passed+1)); }
bad()  { record "$1" FAIL "$2"; failed=$((failed+1)); }

start_daemon() {
	"${BIN}" --unpin >/dev/null 2>&1 || true
	"${BIN}" --pin "${PROFILE}" > "${LOG}" 2>&1 &
	DAEMON_PID=$!
	local i
	for i in $(seq 1 75); do
		grep -q "^\[run\] compartment-bpf live" "${LOG}" 2>/dev/null && return 0
		kill -0 "${DAEMON_PID}" 2>/dev/null || { echo "daemon died:" >&2; cat "${LOG}" >&2; return 1; }
		sleep 0.2
	done
	echo "daemon not live in 15s" >&2; cat "${LOG}" >&2; return 1
}

# All "name=value" counter names from a --stats run.
stats_names() { "${BIN}" --stats 2>/dev/null | grep -oE '[a-z_]+_total=' | sed 's/=$//' | sort -u; }
# One counter's value from --stats.
stats_get()   { "${BIN}" --stats 2>/dev/null | grep -oE "$1=[0-9]+" | head -1 | cut -d= -f2; }
# Pinned counter map names under bpffs.
pinned_counters() { ls "${PIN_ROOT}/maps/" 2>/dev/null | grep -E '_total$' | sort -u; }

echo "=== telemetry-smoke ===" >&2
start_daemon || { bad TM-0 "daemon-start-failed"; echo "SUMMARY pass=${passed} fail=${failed}"; exit 1; }

# ---- TM-1: parity / drift-guard --------------------------------------------
PINNED="$(pinned_counters)"
SURFACED="$(stats_names)"
n_pin=$(echo "${PINNED}"   | grep -c . || true)
n_sur=$(echo "${SURFACED}" | grep -c . || true)
# In pinned but NOT surfaced by --stats = a monitoring blind spot.
MISSING="$(comm -23 <(echo "${PINNED}") <(echo "${SURFACED}") || true)"
# Surfaced by --stats but no pinned map = stale table entry.
EXTRA="$(comm -13 <(echo "${PINNED}") <(echo "${SURFACED}") || true)"
# Floor: with both lists empty, `comm` reports no diff and parity would PASS
# vacuously ("all 0 surfaced") — masking TOTAL drift (counters gone / not pinned).
# Require the known counter floor so an empty surface FAILS loudly.
TM_MIN_COUNTERS="${TM_MIN_COUNTERS:-12}"
if [ "${n_pin}" -lt "${TM_MIN_COUNTERS}" ]; then
	bad TM-1 "too few pinned counters: ${n_pin} < ${TM_MIN_COUNTERS} floor (counter surface missing/empty — not a vacuous PASS)"
elif [ -n "${MISSING}" ]; then
	bad TM-1 "pinned-but-not-in-stats: $(echo ${MISSING} | tr '\n' ' ')"
elif [ -n "${EXTRA}" ]; then
	bad TM-1 "in-stats-but-not-pinned: $(echo ${EXTRA} | tr '\n' ' ')"
else
	ok TM-1 "parity: all ${n_pin} pinned counters surfaced by --stats (>= ${TM_MIN_COUNTERS} floor; none missing/stale)"
fi

# ---- TM-2: counter map type (PERCPU_ARRAY) ---------------------------------
if [ "${n_pin}" -eq 0 ]; then
	bad TM-2 "no pinned counters to type-check (empty surface — see TM-1)"
elif command -v bpftool >/dev/null 2>&1; then
	bad_type=""
	for c in ${PINNED}; do
		t="$(bpftool map show pinned "${PIN_ROOT}/maps/${c}" 2>/dev/null | grep -oE 'percpu_array|array|hash' | head -1)"
		[ "${t}" = "percpu_array" ] || bad_type="${bad_type} ${c}:${t:-?}"
	done
	[ -z "${bad_type}" ] && ok TM-2 "all ${n_pin} counters are PERCPU_ARRAY" \
		|| bad TM-2 "non-percpu counters:${bad_type}"
else
	record TM-2 SKIP "bpftool absent"
fi

# ---- TM-3: at-rest stability (read-only, no drift) -------------------------
snap1="$("${BIN}" --stats 2>/dev/null | grep -oE '[a-z_]+_total=[0-9]+' | sort)"
drift=0
for _ in $(seq 1 10); do
	snap="$("${BIN}" --stats 2>/dev/null | grep -oE '[a-z_]+_total=[0-9]+' | sort)"
	[ "${snap}" = "${snap1}" ] || drift=1
done
[ "${drift}" -eq 0 ] && ok TM-3 "10 --stats reads identical at rest (no spurious drift)" \
	|| bad TM-3 "--stats values changed with no enforcement activity"

# ---- TM-4: minimal-overhead polling (non-perturbing + cheap) ---------------
N=200
base="$(stats_get deny_total)"; base="${base:-0}"
i=0; while [ "${i}" -lt "${N}" ]; do printf 'x' >> "${SEALED}" 2>/dev/null || true; i=$((i+1)); done
after="$(stats_get deny_total)"; after="${after:-0}"
delta=$((after - base))
if [ "${delta}" -eq "${N}" ]; then
	ok TM-4a "deny_total counted exactly ${N} denied writes (delta=${delta})"
else
	bad TM-4a "deny_total delta=${delta} expected ${N}"
fi
# Poll 20x; counts must NOT change (read-only) and reads must be cheap.
start_ns=$(date +%s%N)
poll_drift=0; v0="$(stats_get deny_total)"
for _ in $(seq 1 20); do
	v="$(stats_get deny_total)"; [ "${v}" = "${v0}" ] || poll_drift=1
done
end_ns=$(date +%s%N)
avg_ms=$(( (end_ns - start_ns) / 1000000 / 20 ))
if [ "${poll_drift}" -eq 0 ]; then
	ok TM-4b "20 polls non-perturbing (deny_total stable at ${v0}); avg ~${avg_ms}ms/read"
else
	bad TM-4b "polling --stats perturbed deny_total"
fi
# Soft sanity: a --stats read is out-of-band; flag only if absurdly slow (>2s).
[ "${avg_ms}" -lt 2000 ] && ok TM-4c "poll cost minimal (~${avg_ms}ms/read < 2000ms)" \
	|| bad TM-4c "poll cost ${avg_ms}ms/read suspiciously high"

# ---- TM-5: catalogue coverage (COUNTERS.md) --------------------------------
if [ "${n_pin}" -eq 0 ]; then
	bad TM-5 "no pinned counters to check against COUNTERS.md (empty surface — see TM-1)"
elif [ -f "${COUNTERS_DOC}" ]; then
	undoc=""
	for c in ${PINNED}; do grep -q "${c}" "${COUNTERS_DOC}" || undoc="${undoc} ${c}"; done
	[ -z "${undoc}" ] && ok TM-5 "all ${n_pin} counters documented in COUNTERS.md" \
		|| bad TM-5 "undocumented counters:${undoc}"
else
	bad TM-5 "COUNTERS.md absent (catalogue missing)"
fi

echo "=== SUMMARY pass=${passed} fail=${failed} (CSV: ${CSV}) ===" >&2
[ "${failed}" -eq 0 ]
