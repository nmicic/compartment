#!/usr/bin/env bash
# tests/strict-launch/perf-g11-corrected.sh — corrected G11 perf
# methodology per Review-1 HIGH-1 (2026-05-15).
#
# Pre-fix, the published +4.76% G11 number was measured against the
# spike's `slm_runner` attached as a SECOND BPF program on top of the
# production v0.3 daemon. The deny was `ACTION_DENY_ACTOR_MISMATCH=30`
# from the spike (not v0.4 ACTION_DENY_STRICT_LAUNCH_MISSING=8) and
# the victim seal had flags=0x4 (NO_WRITE only; no SEAL_STRICT_LAUNCH).
# The integrated v0.4 `strict_launch_check_or_deny` path was never
# exercised by the published-perf measurement.
#
# Correct methodology (SPEC §10 5% incremental ceiling):
#   Same daemon binary (the v0.4 build at HEAD), two profiles:
#     A — baseline: actor= legacy binding on victim (no strict-launch).
#         Hot-path file_open hits seal_decision -> actor_check_or_deny
#         and denies with ACTION_DENY_ACTOR_MISMATCH on the test loop.
#     B — incremental: actor-strict NAME on victim + SEAL_STRICT_LAUNCH
#         set on victim seal. Hot-path file_open hits seal_decision ->
#         actor_check_or_deny passes -> strict_launch_check_or_deny
#         denies with ACTION_DENY_STRICT_LAUNCH_MISSING on the test loop.
#
# The deny-counter signal proves topology:
#   A: actor_mismatch_total delta = ITERS (and strict_launch_missing == 0)
#   B: strict_launch_missing_total delta = ITERS (and actor_mismatch == 0)
#
# Δ = (ops_a - ops_b) / ops_a. SPEC §10 accept: < 5%. Halt class: > 10%.
#
# Runs N=5 trials of each profile; prints mean + stdev. Persists CSV
# under tests/results/g11-corrected-${TS}/ for EVIDENCE inclusion.

set -euo pipefail

cd "$(dirname "$0")/../.." || exit 2

[ "$(id -u)" -eq 0 ] || { echo "[perf-g11] SKIP (requires root)"; exit 77; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null || {
    echo "[perf-g11] SKIP (bpf not in active LSMs)"; exit 77; }
[ -x ./compartment-bpf ] || { echo "[perf-g11] SKIP (./compartment-bpf not built)"; exit 77; }

SPIKE_DIR="experimental/strict-launch-marker"
LAUNCHER="$SPIKE_DIR/build/slm-launcher"
ACTOR="$SPIKE_DIR/build/slm-actor"
SLM_PERF="$SPIKE_DIR/build/slm-perf"

if [ ! -x "$LAUNCHER" ] || [ ! -x "$ACTOR" ] || [ ! -x "$SLM_PERF" ]; then
    if [ -x "$SPIKE_DIR/scripts/build_on_vm.sh" ]; then
        ( cd "$SPIKE_DIR" && bash scripts/build_on_vm.sh ) >/tmp/slm-perf-build.log 2>&1 || {
            echo "[perf-g11] SKIP (spike fixture build failed)"; exit 77; }
    else
        echo "[perf-g11] SKIP (spike fixtures not built)"; exit 77
    fi
fi

ITERS="${ITERS:-20000}"
TRIALS="${TRIALS:-5}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="tests/results/g11-corrected-${TS}"
mkdir -p "$OUT"
CSV="$OUT/g11.csv"
LOG="$OUT/run.log"
exec > >(tee -a "$LOG") 2>&1

LAUNCHER_ABS=$(readlink -f "$LAUNCHER")
ACTOR_ABS=$(readlink -f "$ACTOR")
SLM_PERF_ABS=$(readlink -f "$SLM_PERF")

VICTIM=/tmp/g11-corrected-victim
: >"$VICTIM"
DUMMY=$(readlink -f /usr/bin/dash 2>/dev/null || readlink -f /bin/dash)

PIN_ROOT=/sys/fs/bpf/compartment

# Profile A baseline: legacy `actor=` binding to /usr/bin/dash (NOT
# slm-perf), so slm-perf's writes hit `actor_check_or_deny` and deny
# via ACTION_DENY_ACTOR_MISMATCH on every iteration.
# SEAL_NO_WRITE only — no strict-launch.
PROF_A="$OUT/profile-A-baseline.conf"
cat >"$PROF_A" <<EOF
actor wrong = $DUMMY

seal $VICTIM no-write actor=wrong
seal $DUMMY full
EOF

# Profile B incremental: actor-strict on slm-perf itself (so the
# perf process passes `actor_check_or_deny`'s inode-match) +
# SEAL_STRICT_LAUNCH on the victim (so it falls through to
# `strict_launch_check_or_deny`). slm-perf is invoked directly (no
# launcher), so it has no marker → strict_launch_missing on every
# iteration. This is the v0.4 hot-path the SPEC §10 5% ceiling
# measures.
PROF_B="$OUT/profile-B-incremental.conf"
cat >"$PROF_B" <<EOF
actor-strict perf = $SLM_PERF_ABS launcher=$LAUNCHER_ABS

seal $LAUNCHER_ABS full
seal $SLM_PERF_ABS full
seal $VICTIM no-write actor=perf strict-launch
EOF

read_counter() {
    local pin="$PIN_ROOT/maps/$1"
    [ -e "$pin" ] || { echo 0; return; }
    bpftool -j map dump pinned "$pin" 2>/dev/null | python3 -c '
import json, sys
d=json.load(sys.stdin)
total=0
for e in d:
    if "values" in e:
        for cpu in e["values"]:
            v=cpu["value"]
            if isinstance(v, list):
                acc=0
                for i,b in enumerate(v):
                    if isinstance(b,str): b=int(b,16)
                    acc |= b << (8*i)
                v=acc
            total += int(v)
    else:
        v=e["value"]
        if isinstance(v, list):
            acc=0
            for i,b in enumerate(v):
                if isinstance(b,str): b=int(b,16)
                acc |= b << (8*i)
            v=acc
        total += int(v)
print(total)' 2>/dev/null || echo 0
}

run_one() {
    local label="$1" profile="$2" counter="$3"
    local logf="$OUT/${label}.log"

    rm -rf "$PIN_ROOT" 2>/dev/null || true
    ./compartment-bpf --pin "$profile" >"$logf" 2>&1 &
    local dpid=$!
    local ok=0
    for _ in $(seq 1 50); do
        if grep -q '\[run\] compartment-bpf live' "$logf" 2>/dev/null; then
            ok=1; break
        fi
        kill -0 $dpid 2>/dev/null || break
        sleep 0.1
    done
    if [ "$ok" != "1" ]; then
        echo "  $label: daemon failed to go live"
        cat "$logf"
        kill -TERM $dpid 2>/dev/null || true
        wait $dpid 2>/dev/null || true
        return 1
    fi

    local pre post
    pre=$(read_counter "$counter")
    # Hot-path measurement
    local out
    out=$("$SLM_PERF" open-write "$VICTIM" "$ITERS")
    sleep 0.2
    post=$(read_counter "$counter")
    local delta=$((post - pre))
    local ops
    ops=$(echo "$out" | sed 's/.*ops_per_sec=\([0-9]*\).*/\1/')

    kill -TERM $dpid 2>/dev/null || true
    wait $dpid 2>/dev/null || true
    ./compartment-bpf --unpin >/dev/null 2>&1 || true

    # Topology check: the requested counter must == ITERS exact.
    if [ "$delta" != "$ITERS" ]; then
        echo "  $label: topology FAIL — $counter delta=$delta want exact $ITERS (deny is not going through the expected path)"
        return 2
    fi
    echo "  $label: ops/s=$ops $counter+$delta"
    echo "$ops"
}

# CSV header
echo "trial,A_actor_mismatch_ops,B_strict_launch_ops,incr_pct_x100" >"$CSV"

declare -a OPS_A OPS_B
for t in $(seq 1 $TRIALS); do
    echo
    echo "=== trial $t / $TRIALS (ITERS=$ITERS) ==="
    if ! ops_a=$(run_one "trial-${t}-A" "$PROF_A" "actor_mismatch_total" | tail -1); then
        echo "trial $t profile A failed; abort"
        exit 1
    fi
    if ! ops_b=$(run_one "trial-${t}-B" "$PROF_B" "strict_launch_missing_total" | tail -1); then
        echo "trial $t profile B failed; abort"
        exit 1
    fi
    OPS_A[$t]=$ops_a
    OPS_B[$t]=$ops_b
    # incremental % x100 (avoid floating)
    if [ "$ops_a" -gt 0 ]; then
        pct_x100=$(( (ops_a - ops_b) * 10000 / ops_a ))
    else
        pct_x100=0
    fi
    echo "$t,$ops_a,$ops_b,$pct_x100" >>"$CSV"
done

# Mean / stdev for each
python3 - "$CSV" "$ITERS" "$TRIALS" <<'PY'
import csv, sys, math
csv_path = sys.argv[1]
ITERS = int(sys.argv[2])
TRIALS = int(sys.argv[3])
A, B, Pct = [], [], []
with open(csv_path) as f:
    r = csv.DictReader(f)
    for row in r:
        A.append(int(row["A_actor_mismatch_ops"]))
        B.append(int(row["B_strict_launch_ops"]))
        Pct.append(int(row["incr_pct_x100"]) / 100.0)

def mstd(xs):
    n = len(xs)
    m = sum(xs)/n
    s = math.sqrt(sum((x-m)**2 for x in xs)/n) if n>1 else 0.0
    return m, s

mA, sA = mstd(A)
mB, sB = mstd(B)
mPct, sPct = mstd(Pct)
incr_mean = (mA - mB) / mA * 100.0 if mA else 0.0

print()
print("=== HIGH-1 corrected G11 result (Review-1 fix, 2026-05-15) ===")
print(f"Trials       : {TRIALS} x {ITERS} iters")
print(f"Profile A    : actor= legacy mismatch (baseline)        ops/s mean={mA:.0f} stdev={sA:.0f}")
print(f"Profile B    : actor-strict + SEAL_STRICT_LAUNCH         ops/s mean={mB:.0f} stdev={sB:.0f}")
print(f"Incremental  : per-trial mean={mPct:+.2f}% stdev={sPct:.2f}%")
print(f"Overall mean : {incr_mean:+.2f}%  (SPEC §10 ceiling: <5%; halt class: >10%)")
if incr_mean > 10.0:
    print("HALT class: > 10% incremental — release-blocker regression")
    sys.exit(2)
elif incr_mean > 5.0:
    print("Sidebar class: 5-10% incremental — operator-decision required (SPEC §10)")
    sys.exit(3)
else:
    print("Within SPEC §10 ceiling.")
    sys.exit(0)
PY
rc=$?

rm -f "$VICTIM"
exit $rc
