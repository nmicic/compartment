#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Nenad Mićić
#
# open-concurrency-negtest.sh — assert the open-concurrency benchmark's OWN gates
# work (Minimal Witness Set item 8). This is a NEGATIVE test: it does NOT measure
# the file_open hot path, it proves the harness FAILS/SKIPS when it should:
#
#   (a) the C binary (open-concurrency.c) rejects bad numeric args fail-closed
#       (non-numeric, trailing junk, zero/negative, out-of-bounds, overflow);
#   (b) the shell harness (open-concurrency.sh) skips a non-numeric OC_THREADS
#       token with the "skip non-numeric thread token" message;
#   (c) a non-root invocation of the full harness SKIPs cleanly (it needs root +
#       a built daemon); the over-threshold / missing-row FAIL path is only
#       exercised when root is available — otherwise it is SKIPPED, not silently
#       passed.
#
# Exit 0 = all assertions held (including clean SKIPs). Exit 1 = a gate is broken.
# It does NOT need root for (a) and (b); (c) self-gates on `id -u`.

set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="${REPO}/tests/bench/open-concurrency.c"
SH="${REPO}/tests/bench/open-concurrency.sh"

PASS=0
FAIL=0
SKIP=0
pass() { echo "[negtest] PASS — $*"; PASS=$((PASS+1)); }
fail() { echo "[negtest] FAIL — $*"; FAIL=$((FAIL+1)); }
skip() { echo "[negtest] SKIP — $*"; SKIP=$((SKIP+1)); }

WORK="$(mktemp -d /tmp/oc-negtest.XXXXXX)" || { echo "[negtest] mktemp failed" >&2; exit 1; }
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT INT TERM

BENCH="${WORK}/oc-bin"
WL="${WORK}/workload"; echo x > "${WL}"

# ---------------------------------------------------------------------------
# (a) C binary numeric-gate witnesses — no root needed.
# ---------------------------------------------------------------------------
if ! cc -O2 -pthread -o "${BENCH}" "${SRC}" 2>"${WORK}/cc.log"; then
	skip "(a) could not build open-concurrency.c (cc/-pthread unavailable); $(cat "${WORK}/cc.log")"
else
	# Each row: "label|arg1|arg2|expect_rc" where expect_rc!=0 means must reject.
	# A trailing 0 expect_rc means it must SUCCEED (the only valid row).
	run_case() {  # $1=label $2=arg1 $3=arg2 $4=expect_nonzero(1)/zero(0)
		local label="$1" a1="$2" a2="$3" want_nz="$4" rc
		"${BENCH}" "$a1" "$a2" "${WL}" >/dev/null 2>&1; rc=$?
		if [ "$want_nz" -eq 1 ]; then
			if [ "$rc" -ne 0 ]; then pass "(a) ${label}: rejected (rc=${rc})"
			else fail "(a) ${label}: accepted bad arg (rc=0) — gate broken"; fi
		else
			if [ "$rc" -eq 0 ]; then pass "(a) ${label}: valid args accepted"
			else fail "(a) ${label}: valid args rejected (rc=${rc})"; fi
		fi
	}
	run_case "non-numeric nthreads"    abc                   10  1
	run_case "trailing-junk nthreads"  4x                    10  1
	run_case "zero nthreads"           0                     10  1
	run_case "negative nthreads"       -1                    10  1
	run_case "over-max nthreads"       9999                  10  1
	run_case "non-numeric iters"       2                     ten 1
	run_case "overflow iters"          2  99999999999999999999  1
	run_case "over-max iters"          2                2000000000  1
	run_case "valid small run"         2                      5  0
fi

# ---------------------------------------------------------------------------
# (b) Shell token-guard witness — drive the SAME case-glob the harness uses to
#     skip a non-numeric OC_THREADS token, and confirm the harness source still
#     contains that exact guard + message (so this stays in lockstep with it).
# ---------------------------------------------------------------------------
# Replicate the harness guard verbatim (open-concurrency.sh run_sweep):
guard_skips() {  # $1=token -> echoes "SKIP" if the guard would skip it
	local t="$1"
	case "$t" in ''|*[!0-9]*) echo "skip non-numeric thread token '$t'";; *) echo "ACCEPT '$t'";; esac
}
out_bad="$(guard_skips 'abc; rm -rf /')"
out_empty="$(guard_skips '')"
out_good="$(guard_skips '8')"
if echo "${out_bad}" | grep -q "skip non-numeric thread token"; then
	pass "(b) non-numeric token skipped: ${out_bad}"
else
	fail "(b) non-numeric token NOT skipped: ${out_bad}"
fi
if echo "${out_empty}" | grep -q "skip non-numeric thread token"; then
	pass "(b) empty token skipped"
else
	fail "(b) empty token NOT skipped"
fi
if echo "${out_good}" | grep -q "ACCEPT"; then
	pass "(b) numeric token accepted"
else
	fail "(b) numeric token wrongly skipped: ${out_good}"
fi
# Drift guard: the live harness must still carry the exact skip message.
if grep -q "skip non-numeric thread token" "${SH}"; then
	pass "(b) harness still carries the skip-token guard message"
else
	fail "(b) harness skip-token guard message missing — negtest drifted from ${SH}"
fi

# ---------------------------------------------------------------------------
# (c) Full-harness over-threshold / missing-row FAIL path. Needs root + a built
#     daemon; SKIP cleanly otherwise (rc still 0 from this whole script).
# ---------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
	skip "(c) over-threshold/missing-row FAIL path needs root — SKIPPED (not a pass)"
elif [ ! -x "${REPO}/compartment-bpf" ]; then
	skip "(c) needs a built ./compartment-bpf daemon — SKIPPED (run 'make' first)"
elif ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
	# Without bpf in the active LSM list, --pin fails for an UNRELATED reason and
	# the harness would exit nonzero — making (c) "pass" for the wrong cause
	# (P2-5). SKIP instead so the FAIL we assert is the over-threshold gate only.
	skip "(c) needs bpf in the active LSM list (else --pin fails for an unrelated reason) — SKIPPED"
else
	# Force the gate to trip: a 0% soft gate makes any nonzero overhead FAIL, and
	# a single thread keeps the run cheap. The harness must exit nonzero.
	if OC_THREADS="1" OC_ITERS="2000" OC_MAXPCT="-1" "${SH}" >"${WORK}/run.log" 2>&1; then
		fail "(c) harness reported success with an impossible -1% gate — over-threshold FAIL path broken"
	else
		pass "(c) harness failed-closed on the forced over-threshold gate (rc!=0)"
	fi
	# Witness: a non-numeric OC_THREADS in a live run is skipped, not crashed.
	OC_THREADS="bogus 1" OC_ITERS="2000" OC_MAXPCT="60" "${SH}" >"${WORK}/run2.log" 2>&1 || true
	if grep -q "skip non-numeric thread token 'bogus'" "${WORK}/run2.log"; then
		pass "(c) live harness skipped non-numeric OC_THREADS token"
	else
		fail "(c) live harness did NOT emit the non-numeric skip message"
	fi
fi

echo "[negtest] summary: PASS=${PASS} FAIL=${FAIL} SKIP=${SKIP}"
[ "${FAIL}" -eq 0 ] || exit 1
exit 0
