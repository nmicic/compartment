#!/usr/bin/env bash
# deny-to-candidate.sh — e2e for the deny-first bridge (tools/deny-to-candidate.py).
#
# Pins a real daemon, provokes DENY_WRITE on a sealed file, captures the daemon's
# [audit] stream, runs deny-to-candidate.py (bounded, --profile resolve), and asserts
# the emitted CANDIDATE profile (a) carries the candidate marker, (b) resolves dev/ino
# back to the sealed path, (c) suggests the (commented) allow rule, (d) is bounded.
# Plus a synthetic check that an exec-domain deny does NOT get an auto-allow suggestion.
#
# Userspace-only; no kernel/data-plane change. Requires root + a built ./compartment-bpf.

set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"
BIN="${REPO}/compartment-bpf"
TOOL="${REPO}/tools/deny-to-candidate.py"
[ -x "${BIN}" ] || { echo "fatal: build compartment-bpf first" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "fatal: needs root" >&2; exit 1; }
command -v python3 >/dev/null || { echo "[deny-to-candidate] SKIP (no python3)"; exit 0; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
RES="${REPO}/tests/results/deny-to-candidate-${TS}"; mkdir -p "${RES}"
SCR="$(mktemp -d /tmp/deny2cand.XXXXXX)"
VICTIM="${SCR}/secret.txt"; PROFILE="${SCR}/p.conf"; DLOG="${RES}/daemon.log"
echo "secret" > "${VICTIM}"
echo "seal ${VICTIM} no-write" > "${PROFILE}"

PASS=0; FAIL=0
ok()  { echo "[PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "[FAIL] $*"; FAIL=$((FAIL+1)); }
DPID=""
cleanup() {
	[ -n "${DPID}" ] && kill -0 "${DPID}" 2>/dev/null && { kill -TERM "${DPID}" 2>/dev/null; wait "${DPID}" 2>/dev/null; }
	"${BIN}" --unpin >/dev/null 2>&1 || true
	rm -rf "${SCR}"
}
trap cleanup EXIT INT TERM

# ---- real daemon: provoke DENY_WRITE, capture the audit stream -------------
"${BIN}" --unpin >/dev/null 2>&1 || true
"${BIN}" --pin "${PROFILE}" > "${DLOG}" 2>&1 &
DPID=$!
for i in $(seq 1 75); do grep -q "^\[run\] compartment-bpf live" "${DLOG}" 2>/dev/null && break; kill -0 "$DPID" 2>/dev/null || { echo "daemon died"; cat "${DLOG}"; exit 1; }; sleep 0.2; done

N=20
i=0; while [ "$i" -lt "$N" ]; do printf 'x' >> "${VICTIM}" 2>/dev/null || true; i=$((i+1)); done
# let the ringbuf drain to the daemon log
for i in $(seq 1 20); do [ "$(grep -c 'DENY_WRITE' "${DLOG}" 2>/dev/null)" -ge "$N" ] && break; sleep 0.2; done
# grep -c prints "0" AND exits 1 on zero matches; `|| true` keeps that single
# "0" without appending another (|| echo 0 would yield a two-line "0\n0" that
# breaks the [ -ge 1 ] numeric test). Same convention as pin-regression.sh.
ndeny=$(grep -c "DENY_WRITE" "${DLOG}" 2>/dev/null || true)
[ "$ndeny" -ge 1 ] && ok "daemon emitted DENY_WRITE audit events (${ndeny})" || bad "no DENY_WRITE audit events captured"

# ---- translate denies -> candidate profile --------------------------------
CAND="${RES}/candidate.conf"
python3 "${TOOL}" --profile "${PROFILE}" --max 100 < "${DLOG}" > "${CAND}" 2>"${RES}/tool.err"
trc=$?
[ "$trc" -eq 0 ] && ok "deny-to-candidate ran (rc=0)" || bad "tool failed rc=${trc} ($(cat ${RES}/tool.err))"

grep -q "^#@compartment-bpf-profile-status: candidate" "${CAND}" \
	&& ok "candidate marker present" || bad "candidate marker missing"
grep -qE "DENY_WRITE.*target=${VICTIM}" "${CAND}" \
	&& ok "resolved dev/ino back to the sealed path (${VICTIM})" \
	|| { bad "did not resolve target path"; grep -i "DENY_WRITE" "${CAND}" | head -2; }
grep -qE "^#     seal ${VICTIM} no-write actor=<name>" "${CAND}" \
	&& ok "emitted the (commented) suggested allow rule" || bad "no suggested allow rule"
# every suggested rule is commented (fail-safe: nothing active)
if grep -vE "^\s*#" "${CAND}" | grep -qE "^\s*(seal|actor)\b"; then
	bad "candidate contains an ACTIVE seal/actor directive (must be commented)"
else
	ok "all suggestions commented (no active directive — fail-safe)"
fi
# bounded count reflected
grep -qE "^# \[[0-9]+x\] DENY_WRITE" "${CAND}" && ok "per-deny count recorded" || bad "no per-deny count"

# ---- synthetic: exec-domain deny must NOT get an auto-allow ----------------
SYN="${SCR}/syn.log"
cat > "${SYN}" <<'EOF'
[audit] DENY_PTRACE_ACCESS ts=1 pid=10 ppid=1 uid=0 comm=stracer dev=66 ino=99 caller_dev=66 caller_ino=42
EOF
SCAND="${RES}/syn-candidate.conf"
python3 "${TOOL}" --max 100 < "${SYN}" > "${SCAND}" 2>/dev/null
if grep -qi "exec-domain / structural deny" "${SCAND}" && ! grep -qE "seal .* actor=<name>" "${SCAND}"; then
	ok "exec-domain deny flagged as likely-intended (no auto-allow rule)"
else
	bad "exec-domain deny mis-handled (should not suggest an allow)"
fi

# ---- synthetic: DENY_ACTOR_MISMATCH must be REVIEW-ONLY (no fresh actor rule) ---
# The target is already actor-sealed (that is why the caller mismatched); the
# tool must NOT suggest a fresh `seal … actor=<name>` rule (it would duplicate/
# contradict the existing seal). Regression witness for the review-only path.
AMM="${SCR}/amm.log"
cat > "${AMM}" <<'EOF'
[audit] DENY_ACTOR_MISMATCH ts=2 pid=11 ppid=1 uid=0 comm=intruder dev=66 ino=77 caller_dev=66 caller_ino=43 actor=g
EOF
ACAND="${RES}/amm-candidate.conf"
python3 "${TOOL}" --max 100 < "${AMM}" > "${ACAND}" 2>/dev/null
if grep -qiE "review:|extend the existing|actor allowlist" "${ACAND}" \
   && ! grep -qE "^#?\s*seal .* actor=<name>" "${ACAND}"; then
	ok "DENY_ACTOR_MISMATCH is review-only (no fresh actor rule suggested)"
else
	bad "DENY_ACTOR_MISMATCH mis-handled (should be review-only, no 'seal … actor=<name>')"
fi

echo "=== deny-to-candidate SUMMARY: PASS=${PASS} FAIL=${FAIL} (${RES}) ==="
[ "${FAIL}" -eq 0 ]
