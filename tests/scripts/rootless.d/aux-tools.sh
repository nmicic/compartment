#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# aux-tools.sh — rootless tests for tools/syscall.py and the extra/ helpers
#
# Everything here runs as an unprivileged user and starts no daemons.
# The proxy helpers are exercised through stubs (a fake `crontab`, a fake
# PID file) so nothing on the host is touched.
#
# Usage: ./tests/scripts/rootless.d/aux-tools.sh [--verbose]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CU="${REPO_DIR}/compartment-user"
SYSCALL_PY="${REPO_DIR}/tools/syscall.py"
VERBOSE="${1:-}"

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP: $1"; }

WORK="$(mktemp -d -t compartment-aux-XXXXXXXX)"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

vsay() { [ -n "${VERBOSE}" ] && echo "    $*" || true; }

echo "=== Auxiliary tooling tests (syscall.py, extra/) ==="
echo ""

if [ ! -x "${CU}" ]; then
    echo "ERROR: ${CU} not found. Run 'make' first."
    exit 1
fi

# ── Test group: syscall.py ─────────────────────────────────────────

echo "--- Test group: syscall.py ---"

HAVE_PY=0
command -v python3 >/dev/null 2>&1 && HAVE_PY=1
HAVE_STRACE=0
command -v strace >/dev/null 2>&1 && HAVE_STRACE=1

if [ "${HAVE_PY}" -eq 0 ]; then
    skip "syscall.py: python3 not available"
else
    if python3 -m py_compile "${SYSCALL_PY}" 2>"${WORK}/pycompile.err"; then
        pass "syscall.py compiles"
    else
        fail "syscall.py does not compile: $(head -1 "${WORK}/pycompile.err")"
    fi
    rm -rf "${REPO_DIR}/tools/__pycache__"
fi

if [ "${HAVE_PY}" -eq 0 ] || [ "${HAVE_STRACE}" -eq 0 ]; then
    skip "syscall.py profile generation (needs python3 + strace)"
else
    # ── A generated profile must actually load and run ────────────
    # Before the fix, deny mode emitted "inherit ai-agent" (a file that
    # `make install` never deploys, so the load failed outright) and allow
    # mode emitted zero path rules, so compartment-user refused with
    # "landlock enabled but no paths configured".
    for mode in deny allow; do
        GEN="${WORK}/gen-${mode}.conf"
        if ! python3 "${SYSCALL_PY}" profile --seccomp-mode "${mode}" \
             -o "${GEN}" -- /bin/true >"${WORK}/gen.out" 2>"${WORK}/gen.err"; then
            fail "syscall.py profile --seccomp-mode ${mode} failed: $(head -1 "${WORK}/gen.err")"
            continue
        fi
        pass "syscall.py generates a ${mode}-mode profile"

        DRY_ERR="${WORK}/dry-${mode}.err"
        if "${CU}" --dry-run --profile "${GEN}" -- /bin/true \
              >"${WORK}/dry.out" 2>"${DRY_ERR}"; then
            pass "generated ${mode}-mode profile parses (--dry-run)"
        else
            fail "generated ${mode}-mode profile does not parse: $(head -1 "${DRY_ERR}")"
        fi
        vsay "$(cat "${DRY_ERR}")"

        if grep -qiE 'not found|unknown (profile|syscall)|warning' "${DRY_ERR}"; then
            fail "generated ${mode}-mode profile parses with complaints: $(grep -iE 'not found|unknown|warning' "${DRY_ERR}" | head -1)"
        else
            pass "generated ${mode}-mode profile parses with no complaints"
        fi

        # A path-rule count of 0 means Landlock is refused at run time.
        if grep -qE 'landlock: yes \([1-9][0-9]* path rules\)' "${DRY_ERR}"; then
            pass "generated ${mode}-mode profile carries Landlock path rules"
        else
            fail "generated ${mode}-mode profile has no Landlock path rules"
        fi

        if "${CU}" --profile "${GEN}" -- /bin/true >/dev/null 2>"${WORK}/run.err"; then
            pass "generated ${mode}-mode profile enforces and runs /bin/true"
        else
            fail "generated ${mode}-mode profile fails at run time: $(head -1 "${WORK}/run.err")"
        fi
    done

    if grep -q '^inherit ' "${WORK}/gen-deny.conf" 2>/dev/null; then
        fail "deny-mode profile still uses 'inherit' (resolves only to a deployed file)"
    else
        pass "deny-mode profile is self-contained (no 'inherit')"
    fi

    # Syscalls compartment.h can name must be emitted as names, not as
    # architecture-specific numbers.
    if grep -q '^allow openat$' "${WORK}/gen-allow.conf" 2>/dev/null; then
        pass "allow-mode profile emits syscall names, not bare numbers"
    else
        fail "allow-mode profile does not emit 'allow openat' by name"
    fi

    # ── --with-env must not re-admit credentials ──────────────────
    ENVGEN="${WORK}/gen-env.conf"
    OPENAI_API_KEY="test-not-a-real-key" \
    MY_SERVICE_API_KEY="test-not-a-real-key" \
    MY_SERVICE_TOKEN="test-not-a-real-token" \
        python3 "${SYSCALL_PY}" profile --with-env -o "${ENVGEN}" -- /bin/true \
        >/dev/null 2>"${WORK}/env.err" || true
    if [ -f "${ENVGEN}" ] && grep -qiE '^env-allow .*(API_KEY|TOKEN|SECRET|PASSWORD)' "${ENVGEN}"; then
        fail "--with-env emits a credential: $(grep -iE '^env-allow .*(API_KEY|TOKEN|SECRET|PASSWORD)' "${ENVGEN}" | head -1)"
    else
        pass "--with-env emits no credential-looking env-allow line"
    fi
    if [ -f "${ENVGEN}" ] && grep -q '^env-allow PATH$' "${ENVGEN}"; then
        pass "--with-env still emits the benign variables"
    else
        fail "--with-env dropped the benign variables too"
    fi

    # ── A dangerous syscall that only ever failed must still be blocked ─
    cat > "${WORK}/fail-mount.py" <<'PYEOF'
import ctypes
ctypes.CDLL(None, use_errno=True).syscall(165, 0, 0, 0, 0, 0)  # mount() -> EPERM
PYEOF
    M14GEN="${WORK}/gen-m14.conf"
    python3 "${SYSCALL_PY}" profile -o "${M14GEN}" -- \
        python3 "${WORK}/fail-mount.py" >/dev/null 2>&1 || true
    if [ -f "${M14GEN}" ] && grep -q '^block mount$' "${M14GEN}"; then
        pass "attempted-but-denied syscall is still blocked"
    else
        fail "a dangerous syscall that only failed was treated as needed and left unblocked"
    fi
    if [ -f "${M14GEN}" ] && grep -q 'Attempted but never succeeded' "${M14GEN}"; then
        pass "profile records why the attempted syscall is still blocked"
    else
        fail "profile does not record the attempted-but-failed syscall"
    fi

    # ── Failed traces must not report success ─────────────────────
    if python3 "${SYSCALL_PY}" check --profile ai-agent -- /no/such/program \
         >"${WORK}/check.out" 2>&1; then
        fail "check on a nonexistent program reports success"
    else
        pass "check on a nonexistent program exits non-zero"
    fi
    if grep -q 'safe for this program' "${WORK}/check.out"; then
        fail "check on a nonexistent program printed 'safe for this program'"
    else
        pass "check on a nonexistent program does not claim the profile is safe"
    fi
    if python3 "${SYSCALL_PY}" profile -- /no/such/program \
         >/dev/null 2>&1; then
        fail "profile of a nonexistent program reports success"
    else
        pass "profile of a nonexistent program exits non-zero"
    fi

    # ── argv[0] must not inject directives into the .conf ─────────
    INJ_DIR="${WORK}/inject"
    mkdir -p "${INJ_DIR}"
    INJ_BIN="${INJ_DIR}/$(printf 'x\nallow 101')"
    cp /bin/true "${INJ_BIN}"
    INJGEN="${WORK}/gen-inject.conf"
    python3 "${SYSCALL_PY}" profile -o "${INJGEN}" -- "${INJ_BIN}" \
        >/dev/null 2>&1 || true
    if [ -f "${INJGEN}" ] && grep -qE '^[[:space:]]*allow ' "${INJGEN}"; then
        fail "a newline in the program name injected a directive: $(grep -nE '^[[:space:]]*allow ' "${INJGEN}" | head -1)"
    else
        pass "a newline in the program name injects no directive"
    fi
fi

echo ""

# ── Summary ────────────────────────────────────────────────────────

echo "=== Results ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  SKIP: ${SKIP}"
echo ""

if [ "${FAIL}" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
