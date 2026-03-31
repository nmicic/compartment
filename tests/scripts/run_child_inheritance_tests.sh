#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# run_child_inheritance_tests.sh — verify sandbox restrictions survive fork/exec
#
# Key property: Landlock, seccomp, and no-new-privs are inherited by children.
# This script verifies that a child process spawned inside the sandbox
# cannot escape restrictions.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PROBE="${REPO_DIR}/tests/probes/deny_probe"
PROBE_FIX="/tmp/compartment-fixtures/readable/deny_probe"
CU="${REPO_DIR}/compartment-user"
PROFILES="${REPO_DIR}/tests/profiles"
FIXTURES="/tmp/compartment-fixtures"

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP: $1"; }

echo "=== Child inheritance tests ==="
echo ""

if [ ! -x "${CU}" ] || [ ! -x "${PROBE}" ]; then
    echo "ERROR: Build compartment-user and deny_probe first"
    exit 1
fi

# Check Landlock
if ! "${CU}" --verify > /dev/null 2>&1; then
    NO_LANDLOCK=1
else
    NO_LANDLOCK=0
fi

# Create fixtures
bash "${SCRIPT_DIR}/make_fixtures.sh" > /dev/null 2>&1

echo "--- Test group: Child process inherits seccomp ---"

# spawn_sh runs: /bin/sh -c "CMD"
# The child shell should still be blocked by seccomp
# seccomp-only profile (no landlock) — use original PROBE path
OUT=$("${CU}" --profile "${PROFILES}/test-seccomp-deny.conf" -- \
    "${PROBE}" spawn_sh "${PROBE} sc_ptrace_traceme" 2>/dev/null) || true
if echo "${OUT}" | grep -q "rc=0" && echo "${OUT}" | grep -q "op=sc_ptrace_traceme"; then
    fail "child /bin/sh escaped seccomp (ptrace allowed)"
else
    pass "child /bin/sh inherits seccomp (ptrace blocked)"
fi

# spawn_abs_bash: /bin/bash -c "CMD"
OUT=$("${CU}" --profile "${PROFILES}/test-seccomp-deny.conf" -- \
    "${PROBE}" spawn_abs_bash "${PROBE} sc_unshare_user" 2>/dev/null) || true
if echo "${OUT}" | grep -q "rc=0" && echo "${OUT}" | grep -q "op=sc_unshare_user"; then
    fail "child /bin/bash escaped seccomp (unshare allowed)"
else
    pass "child /bin/bash inherits seccomp (unshare blocked)"
fi

echo ""

echo "--- Test group: Child process inherits Landlock ---"

if [ "${NO_LANDLOCK}" -eq 1 ]; then
    skip "Landlock not available"
else
    # Landlock profiles: use PROBE_FIX (copy in fixtures, accessible under sandbox)
    # Child should not be able to write outside rw paths
    OUT=$("${CU}" --profile "${PROFILES}/test-fs-readonly.conf" -- \
        "${PROBE_FIX}" spawn_sh "${PROBE_FIX} fs_create ${FIXTURES}/writable/child-escape.txt" 2>/dev/null) || true
    if echo "${OUT}" | grep -q "rc=0" && echo "${OUT}" | grep -q "op=fs_create"; then
        fail "child escaped Landlock (wrote to ro path)"
    else
        pass "child inherits Landlock (cannot write to ro path)"
    fi

    # Child CAN read from ro path
    OUT=$("${CU}" --profile "${PROFILES}/test-fs-readonly.conf" -- \
        "${PROBE_FIX}" spawn_sh "${PROBE_FIX} fs_read ${FIXTURES}/readable/file.txt" 2>/dev/null) || true
    if echo "${OUT}" | grep -q "rc=0"; then
        pass "child can read from ro path"
    else
        fail "child cannot read from ro path (should be allowed)"
    fi
fi

echo ""

echo "--- Test group: Child inherits env sanitization ---"

# env-only profile (no landlock) — use original PROBE path
OUT=$(LD_PRELOAD=evil.so \
    "${CU}" --profile "${PROFILES}/test-env-deny.conf" -- \
    "${PROBE}" spawn_sh "${PROBE} env_get LD_PRELOAD" 2>/dev/null) || true
if echo "${OUT}" | grep -q "value=(null)"; then
    pass "child inherits env sanitization (LD_PRELOAD stripped)"
else
    fail "child has LD_PRELOAD (env sanitization not inherited)"
fi

echo ""

echo "--- Test group: Nested child (grandchild) ---"

# spawn_nested: deny_probe spawns deny_probe which runs the actual probe
# Tests that restrictions survive two levels of fork/exec
OUT=$("${CU}" --profile "${PROFILES}/test-seccomp-deny.conf" -- \
    "${PROBE}" spawn_nested "${PROBE} sc_ptrace_traceme" 2>/dev/null) || true
if echo "${OUT}" | grep -q "rc=0" && echo "${OUT}" | grep -q "op=sc_ptrace_traceme"; then
    fail "grandchild escaped seccomp"
else
    pass "grandchild inherits seccomp (ptrace blocked at depth 2)"
fi

echo ""

# ── Summary ───────────────────────────────────────────────────────

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
