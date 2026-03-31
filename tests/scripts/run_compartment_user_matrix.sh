#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# run_compartment_user_matrix.sh — filesystem, seccomp, and env tests
#
# Runs deny_probe under compartment-user with various profiles and
# checks that operations succeed or fail as expected.
#
# Usage: ./tests/scripts/run_compartment_user_matrix.sh [--verbose]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PROBE="${REPO_DIR}/tests/probes/deny_probe"
PROBE_FIX="/tmp/compartment-fixtures/readable/deny_probe"  # copy accessible inside sandbox
CU="${REPO_DIR}/compartment-user"
PROFILES="${REPO_DIR}/tests/profiles"
FIXTURES="/tmp/compartment-fixtures"
VERBOSE="${1:-}"

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP: $1"; }

# Run a probe under compartment-user, capture output and exit code
# Usage: run_probe PROFILE PROBE_CMD [PROBE_ARGS...]
# Sets: PROBE_OUT, PROBE_RC
#
# Uses the fixture copy of deny_probe (PROBE_FIX) so Landlock profiles
# that restrict to /tmp/compartment-fixtures can exec it.
run_probe() {
    local profile="$1"; shift
    PROBE_OUT=""
    PROBE_RC=0
    PROBE_ERR=""
    if [ -n "${VERBOSE}" ]; then
        echo "    CMD: ${CU} --profile ${profile} -- ${PROBE_FIX} $*"
    fi
    PROBE_ERR=$(mktemp)
    PROBE_OUT=$("${CU}" --profile "${profile}" -- "${PROBE_FIX}" "$@" 2>"${PROBE_ERR}") || PROBE_RC=$?
    if [ -n "${VERBOSE}" ]; then
        echo "    OUT: ${PROBE_OUT}"
        echo "    RC:  ${PROBE_RC}"
        [ -s "${PROBE_ERR}" ] && echo "    ERR: $(cat "${PROBE_ERR}")"
    fi
    # Detect compartment-user setup failures (probe never ran)
    if [ -z "${PROBE_OUT}" ] && [ "${PROBE_RC}" -ne 0 ] && grep -qi "compartment-user\|landlock\|seccomp\|profile" "${PROBE_ERR}" 2>/dev/null; then
        echo "    WARNING: compartment-user failed before probe ran (rc=${PROBE_RC}): $(head -1 "${PROBE_ERR}")"
    fi
    rm -f "${PROBE_ERR}"
}

# Check that output contains expected pattern
expect_contains() {
    local label="$1" pattern="$2"
    if echo "${PROBE_OUT}" | grep -q "${pattern}"; then
        pass "${label}"
    else
        fail "${label} (expected '${pattern}' in output)"
    fi
}

# Check that output does NOT contain pattern
expect_not_contains() {
    local label="$1" pattern="$2"
    if echo "${PROBE_OUT}" | grep -q "${pattern}"; then
        fail "${label} (unexpected '${pattern}' in output)"
    else
        pass "${label}"
    fi
}

# Check exit code
expect_rc() {
    local label="$1" expected="$2"
    if [ "${PROBE_RC}" -eq "${expected}" ]; then
        pass "${label}"
    else
        fail "${label} (expected rc=${expected}, got rc=${PROBE_RC})"
    fi
}

# ── Prerequisites ──────────────────────────────────────────────────

echo "=== Compartment-user test matrix ==="
echo ""

if [ ! -x "${CU}" ]; then
    echo "ERROR: ${CU} not found. Run 'make' first."
    exit 1
fi

if [ ! -x "${PROBE}" ]; then
    echo "ERROR: ${PROBE} not found. Build with:"
    echo "  cc -o tests/probes/deny_probe tests/probes/deny_probe.c"
    exit 1
fi

# Check Landlock support
if ! "${CU}" --verify > /dev/null 2>&1; then
    echo "WARNING: Landlock not supported on this kernel, skipping Landlock tests"
    NO_LANDLOCK=1
else
    NO_LANDLOCK=0
fi

# Create fixtures
bash "${SCRIPT_DIR}/make_fixtures.sh"
echo ""

# ── Test 1: Filesystem — read-only profile ─────────────────────────

echo "--- Test group: Filesystem read-only profile ---"

if [ "${NO_LANDLOCK}" -eq 1 ]; then
    skip "Landlock not available"
else
    # Should be able to read fixture files
    run_probe "${PROFILES}/test-fs-readonly.conf" fs_read "${FIXTURES}/readable/file.txt"
    expect_contains "fs_read readable file" "rc=0"

    # Should be able to stat
    run_probe "${PROFILES}/test-fs-readonly.conf" fs_stat "${FIXTURES}/readable/file.txt"
    expect_contains "fs_stat readable file" "rc=0"

    # Should NOT be able to write
    run_probe "${PROFILES}/test-fs-readonly.conf" fs_write "${FIXTURES}/writable/existing.txt"
    expect_contains "fs_write blocked by ro" "errno="
    expect_not_contains "fs_write blocked by ro (no rc=0)" "rc=0"

    # Should NOT be able to create files
    run_probe "${PROFILES}/test-fs-readonly.conf" fs_create "${FIXTURES}/writable/new-file.txt"
    expect_not_contains "fs_create blocked by ro" "rc=0"

    # Should NOT be able to unlink
    run_probe "${PROFILES}/test-fs-readonly.conf" fs_unlink "${FIXTURES}/writable/existing.txt"
    expect_not_contains "fs_unlink blocked by ro" "rc=0"

    # Should NOT be able to mkdir
    run_probe "${PROFILES}/test-fs-readonly.conf" fs_mkdir "${FIXTURES}/writable/newdir"
    expect_not_contains "fs_mkdir blocked by ro" "rc=0"

    # Can read /etc (system path)
    run_probe "${PROFILES}/test-fs-readonly.conf" fs_read /etc/hostname
    expect_contains "fs_read /etc/hostname" "rc=0"

    # Cannot write to /tmp (not in profile)
    run_probe "${PROFILES}/test-fs-readonly.conf" fs_create /tmp/compartment-test-outside.txt
    expect_not_contains "fs_create /tmp outside fixtures" "rc=0"
fi

echo ""

# ── Test 2: Filesystem — read-write profile ────────────────────────

echo "--- Test group: Filesystem read-write profile ---"

if [ "${NO_LANDLOCK}" -eq 1 ]; then
    skip "Landlock not available"
else
    # Recreate fixtures (previous tests may have modified them)
    bash "${SCRIPT_DIR}/make_fixtures.sh" > /dev/null 2>&1

    # Should read fixture files
    run_probe "${PROFILES}/test-fs-rw.conf" fs_read "${FIXTURES}/readable/file.txt"
    expect_contains "fs_read in rw profile" "rc=0"

    # Should write to writable area
    run_probe "${PROFILES}/test-fs-rw.conf" fs_write "${FIXTURES}/writable/existing.txt"
    expect_contains "fs_write in rw profile" "rc=0"

    # Should create new files
    run_probe "${PROFILES}/test-fs-rw.conf" fs_create "${FIXTURES}/writable/new-created.txt"
    expect_contains "fs_create in rw profile" "rc=0"

    # Should append
    run_probe "${PROFILES}/test-fs-rw.conf" fs_append "${FIXTURES}/writable/existing.txt"
    expect_contains "fs_append in rw profile" "rc=0"

    # Should truncate
    run_probe "${PROFILES}/test-fs-rw.conf" fs_truncate "${FIXTURES}/writable/truncate-me.txt"
    expect_contains "fs_truncate in rw profile" "rc=0"

    # Should unlink
    run_probe "${PROFILES}/test-fs-rw.conf" fs_create "${FIXTURES}/writable/to-delete.txt"
    run_probe "${PROFILES}/test-fs-rw.conf" fs_unlink "${FIXTURES}/writable/to-delete.txt"
    expect_contains "fs_unlink in rw profile" "rc=0"

    # Should mkdir
    run_probe "${PROFILES}/test-fs-rw.conf" fs_mkdir "${FIXTURES}/writable/new-subdir"
    expect_contains "fs_mkdir in rw profile" "rc=0"

    # Should rmdir (empty dir)
    run_probe "${PROFILES}/test-fs-rw.conf" fs_rmdir "${FIXTURES}/writable/new-subdir"
    expect_contains "fs_rmdir in rw profile" "rc=0"

    # Should rename within writable
    run_probe "${PROFILES}/test-fs-rw.conf" fs_rename "${FIXTURES}/writable/rename-src.txt" "${FIXTURES}/writable/rename-dst.txt"
    expect_contains "fs_rename in rw profile" "rc=0"

    # Should exec from /bin (ro system path)
    run_probe "${PROFILES}/test-fs-rw.conf" fs_exec /bin/true
    expect_contains "fs_exec /bin/true" "rc=0"

    # Cannot write outside fixtures (no /tmp rw)
    run_probe "${PROFILES}/test-fs-rw.conf" fs_create /tmp/compartment-test-escape.txt
    expect_not_contains "fs_create outside fixtures" "rc=0"
fi

echo ""

# ── Test 3: seccomp deny-list ──────────────────────────────────────

echo "--- Test group: seccomp deny-list ---"

# ptrace should be blocked (SIGSYS → exit 159 or similar)
run_probe "${PROFILES}/test-seccomp-deny.conf" sc_ptrace_traceme
expect_not_contains "ptrace blocked" "rc=0"

# unshare should be blocked
run_probe "${PROFILES}/test-seccomp-deny.conf" sc_unshare_user
expect_not_contains "unshare blocked" "rc=0"

# process_vm_readv should be blocked (SIGSYS, not just EPERM/ESRCH)
run_probe "${PROFILES}/test-seccomp-deny.conf" sc_process_vm_readv
expect_not_contains "process_vm_readv blocked" "rc=0"

# process_vm_writev should be blocked
run_probe "${PROFILES}/test-seccomp-deny.conf" sc_process_vm_writev
expect_not_contains "process_vm_writev blocked" "rc=0"

# userfaultfd should be blocked
run_probe "${PROFILES}/test-seccomp-deny.conf" sc_userfaultfd
expect_not_contains "userfaultfd blocked" "rc=0"

# perf_event_open should be blocked
run_probe "${PROFILES}/test-seccomp-deny.conf" sc_perf_event_open
expect_not_contains "perf_event_open blocked" "rc=0"

# Normal operations should still work (read, write, etc.)
run_probe "${PROFILES}/test-seccomp-deny.conf" fs_read /etc/hostname
expect_contains "fs_read still works with seccomp" "rc=0"

echo ""

# ── Test 4: Environment sanitization ──────────────────────────────

echo "--- Test group: Environment sanitization ---"

# Set dangerous vars and check they're stripped
PROBE_OUT=""
PROBE_RC=0
PROBE_OUT=$(LD_PRELOAD=libevil.so LD_LIBRARY_PATH=/evil LD_AUDIT=audit.so SECRET_TOKEN=s3cret \
    "${CU}" --profile "${PROFILES}/test-env-deny.conf" -- "${PROBE}" env_get LD_PRELOAD 2>/dev/null) || PROBE_RC=$?
expect_contains "LD_PRELOAD stripped" "value=(null)"

PROBE_OUT=$(LD_PRELOAD=libevil.so SECRET_TOKEN=s3cret \
    "${CU}" --profile "${PROFILES}/test-env-deny.conf" -- "${PROBE}" env_get SECRET_TOKEN 2>/dev/null) || PROBE_RC=$?
expect_contains "SECRET_TOKEN stripped" "value=(null)"

# PATH should survive (not in deny list)
PROBE_OUT=$(PATH=/usr/bin:/bin \
    "${CU}" --profile "${PROFILES}/test-env-deny.conf" -- "${PROBE}" env_get PATH 2>/dev/null) || PROBE_RC=$?
expect_contains "PATH preserved" "value=/usr/bin:/bin"

# HOME should survive
PROBE_OUT=$("${CU}" --profile "${PROFILES}/test-env-deny.conf" -- "${PROBE}" env_get HOME 2>/dev/null) || PROBE_RC=$?
expect_contains "HOME preserved" "value=/"

echo ""

# ── Test 5: Combined profile ──────────────────────────────────────

echo "--- Test group: Combined profile (Landlock + seccomp + env) ---"

if [ "${NO_LANDLOCK}" -eq 1 ]; then
    skip "Landlock not available"
else
    # Recreate fixtures
    bash "${SCRIPT_DIR}/make_fixtures.sh" > /dev/null 2>&1

    # FS read in rw area: should work
    run_probe "${PROFILES}/test-combined.conf" fs_read "${FIXTURES}/readable/file.txt"
    expect_contains "combined: fs_read" "rc=0"

    # FS write in rw area: should work
    run_probe "${PROFILES}/test-combined.conf" fs_write "${FIXTURES}/writable/existing.txt"
    expect_contains "combined: fs_write rw" "rc=0"

    # FS write outside: should fail
    run_probe "${PROFILES}/test-combined.conf" fs_create /tmp/compartment-test-escape2.txt
    expect_not_contains "combined: fs_create outside" "rc=0"

    # seccomp: ptrace blocked
    run_probe "${PROFILES}/test-combined.conf" sc_ptrace_traceme
    expect_not_contains "combined: ptrace blocked" "rc=0"

    # env: LD_PRELOAD stripped
    PROBE_OUT=$(LD_PRELOAD=evil.so \
        "${CU}" --profile "${PROFILES}/test-combined.conf" -- "${PROBE_FIX}" env_get LD_PRELOAD 2>/dev/null) || PROBE_RC=$?
    expect_contains "combined: LD_PRELOAD stripped" "value=(null)"
fi

echo ""

# ── Test 6: --dry-run ─────────────────────────────────────────────

echo "--- Test group: --dry-run ---"

DRY_OUT=$("${CU}" --profile "${PROFILES}/test-combined.conf" --dry-run -- /bin/true 2>&1) || true
if echo "${DRY_OUT}" | grep -qi "landlock\|seccomp\|block\|read-only"; then
    pass "--dry-run produces policy output"
else
    fail "--dry-run produces no policy output"
fi

echo ""

# ── Test 7: --verify ──────────────────────────────────────────────

echo "--- Test group: --verify ---"

VERIFY_RC=0
VERIFY_OUT=$("${CU}" --verify 2>&1) || VERIFY_RC=$?
if echo "${VERIFY_OUT}" | grep -qi "landlock\|seccomp\|arch\|kernel"; then
    pass "--verify shows system info"
else
    fail "--verify shows no system info"
fi

# Verify exit code semantics: should return 0 when all checks pass
if [ "${VERIFY_RC}" -eq 0 ] && echo "${VERIFY_OUT}" | grep -q "All checks passed"; then
    pass "--verify returns 0 on success"
elif [ "${VERIFY_RC}" -ne 0 ] && echo "${VERIFY_OUT}" | grep -q "VERIFICATION FAILED"; then
    pass "--verify returns non-zero on failure"
else
    fail "--verify exit code does not match output (rc=${VERIFY_RC})"
fi

echo ""

# ── Test 8: Default ai-agent profile ──────────────────────────────

echo "--- Test group: Default ai-agent profile ---"

# seccomp should block ptrace with default profile
run_probe ai-agent sc_ptrace_traceme
expect_not_contains "ai-agent: ptrace blocked" "rc=0"

# Should be able to read /etc
if [ "${NO_LANDLOCK}" -eq 0 ]; then
    run_probe ai-agent fs_read /etc/hostname
    expect_contains "ai-agent: fs_read /etc" "rc=0"
fi

echo ""

# ── Test 9: Profile inheritance ───────────────────────────────────

echo "--- Test group: Profile inheritance (strict inherits ai-agent) ---"

# strict inherits ai-agent, so ptrace should still be blocked
run_probe strict sc_ptrace_traceme
expect_not_contains "strict: ptrace blocked (inherited)" "rc=0"

# Same test via explicit file path (regression: file-based inherit must work)
run_probe "${REPO_DIR}/examples/strict.conf" sc_ptrace_traceme
expect_not_contains "strict file: ptrace blocked (file inherit)" "rc=0"

# Verify strict.conf file actually loads ai-agent rules (dry-run check)
DRY_OUT=$("${CU}" --profile "${REPO_DIR}/examples/strict.conf" --dry-run -- /bin/true 2>&1) || true
if echo "${DRY_OUT}" | grep -q "14 path rules" && echo "${DRY_OUT}" | grep -q "36 blocked"; then
    pass "strict.conf file: inherits full ai-agent policy (14 paths, 36 blocks)"
else
    fail "strict.conf file: incomplete inheritance (expected 14 paths + 36 blocks)"
fi

# ── Test 10: Shell-replacement mode ──────────────────────────────

echo "--- Test group: Shell-replacement mode ---"

if [ "${NO_LANDLOCK}" -eq 1 ]; then
    skip "Landlock not available"
else
    # Create a symlink to compartment-user that looks like a shell
    SHELL_LINK=$(mktemp -d)/fake-bash
    ln -sf "$(readlink -f "${CU}")" "${SHELL_LINK}"
    mkdir -p "$(dirname "${SHELL_LINK}")/shells"
    cp /bin/true "$(dirname "${SHELL_LINK}")/shells/fake-bash"

    # When invoked via symlink, compartment-user should apply sandbox and exec real shell
    SHELL_RC=0
    SHELL_OUT=$(COMPARTMENT_SHELL_DIR="$(dirname "${SHELL_LINK}")/shells" \
        "${SHELL_LINK}" -c "echo shell-replacement-works" 2>/dev/null) || SHELL_RC=$?

    # /bin/true ignores arguments so we just check it ran (rc=0)
    if [ "${SHELL_RC}" -eq 0 ]; then
        pass "shell-replacement mode: symlink invocation works"
    else
        fail "shell-replacement mode: symlink invocation failed (rc=${SHELL_RC})"
    fi

    rm -rf "$(dirname "${SHELL_LINK}")"
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
