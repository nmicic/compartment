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
# shellcheck source=tests/scripts/lib/harness.sh
. "${SCRIPT_DIR}/lib/harness.sh"

REPO_DIR="$(harness_repo_dir)"
PROBE="${REPO_DIR}/tests/probes/deny_probe"
CU="${REPO_DIR}/compartment-user"
VERBOSE="${1:-}"

# Extra compartment-user flags for the next run_probe call (array).
RUN_PROBE_EXTRA=()

# Run a probe under compartment-user, capture output and exit code
# Usage: run_probe PROFILE PROBE_CMD [PROBE_ARGS...]
# Sets: PROBE_OUT, PROBE_RC, PROBE_RAN, PROBE_OP, PROBE_ARGS, PROBE_ERR_TEXT
#
# Uses the fixture copy of deny_probe (PROBE_FIX) so Landlock profiles
# that restrict access to ${FIXTURES} can exec it.
#
# PROBE_RAN is the anti-false-green guard: it is 1 only when the probe's
# PROBE_START marker for this exact op is present in the captured output.
# An empty capture because compartment-user refused to exec the probe used
# to look identical to an empty capture because the operation was blocked,
# and every expect_not_contains assertion passed on it.
run_probe() {
    local profile="$1"; shift
    PROBE_OUT=""
    PROBE_RC=0
    PROBE_RAN=0
    PROBE_OP="$1"
    PROBE_ARGS=("$@")
    local errfile
    errfile=$(mktemp)
    if [ -n "${VERBOSE}" ]; then
        echo "    CMD: ${CU} --profile ${profile} ${RUN_PROBE_EXTRA[*]-} -- ${PROBE_FIX} $*"
    fi
    PROBE_OUT=$("${CU}" --profile "${profile}" \
        ${RUN_PROBE_EXTRA[@]+"${RUN_PROBE_EXTRA[@]}"} \
        -- "${PROBE_FIX}" "$@" 2>"${errfile}") || PROBE_RC=$?
    PROBE_ERR_TEXT=$(head -1 "${errfile}" 2>/dev/null || true)
    rm -f "${errfile}"
    RUN_PROBE_EXTRA=()
    case "${PROBE_OUT}" in
        *"PROBE_START op=${PROBE_OP} "*) PROBE_RAN=1 ;;
    esac
    if [ -n "${VERBOSE}" ]; then
        echo "    OUT: ${PROBE_OUT}"
        echo "    RC:  ${PROBE_RC}  RAN: ${PROBE_RAN}"
        [ -n "${PROBE_ERR_TEXT}" ] && echo "    ERR: ${PROBE_ERR_TEXT}"
    fi
}

# Guard every expectation: an assertion about a probe that never executed
# is meaningless, so it is a failure, not a pass.
probe_ran_or_fail() {
    if [ "${PROBE_RAN:-0}" -eq 1 ]; then
        return 0
    fi
    fail "$1 (probe never ran: rc=${PROBE_RC:-?} ${PROBE_ERR_TEXT:-no stderr})"
    return 1
}

# Check that output contains expected pattern
expect_contains() {
    local label="$1" pattern="$2"
    probe_ran_or_fail "${label}" || return 0
    if echo "${PROBE_OUT}" | grep -q "${pattern}"; then
        pass "${label}"
    else
        fail "${label} (expected '${pattern}' in output)"
    fi
}

# Check that output does NOT contain pattern
expect_not_contains() {
    local label="$1" pattern="$2"
    probe_ran_or_fail "${label}" || return 0
    if echo "${PROBE_OUT}" | grep -q "${pattern}"; then
        fail "${label} (unexpected '${pattern}' in output)"
    else
        pass "${label}"
    fi
}

# Check exit code
expect_rc() {
    local label="$1" expected="$2"
    probe_ran_or_fail "${label}" || return 0
    if [ "${PROBE_RC}" -eq "${expected}" ]; then
        pass "${label}"
    else
        fail "${label} (expected rc=${expected}, got rc=${PROBE_RC})"
    fi
}

# capture OP -- COMMAND...
#
# Run an arbitrary command (a compartment-user invocation that does not fit
# run_probe, e.g. one that needs env vars in front of it) and set the same
# PROBE_* state, so the expect_* helpers keep their "did the probe run"
# guarantee.
capture() {
    PROBE_OP="$1"; shift
    [ "${1:-}" = "--" ] && shift
    PROBE_OUT=""
    PROBE_RC=0
    PROBE_RAN=0
    PROBE_ERR_TEXT=""
    PROBE_ARGS=("${PROBE_OP}")
    PROBE_OUT=$("$@" 2>/dev/null) || PROBE_RC=$?
    case "${PROBE_OUT}" in
        *"PROBE_START op=${PROBE_OP} "*) PROBE_RAN=1 ;;
    esac
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

# Create fixtures (unpredictable mktemp root, removed on exit)
harness_fixtures
PROBE_FIX="${FIXTURES}/readable/deny_probe"   # copy the sandbox can exec
echo "Fixture root: ${FIXTURES}"
echo ""

# ── Test 1: Filesystem — read-only profile ─────────────────────────

echo "--- Test group: Filesystem read-only profile ---"

if [ "${NO_LANDLOCK}" -eq 1 ]; then
    skip "Landlock not available"
else
    # Should be able to read fixture files
    run_probe "$(harness_profile test-fs-readonly.conf)" fs_read "${FIXTURES}/readable/file.txt"
    expect_contains "fs_read readable file" "rc=0"

    # Should be able to stat
    run_probe "$(harness_profile test-fs-readonly.conf)" fs_stat "${FIXTURES}/readable/file.txt"
    expect_contains "fs_stat readable file" "rc=0"

    # Should NOT be able to write
    run_probe "$(harness_profile test-fs-readonly.conf)" fs_write "${FIXTURES}/writable/existing.txt"
    expect_contains "fs_write blocked by ro" "errno="
    expect_not_contains "fs_write blocked by ro (no rc=0)" "rc=0"

    # Should NOT be able to create files
    run_probe "$(harness_profile test-fs-readonly.conf)" fs_create "${FIXTURES}/writable/new-file.txt"
    expect_not_contains "fs_create blocked by ro" "rc=0"

    # Should NOT be able to unlink
    run_probe "$(harness_profile test-fs-readonly.conf)" fs_unlink "${FIXTURES}/writable/existing.txt"
    expect_not_contains "fs_unlink blocked by ro" "rc=0"

    # Should NOT be able to mkdir
    run_probe "$(harness_profile test-fs-readonly.conf)" fs_mkdir "${FIXTURES}/writable/newdir"
    expect_not_contains "fs_mkdir blocked by ro" "rc=0"

    # Can read /etc (system path)
    run_probe "$(harness_profile test-fs-readonly.conf)" fs_read /etc/hostname
    expect_contains "fs_read /etc/hostname" "rc=0"

    # Cannot write to /tmp (not in profile)
    run_probe "$(harness_profile test-fs-readonly.conf)" fs_create /tmp/compartment-test-outside.txt
    expect_not_contains "fs_create /tmp outside fixtures" "rc=0"
fi

echo ""

# ── Test 2: Filesystem — read-write profile ────────────────────────

echo "--- Test group: Filesystem read-write profile ---"

if [ "${NO_LANDLOCK}" -eq 1 ]; then
    skip "Landlock not available"
else
    # Recreate fixtures (previous tests may have modified them)
    harness_fixtures

    # Should read fixture files
    run_probe "$(harness_profile test-fs-rw.conf)" fs_read "${FIXTURES}/readable/file.txt"
    expect_contains "fs_read in rw profile" "rc=0"

    # Should write to writable area
    run_probe "$(harness_profile test-fs-rw.conf)" fs_write "${FIXTURES}/writable/existing.txt"
    expect_contains "fs_write in rw profile" "rc=0"

    # Should create new files
    run_probe "$(harness_profile test-fs-rw.conf)" fs_create "${FIXTURES}/writable/new-created.txt"
    expect_contains "fs_create in rw profile" "rc=0"

    # Should append
    run_probe "$(harness_profile test-fs-rw.conf)" fs_append "${FIXTURES}/writable/existing.txt"
    expect_contains "fs_append in rw profile" "rc=0"

    # Should truncate
    run_probe "$(harness_profile test-fs-rw.conf)" fs_truncate "${FIXTURES}/writable/truncate-me.txt"
    expect_contains "fs_truncate in rw profile" "rc=0"

    # Should unlink
    run_probe "$(harness_profile test-fs-rw.conf)" fs_create "${FIXTURES}/writable/to-delete.txt"
    run_probe "$(harness_profile test-fs-rw.conf)" fs_unlink "${FIXTURES}/writable/to-delete.txt"
    expect_contains "fs_unlink in rw profile" "rc=0"

    # Should mkdir
    run_probe "$(harness_profile test-fs-rw.conf)" fs_mkdir "${FIXTURES}/writable/new-subdir"
    expect_contains "fs_mkdir in rw profile" "rc=0"

    # Should rmdir (empty dir)
    run_probe "$(harness_profile test-fs-rw.conf)" fs_rmdir "${FIXTURES}/writable/new-subdir"
    expect_contains "fs_rmdir in rw profile" "rc=0"

    # Should rename within writable
    run_probe "$(harness_profile test-fs-rw.conf)" fs_rename "${FIXTURES}/writable/rename-src.txt" "${FIXTURES}/writable/rename-dst.txt"
    expect_contains "fs_rename in rw profile" "rc=0"

    # Should exec from /bin (ro system path)
    run_probe "$(harness_profile test-fs-rw.conf)" fs_exec /bin/true
    expect_contains "fs_exec /bin/true" "rc=0"

    # Cannot write outside fixtures (no /tmp rw)
    run_probe "$(harness_profile test-fs-rw.conf)" fs_create /tmp/compartment-test-escape.txt
    expect_not_contains "fs_create outside fixtures" "rc=0"
fi

echo ""

# ── Test 3: seccomp deny-list ──────────────────────────────────────

echo "--- Test group: seccomp deny-list ---"

# expect_blocked LABEL [ERRNO_NAME]
#
# Assert that the syscall the last run_probe exercised was blocked *by
# seccomp*.  Two guards, both of which the old helper lacked:
#
#   1. Exact errno.  The old test accepted any line containing "rc=", which
#      every RESULT line contains, so the only real check was "not rc=0".
#   2. A baseline run of the same op with no sandbox at all.  Several of these
#      syscalls are already refused by host policy (vm.unprivileged_userfaultfd,
#      kernel.perf_event_paranoid, io_uring_disabled, seccomp in an outer
#      container).  If the unsandboxed run fails with the *same* errno we
#      expect from seccomp, the sandboxed failure cannot be attributed to
#      seccomp and the case is skipped rather than counted as a pass.
expect_blocked() {
    local label="$1" errno_name="${2:-EPERM}" errno_num
    case "${errno_name}" in
        EPERM)  errno_num=1 ;;
        EACCES) errno_num=13 ;;
        *) fail "${label} (unsupported expected errno '${errno_name}')"; return 0 ;;
    esac
    probe_ran_or_fail "${label}" || return 0

    local want="op=${PROBE_OP} .*rc=-1 errno=${errno_num} name=${errno_name}"

    local baseline
    baseline=$("${PROBE}" "${PROBE_ARGS[@]}" 2>/dev/null) || true
    if echo "${baseline}" | grep -q "${want}"; then
        skip "${label} (host policy already returns ${errno_name} without seccomp — not attributable)"
        return 0
    fi

    if echo "${PROBE_OUT}" | grep -q "${want}"; then
        pass "${label}"
    else
        fail "${label} (expected errno=${errno_num} name=${errno_name}, got: $(echo "${PROBE_OUT}" | grep "RESULT op=${PROBE_OP}" | head -1))"
    fi
}

# ptrace should be blocked (seccomp returns EPERM)
run_probe "$(harness_profile test-seccomp-deny.conf)" sc_ptrace_traceme
expect_blocked "ptrace blocked"

# unshare should be blocked
run_probe "$(harness_profile test-seccomp-deny.conf)" sc_unshare_user
expect_blocked "unshare blocked"

# process_vm_readv should be blocked
run_probe "$(harness_profile test-seccomp-deny.conf)" sc_process_vm_readv
expect_blocked "process_vm_readv blocked"

# process_vm_writev should be blocked
run_probe "$(harness_profile test-seccomp-deny.conf)" sc_process_vm_writev
expect_blocked "process_vm_writev blocked"

# userfaultfd should be blocked
run_probe "$(harness_profile test-seccomp-deny.conf)" sc_userfaultfd
expect_blocked "userfaultfd blocked"

# perf_event_open should be blocked
run_probe "$(harness_profile test-seccomp-deny.conf)" sc_perf_event_open
expect_blocked "perf_event_open blocked"

# io_uring_setup should be blocked
run_probe "$(harness_profile test-seccomp-deny.conf)" sc_io_uring_setup
expect_blocked "io_uring_setup blocked"

# Normal operations should still work (read, write, etc.)
run_probe "$(harness_profile test-seccomp-deny.conf)" fs_read /etc/hostname
expect_contains "fs_read still works with seccomp" "rc=0"

echo ""

# ── Test 4: Environment sanitization ──────────────────────────────

echo "--- Test group: Environment sanitization ---"

# Set dangerous vars and check they're stripped
capture env_get -- env LD_PRELOAD=libevil.so LD_LIBRARY_PATH=/evil LD_AUDIT=audit.so SECRET_TOKEN=s3cret \
    "${CU}" --profile "$(harness_profile test-env-deny.conf)" -- "${PROBE}" env_get LD_PRELOAD
expect_contains "LD_PRELOAD stripped" "value=(null)"

capture env_get -- env LD_PRELOAD=libevil.so SECRET_TOKEN=s3cret \
    "${CU}" --profile "$(harness_profile test-env-deny.conf)" -- "${PROBE}" env_get SECRET_TOKEN
expect_contains "SECRET_TOKEN stripped" "value=(null)"

# PATH should survive (not in deny list)
capture env_get -- env PATH=/usr/bin:/bin \
    "${CU}" --profile "$(harness_profile test-env-deny.conf)" -- "${PROBE}" env_get PATH
expect_contains "PATH preserved" "value=/usr/bin:/bin"

# HOME should survive
capture env_get -- "${CU}" --profile "$(harness_profile test-env-deny.conf)" -- "${PROBE}" env_get HOME
expect_contains "HOME preserved" "value=/"

# Cloud credentials should be stripped by default ai-agent profile
# Use --no-landlock so preflight doesn't refuse in environments without Landlock
# (these tests target env sanitization, not filesystem restriction)
capture env_get -- env AWS_SECRET_ACCESS_KEY=supersecret \
    "${CU}" --no-landlock -- "${PROBE}" env_get AWS_SECRET_ACCESS_KEY
expect_contains "AWS_SECRET_ACCESS_KEY stripped" "value=(null)"

# SSH agent socket should be stripped
capture env_get -- env SSH_AUTH_SOCK=/tmp/ssh-agent.sock \
    "${CU}" --no-landlock -- "${PROBE}" env_get SSH_AUTH_SOCK
expect_contains "SSH_AUTH_SOCK stripped" "value=(null)"

echo ""

# ── Test 5: Combined profile ──────────────────────────────────────

echo "--- Test group: Combined profile (Landlock + seccomp + env) ---"

if [ "${NO_LANDLOCK}" -eq 1 ]; then
    skip "Landlock not available"
else
    # Recreate fixtures
    harness_fixtures

    # FS read in rw area: should work
    run_probe "$(harness_profile test-combined.conf)" fs_read "${FIXTURES}/readable/file.txt"
    expect_contains "combined: fs_read" "rc=0"

    # FS write in rw area: should work
    run_probe "$(harness_profile test-combined.conf)" fs_write "${FIXTURES}/writable/existing.txt"
    expect_contains "combined: fs_write rw" "rc=0"

    # FS write outside: should fail
    run_probe "$(harness_profile test-combined.conf)" fs_create /tmp/compartment-test-escape2.txt
    expect_not_contains "combined: fs_create outside" "rc=0"

    # seccomp: ptrace blocked
    run_probe "$(harness_profile test-combined.conf)" sc_ptrace_traceme
    expect_not_contains "combined: ptrace blocked" "rc=0"

    # env: LD_PRELOAD stripped
    capture env_get -- env LD_PRELOAD=evil.so \
        "${CU}" --profile "$(harness_profile test-combined.conf)" -- "${PROBE_FIX}" env_get LD_PRELOAD
    expect_contains "combined: LD_PRELOAD stripped" "value=(null)"
fi

echo ""

# ── Test 6: --dry-run ─────────────────────────────────────────────

echo "--- Test group: --dry-run ---"

DRY_OUT=$("${CU}" --profile "$(harness_profile test-combined.conf)" --dry-run -- /bin/true 2>&1) || true
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

# ai-agent maps $HOME rwx and /tmp rw (W^X: no exec). The fixture root lives
# under ${HOME}/.cache, so PROBE_FIX is directly exec'able here.

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

# strict inherits ai-agent, so ptrace should still be blocked.
run_probe strict sc_ptrace_traceme
expect_blocked "strict: ptrace blocked (inherited)"

# Same test via explicit file path (regression: file-based inherit must work).
#
# examples/strict.conf resolves "inherit ai-agent" to a policy that maps $HOME
# rw, not rwx, so W^X denies exec of the probe from anywhere writable and the
# probe cannot run at all.  --exec grants execute on the fixture root only;
# the seccomp policy under test is untouched, and PROBE_START now proves the
# probe really executed instead of the assertion passing on empty output.
RUN_PROBE_EXTRA=(--exec "${FIXTURES}")
run_probe "${REPO_DIR}/examples/strict.conf" sc_ptrace_traceme
expect_blocked "strict file: ptrace blocked (file inherit)"

# Verify strict.conf file actually loads ai-agent rules (dry-run check)
DRY_OUT=$("${CU}" --profile "${REPO_DIR}/examples/strict.conf" --dry-run -- /bin/true 2>&1) || true
if echo "${DRY_OUT}" | grep -q "21 path rules" && echo "${DRY_OUT}" | grep -q "49 blocked"; then
    pass "strict.conf file: inherits full ai-agent policy (21 paths, 49 blocks)"
else
    fail "strict.conf file: incomplete inheritance (expected 21 paths + 49 blocks)"
fi

# ── Test 10: Shell-replacement mode ──────────────────────────────

echo "--- Test group: Shell-replacement mode ---"

if [ "${NO_LANDLOCK}" -eq 1 ]; then
    skip "Landlock not available"
else
    # Create a symlink to compartment-user that looks like a shell.
    # Use $HOME (which has rwx in ai-agent profile) not /tmp (rw only).
    SHELL_TEST_DIR="${FIXTURES}/shelltest"
    mkdir -p "${SHELL_TEST_DIR}/shells"
    SHELL_LINK="${SHELL_TEST_DIR}/fake-bash"
    ln -sf "$(readlink -f "${CU}")" "${SHELL_LINK}"
    # The stashed "real shell" is the probe: it prints PROBE_START, so the
    # assertion can tell "sandbox applied and shell exec'd" from "exited 0
    # without ever reaching the shell".
    cp "${PROBE}" "${SHELL_TEST_DIR}/shells/fake-bash"

    SHELL_RC=0
    SHELL_OUT=$(COMPARTMENT_SHELL_DIR="${SHELL_TEST_DIR}/shells" \
        "${SHELL_LINK}" env_get PATH 2>/dev/null) || SHELL_RC=$?

    if [ "${SHELL_RC}" -eq 0 ] && echo "${SHELL_OUT}" | grep -q "PROBE_START op=env_get "; then
        pass "shell-replacement mode: symlink invocation execs the stashed shell"
    else
        fail "shell-replacement mode: symlink invocation failed (rc=${SHELL_RC}, out=${SHELL_OUT})"
    fi
fi

# ── Test 11: FD inheritance ──────────────────────────────────────

echo "--- Test group: FD inheritance ---"

# Verify no unexpected FDs leak to sandboxed process
# Under sandboxing, only stdin/stdout/stderr (0,1,2) should be open
# plus any FDs compartment-user legitimately passes through
# deny_probe prints one "FD <n> -> <target>" line per open descriptor and a
# "count=<n>" field.  The old assertion grepped for "fd=", a string the probe
# never prints, so FD_COUNT was permanently 0, "0 <= 5" always held and the
# case passed without inspecting anything.
#
# fd 9 below is a canary: the shell opens it on /etc/hostname, and
# compartment-user must close it (close_range(3, ~0U)) before exec.
if [ "${NO_LANDLOCK}" -eq 1 ]; then
    skip "FD test requires Landlock"
else
    FD_RC=0
    FD_OUT=$("${CU}" --profile "$(harness_profile test-fs-readonly.conf)" \
        -- "${PROBE_FIX}" fd_list 9</etc/hostname 2>/dev/null) || FD_RC=$?
    FD_LINES=$(echo "${FD_OUT}" | grep -c '^FD ' || true)
    FD_COUNT=$(echo "${FD_OUT}" | sed -n 's/.*RESULT op=fd_list count=\([0-9]*\) .*/\1/p')

    if ! echo "${FD_OUT}" | grep -q "PROBE_START op=fd_list "; then
        fail "FD inheritance: probe never ran (rc=${FD_RC})"
    elif [ -z "${FD_COUNT}" ]; then
        fail "FD inheritance: no count= field in probe output"
    elif [ "${FD_COUNT}" != "${FD_LINES}" ]; then
        fail "FD inheritance: count=${FD_COUNT} but ${FD_LINES} FD lines printed"
    elif echo "${FD_OUT}" | grep -q '^FD 9 ->'; then
        fail "FD inheritance: caller fd 9 leaked into the sandboxed child"
    elif [ "${FD_COUNT}" -ne 3 ]; then
        fail "FD inheritance: expected exactly 3 FDs (0,1,2), got ${FD_COUNT}"
    else
        pass "FD inheritance: exactly 3 FDs (0,1,2), caller fd 9 closed"
    fi
fi

# ── Test 12: Profile hardening negative tests ──────────────────────

echo "--- Test group: Profile hardening ---"

# Test: malformed boolean values should be rejected
BAD_PROFILE=$(mktemp --suffix=.conf)
echo 'landlock enabled' > "$BAD_PROFILE"
BAD_OUT=$("${CU}" --profile "$BAD_PROFILE" --dry-run -- /bin/true 2>&1) || true
if echo "$BAD_OUT" | grep -qi "invalid value for landlock"; then
    pass "profile: invalid boolean value rejected"
else
    fail "profile: 'landlock enabled' should be rejected (got: $BAD_OUT)"
fi
rm -f "$BAD_PROFILE"

# Test: unknown directives produce a warning
WARN_PROFILE=$(mktemp --suffix=.conf)
printf 'blokc ptrace\n' > "$WARN_PROFILE"
WARN_OUT=$("${CU}" --profile "$WARN_PROFILE" --dry-run -- /bin/true 2>&1) || true
if echo "$WARN_OUT" | grep -qi "unknown directive.*blokc"; then
    pass "profile: unknown directive warned"
else
    fail "profile: typo 'blokc' should produce warning"
fi
rm -f "$WARN_PROFILE"

# Test: COMPARTMENT_SHELL_DIR path traversal rejected
SHELL_LINK2=$(mktemp -d)/test-bash
ln -sf "$(readlink -f "${CU}")" "${SHELL_LINK2}"
TRAV_OUT=$(COMPARTMENT_SHELL_DIR="/usr/../tmp" "${SHELL_LINK2}" -c "echo hi" 2>&1) || true
if echo "$TRAV_OUT" | grep -qi "contains '..'"; then
    pass "shell-replacement: path traversal in COMPARTMENT_SHELL_DIR rejected"
else
    fail "shell-replacement: COMPARTMENT_SHELL_DIR with .. should be rejected"
fi
rm -rf "$(dirname "${SHELL_LINK2}")"

echo ""

# ── Test 13: Harness self-tests ───────────────────────────────────
#
# Every assertion above is only worth as much as the helper that evaluates
# it.  These cases feed the helpers inputs they MUST NOT accept, with the
# real counters saved and restored around each run, and record one assertion
# about the helper's own verdict.

echo "--- Test group: Harness self-tests ---"

# selftest LABEL fail|not-pass FUNCTION
selftest() {
    local label="$1" want="$2"; shift 2
    local sp="${PASS}" sf="${FAIL}" sk="${SKIP}"
    "$@" > /dev/null 2>&1
    local dp=$((PASS - sp)) df=$((FAIL - sf)) dk=$((SKIP - sk))
    PASS="${sp}"; FAIL="${sf}"; SKIP="${sk}"
    case "${want}" in
        fail)
            if [ "${df}" -gt 0 ] && [ "${dp}" -eq 0 ]; then
                pass "${label}"
            else
                fail "${label} (helper returned pass=${dp} fail=${df} skip=${dk})"
            fi ;;
        not-pass)
            if [ "${dp}" -eq 0 ] && [ $((df + dk)) -gt 0 ]; then
                pass "${label}"
            else
                fail "${label} (helper returned pass=${dp} fail=${df} skip=${dk})"
            fi ;;
    esac
}

# (a) A probe that never executes must not satisfy any expectation.
_st_probe_never_runs() {
    local saved="${PROBE_FIX}"
    PROBE_FIX="${FIXTURES}/readable/no-such-probe"
    run_probe "$(harness_profile test-seccomp-deny.conf)" sc_ptrace_traceme
    expect_not_contains "inner" "rc=0"
    PROBE_FIX="${saved}"
}
selftest "self-test: expect_not_contains fails when the probe never ran" \
    fail _st_probe_never_runs

_st_probe_never_runs_blocked() {
    local saved="${PROBE_FIX}"
    PROBE_FIX="${FIXTURES}/readable/no-such-probe"
    run_probe "$(harness_profile test-seccomp-deny.conf)" sc_ptrace_traceme
    expect_blocked "inner"
    PROBE_FIX="${saved}"
}
selftest "self-test: expect_blocked fails when the probe never ran" \
    fail _st_probe_never_runs_blocked

# (b) A syscall that is not blocked at all must not read as "blocked".
_st_syscall_not_blocked() {
    run_probe "$(harness_profile test-env-deny.conf)" sc_ptrace_traceme
    expect_blocked "inner"
}
selftest "self-test: expect_blocked fails with no seccomp filter installed" \
    fail _st_syscall_not_blocked

# (c) A syscall the host already refuses must never count as a seccomp pass.
_st_host_policy_block() {
    run_probe "$(harness_profile test-env-deny.conf)" sc_userfaultfd
    expect_blocked "inner"
}
selftest "self-test: expect_blocked never passes on a host-policy denial" \
    not-pass _st_host_policy_block

echo ""

# ── Summary ───────────────────────────────────────────────────────

# The suite declares its own assertion count. A block that stops
# running — a `skip` standing in for twenty assertions, a group
# guarded by a tool that is not installed — changes the total, and a
# changed total is a failure rather than a smaller number nobody
# compares against anything.
harness_expect_total 57
harness_summary "compartment-user-matrix" || exit 1
exit 0
