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
# shellcheck source=tests/scripts/lib/harness.sh
. "${SCRIPT_DIR}/lib/harness.sh"

REPO_DIR="$(harness_repo_dir)"
PROBE="${REPO_DIR}/tests/probes/deny_probe"
CU="${REPO_DIR}/compartment-user"

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

# Create fixtures (unpredictable mktemp root, removed on exit)
harness_fixtures
PROBE_FIX="${FIXTURES}/readable/deny_probe"

# Every assertion below used to be `grep -q "rc=0" && grep -q "op=<name>"`
# against the whole capture, with no liveness guard. deny_probe echoes the
# child command line back in the spawn RESULT's `cmd=` field, so the
# `op=` conjunct was satisfied by that echo, and the outer spawn RESULT
# carries an `rc=0` of its own — leaving the test as "the output does not
# happen to contain rc=0". An empty OUT (a refused exec, a wrong profile
# path, a renamed op) passed. These four are the only witnesses that the
# restrictions survive fork/exec, so they assert the inner probe started
# and then match its whole RESULT line.

# inherit_started OP — did the inner probe run at all?
inherit_started() {
    printf '%s\n' "${OUT}" | grep -q "^PROBE_START op=$1 "
}
inherit_ctx() { printf '%s' "${OUT}" | tr '\n' '|' | cut -c1-200; }

# The inner probe must have started and must NOT have succeeded.
inherit_blocked() {
    local label="$1" op="$2"
    if ! inherit_started "${op}"; then
        fail "${label} — the ${op} probe never started: $(inherit_ctx)"
    elif printf '%s\n' "${OUT}" | grep -qE "^RESULT op=${op} .*rc=0 "; then
        fail "${label} — ${op} succeeded inside the sandbox"
    else
        pass "${label}"
    fi
}

# The inner probe must have started and must have succeeded.
inherit_allowed() {
    local label="$1" op="$2"
    if ! inherit_started "${op}"; then
        fail "${label} — the ${op} probe never started: $(inherit_ctx)"
    elif printf '%s\n' "${OUT}" | grep -qE "^RESULT op=${op} .*rc=0 "; then
        pass "${label}"
    else
        fail "${label} — ${op} did not succeed: $(inherit_ctx)"
    fi
}

echo "--- Test group: Child process inherits seccomp ---"

# spawn_sh runs: /bin/sh -c "CMD"
# The child shell should still be blocked by seccomp
# seccomp-only profile (no landlock) — use original PROBE path
OUT=$("${CU}" --profile "$(harness_profile test-seccomp-deny.conf)" -- \
    "${PROBE}" spawn_sh "${PROBE} sc_ptrace_traceme" 2>/dev/null) || true
inherit_blocked "child /bin/sh inherits seccomp (ptrace blocked)" sc_ptrace_traceme

# spawn_abs_bash: /bin/bash -c "CMD"
OUT=$("${CU}" --profile "$(harness_profile test-seccomp-deny.conf)" -- \
    "${PROBE}" spawn_abs_bash "${PROBE} sc_unshare_user" 2>/dev/null) || true
inherit_blocked "child /bin/bash inherits seccomp (unshare blocked)" sc_unshare_user

echo ""

echo "--- Test group: Child process inherits Landlock ---"

if [ "${NO_LANDLOCK}" -eq 1 ]; then
    skip "Landlock not available"
else
    # Landlock profiles: use PROBE_FIX (copy in fixtures, accessible under sandbox)
    # Child should not be able to write outside rw paths
    OUT=$("${CU}" --profile "$(harness_profile test-fs-readonly.conf)" -- \
        "${PROBE_FIX}" spawn_sh "${PROBE_FIX} fs_create ${FIXTURES}/writable/child-escape.txt" 2>/dev/null) || true
    inherit_blocked "child inherits Landlock (cannot write to ro path)" fs_create

    # Child CAN read from ro path
    OUT=$("${CU}" --profile "$(harness_profile test-fs-readonly.conf)" -- \
        "${PROBE_FIX}" spawn_sh "${PROBE_FIX} fs_read ${FIXTURES}/readable/file.txt" 2>/dev/null) || true
    inherit_allowed "child can read from ro path" fs_read
fi

echo ""

echo "--- Test group: Child inherits env sanitization ---"

# env-only profile (no landlock) — use original PROBE path
OUT=$(LD_PRELOAD=evil.so \
    "${CU}" --profile "$(harness_profile test-env-deny.conf)" -- \
    "${PROBE}" spawn_sh "${PROBE} env_get LD_PRELOAD" 2>/dev/null) || true
if ! inherit_started env_get; then
    fail "child inherits env sanitization — the env_get probe never started: $(inherit_ctx)"
elif printf '%s\n' "${OUT}" | grep -qE "^RESULT op=env_get .*value=\(null\)"; then
    pass "child inherits env sanitization (LD_PRELOAD stripped)"
else
    fail "child has LD_PRELOAD (env sanitization not inherited): $(inherit_ctx)"
fi

echo ""

echo "--- Test group: Nested child (grandchild) ---"

# spawn_nested: deny_probe spawns deny_probe which runs the actual probe
# Tests that restrictions survive two levels of fork/exec
OUT=$("${CU}" --profile "$(harness_profile test-seccomp-deny.conf)" -- \
    "${PROBE}" spawn_nested "${PROBE} sc_ptrace_traceme" 2>/dev/null) || true
inherit_blocked "grandchild inherits seccomp (ptrace blocked at depth 2)" sc_ptrace_traceme

echo ""

# ── Summary ───────────────────────────────────────────────────────

# The suite declares its own assertion count. A block that stops
# running — a `skip` standing in for twenty assertions, a group
# guarded by a tool that is not installed — changes the total, and a
# changed total is a failure rather than a smaller number nobody
# compares against anything.
harness_expect_total 7
harness_summary "child-inheritance" || exit 1
exit 0
