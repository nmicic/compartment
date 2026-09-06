# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# harness.sh — shared helpers for compartment test suites
#
# This file is sourced, never executed: it has no shebang and is mode 644 on
# purpose (the CI executable-bit check only applies to scripts with a shebang).
#
# shellcheck shell=bash
#
# Provides:
#   harness_repo_dir            echo the repository root
#   harness_fixtures            set FIXTURES to a private fixture tree
#   harness_profile NAME        echo the path of a rendered test profile
#   harness_cleanup_add PATH    remove PATH when the shell exits
#   pass/fail/skip LABEL        record one assertion
#   harness_summary             print the one-line summary, exit non-zero on FAIL
#
# Suites that source this file must not install their own EXIT trap; use
# harness_cleanup_add instead.

# Guard against double-sourcing.
if [ -n "${HARNESS_SH_LOADED:-}" ]; then
    return 0
fi
HARNESS_SH_LOADED=1

HARNESS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS_SCRIPT_DIR="$(cd "${HARNESS_LIB_DIR}/.." && pwd)"
HARNESS_REPO_DIR="$(cd "${HARNESS_SCRIPT_DIR}/../.." && pwd)"

harness_repo_dir() { printf '%s\n' "${HARNESS_REPO_DIR}"; }

# ── Cleanup ────────────────────────────────────────────────────────

HARNESS_CLEANUP_PATHS=()

harness_cleanup_add() { HARNESS_CLEANUP_PATHS+=("$1"); }

harness_run_cleanup() {
    local p
    for p in "${HARNESS_CLEANUP_PATHS[@]}"; do
        case "${p}" in
            /|/tmp|/home|"${HOME}") continue ;;   # never remove these
        esac
        [ -n "${p}" ] && rm -rf -- "${p}"
    done
    HARNESS_CLEANUP_PATHS=()
}

trap harness_run_cleanup EXIT

# ── Assertion counters ─────────────────────────────────────────────

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP: $1"; }

# skip_group N REASON — one skip standing in for a block of N assertions.
#
# A bare `skip` in front of a twenty-assertion block makes pass+fail+skip
# depend on the machine: the same tree reported 45 assertions on the
# developer's host and 25 in a stock 22.04 container, with `skip=1` as the
# only trace. Counting the assertions that did not run keeps the total
# invariant, so a drop in the total is itself a signal.
skip_group() {
    local n="$1" reason="$2"
    SKIP=$((SKIP + n))
    echo "  SKIP: ${reason} (${n} assertions)"
}

# skip_to_total N REASON — for a guard that stands in front of everything
# the suite has left to do: skip exactly as many assertions as are still
# owed against the declared total, so the count can never go stale.
skip_to_total() {
    local want="$1" reason="$2"
    local owed=$((want - PASS - FAIL - SKIP - 1))
    if [ "${owed}" -gt 0 ]; then
        skip_group "${owed}" "${reason}"
    fi
}

# harness_expect_total N — the suite declares how many assertions it
# contains, counting this check.  A suite that silently grew or shrank
# fails instead of quietly reporting a different number.
harness_expect_total() {
    local want="$1"
    local got=$((PASS + FAIL + SKIP + 1))
    if [ "${got}" -eq "${want}" ]; then
        pass "suite ran all ${want} assertions"
    else
        fail "suite ran ${got} assertions, declared ${want} — a block was added, removed or silently skipped"
    fi
}

# Print the summary line every suite must emit and set the exit status.
harness_summary() {
    local name="${1:-suite}"
    echo ""
    echo "=== Results ==="
    echo "  PASS: ${PASS}"
    echo "  FAIL: ${FAIL}"
    echo "  SKIP: ${SKIP}"
    echo ""
    echo "SUMMARY ${name}: pass=${PASS} fail=${FAIL} skip=${SKIP}"
    if [ "${FAIL}" -gt 0 ]; then
        echo "SOME TESTS FAILED"
        return 1
    fi
    echo "ALL TESTS PASSED"
    return 0
}

# ── Fixtures ───────────────────────────────────────────────────────
#
# The fixture root is created with mktemp so its path is unpredictable:
# a world-writable, guessable path such as /tmp/compartment-fixtures lets
# any local user pre-create or swap the tree the assertions rely on.
#
# The default base is ${HOME}/.cache, not ${TMPDIR}: the built-in ai-agent
# profile maps ${HOME} rwx but /tmp only rw (W^X), so a probe binary under
# /tmp cannot be exec'd and the assertions that depend on it never run.
#
# Sets: FIXTURES

harness_fixtures() {
    if [ -n "${COMPARTMENT_FIXTURES:-}" ] && [ -d "${COMPARTMENT_FIXTURES}" ]; then
        FIXTURES="${COMPARTMENT_FIXTURES}"
        bash "${HARNESS_SCRIPT_DIR}/make_fixtures.sh" "${FIXTURES}" >/dev/null
        return 0
    fi

    local base="${COMPARTMENT_FIXTURE_BASE:-${HOME}/.cache}"
    if ! mkdir -p "${base}" 2>/dev/null || [ ! -w "${base}" ]; then
        echo "  NOTE: ${base} not writable, falling back to \${TMPDIR}" >&2
        base="${TMPDIR:-/tmp}"
    fi
    FIXTURES="$(mktemp -d "${base}/compartment-fixtures.XXXXXXXXXX")"
    harness_cleanup_add "${FIXTURES}"
    export COMPARTMENT_FIXTURES="${FIXTURES}"
    bash "${HARNESS_SCRIPT_DIR}/make_fixtures.sh" "${FIXTURES}" >/dev/null
}

# Path of a rendered test profile (see make_fixtures.sh).
harness_profile() { printf '%s/profiles/%s\n' "${FIXTURES}" "$1"; }
