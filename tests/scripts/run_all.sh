#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# run_all.sh — run all compartment test suites
#
# Usage:
#   ./tests/scripts/run_all.sh              # run all tests
#   ./tests/scripts/run_all.sh --quick      # skip Claude smoke + sandbox proxy
#   ./tests/scripts/run_all.sh --verbose    # verbose output from test runners

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
QUICK=0
VERBOSE=""

for arg in "$@"; do
    case "${arg}" in
        --quick)   QUICK=1 ;;
        --verbose) VERBOSE="--verbose" ;;
    esac
done

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
SUITES_RUN=0
SUITES_FAILED=0

run_suite() {
    local name="$1" script="$2"
    shift 2

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ${name}"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    SUITES_RUN=$((SUITES_RUN + 1))
    if bash "${script}" "$@" 2>&1; then
        echo ""
    else
        SUITES_FAILED=$((SUITES_FAILED + 1))
        echo ""
        echo "^^^ SUITE FAILED ^^^"
        echo ""
    fi
}

# ── Build prerequisites ───────────────────────────────────────────

echo "Building compartment tools..."
cd "${REPO_DIR}"
make 2>&1 | tail -5

echo "Building deny_probe..."
cc -Wall -Wextra -Wpedantic -std=c11 -O2 \
    -o tests/probes/deny_probe tests/probes/deny_probe.c 2>&1

echo "Creating fixtures..."
bash tests/scripts/make_fixtures.sh > /dev/null 2>&1

echo "Ready."

# ── Core tests (always run) ──────────────────────────────────────

run_suite "Compartment-user matrix (fs + seccomp + env)" \
    "${SCRIPT_DIR}/run_compartment_user_matrix.sh" ${VERBOSE}

run_suite "Child inheritance tests" \
    "${SCRIPT_DIR}/run_child_inheritance_tests.sh" ${VERBOSE}

# ── Extended tests (skip with --quick) ────────────────────────────

if [ "${QUICK}" -eq 0 ]; then
    run_suite "Sandbox.sh proxy/network tests" \
        "${SCRIPT_DIR}/run_sandbox_proxy_matrix.sh" ${VERBOSE}

    run_suite "Claude CLI smoke test" \
        "${SCRIPT_DIR}/run_claude_smoke.sh" ${VERBOSE}
else
    echo ""
    echo "(Skipping sandbox proxy and Claude smoke tests — use without --quick to include)"
fi

# ── Final summary ────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  FINAL SUMMARY                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Suites run:    ${SUITES_RUN}"
echo "  Suites failed: ${SUITES_FAILED}"
echo ""

if [ "${SUITES_FAILED}" -gt 0 ]; then
    echo "SOME SUITES FAILED"
    exit 1
else
    echo "ALL SUITES PASSED"
    exit 0
fi
