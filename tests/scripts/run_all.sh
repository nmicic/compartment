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
# shellcheck source=tests/scripts/lib/harness.sh
. "${SCRIPT_DIR}/lib/harness.sh"

REPO_DIR="$(harness_repo_dir)"
QUICK=0
VERBOSE=""

for arg in "$@"; do
    case "${arg}" in
        --quick)   QUICK=1 ;;
        --verbose) VERBOSE="--verbose" ;;
    esac
done

SUITES_RUN=0
SUITES_FAILED=0
FAILED_SUITES=""

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
        FAILED_SUITES="${FAILED_SUITES}  - ${name}"$'\n'
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
# One fixture root for the whole run; exported so every suite reuses it and
# removed by the harness EXIT trap.
harness_fixtures
echo "Fixture root: ${FIXTURES}"

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
if [ -n "${FAILED_SUITES}" ]; then
    echo ""
    printf '%s' "${FAILED_SUITES}"
fi
echo ""

if [ "${SUITES_FAILED}" -gt 0 ]; then
    echo "SOME SUITES FAILED"
    exit 1
else
    echo "ALL SUITES PASSED"
    exit 0
fi
