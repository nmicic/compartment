#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# run_all.sh — run all compartment test suites
#
# Usage:
#   ./tests/scripts/run_all.sh                # run all tests
#   ./tests/scripts/run_all.sh --quick        # skip Claude smoke + sandbox proxy
#   ./tests/scripts/run_all.sh --verbose      # verbose output from test runners
#   ./tests/scripts/run_all.sh --no-external  # skip suites that need a
#                                             # third-party CLI or an outbound
#                                             # proxy (also: COMPARTMENT_SKIP_EXTERNAL=1)
#
# Every executable tests/scripts/rootless.d/*.sh is discovered and run as its
# own suite; see tests/scripts/rootless.d/README.md for the contract.
# Root-only suites live in tests/scripts/root.d/ and are run by
# tests/scripts/run_root_tests.sh (`sudo make test-root`).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/scripts/lib/harness.sh
. "${SCRIPT_DIR}/lib/harness.sh"

REPO_DIR="$(harness_repo_dir)"
QUICK=0
VERBOSE=""
SKIP_EXTERNAL="${COMPARTMENT_SKIP_EXTERNAL:-0}"

for arg in "$@"; do
    case "${arg}" in
        --quick)       QUICK=1 ;;
        --verbose)     VERBOSE="--verbose" ;;
        --no-external) SKIP_EXTERNAL=1 ;;
    esac
done

SUITES_RUN=0
SUITES_FAILED=0
SUITES_SKIPPED=0
FAILED_SUITES=""
SKIPPED_SUITES=""

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

# Record a suite that was not run at all, with the reason.  A suite that
# needs something the machine does not have must be visibly skipped, never
# silently dropped and never a failure.
skip_suite() {
    SUITES_SKIPPED=$((SUITES_SKIPPED + 1))
    SKIPPED_SUITES="${SKIPPED_SUITES}  - $1 ($2)"$'\n'
    echo ""
    echo "(skipping suite: $1 — $2)"
}

# Run every executable *.sh in a discovery directory as its own suite.
# A non-executable *.sh is a failure, not a silent skip: a test that never
# runs is the defect this harness exists to catch.
run_discovered() {
    local dir="$1" label="$2" script
    if [ ! -d "${dir}" ]; then
        return 0
    fi
    for script in "${dir}"/*.sh; do
        [ -e "${script}" ] || continue          # empty glob
        if [ ! -x "${script}" ]; then
            SUITES_RUN=$((SUITES_RUN + 1))
            SUITES_FAILED=$((SUITES_FAILED + 1))
            FAILED_SUITES="${FAILED_SUITES}  - ${label}: $(basename "${script}") (not executable)"$'\n'
            echo ""
            echo "^^^ SUITE NOT EXECUTABLE: ${script} (chmod 755 it) ^^^"
            echo ""
            continue
        fi
        run_suite "${label}: $(basename "${script}")" "${script}" ${VERBOSE}
    done
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

# ── Discovered rootless suites ────────────────────────────────────

run_discovered "${SCRIPT_DIR}/rootless.d" "rootless.d"

# ── Extended tests (skip with --quick) ────────────────────────────

if [ "${QUICK}" -eq 0 ]; then
    # sandbox.sh needs unprivileged user namespaces; the suite itself skips
    # cleanly without them, and its one proxy case skips without a proxy.
    run_suite "Sandbox.sh proxy/network tests" \
        "${SCRIPT_DIR}/run_sandbox_proxy_matrix.sh" ${VERBOSE}

    # The Claude smoke suite needs a third-party CLI and an authenticated
    # session, neither of which exists on a build machine.
    if [ "${SKIP_EXTERNAL}" = "1" ]; then
        skip_suite "Claude CLI smoke test" "--no-external / COMPARTMENT_SKIP_EXTERNAL=1"
    elif ! command -v claude > /dev/null 2>&1; then
        skip_suite "Claude CLI smoke test" "claude CLI not installed"
    elif [ ! -d "${HOME}/.claude" ]; then
        skip_suite "Claude CLI smoke test" "no ${HOME}/.claude — CLI not authenticated"
    else
        run_suite "Claude CLI smoke test" \
            "${SCRIPT_DIR}/run_claude_smoke.sh" ${VERBOSE}
    fi
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
echo "  Suites run:     ${SUITES_RUN}"
echo "  Suites failed:  ${SUITES_FAILED}"
echo "  Suites skipped: ${SUITES_SKIPPED}"
if [ -n "${SKIPPED_SUITES}" ]; then
    echo ""
    printf '%s' "${SKIPPED_SUITES}"
fi
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
