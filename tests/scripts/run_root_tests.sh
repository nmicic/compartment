#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# run_root_tests.sh — run every root-only test suite
#
# Discovers and runs every executable tests/scripts/root.d/*.sh as its own
# suite, in glob order, with the same PASS/FAIL accounting and exit-code
# semantics as run_all.sh.  See tests/scripts/root.d/README.md for the
# contract each script must honour.
#
# Usage:
#   sudo make test-root
#   sudo ./tests/scripts/run_root_tests.sh [--verbose]
#
# Refuses to run as a non-root user: these suites create namespaces, mounts
# and container roots, and half-applying them as an ordinary user produces
# failures that say nothing about the code.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/scripts/lib/harness.sh
. "${SCRIPT_DIR}/lib/harness.sh"

REPO_DIR="$(harness_repo_dir)"
ROOT_D="${SCRIPT_DIR}/root.d"
VERBOSE=""

for arg in "$@"; do
    case "${arg}" in
        --verbose) VERBOSE="--verbose" ;;
        *) echo "run_root_tests.sh: unknown argument: ${arg}" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "run_root_tests.sh: must be run as root (try: sudo make test-root)" >&2
    exit 2
fi

SUITES_RUN=0
SUITES_FAILED=0
FAILED_SUITES=""
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
SUITES_REPORTING=0

run_suite() {
    local name="$1" script="$2"
    shift 2

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ${name}"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    SUITES_RUN=$((SUITES_RUN + 1))

    local out rc=0
    out=$(mktemp)
    # `|| true` here would reset PIPESTATUS and hide the suite's exit code.
    set +e
    bash "${script}" "$@" 2>&1 | tee "${out}"
    rc=${PIPESTATUS[0]}
    set -e

    # Sum whatever the suite reported about its own assertions, exactly as
    # run_all.sh does, so "sudo make test-root" reports totals instead of
    # leaving them to be counted by hand.
    local p f s
    while read -r p f s; do
        TOTAL_PASS=$((TOTAL_PASS + p))
        TOTAL_FAIL=$((TOTAL_FAIL + f))
        TOTAL_SKIP=$((TOTAL_SKIP + s))
        SUITES_REPORTING=$((SUITES_REPORTING + 1))
    done < <(sed -n 's/^SUMMARY [^:]*: pass=\([0-9]*\) fail=\([0-9]*\) skip=\([0-9]*\).*/\1 \2 \3/p' "${out}")

    # Exactly one SUMMARY line per suite. A suite that exits 0 without one
    # used to count as a passing suite contributing zero assertions, and
    # the only trace was the "reported by N/M suites" counter that nothing
    # asserts on; two lines from one suite would double-count. The bypass
    # runner in compartment-bpf/ enforces the same invariant on its own
    # labels — this is the core runner catching up.
    local nsummary
    nsummary=$(grep -c '^SUMMARY [^:]*: pass=' "${out}" || true)
    rm -f "${out}"
    if [ "${nsummary}" -ne 1 ] && [ "${rc}" -eq 0 ]; then
        rc=1
        SUITES_FAILED=$((SUITES_FAILED + 1))
        FAILED_SUITES="${FAILED_SUITES}  - ${name} (${nsummary} SUMMARY lines, expected exactly 1)"$'\n'
        echo ""
        echo "^^^ SUITE FAILED: ${nsummary} SUMMARY lines, expected exactly 1 ^^^"
        echo ""
        return 0
    fi

    if [ "${rc}" -eq 0 ]; then
        echo ""
    else
        SUITES_FAILED=$((SUITES_FAILED + 1))
        FAILED_SUITES="${FAILED_SUITES}  - ${name}"$'\n'
        echo ""
        echo "^^^ SUITE FAILED ^^^"
        echo ""
    fi
}

echo "=== Compartment root-only test suites ==="
echo "  repo:   ${REPO_DIR}"
echo "  suites: ${ROOT_D}"
echo "  uid:    $(id -u)  kernel: $(uname -r)"
echo ""

if [ ! -d "${ROOT_D}" ]; then
    echo "ERROR: ${ROOT_D} does not exist" >&2
    exit 1
fi

# Shared fixture root (unpredictable, removed on exit).  Keep it out of
# $HOME: under `sudo` that may still be the invoking user's home directory,
# and a root-owned tree left there after a crash is a nuisance at best.
: "${COMPARTMENT_FIXTURE_BASE:=${TMPDIR:-/tmp}}"
export COMPARTMENT_FIXTURE_BASE
harness_fixtures
echo "Fixture root: ${FIXTURES}"

FOUND=0
for script in "${ROOT_D}"/*.sh; do
    [ -e "${script}" ] || continue              # empty glob
    FOUND=1
    if [ ! -x "${script}" ]; then
        SUITES_RUN=$((SUITES_RUN + 1))
        SUITES_FAILED=$((SUITES_FAILED + 1))
        FAILED_SUITES="${FAILED_SUITES}  - $(basename "${script}") (not executable)"$'\n'
        echo ""
        echo "^^^ SUITE NOT EXECUTABLE: ${script} (chmod 755 it) ^^^"
        echo ""
        continue
    fi
    run_suite "root.d: $(basename "${script}")" "${script}" ${VERBOSE}
done

if [ "${FOUND}" -eq 0 ]; then
    echo "No suites found in ${ROOT_D} — nothing to do."
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ROOT SUITE SUMMARY                                          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Suites run:    ${SUITES_RUN}"
echo "  Suites failed: ${SUITES_FAILED}"
echo "  Assertions:    pass=${TOTAL_PASS} fail=${TOTAL_FAIL} skip=${TOTAL_SKIP}" \
     "(reported by ${SUITES_REPORTING}/${SUITES_RUN} suites)"
if [ -n "${FAILED_SUITES}" ]; then
    echo ""
    printf '%s' "${FAILED_SUITES}"
fi
echo ""

if [ "${SUITES_FAILED}" -gt 0 ]; then
    echo "SOME SUITES FAILED"
    exit 1
fi
echo "ALL SUITES PASSED"
exit 0
