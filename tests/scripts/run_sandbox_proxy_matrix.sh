#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# run_sandbox_proxy_matrix.sh — sandbox.sh network and proxy tests
#
# Tests sandbox.sh in various modes:
#   1. HARD mode (no proxy): no network access at all
#   2. HARD mode (with proxy): only proxy bridge works
#   3. SOFT mode: slirp4netns fallback
#
# Requires: unshare, socat (for proxy bridge)
# Optional: slirp4netns (for SOFT mode), squid on localhost:8080

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SANDBOX="${REPO_DIR}/sandbox.sh"

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP: $1"; }

# One skip standing in for a block of N assertions, so pass+fail+skip is
# the same number on every machine (tests/scripts/lib/harness.sh).
skip_group() {
    local n="$1" reason="$2"
    SKIP=$((SKIP + n))
    echo "  SKIP: ${reason} (${n} assertions)"
}

# The suite declares its own assertion count, counting this check, so a
# block that silently stops running fails instead of shrinking the total.
harness_expect_total() {
    local want="$1"
    local got=$((PASS + FAIL + SKIP + 1))
    if [ "${got}" -eq "${want}" ]; then
        pass "suite ran all ${want} assertions"
    else
        fail "suite ran ${got} assertions, declared ${want} — a block was added, removed or silently skipped"
    fi
}

echo "=== Sandbox.sh test matrix ==="
echo ""

if [ ! -x "${SANDBOX}" ]; then
    echo "ERROR: ${SANDBOX} not found or not executable"
    exit 1
fi

# Check prerequisites
HAS_UNSHARE=0
if command -v unshare >/dev/null 2>&1; then
    HAS_UNSHARE=1
fi

HAS_SOCAT=0
if command -v socat >/dev/null 2>&1; then
    HAS_SOCAT=1
fi

HAS_SLIRP=0
if command -v slirp4netns >/dev/null 2>&1; then
    HAS_SLIRP=1
fi

HAS_PROXY=0
if curl -s --proxy http://127.0.0.1:8080 --connect-timeout 2 http://example.com >/dev/null 2>&1; then
    HAS_PROXY=1
fi

echo "Prerequisites:"
echo "  unshare:    $([ ${HAS_UNSHARE} -eq 1 ] && echo 'yes' || echo 'NO')"
echo "  socat:      $([ ${HAS_SOCAT} -eq 1 ] && echo 'yes' || echo 'NO')"
echo "  slirp4netns: $([ ${HAS_SLIRP} -eq 1 ] && echo 'yes' || echo 'NO')"
echo "  squid@8080: $([ ${HAS_PROXY} -eq 1 ] && echo 'yes' || echo 'NO')"
echo ""

# Test: can we create user namespaces?
CAN_USERNS=0
if unshare --user --map-root-user true 2>/dev/null; then
    CAN_USERNS=1
fi

echo "  user-ns:    $([ ${CAN_USERNS} -eq 1 ] && echo 'yes' || echo 'NO')"
echo ""

# shellcheck source=tests/scripts/lib/sandbox-hard.sh
. "${SCRIPT_DIR}/lib/sandbox-hard.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sandbox-proxy-matrix.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

# Every negative outcome below used to route to skip(), and fail() was
# defined and never called from anywhere in this file — so FAIL was
# structurally always 0 and "ALL TESTS PASSED" was unconditional, on
# every host, forever. The assertions now live in lib/sandbox-hard.sh and
# are shared with root.d/sandbox-hard.sh, which clears
# kernel.apparmor_restrict_unprivileged_userns for the duration so they
# actually run on a machine like this one.
if [ "${CAN_USERNS}" -eq 0 ]; then
    echo "Cannot create an unprivileged user namespace as this user."
    echo "(sudo make test-root runs the same assertions through"
    echo " tests/scripts/root.d/sandbox-hard.sh.)"
    skip_group "${SANDBOX_HARD_COUNT}" "user namespaces not available to this user"
else
    echo "--- Test group: sandbox.sh HARD mode against a real namespace ---"
    sandbox_hard_assertions "${SANDBOX}" "${WORK}"
fi

echo ""

harness_expect_total $(( SANDBOX_HARD_COUNT + 1 ))

# ── Summary ───────────────────────────────────────────────────────

echo "=== Results ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  SKIP: ${SKIP}"
echo "SUMMARY sandbox-proxy-matrix: pass=${PASS} fail=${FAIL} skip=${SKIP}"
echo ""

if [ "${FAIL}" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
