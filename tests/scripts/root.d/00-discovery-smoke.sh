#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# 00-discovery-smoke.sh — proves run_root_tests.sh discovery works
#
# Deliberately tiny and deliberately harmless: it creates no namespace, no
# mount and no container root. It asserts only that a script dropped into
# tests/scripts/root.d/ is picked up, that it is running as root, and that
# the harness helpers are reachable. Real root tests go in sibling scripts;
# see README.md for the contract (especially the cleanup rules).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/scripts/lib/harness.sh
. "${SCRIPT_DIR}/../lib/harness.sh"

REPO_DIR="$(harness_repo_dir)"

echo "=== root.d discovery smoke ==="
echo ""

if [ "$(id -u)" -eq 0 ]; then
    pass "running as root (uid=0)"
else
    fail "root.d suites must run as root (uid=$(id -u))"
fi

if [ -x "${REPO_DIR}/compartment-root" ]; then
    pass "repo root resolved: ${REPO_DIR}"
else
    fail "repo root resolved (no compartment-root at ${REPO_DIR})"
fi

# --version is the one compartment-root path that touches nothing.
if VER=$("${REPO_DIR}/compartment-root" --version 2>&1) && [ -n "${VER}" ]; then
    pass "compartment-root --version as root: ${VER}"
else
    fail "compartment-root --version as root"
fi

# A scratch dir under the runner's fixture root, removed by the EXIT trap:
# the pattern every real root suite must follow.
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/compartment-root-smoke.XXXXXXXX")"
harness_cleanup_add "${SCRATCH}"
if mkdir -p "${SCRATCH}/jail" && [ -d "${SCRATCH}/jail" ]; then
    pass "scratch tree created and registered for cleanup"
else
    fail "scratch tree created"
fi

echo ""
# The suite declares its own assertion count. A block that stops
# running — a `skip` standing in for twenty assertions, a group
# guarded by a tool that is not installed — changes the total, and a
# changed total is a failure rather than a smaller number nobody
# compares against anything.
harness_expect_total 5
harness_summary "root-discovery-smoke" || exit 1
exit 0
