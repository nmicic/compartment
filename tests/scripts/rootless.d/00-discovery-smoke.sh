#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# 00-discovery-smoke.sh — proves run_all.sh discovery works
#
# Deliberately tiny: it asserts only that a script dropped into
# tests/scripts/rootless.d/ is picked up, that the harness helpers are
# reachable, and that the fixture root exists. Real tests go in sibling
# scripts; see README.md for the contract.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/scripts/lib/harness.sh
. "${SCRIPT_DIR}/../lib/harness.sh"

REPO_DIR="$(harness_repo_dir)"

echo "=== rootless.d discovery smoke ==="
echo ""

if [ "$(id -u)" -ne 0 ]; then
    pass "runs unprivileged (uid=$(id -u))"
else
    fail "rootless.d suites must not need root (uid=0)"
fi

if [ -x "${REPO_DIR}/compartment-user" ]; then
    pass "repo root resolved: ${REPO_DIR}"
else
    fail "repo root resolved (no compartment-user at ${REPO_DIR})"
fi

harness_fixtures
if [ -d "${FIXTURES}/readable" ] && [ -f "${FIXTURES}/profiles/test-combined.conf" ]; then
    pass "fixture root usable: ${FIXTURES}"
else
    fail "fixture root incomplete: ${FIXTURES}"
fi

echo ""
# The suite declares its own assertion count. A block that stops
# running — a `skip` standing in for twenty assertions, a group
# guarded by a tool that is not installed — changes the total, and a
# changed total is a failure rather than a smaller number nobody
# compares against anything.
harness_expect_total 4
harness_summary "rootless-discovery-smoke" || exit 1
exit 0
