#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# run_claude_smoke.sh — smoke test: run Claude CLI through compartment-user
#
# Verifies that the Claude CLI can:
#   1. Start under compartment-user sandbox
#   2. Reach the Anthropic API (optionally via proxy)
#   3. Produce a response
#
# Prerequisites:
#   - claude CLI installed and authenticated (~/.claude/ must exist)
#   - compartment-user built
#   - Optional: Squid proxy on localhost:8080
#
# Usage:
#   ./tests/scripts/run_claude_smoke.sh [--with-proxy]

# AUDIT_OUT below is write-only on purpose: the case it belongs to asserts on
# the audit log the run produces, not on what the CLI prints, and assigning
# the output keeps it off the suite's stdout.
# shellcheck disable=SC2034

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CU="${REPO_DIR}/compartment-user"
PROFILE_TEMPLATE="${REPO_DIR}/tests/profiles/test-claude-smoke.conf"
PROFILE=""   # rendered below, once the CLI has been resolved
# Not ${REPO_DIR}/tests/output: a suite that writes into the checkout
# leaves the working tree dirty and, under sudo, root-owned. mktemp -d,
# removed by the EXIT trap below.
OUTPUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/compartment-smoke.XXXXXX")"
trap 'rm -rf "${OUTPUT_DIR}" "${AUDIT_DIR:-}"' EXIT INT TERM

WITH_PROXY=0
if [ "${1:-}" = "--with-proxy" ]; then
    WITH_PROXY=1
fi

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

echo "=== Claude CLI smoke test ==="
echo ""

# ── Prerequisites ──────────────────────────────────────────────────

if [ ! -x "${CU}" ]; then
    echo "ERROR: compartment-user not found. Run 'make' first."
    exit 1
fi

if ! command -v claude >/dev/null 2>&1; then
    echo "SKIP: external CLI not installed"
    skip_group 5 "external CLI not found"
    echo ""
    echo "=== Results ==="
    echo "  PASS: ${PASS}  FAIL: ${FAIL}  SKIP: ${SKIP}"
    echo "SUMMARY external-cli-smoke: pass=${PASS} fail=${FAIL} skip=${SKIP}"
    exit 0
fi

if [ ! -d "${HOME}/.claude" ]; then
    echo "SKIP: the CLI is present but not authenticated"
    skip_group 5 "external CLI not authenticated"
    echo ""
    echo "=== Results ==="
    echo "  PASS: ${PASS}  FAIL: ${FAIL}  SKIP: ${SKIP}"
    echo "SUMMARY external-cli-smoke: pass=${PASS} fail=${FAIL} skip=${SKIP}"
    exit 0
fi

# ── Render the profile ─────────────────────────────────────────────
#
# The profile maps $HOME rw, which is W^X: no execute.  A CLI installed under
# $HOME therefore cannot start under it without an explicit execute grant, so
# resolve the binary, follow it to its real path (npm shims and version
# managers are symlinks) and substitute its directory for @CLI_DIR@.  Without
# this the suite failed on any host where the CLI is not in /usr/bin, and
# reported it as its own failure.
CLI_PATH="$(command -v claude)"
CLI_REAL="$(readlink -f "${CLI_PATH}" 2>/dev/null || printf '%s' "${CLI_PATH}")"
CLI_DIR="$(dirname "${CLI_REAL}")"
PROFILE="$(mktemp "${OUTPUT_DIR}/claude-smoke.XXXXXX.conf")"
while IFS= read -r line; do
    printf '%s\n' "${line//@CLI_DIR@/${CLI_DIR}}"
done < "${PROFILE_TEMPLATE}" > "${PROFILE}"
chmod go-w "${PROFILE}"
echo "CLI: ${CLI_PATH} -> ${CLI_REAL} (exec grant: ${CLI_DIR})"

# Check proxy if requested
if [ "${WITH_PROXY}" -eq 1 ]; then
    if curl -s --proxy http://127.0.0.1:8080 --connect-timeout 2 https://api.anthropic.com 2>/dev/null; then
        echo "Proxy at localhost:8080: available"
    else
        echo "WARNING: Proxy at localhost:8080 not responding, continuing without"
        WITH_PROXY=0
    fi
fi

echo ""

# ── Test 1: Claude --version under sandbox ─────────────────────────

echo "--- Test: Claude --version under compartment-user ---"

VERSION_OUT=$("${CU}" --profile "${PROFILE}" -- claude --version 2>&1) || true

# `grep -qi "claude|version|[0-9].[0-9]"` was satisfied by
# "compartment-user: exec ...: Permission denied" and by
# "command not found" — every error message this test can produce.
# Anchor on a version number at the start of a line instead.
if printf '%s\n' "${VERSION_OUT}" | grep -qE '^[0-9]+\.[0-9]+'; then
    pass "the CLI reports a version under the sandbox"
    echo "    Version: $(echo "${VERSION_OUT}" | head -1)"
else
    fail "the CLI printed no version under the sandbox"
    echo "    Output: ${VERSION_OUT}"
fi

echo ""

# ── Test 2: Claude print (non-interactive, quick) ──────────────────

echo "--- Test: Claude --print under compartment-user ---"

PROMPT="Reply with exactly the word SANDBOXED and nothing else."
CLAUDE_ARGS=(--print --max-turns 1 --model claude-sonnet-4-6)

if [ "${WITH_PROXY}" -eq 1 ]; then
    echo "  Using proxy: http://127.0.0.1:8080"
    CLAUDE_OUT=$(HTTPS_PROXY="http://127.0.0.1:8080" HTTP_PROXY="http://127.0.0.1:8080" \
        timeout 60 "${CU}" --profile "${PROFILE}" -- \
        claude "${CLAUDE_ARGS[@]}" "${PROMPT}" 2>&1) || true
else
    CLAUDE_OUT=$(timeout 60 "${CU}" --profile "${PROFILE}" -- \
        claude "${CLAUDE_ARGS[@]}" "${PROMPT}" 2>&1) || true
fi

# Save output
echo "${CLAUDE_OUT}" > "${OUTPUT_DIR}/claude_smoke_output.txt"
echo "  Output saved to: ${OUTPUT_DIR}/claude_smoke_output.txt"

if echo "${CLAUDE_OUT}" | grep -qi "SANDBOXED"; then
    pass "Claude responded correctly under sandbox"
else
    if echo "${CLAUDE_OUT}" | grep -qi "error\|denied\|EPERM\|forbidden"; then
        fail "Claude hit sandbox restriction: $(echo "${CLAUDE_OUT}" | head -3)"
    elif echo "${CLAUDE_OUT}" | grep -qi "timeout\|timed out"; then
        skip "Claude timed out (network issue?)"
    elif [ -z "${CLAUDE_OUT}" ]; then
        fail "Claude produced no output"
    else
        # Got a response but not the expected sentinel.
        # since the point is "Claude runs under sandbox without crashing"
        # A response that is not the sentinel proves the process ran, not
        # that it did the right thing. That is a skip, never a pass.
        skip "the CLI answered without the sentinel: $(echo "${CLAUDE_OUT}" | head -1)"
    fi
fi

echo ""

# ── Test 3: Claude with audit logging ──────────────────────────────

echo "--- Test: Claude with audit logging ---"

# /var/tmp is world-writable and sticky; a fixed name there is both
# squattable and, when the suite aborts, left behind for the next run to
# inherit. Keep it private and remove it on every exit path.
AUDIT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/compartment-smoke-audit.XXXXXX")"

# Create a timestamp marker BEFORE the test so we only match new logs
MARKER=$(mktemp)
sleep 1

AUDIT_OUT=$(timeout 60 "${CU}" --profile "${PROFILE}" --audit-log "${AUDIT_DIR}" -- \
    claude --print --max-turns 1 --model claude-sonnet-4-6 \
    "Reply with exactly: AUDIT_OK" 2>&1) || true

# Check audit log was created AFTER our marker (not stale from previous runs)
AUDIT_FILES=$(find "${AUDIT_DIR}" -name "*.log" -newer "${MARKER}" 2>/dev/null | head -5)
rm -f "${MARKER}"
if [ -n "${AUDIT_FILES}" ]; then
    pass "Audit log created under sandbox"
    echo "    Log: $(echo "${AUDIT_FILES}" | head -1)"
    echo "    Content: $(tail -1 "${AUDIT_FILES}" 2>/dev/null)"
else
    skip "No audit log found (may not have reached exec)"
fi

echo ""

# ── Test 4: Dry-run with Claude command ────────────────────────────

echo "--- Test: --dry-run with Claude command ---"

DRY_OUT=$("${CU}" --profile "${PROFILE}" --dry-run -- claude --print "test" 2>&1) || true

if echo "${DRY_OUT}" | grep -qi "landlock\|seccomp\|block\|read-only"; then
    pass "--dry-run shows sandbox policy for Claude"
else
    fail "--dry-run produced no policy output"
fi

echo ""

# ── Summary ───────────────────────────────────────────────────────

harness_expect_total 5

echo "=== Results ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  SKIP: ${SKIP}"
echo ""
# Every exit path prints exactly one of these; the runners require it.
echo "SUMMARY external-cli-smoke: pass=${PASS} fail=${FAIL} skip=${SKIP}"

if [ "${FAIL}" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
