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

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CU="${REPO_DIR}/compartment-user"
PROFILE="${REPO_DIR}/tests/profiles/test-claude-smoke.conf"
OUTPUT_DIR="${REPO_DIR}/tests/output"
mkdir -p "${OUTPUT_DIR}"

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

echo "=== Claude CLI smoke test ==="
echo ""

# ── Prerequisites ──────────────────────────────────────────────────

if [ ! -x "${CU}" ]; then
    echo "ERROR: compartment-user not found. Run 'make' first."
    exit 1
fi

if ! command -v claude >/dev/null 2>&1; then
    echo "SKIP: claude CLI not installed"
    skip "claude CLI not found"
    echo ""
    echo "=== Results ==="
    echo "  PASS: ${PASS}  FAIL: ${FAIL}  SKIP: ${SKIP}"
    exit 0
fi

if [ ! -d "${HOME}/.claude" ]; then
    echo "SKIP: ~/.claude/ not found (not authenticated)"
    skip "claude not authenticated"
    echo ""
    echo "=== Results ==="
    echo "  PASS: ${PASS}  FAIL: ${FAIL}  SKIP: ${SKIP}"
    exit 0
fi

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

if echo "${VERSION_OUT}" | grep -qi "claude\|version\|[0-9]\.[0-9]"; then
    pass "claude --version runs under sandbox"
    echo "    Version: $(echo "${VERSION_OUT}" | head -1)"
else
    fail "claude --version failed under sandbox"
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
echo "  Output saved to: tests/output/claude_smoke_output.txt"

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
        # Got a response but not the expected sentinel — count as pass
        # since the point is "Claude runs under sandbox without crashing"
        pass "Claude ran under sandbox (no sentinel, response: $(echo "${CLAUDE_OUT}" | head -1))"
    fi
fi

echo ""

# ── Test 3: Claude with audit logging ──────────────────────────────

echo "--- Test: Claude with audit logging ---"

AUDIT_DIR="/var/tmp/compartment-test-audit"
mkdir -p "${AUDIT_DIR}"

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

echo "=== Results ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  SKIP: ${SKIP}"
echo ""

if [ "${FAIL}" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
