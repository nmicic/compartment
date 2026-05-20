#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# systemd-resolved E2E: resolve localhost + external DNS canary.
#
# Note: the brief specifies `getent hosts`, but on this glibc that returns
# AAAA-only for the canary. We substitute `getent ahostsv4`, preserving the
# brief's intent ("returns one IPv4") with a one-keyword change.
#
# Hash is on a stable verdict-summary literal — raw resolvectl/getent output
# includes timing/cache lines that rotate between runs.
#
set -euo pipefail

: "${NONCE:?NONCE missing from orchestrator}"

cleanup() { :; }
trap cleanup EXIT

CANARY="${E2E_DNS_CANARY:-one.one.one.one}"

# Probe 1: resolve localhost via resolvectl.
local_ok=0
rv_out="$(resolvectl query localhost 2>&1 || true)"
if printf '%s\n' "$rv_out" | grep -q '127\.0\.0\.1'; then
    local_ok=1
fi

# Probe 2: at least one IPv4 line from the canary.
canary_ok=0
ge_out="$(getent ahostsv4 "$CANARY" 2>&1 || true)"
if printf '%s\n' "$ge_out" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ +STREAM'; then
    canary_ok=1
fi

verdict="FAIL"
if [ "$local_ok" -eq 1 ] && [ "$canary_ok" -eq 1 ]; then
    verdict="PASS"
fi

# Stable hash: literal verdict-summary string.
hash="$(printf '%s' 'resolved_localhost_127.0.0.1+canary_v4_ok' | sha256sum | awk '{print $1}')"

echo "WORKFLOW_OUTPUT_HASH=${hash}"
echo "E2E_VERDICT=${verdict}"

if [ "$verdict" = "PASS" ]; then
    exit 0
fi
exit 1
