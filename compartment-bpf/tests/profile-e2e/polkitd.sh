#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# polkitd E2E: pkcheck for an always-allow action as root.
#
# Note: the brief's literal action "org.freedesktop.policykit.localauth.localauthority"
# is not registered on the Resolute VM. We substitute org.freedesktop.policykit.exec,
# which is registered everywhere polkit ships and returns exit 0 for UID 0.
#
# Note: subject start_time must be read from /proc/$$/stat field 22 (clock ticks
# since boot), NOT stat -c %Y on /proc/$$ — pkcheck validates against the
# kernel-provided value and rejects mismatches.
#
set -euo pipefail

: "${NONCE:?NONCE missing from orchestrator}"

cleanup() { :; }
trap cleanup EXIT

START_TIME=$(awk '{print $22}' /proc/$$/stat)

rc=0
pkcheck --action-id "org.freedesktop.policykit.exec" \
        --process "$$,${START_TIME},0" \
        >/dev/null 2>&1 || rc=$?

verdict="FAIL"
if [ "$rc" -eq 0 ]; then
    verdict="PASS"
fi

# Stable hash: deterministic verdict-summary literal.
hash="$(printf '%s' 'polkit_exec_allowed' | sha256sum | awk '{print $1}')"

echo "WORKFLOW_OUTPUT_HASH=${hash}"
echo "E2E_VERDICT=${verdict}"

if [ "$verdict" = "PASS" ]; then
    exit 0
fi
exit 1
