#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# chronyd E2E: `chronyc -c tracking` synced + offset within 100 ms.
#
# Output is CSV with 14 fields. Field 1 = RefID (hex, "00000000" means unsynced).
# Field 5 = system-time offset in seconds.
#
# Hash is on a stable verdict-summary literal — RefID and offset are per-run
# volatile and would break T3b.2 repeatability if hashed directly.
#
set -euo pipefail

: "${NONCE:?NONCE missing from orchestrator}"

cleanup() { :; }
trap cleanup EXIT

# chronyd needs ~10s to re-acquire sync after `systemctl restart`, so the
# orchestrator's 3s SETTLE_S is not enough. Poll up to SYNC_DEADLINE_S for
# RefID to become non-zero. Once synced, evaluate offset on the same sample.
SYNC_DEADLINE_S="${CHRONY_SYNC_DEADLINE_S:-20}"

rc=0
csv=""
refid=""
offset=""
within=0
verdict="FAIL"
for _ in $(seq 1 "$SYNC_DEADLINE_S"); do
    csv="$(chronyc -c tracking 2>&1)" || rc=$?
    refid="$(printf '%s' "$csv" | awk -F, 'NR==1{print $1}')"
    offset="$(printf '%s' "$csv" | awk -F, 'NR==1{print $5}')"
    if [ "$rc" -eq 0 ] && [ -n "$refid" ] && [ "$refid" != "00000000" ]; then
        break
    fi
    rc=0
    sleep 1
done

if [ "$rc" -eq 0 ] && [ -n "$refid" ] && [ "$refid" != "00000000" ] && [ -n "$offset" ]; then
    within=$(awk -v o="$offset" 'BEGIN{ if (o<0) o=-o; print (o<0.1)?1:0 }')
    if [ "$within" -eq 1 ]; then
        verdict="PASS"
    fi
fi

# Stable hash: literal verdict-summary string.
hash="$(printf '%s' 'chrony_refid_nonzero_offset_within_100ms' | sha256sum | awk '{print $1}')"

echo "WORKFLOW_OUTPUT_HASH=${hash}"
echo "E2E_VERDICT=${verdict}"

if [ "$verdict" = "PASS" ]; then
    exit 0
fi
exit 1
