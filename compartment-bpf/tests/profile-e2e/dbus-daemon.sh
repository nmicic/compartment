#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# dbus-daemon E2E: ListNames against the system bus.
#
# Verifiable output: sorted list of bus names from the reply.
# Raw dbus-send output includes a per-call serial number + reply timestamp,
# so we hash a stable derivative (sorted unique bus-name strings).
#
set -euo pipefail

: "${NONCE:?NONCE missing from orchestrator}"

cleanup() { :; }
trap cleanup EXIT

raw=""
rc=0
raw="$(dbus-send --system --print-reply \
        --dest=org.freedesktop.DBus / \
        org.freedesktop.DBus.ListNames 2>&1)" || rc=$?

verdict="FAIL"
hash="-"

if [ "$rc" -eq 0 ] \
   && printf '%s\n' "$raw" | grep -q 'method return' \
   && printf '%s\n' "$raw" | grep -q 'org.freedesktop.DBus'; then
    # Extract the bus-name strings, sort+uniq for repeatability.
    names="$(printf '%s\n' "$raw" \
                | grep -oE 'string "[^"]+"' \
                | sed 's/^string "//;s/"$//' \
                | sort -u)"
    hash="$(printf '%s\n' "$names" | sha256sum | awk '{print $1}')"
    verdict="PASS"
fi

# Note: hash on stable sorted derivative; raw output contains a serial that rotates.
echo "WORKFLOW_OUTPUT_HASH=${hash}"
echo "E2E_VERDICT=${verdict}"

if [ "$verdict" = "PASS" ]; then
    exit 0
fi
exit 1
