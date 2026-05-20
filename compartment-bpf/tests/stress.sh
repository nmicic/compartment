#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# tests/stress.sh — host driver for the stress runner.
set -eu
cd "$(dirname "$0")/.."
. tests/lib.sh

ts=$(date -u +%Y%m%dT%H%M%SZ)
out="tests/stress-summary-${ts}.txt"
DURATION=${DURATION:-60}
WORKERS=${WORKERS:-8}

vm_sync_repo
vm_have_lsm
vm_build

vm_run "cd ${VM_WORKDIR} && REPO=${VM_WORKDIR} DURATION=${DURATION} WORKERS=${WORKERS} sh tests/stress-runner.sh" | tee "$out"

if grep -q 'stress-runner: PASS' "$out"; then
	echo "[stress] PASS"
	exit 0
fi
echo "[stress] FAIL — see $out" >&2
exit 1
