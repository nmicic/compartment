#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# tests/fuzz.sh — host driver for the property/fuzz oracle.
# Syncs+builds, then runs tests/fuzz-runner.sh on the VM. Stores the
# JSON summary to tests/fuzz-summary-<TS>.json.
set -eu
cd "$(dirname "$0")/.."
. tests/lib.sh

ts=$(date -u +%Y%m%dT%H%M%SZ)
out="tests/fuzz-summary-${ts}.json"
ITERS=${ITERS:-10000}
N_FILES=${N_FILES:-200}
N_SEALED=${N_SEALED:-150}
SEED=${SEED:-$RANDOM}

vm_sync_repo
vm_have_lsm
vm_build

vm_run "cd ${VM_WORKDIR} && REPO=${VM_WORKDIR} ITERS=${ITERS} N_FILES=${N_FILES} N_SEALED=${N_SEALED} SEED=${SEED} sh tests/fuzz-runner.sh" > "$out"
rc=$?

echo "[fuzz] json: $out (rc=$rc)" >&2
cat "$out"

if [ "$rc" -ne 0 ]; then
	echo "[fuzz] FAIL — divergences detected (or runner errored, rc=$rc)" >&2
	exit 1
fi

div=$(grep -E '"divergences"' "$out" | grep -oE '[0-9]+')
serr=$(grep -E '"stage_errors"' "$out" | grep -oE '[0-9]+')
echo "[fuzz] divergences=${div:-?} stage_errors=${serr:-?}" >&2
if [ "${div:-1}" -ne 0 ]; then
	echo "[fuzz] FAIL" >&2
	exit 1
fi
echo "[fuzz] PASS"
