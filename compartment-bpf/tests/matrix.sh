#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# tests/matrix.sh — host-side driver for the (4 flags × N ops) functional matrix.
# rsyncs the repo to the VM, builds, ssh-invokes tests/matrix-runner.sh,
# captures CSV output to tests/matrix-results-<TIMESTAMP>.csv, and asserts
# all 24 cells PASS.
#
# Usage: tests/matrix.sh
# Env:   VM_HOST (default 192.168.122.253), VM_USER (default root)
#
# Exit: 0 if 24/24 PASS, 1 otherwise.

set -eu

cd "$(dirname "$0")/.."
. tests/lib.sh

ts=$(date -u +%Y%m%dT%H%M%SZ)
out="tests/matrix-results-${ts}.csv"

echo "[matrix] sync + build on ${VM_USER}@${VM_HOST}" >&2
vm_sync_repo
vm_have_lsm
vm_build

echo "[matrix] running matrix-runner.sh on VM" >&2
vm_run "cd ${VM_WORKDIR} && REPO=${VM_WORKDIR} sh tests/matrix-runner.sh" > "$out"

echo "[matrix] CSV: $out" >&2
cat "$out"

total=$(awk -F, 'NR>1 {n++} END {print n+0}' "$out")
pass=$(awk -F, 'NR>1 && $6=="PASS" {n++} END {print n+0}' "$out")
fail=$(awk -F, 'NR>1 && $6=="FAIL" {n++} END {print n+0}' "$out")
err=$(awk -F, 'NR>1 && $6=="ERROR" {n++} END {print n+0}' "$out")

echo "" >&2
echo "[matrix] total=$total pass=$pass fail=$fail error=$err" >&2

# Matrix size is 4 flags × N ops where N grows when the suite adds an
# op row. Read the actual op list from matrix-runner.sh's OPS=... line
# so the gate tracks runner additions without stale literal drift
# (caught a 24 → 28 drift when mmap_after_ro_open was
# added alongside the existing mmap_shared_write row).
n_ops=$(awk -F'"' '/^OPS="/{n=split($2,a," "); print n; exit}' tests/matrix-runner.sh)
expected=$((n_ops * 4))
if [ "$total" -ne "$expected" ] || [ "$pass" -ne "$expected" ]; then
	echo "[matrix] FAIL — expected ${expected}/${expected} PASS (4 flags × ${n_ops} ops)" >&2
	exit 1
fi
echo "[matrix] PASS — ${expected}/${expected}" >&2
