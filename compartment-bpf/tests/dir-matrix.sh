#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# tests/dir-matrix.sh — host-side driver for the 40-cell directory functional
# matrix (PHASE-0.md §3.V-3). Mirrors tests/matrix.sh shape against
# directory-applicable hooks (inode_create, inode_mkdir, inode_mknod,
# inode_symlink, inode_link, inode_rename, inode_rmdir + the declared
# superset inode_unlink-on-child and inode_setattr-on-dir per V-3 D-V3.A).
# 10 ops × 4 primitive flags = 40 cells.
#
# Usage: tests/dir-matrix.sh
# Env:   VM_HOST (default 192.168.122.253), VM_USER (default root)
#
# Exit: 0 if 40/40 PASS, 1 otherwise.

set -eu

cd "$(dirname "$0")/.."
. tests/lib.sh

ts=$(date -u +%Y%m%dT%H%M%SZ)
out="tests/dir-matrix-results-${ts}.csv"

echo "[dir-matrix] sync + build on ${VM_USER}@${VM_HOST}" >&2
vm_sync_repo
vm_have_lsm
vm_build

echo "[dir-matrix] running dir-matrix-runner.sh on VM" >&2
vm_run "cd ${VM_WORKDIR} && REPO=${VM_WORKDIR} sh tests/dir-matrix-runner.sh" > "$out"

echo "[dir-matrix] CSV: $out" >&2
cat "$out"

total=$(awk -F, 'NR>1 {n++} END {print n+0}' "$out")
pass=$(awk -F, 'NR>1 && $6=="PASS" {n++} END {print n+0}' "$out")
fail=$(awk -F, 'NR>1 && $6=="FAIL" {n++} END {print n+0}' "$out")
err=$(awk -F, 'NR>1 && $6=="ERROR" {n++} END {print n+0}' "$out")

echo "" >&2
echo "[dir-matrix] total=$total pass=$pass fail=$fail error=$err" >&2

if [ "$total" -ne 40 ] || [ "$pass" -ne 40 ]; then
	echo "[dir-matrix] FAIL — expected 40/40 PASS" >&2
	exit 1
fi
echo "[dir-matrix] PASS — 40/40" >&2
