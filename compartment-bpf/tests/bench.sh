#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# tests/bench.sh — host driver for the benchmark suite.
set -eu
cd "$(dirname "$0")/.."
. tests/lib.sh

ts=$(date -u +%Y%m%dT%H%M%SZ)
out="tests/bench-results-${ts}.csv"

vm_sync_repo
vm_have_lsm
vm_build

vm_run "cd ${VM_WORKDIR} && REPO=${VM_WORKDIR} sh tests/bench-runner.sh" > "$out"

echo "[bench] CSV: $out" >&2
cat "$out"

# R2-M14 (Review-2 MEDIUM): row-count guard. A bench-runner.sh that
# silently produced zero data rows (e.g. the daemon crashed before
# any row emit; ssh died after the header) would currently land an
# 'OK' verdict because there is nothing matching ',FAIL$'. Assert
# we got at least N rows. bench-runner.sh emits one header line +
# at least:
#   modeB: 3 bench-load rows + bench-open-empty + bench-open-full-miss
#          + bench-open-full-miss-write + bench-deny + R2-F3's
#          3 bench-load-actor rows + bench-deny-actor-match
#          + bench-deny-actor-mismatch = 12 rows
#   modeA: 3 bench-load-modeA + 4 mode-A rows = 7 rows
# Pick a conservative lower bound (5) that catches the wedge-case
# without coupling to row-list churn.
data_rows=$(grep -cvE '^test,kernel,n,workers,duration_s,ops,ops_sec,denies,loader_ms,result$|^$' "$out" || true)
data_rows=${data_rows:-0}
if [ "$data_rows" -lt 5 ]; then
	echo "[bench] FAIL — bench-runner emitted only $data_rows data rows (expected ≥5); see $out" >&2
	exit 1
fi

if grep -qE ',FAIL$' "$out"; then
	echo "[bench] FAIL — see $out" >&2
	exit 1
fi
echo "[bench] OK ($data_rows data rows)"
