#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/stability/corner-cases/CC-04-child-actor-unpin.sh
# Corner case 04: pin → forked child accessing a sealed file → --unpin
# while the child is in flight.
#
# Assertion: the child's file-op resolves consistently (succeeds or denies,
# no half-state); no D-state; no kernel error.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
export REPO
STAB_DIR="${STAB_DIR:-/tmp/stab-cc04-$$}"
mkdir -p "$STAB_DIR"
. "$SCRIPT_DIR/../lib-stability.sh"

DAEMON="$REPO/compartment-bpf"
PROF="$SCRIPT_DIR/../baseline-profile.conf"

if [ "$(id -u)" -ne 0 ]; then stab_skip "CC-04 requires root"; exit 0; fi
[ -x "$DAEMON" ] || { stab_skip "CC-04: compartment-bpf missing"; exit 0; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| { stab_skip "CC-04: bpf not in active LSM"; exit 0; }

mkdir -p /tmp/stab-datadir
[ -e /tmp/stab-file ] || : > /tmp/stab-file

stab_snapshot_baseline

"$DAEMON" --pin "$PROF" >"$STAB_DIR/cc04-pin.log" 2>&1 || {
	stab_fail "CC-04: initial --pin failed"
	exit 1
}

# Long-running child doing reads + stats on the sealed paths.
(
	for _ in $(seq 1 200); do
		cat /tmp/stab-file >/dev/null 2>&1 || true
		stat /tmp/stab-datadir >/dev/null 2>&1 || true
	done
) &
CHILD=$!

sleep 0.2
"$DAEMON" --unpin >>"$STAB_DIR/cc04-pin.log" 2>&1
UNPIN_RC=$?

wait "$CHILD" 2>/dev/null
CHILD_RC=$?

dstate=$(ps -eo stat,pid,comm | awk '$1 ~ /^D/ {print}' || true)
if [ -n "$dstate" ]; then
	stab_fail "CC-04 D-state after race:"
	echo "$dstate" | tee "$STAB_DIR/cc04-dstate.txt"
fi

stab_check_dmesg
stab_check_taint
stab_check_bpffs_clean

stab_log "CC-04 summary: unpin_rc=$UNPIN_RC child_rc=$CHILD_RC"
if [ "$STAB_FAIL" -eq 0 ]; then
	stab_pass "CC-04 child-actor-unpin: child resolved, kernel clean"
	exit 0
else
	exit 1
fi
