#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/stability/corner-cases/CC-02-unpin-during-enforcement.sh
# Corner case 02: --unpin called while non-actor processes are accessing
# a sealed path (active enforcement).
#
# Assertion: file-op processes complete without D-state; no kernel error
# in dmesg; no taint change; bpffs clean after the unpin.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
export REPO
STAB_DIR="${STAB_DIR:-/tmp/stab-cc02-$$}"
mkdir -p "$STAB_DIR"
. "$SCRIPT_DIR/../lib-stability.sh"

DAEMON="$REPO/compartment-bpf"
PROF="$SCRIPT_DIR/../baseline-profile.conf"

if [ "$(id -u)" -ne 0 ]; then stab_skip "CC-02 requires root"; exit 0; fi
[ -x "$DAEMON" ] || { stab_skip "CC-02: compartment-bpf missing"; exit 0; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| { stab_skip "CC-02: bpf not in active LSM"; exit 0; }

mkdir -p /tmp/stab-datadir
[ -e /tmp/stab-file ] || : > /tmp/stab-file

stab_snapshot_baseline

"$DAEMON" --pin "$PROF" >"$STAB_DIR/cc02-pin.log" 2>&1 || {
	stab_fail "CC-02: initial --pin failed"
	exit 1
}

# Read-loop pressuring the sealed path. We do not need to actually
# trip the enforcement to expose lifecycle races — read traffic alone
# is enough to give --unpin something to race against.
( while true; do
	cat /tmp/stab-file >/dev/null 2>&1 || true
done ) &
RL1=$!
( while true; do
	stat /tmp/stab-datadir >/dev/null 2>&1 || true
done ) &
RL2=$!

# Brief warm-up, then unpin.
sleep 0.3
"$DAEMON" --unpin >>"$STAB_DIR/cc02-pin.log" 2>&1
UNPIN_RC=$?

# Stop the readers.
kill "$RL1" "$RL2" 2>/dev/null || true
wait "$RL1" 2>/dev/null
wait "$RL2" 2>/dev/null

# D-state survey: anything still uninterruptible?
dstate=$(ps -eo stat,pid,comm | awk '$1 ~ /^D/ {print}' || true)
if [ -n "$dstate" ]; then
	stab_fail "CC-02 D-state processes after unpin:"
	echo "$dstate" | tee "$STAB_DIR/cc02-dstate.txt"
fi

stab_check_dmesg
stab_check_taint
stab_check_bpffs_clean

stab_log "CC-02 summary: unpin_rc=$UNPIN_RC"
if [ "$STAB_FAIL" -eq 0 ]; then
	stab_pass "CC-02 unpin-during-enforcement: file-ops clean, kernel clean"
	exit 0
else
	exit 1
fi
