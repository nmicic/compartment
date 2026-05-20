#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/stability/corner-cases/CC-07-unpin-during-ringbuf.sh
# Corner case 07: --unpin during active ringbuf event emission.
#
# Best-effort witness: generates audit events by repeatedly hitting a
# sealed path from a non-actor process, then calls --unpin mid-burst.
#
# Assertion: no ringbuf corruption in dmesg; no kernel error; no taint.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
export REPO
STAB_DIR="${STAB_DIR:-/tmp/stab-cc07-$$}"
mkdir -p "$STAB_DIR"
. "$SCRIPT_DIR/../lib-stability.sh"

DAEMON="$REPO/compartment-bpf"
PROF="$SCRIPT_DIR/../baseline-profile.conf"

if [ "$(id -u)" -ne 0 ]; then stab_skip "CC-07 requires root"; exit 0; fi
[ -x "$DAEMON" ] || { stab_skip "CC-07: compartment-bpf missing"; exit 0; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| { stab_skip "CC-07: bpf not in active LSM"; exit 0; }

mkdir -p /tmp/stab-datadir
[ -e /tmp/stab-file ] || : > /tmp/stab-file

stab_snapshot_baseline

"$DAEMON" --pin "$PROF" >"$STAB_DIR/cc07-pin.log" 2>&1 || {
	stab_fail "CC-07: initial --pin failed"
	exit 1
}

# Event-burst loop: open + truncate-write attempts trip the LSM hook and
# enqueue audit records. We don't care whether the writes succeed or are
# denied — we just want to keep the ringbuf busy.
(
	for _ in $(seq 1 1000); do
		( echo x >> /tmp/stab-file ) 2>/dev/null || true
		( : > /tmp/stab-file ) 2>/dev/null || true
	done
) &
BURST=$!

# Unpin mid-burst.
sleep 0.05
"$DAEMON" --unpin >>"$STAB_DIR/cc07-pin.log" 2>&1
UNPIN_RC=$?

wait "$BURST" 2>/dev/null

stab_check_dmesg
stab_check_taint
stab_check_bpffs_clean

stab_log "CC-07 summary: unpin_rc=$UNPIN_RC"
if [ "$STAB_FAIL" -eq 0 ]; then
	stab_pass "CC-07 unpin-during-ringbuf: no ringbuf corruption, kernel clean"
	exit 0
else
	exit 1
fi
