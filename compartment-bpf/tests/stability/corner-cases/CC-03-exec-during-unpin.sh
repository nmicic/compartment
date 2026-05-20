#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/stability/corner-cases/CC-03-exec-during-unpin.sh
# Corner case 03: race marker-set at exec vs --unpin clearing task storage.
#
# Best-effort witness: we cannot deterministically schedule the exec onto
# the exact same instant as --unpin without kernel probes, so this just
# verifies that the macro race is non-fatal — child either succeeds with
# marker set OR fails cleanly with deny, never wedges or oops's the box.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
export REPO
STAB_DIR="${STAB_DIR:-/tmp/stab-cc03-$$}"
mkdir -p "$STAB_DIR"
. "$SCRIPT_DIR/../lib-stability.sh"

DAEMON="$REPO/compartment-bpf"
PROF="$SCRIPT_DIR/../baseline-profile.conf"

if [ "$(id -u)" -ne 0 ]; then stab_skip "CC-03 requires root"; exit 0; fi
[ -x "$DAEMON" ] || { stab_skip "CC-03: compartment-bpf missing"; exit 0; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| { stab_skip "CC-03: bpf not in active LSM"; exit 0; }

mkdir -p /tmp/stab-datadir
[ -e /tmp/stab-file ] || : > /tmp/stab-file

stab_snapshot_baseline

"$DAEMON" --pin "$PROF" >"$STAB_DIR/cc03-pin.log" 2>&1 || {
	stab_fail "CC-03: initial --pin failed"
	exit 1
}

# Fork an exec of the sealed actor binary (/usr/bin/true) in the
# background, then race --unpin against it.
/usr/bin/true &
CHILD=$!
"$DAEMON" --unpin >>"$STAB_DIR/cc03-pin.log" 2>&1
UNPIN_RC=$?
wait "$CHILD" 2>/dev/null
CHILD_RC=$?

# Acceptable: rc=0 (success) or rc=126/127/non-zero deny. Unacceptable:
# the child entering D-state (already checked below) or panicking the box.

dstate=$(ps -eo stat,pid,comm | awk '$1 ~ /^D/ {print}' || true)
if [ -n "$dstate" ]; then
	stab_fail "CC-03 D-state after race:"
	echo "$dstate" | tee "$STAB_DIR/cc03-dstate.txt"
fi

stab_check_dmesg
stab_check_taint
stab_check_bpffs_clean

stab_log "CC-03 summary: unpin_rc=$UNPIN_RC child_rc=$CHILD_RC"
if [ "$STAB_FAIL" -eq 0 ]; then
	stab_pass "CC-03 exec-during-unpin: race non-fatal (best-effort witness)"
	exit 0
else
	exit 1
fi
