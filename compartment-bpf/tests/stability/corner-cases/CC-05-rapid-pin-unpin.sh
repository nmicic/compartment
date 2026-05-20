#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/stability/corner-cases/CC-05-rapid-pin-unpin.sh
# Corner case 05: 10 rapid pin/unpin cycles with no sleep, in parallel
# with a synthetic file-op loop (mesh-trial stand-in).
#
# Assertion: no kernel error in dmesg; bpffs empty after the final unpin;
# no D-state survivors.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
export REPO
STAB_DIR="${STAB_DIR:-/tmp/stab-cc05-$$}"
mkdir -p "$STAB_DIR"
. "$SCRIPT_DIR/../lib-stability.sh"

DAEMON="$REPO/compartment-bpf"
PROF="$SCRIPT_DIR/../baseline-profile.conf"

if [ "$(id -u)" -ne 0 ]; then stab_skip "CC-05 requires root"; exit 0; fi
[ -x "$DAEMON" ] || { stab_skip "CC-05: compartment-bpf missing"; exit 0; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| { stab_skip "CC-05: bpf not in active LSM"; exit 0; }

mkdir -p /tmp/stab-datadir
[ -e /tmp/stab-file ] || : > /tmp/stab-file

stab_snapshot_baseline

# Synthetic mesh-trial stand-in: a tight read loop pressuring the sealed paths.
(
	for _ in $(seq 1 500); do
		cat /tmp/stab-file >/dev/null 2>&1 || true
	done
) &
BG=$!

FAILED=0
for i in 1 2 3 4 5 6 7 8 9 10; do
	"$DAEMON" --pin "$PROF" >>"$STAB_DIR/cc05.log" 2>&1
	RP=$?
	"$DAEMON" --unpin >>"$STAB_DIR/cc05.log" 2>&1
	RU=$?
	# Either both succeed, or fail-closed with non-zero — what matters is
	# we don't hang and we don't taint the kernel. EBUSY (Sec-9/F14
	# pin/unpin serialisation) is rare but legal under burst contention,
	# so we record the rc but do not FAIL the cycle on it alone.
	echo "cycle $i pin_rc=$RP unpin_rc=$RU" >>"$STAB_DIR/cc05.log"
done

wait "$BG" 2>/dev/null

dstate=$(ps -eo stat,pid,comm | awk '$1 ~ /^D/ {print}' || true)
if [ -n "$dstate" ]; then
	stab_fail "CC-05 D-state after rapid churn:"
	echo "$dstate" | tee "$STAB_DIR/cc05-dstate.txt"
fi

stab_check_dmesg
stab_check_taint
stab_check_bpffs_clean

if [ "$STAB_FAIL" -eq 0 ]; then
	stab_pass "CC-05 rapid-pin-unpin: 10 cycles complete, kernel clean, bpffs clean"
	exit 0
else
	exit 1
fi
