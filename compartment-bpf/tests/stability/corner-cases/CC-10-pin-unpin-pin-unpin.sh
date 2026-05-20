#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/stability/corner-cases/CC-10-pin-unpin-pin-unpin.sh
# Corner case 10: profile reload via pin/unpin/pin/unpin.
#
# Assertion: bpffs empty after the final unpin; BPF prog/map counts return
# to baseline (within ±4 to allow for unrelated kernel-internal programs);
# no kernel error in dmesg.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
export REPO
STAB_DIR="${STAB_DIR:-/tmp/stab-cc10-$$}"
mkdir -p "$STAB_DIR"
. "$SCRIPT_DIR/../lib-stability.sh"

DAEMON="$REPO/compartment-bpf"
PROF="$SCRIPT_DIR/../baseline-profile.conf"

if [ "$(id -u)" -ne 0 ]; then stab_skip "CC-10 requires root"; exit 0; fi
[ -x "$DAEMON" ] || { stab_skip "CC-10: compartment-bpf missing"; exit 0; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| { stab_skip "CC-10: bpf not in active LSM"; exit 0; }

mkdir -p /tmp/stab-datadir
[ -e /tmp/stab-file ] || : > /tmp/stab-file

# Start clean.
"$DAEMON" --unpin >/dev/null 2>&1 || true

stab_snapshot_baseline

"$DAEMON" --pin "$PROF"   >"$STAB_DIR/cc10.log" 2>&1
P1=$?
"$DAEMON" --unpin        >>"$STAB_DIR/cc10.log" 2>&1
U1=$?
"$DAEMON" --pin "$PROF"  >>"$STAB_DIR/cc10.log" 2>&1
P2=$?
"$DAEMON" --unpin        >>"$STAB_DIR/cc10.log" 2>&1
U2=$?

stab_log "CC-10 rc series: p1=$P1 u1=$U1 p2=$P2 u2=$U2"

# Each pin must succeed (otherwise we're not exercising the reload path).
if [ "$P1" -ne 0 ] || [ "$P2" -ne 0 ]; then
	stab_fail "CC-10: --pin failed (p1=$P1 p2=$P2)"
fi

stab_check_dmesg
stab_check_taint
stab_check_bpffs_clean
stab_check_bpf_count_consistency

if [ "$STAB_FAIL" -eq 0 ]; then
	stab_pass "CC-10 pin-unpin-pin-unpin: clean reload, no stale state"
	exit 0
else
	exit 1
fi
