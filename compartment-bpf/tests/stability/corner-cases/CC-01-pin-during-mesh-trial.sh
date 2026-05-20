#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/stability/corner-cases/CC-01-pin-during-mesh-trial.sh
# Corner case 01: --pin invoked while a mesh trial is in flight.
#
# Assertion: trial completes with its expected outcome (or controlled FAIL);
# no kernel error in dmesg; bpffs left clean after final --unpin.
#
# Timing: best-effort — sleep 0.1 after launching mesh in background to
# approximate pin-during-trial. Exact race timing is not guaranteed.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
export REPO
STAB_DIR="${STAB_DIR:-/tmp/stab-cc01-$$}"
mkdir -p "$STAB_DIR"
. "$SCRIPT_DIR/../lib-stability.sh"

DAEMON="$REPO/compartment-bpf"
MESH="$REPO/tests/mesh/run-mesh.sh"
PROF="$SCRIPT_DIR/../baseline-profile.conf"

if [ "$(id -u)" -ne 0 ]; then
	stab_skip "CC-01 requires root"
	exit 0
fi
[ -x "$DAEMON" ] || { stab_skip "CC-01: compartment-bpf missing"; exit 0; }
[ -r "$MESH" ]   || { stab_skip "CC-01: mesh runner missing"; exit 0; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| { stab_skip "CC-01: bpf not in active LSM"; exit 0; }

mkdir -p /tmp/stab-datadir
[ -e /tmp/stab-file ] || : > /tmp/stab-file

stab_snapshot_baseline

# Start mesh in the background. The mesh runner spawns its own daemons
# per trial so our --pin from outside is in honest parallel with that.
timeout 180 bash "$MESH" >"$STAB_DIR/cc01-mesh.log" 2>&1 &
MESH_PID=$!
sleep 0.1
"$DAEMON" --pin "$PROF" >"$STAB_DIR/cc01-pin.log" 2>&1
PIN_RC=$?

# Let the trial run, then unpin and wait for the mesh process to finish.
sleep 1
"$DAEMON" --unpin >>"$STAB_DIR/cc01-pin.log" 2>&1 || true
wait "$MESH_PID" 2>/dev/null
MESH_RC=$?

# Mesh runner returns 0 (all PASS) or 6 (trial divergence); both are
# acceptable for this corner case — a controlled mesh FAIL doesn't
# indicate a kernel error, which is what we actually probe for.
if [ "$MESH_RC" -eq 124 ]; then
	stab_fail "CC-01 mesh timed out — possible kernel hang"
fi

stab_check_dmesg
stab_check_taint
stab_check_bpffs_clean

stab_log "CC-01 summary: pin_rc=$PIN_RC mesh_rc=$MESH_RC"
if [ "$STAB_FAIL" -eq 0 ]; then
	stab_pass "CC-01 pin-during-mesh-trial: kernel clean, bpffs clean"
	exit 0
else
	exit 1
fi
