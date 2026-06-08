#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/run-local.sh — VM-side (in-place) bypass aggregator.
#
# The companion tests/bypass/run-all.sh is a HOST-side driver that rsyncs the
# repo to a VM and ssh-runs each witness — it cannot run inside `make check`
# (there is no nested VM). This runner iterates the same witnesses LOCALLY,
# on the machine it runs on, with the identical label discipline, so the
# bypass suite can be wired into `make check` / `make check-release`.
#
# Each tests/bypass/[0-9][0-9]-*.sh and tests/bypass/exec-domain/BX-*.sh is a
# self-contained witness that emits exactly one PASS/FAIL/SKIP line (see
# lib-bypass.sh). A script that exits WITHOUT a label is treated as FAIL
# (Codex gate 1 false-green guard, mirrored from run-all.sh).
#
# Exit: 0 if every script PASS or SKIP, 1 if any FAIL. The whole suite SKIPs
# (rc=77) if the environment cannot run any witness (no root / no BPF LSM),
# so the default developer-host `make check` stays green; it becomes a real
# gate inside the smoke VM.
set -u
cd "$(dirname "$0")/../.."
REPO=${REPO:-$(pwd)}
export REPO

# Whole-suite environment gate → clean SKIP (rc=77) on a dev host. The
# individual witnesses also self-skip, but gating up front keeps the output
# readable and the convention identical to check-mesh / check-strict-launch.
if [ "$(id -u)" -ne 0 ]; then
	echo "[bypass-local] SKIP (requires root + BPF LSM)" >&2
	exit 77
fi
if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
	echo "[bypass-local] SKIP (bpf not in active LSM)" >&2
	exit 77
fi
if [ ! -x "$REPO/compartment-bpf" ]; then
	echo "[bypass-local] SKIP (daemon not built at $REPO/compartment-bpf)" >&2
	exit 77
fi

scripts=$(ls tests/bypass/[0-9][0-9]-*.sh tests/bypass/exec-domain/BX-*.sh 2>/dev/null | sort || true)
nscripts=$(printf '%s\n' $scripts | grep -c . || true); nscripts=${nscripts:-0}
if [ "$nscripts" -le 0 ]; then
	echo "[bypass-local] FAIL — no bypass scripts matched the glob" >&2
	exit 1
fi

pass=0; fail=0; skip=0; failed_list=""
for script in $scripts; do
	name=${script#tests/bypass/}
	echo "=== $name ==="
	per=$(mktemp /tmp/bypass-local.XXXXXX)
	# Same 60s/SIGKILL+5s cap as run-all.sh; the longest shipped witness is
	# BX-9 (~3s). REPO is exported so lib-bypass.sh finds the daemon/sealprobe.
	timeout --kill-after=5s 60s bash "$script" >"$per" 2>&1 || true
	cat "$per"
	if grep -qE '^PASS ' "$per"; then
		pass=$((pass + 1))
	elif grep -qE '^SKIP ' "$per"; then
		skip=$((skip + 1))
	elif grep -qE '^FAIL ' "$per"; then
		fail=$((fail + 1)); failed_list="$failed_list $name"
	else
		# No label → FAIL (crash / set -e trip before bypass_pass/fail/skip).
		echo "FAIL $name: script exited without a PASS/FAIL/SKIP label (false-green guard)"
		fail=$((fail + 1)); failed_list="$failed_list $name(no-label)"
	fi
	rm -f "$per"
done

echo "[bypass-local] $pass PASS / $fail FAIL / $skip SKIP over $nscripts scripts"
if [ "$fail" -ne 0 ]; then
	echo "[bypass-local] FAILED:$failed_list" >&2
	exit 1
fi
exit 0
