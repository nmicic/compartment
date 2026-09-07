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
# REPO is authoritative for BOTH the witness list and the binaries the
# witnesses resolve through lib-bypass.sh. It used to only affect the latter,
# so `REPO=/elsewhere run-local.sh` ran /elsewhere's daemon against THIS
# checkout's scripts.
REPO=${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}
cd "$REPO" || { echo "[bypass-local] FAIL — REPO=$REPO is not a directory" >&2; exit 1; }
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

# The glob only failed when it matched NOTHING, so deleting or renaming a
# witness silently shrank the corpus — and the release allowlist entry for
# the tally line is unanchored and unbounded, so it swallowed the smaller
# number too. Compare the found set against the tracked one.
expected="tests/bypass/expected-witnesses.txt"
if [ ! -f "$expected" ]; then
	echo "[bypass-local] FAIL — $expected is missing" >&2
	exit 1
fi
found_list=$(mktemp /tmp/bypass-found.XXXXXX)
want_list=$(mktemp /tmp/bypass-want.XXXXXX)
printf '%s\n' $scripts | sed 's|^tests/bypass/||' | sort > "$found_list"
grep -vE '^[[:space:]]*(#|$)' "$expected" | sort > "$want_list"
if ! diff -u "$want_list" "$found_list" > /tmp/bypass-witness-diff.$$ 2>&1; then
	echo "[bypass-local] FAIL — the witness set does not match $expected:" >&2
	sed 's/^/  /' /tmp/bypass-witness-diff.$$ >&2
	rm -f "$found_list" "$want_list" /tmp/bypass-witness-diff.$$
	exit 1
fi
rm -f "$found_list" "$want_list" /tmp/bypass-witness-diff.$$

pass=0; fail=0; skip=0; failed_list=""
for script in $scripts; do
	name=${script#tests/bypass/}
	echo "=== $name ==="
	per=$(mktemp /tmp/bypass-local.XXXXXX)
	# Same 60s/SIGKILL+5s cap as run-all.sh; the longest of the original
	# witnesses is BX-9 (~3s). REPO is exported so lib-bypass.sh finds the
	# daemon/sealprobe.
	#
	# The self-protection witnesses get 180s. They are a different shape from
	# every other witness here: each PINS a real policy, exercises it, unpins
	# it and waits for the kernel to drain the programs, and 25-loader-upgrade
	# does that cycle three times. A witness killed at 60s mid-cycle exits
	# without a label — counted FAIL by the loop below, correctly — but its
	# teardown never runs either, so it leaves a SELF-PROTECTED policy pinned
	# whose only authorised loader image is in the $TMP the kill prevented it
	# from cleaning up. That costs a reboot. The cap has to be larger than the
	# work, not the other way round.
	case "$name" in
		2[2-6]-*) cap=180s ;;
		*)        cap=60s ;;
	esac
	timeout --kill-after=5s "$cap" bash "$script" >"$per" 2>&1 || true
	cat "$per"
	# Exactly one label per script. run-all.sh has enforced this since
	# A-2 (2026-05-15) with an explicit comment: a multi-subtest script
	# emitting more than one label can mask a sub-attack flipping from
	# PASS to FAIL. This runner — the one `make check-bypass` uses —
	# mirrored the no-label half and not the exactly-one half, so a
	# witness printing both PASS and FAIL was counted as a PASS and the
	# FAIL was discarded.
	nlabels=$(grep -cE '^(PASS|FAIL|SKIP) ' "$per")
	if [ "$nlabels" -eq 0 ]; then
		# No label → FAIL (crash / set -e trip before bypass_pass/fail/skip).
		echo "FAIL $name: script exited without a PASS/FAIL/SKIP label (false-green guard)"
		fail=$((fail + 1)); failed_list="$failed_list $name(no-label)"
	elif [ "$nlabels" -gt 1 ]; then
		echo "FAIL $name: script emitted $nlabels PASS/FAIL/SKIP labels, expected exactly 1"
		fail=$((fail + 1)); failed_list="$failed_list $name(${nlabels}-labels)"
	elif grep -qE '^FAIL ' "$per"; then
		fail=$((fail + 1)); failed_list="$failed_list $name"
	elif grep -qE '^SKIP ' "$per"; then
		skip=$((skip + 1))
	else
		pass=$((pass + 1))
	fi
	rm -f "$per"
done

echo "[bypass-local] $pass PASS / $fail FAIL / $skip SKIP over $nscripts scripts"
echo "RESULT check-bypass: pass=$pass fail=$fail skip=$skip"
if [ "$fail" -ne 0 ]; then
	echo "[bypass-local] FAILED:$failed_list" >&2
	exit 1
fi
exit 0
