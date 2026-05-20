#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/run-all.sh — host-side driver. Syncs repo to VM, builds,
# ssh-runs every tests/bypass/[0-9][0-9]-*.sh in order, aggregates.
#
# Exit: 0 if every script PASS or SKIP, 1 if any FAIL.
#
# Codex gate 1 hardening (Leader-8, 2026-05-14): a per-script run that
# exits without emitting one of `PASS ` / `FAIL ` / `SKIP ` is treated
# as FAIL, not silent pass. Previously a crash-before-label produced no
# label line and the global tally counted only what was emitted — so a
# script that segfaulted before reaching bypass_pass / bypass_fail /
# bypass_skip disappeared into the silence. Now each script's output is
# inspected for at least one label and a synthesized FAIL is recorded
# if none was found.
set -eu
cd "$(dirname "$0")/../.."
. tests/lib.sh

ts=$(date -u +%Y%m%dT%H%M%SZ)
out="tests/bypass-results-${ts}.txt"

vm_sync_repo
vm_have_lsm
vm_build

# Materialise the script list once so the per-script counter below
# matches what actually ran (in particular, ls glob expansion happens
# once on the host).
scripts=$(ls tests/bypass/[0-9][0-9]-*.sh tests/bypass/exec-domain/BX-*.sh 2>/dev/null | sort || true)

# R2-M13 (Review-2 MEDIUM): empty-script-list guard. If both globs
# expand to nothing the per-script loop runs zero times, every
# tally is zero, and we declare '[bypass] OK' even though we ran
# nothing. Fail loudly if no scripts were found.
nscripts_pre=$(printf '%s\n' $scripts | grep -c . || true); nscripts_pre=${nscripts_pre:-0}
if [ "$nscripts_pre" -le 0 ]; then
	echo "[bypass] FAIL — no bypass scripts matched the glob (tests/bypass/[0-9][0-9]-*.sh nor tests/bypass/exec-domain/BX-*.sh found)" >&2
	exit 1
fi

# R2-M12 (Review-2 MEDIUM): per-script-name presence pre-flight on
# the VM. Without this, a missing file on the VM side becomes
# 'script exited without label' which is correctly classified as
# FAIL by the Codex-gate-1 guard below but the diagnostic is
# muddled. Test 'test -f' on the remote up-front for each script;
# loud-skip with a clear message if anything is missing.
for script in $scripts; do
	name=${script#tests/bypass/}
	if ! vm_run "cd ${VM_WORKDIR} && test -f tests/bypass/$name" >/dev/null 2>&1; then
		echo "[bypass] WARNING: tests/bypass/$name absent on VM (host has it; rsync drift?)" >&2
	fi
done

: > "$out"
# ED-8: aggregate the original tests/bypass/[0-9][0-9]-*.sh suite with the
# new actor-allowlist witnesses under tests/bypass/exec-domain/BX-*.sh.
# Both subdirs share lib-bypass.sh's PASS/FAIL/SKIP convention.
for script in $scripts; do
	name=${script#tests/bypass/}
	echo "=== $name ===" | tee -a "$out"
	# Capture this script's run separately so we can verify it emitted
	# a label before letting the global tally consume it.
	per_script=$(mktemp /tmp/bypass-runall.XXXXXX)
	# vm_run may exit non-zero (bypass_skip exits 77, bypass_fail exits 1).
	# We do not gate on rc; rc-without-label is exactly the false-green
	# case the hardening addresses below.
	# R2-M10 (Review-2 MEDIUM): wall-clock cap per script. A
	# wedged script (e.g. waiting on a never-arriving fd, racing
	# daemon liveness check, missing skip case) hung the whole
	# run-all run before this. 60s is generous for every shipped
	# witness; the longest is BX-9-version-mismatch ~3s. SIGTERM
	# at the cap then SIGKILL 5s later if still alive.
	vm_run "cd ${VM_WORKDIR} && REPO=${VM_WORKDIR} timeout --kill-after=5s 60s bash tests/bypass/$name 2>&1" \
		> "$per_script" 2>&1 || true
	# Per-script label check.
	if grep -qE '^(PASS|FAIL|SKIP) ' "$per_script"; then
		cat "$per_script" | tee -a "$out"
	else
		# Script exited without emitting a label. Most common causes:
		# a SIGSEGV in the test harness, a `set -e` trip before
		# bypass_pass/fail/skip, or an ssh-side error masquerading as
		# script output. Either way, treat as FAIL: the witness did
		# not assert its outcome.
		cat "$per_script" | tee -a "$out"
		printf 'FAIL %s: script exited without printing a PASS/FAIL/SKIP label (Codex gate 1 false-green guard)\n' \
			"$name" | tee -a "$out"
	fi
	rm -f "$per_script"
done

# Tally by parsing labels from the captured stream. grep -c writes "0"
# AND exits 1 when there are no matches; |( || echo 0) would cause two
# values to be captured. Use `|| true` and a default separately.
pass=$(grep -c '^PASS ' "$out" || true); pass=${pass:-0}
fail=$(grep -c '^FAIL ' "$out" || true); fail=${fail:-0}
skip=$(grep -c '^SKIP ' "$out" || true); skip=${skip:-0}

# Cross-check: every script must have produced exactly one label.
# A-2 (2026-05-15): tightened from `nlabels < nscripts` (at-least-one) to
# `nlabels != nscripts` (exactly-one). The old check only caught the
# missing-label case; a multi-subtest script emitting >1 label could
# mask a sub-attack flip from PASS to FAIL because the spurious PASS in
# the stream still tallied a label and a script-level FAIL could be
# dwarfed. Per-script consolidation (BX-7-inplace-modify.sh and any
# future multi-subtest witness) keeps the invariant 1-label-per-script.
nscripts=$(printf '%s\n' $scripts | grep -c . || true); nscripts=${nscripts:-0}
nlabels=$((pass + fail + skip))

echo
echo "[bypass] pass=$pass fail=$fail skip=$skip (scripts=$nscripts labels=$nlabels)"
if [ "$nlabels" -ne "$nscripts" ]; then
	# Defence-in-depth: even if the per-script synthesised FAIL above
	# was somehow missed, or a multi-subtest script slipped a second
	# label through, surface the mismatch here. If this fires, either
	# the test harness has a bug or a script needs consolidation.
	echo "[bypass] FAIL — label/script count mismatch (expected exactly one PASS/FAIL/SKIP per script)"
	exit 1
fi
if [ "$fail" -gt 0 ]; then
	echo "[bypass] FAIL — at least one bypass failed (or passed silently)"
	exit 1
fi
echo "[bypass] OK"
