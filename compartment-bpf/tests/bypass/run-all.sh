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
#
# ---------------------------------------------------------------------------
# HOW TO RUN THIS
# ---------------------------------------------------------------------------
# This script is a HOST-side driver. It rsyncs the tree to a VM and ssh-runs
# every witness there. It is NOT the way to run the bypass suite inside a
# guest — for that use tests/bypass/run-local.sh (which is what
# `make check-bypass` invokes) or pass --local here.
#
#   usage: tests/bypass/run-all.sh [--local] [--check] [--help]
#
#     --local   run every witness on THIS machine via run-local.sh
#     --check   preflight only: validate the driver's preconditions and exit
#     --help    this text
#
# Environment (defaults come from tests/lib.sh):
#   VM_HOST      target VM address           (default 192.168.122.253)
#   VM_USER      ssh user, needs CAP_BPF     (default root)
#   VM_WORKDIR   tree location ON THE VM     (default /root/compartment-bpf)
#   REPO         tree location on THIS host  (default: this checkout)
#   SSH_OPTS     ssh/rsync options
#
# Preconditions on the VM, none of which any image ships by default:
#   1. `ssh $VM_USER@$VM_HOST` works non-interactively (BatchMode, key auth);
#   2. $VM_WORKDIR is a real directory the driver may `rsync --delete` into
#      — never a symlink back into the source tree, and never the source
#      tree itself (rsync would delete the files it is copying);
#   3. the VM has clang/gcc + kernel headers so `make` works there.
#
# Running it INSIDE a guest means ssh-ing to yourself as root, which needs a
# root keypair in that guest's own /root/.ssh/authorized_keys and a separate
# $VM_WORKDIR. If that is not set up the driver used to fail one witness at a
# time as an unreadable cascade of ssh errors; it now refuses up front with
# the exact remediation.
set -eu

BYPASS_MODE=driver
for arg in "$@"; do
	case "$arg" in
	--local)  BYPASS_MODE=local ;;
	--check)  BYPASS_MODE=check ;;
	-h|--help)
		sed -n '/^# HOW TO RUN THIS/,/^set -eu$/p' "$0" | sed 's/^# \{0,1\}//; $d'
		exit 0 ;;
	*)
		echo "run-all.sh: unknown argument '$arg' (try --help)" >&2
		exit 2 ;;
	esac
done

# REPO is the source tree on THIS host. Everything below reads it, so honour
# an override instead of assuming the script lives in the tree under test.
REPO=${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}
cd "$REPO"
. tests/lib.sh

if [ "$BYPASS_MODE" = local ]; then
	exec env REPO="$REPO" bash "$REPO/tests/bypass/run-local.sh"
fi

# --- driver preconditions ---------------------------------------------------
#
# Fail loudly and specifically here rather than letting every witness fail
# with an ssh diagnostic that looks like a test failure.
bypass_driver_preflight() {
	_bd_fail=0

	# 1. Are we pointed at ourselves? That is legal but needs root
	#    ssh-to-self AND a $VM_WORKDIR that is not this tree.
	_bd_self=0
	_bd_ips=$( { hostname -I 2>/dev/null || true; \
	             ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true; } | tr '\n' ' ')
	case " $_bd_ips " in
	*" $VM_HOST "*) _bd_self=1 ;;
	esac
	case "$VM_HOST" in
	localhost|127.0.0.1|::1|"$(hostname 2>/dev/null)") _bd_self=1 ;;
	esac

	# 2. ssh must work non-interactively as $VM_USER.
	if ! ssh $SSH_OPTS "${VM_USER}@${VM_HOST}" true >/dev/null 2>&1; then
		echo "[bypass] FAIL: cannot ssh ${VM_USER}@${VM_HOST} non-interactively." >&2
		if [ "$_bd_self" = 1 ]; then
			echo "[bypass]   VM_HOST is THIS machine, so this is ssh-to-self. Either run" >&2
			echo "[bypass]     tests/bypass/run-all.sh --local        (or: make check-bypass)" >&2
			echo "[bypass]   or set up a root keypair in this guest:" >&2
			echo "[bypass]     sudo ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519" >&2
			echo "[bypass]     sudo sh -c 'cat /root/.ssh/id_ed25519.pub >> /root/.ssh/authorized_keys'" >&2
		else
			echo "[bypass]   Check VM_HOST/VM_USER and that your key is in that host's authorized_keys." >&2
			echo "[bypass]   Current: VM_HOST=$VM_HOST VM_USER=$VM_USER VM_WORKDIR=$VM_WORKDIR" >&2
		fi
		_bd_fail=1
	fi

	# 3. VM_WORKDIR must not be (or link to) the tree we are syncing FROM.
	#    vm_sync_repo runs `rsync -az --delete`, so syncing a directory onto
	#    itself deletes the sources mid-copy.
	if [ "$_bd_self" = 1 ]; then
		_bd_src=$(cd "$REPO" && pwd -P)
		_bd_dst=$(readlink -f "$VM_WORKDIR" 2>/dev/null || echo "$VM_WORKDIR")
		if [ "$_bd_src" = "$_bd_dst" ]; then
			echo "[bypass] FAIL: VM_WORKDIR ($VM_WORKDIR) resolves to the source tree ($_bd_src)." >&2
			echo "[bypass]   'rsync -az --delete' would sync a directory onto itself." >&2
			echo "[bypass]   Use a separate copy, e.g.:" >&2
			echo "[bypass]     sudo cp -a $_bd_src /root/compartment-bpf" >&2
			echo "[bypass]     sudo VM_HOST=$VM_HOST VM_USER=root VM_WORKDIR=/root/compartment-bpf \\" >&2
			echo "[bypass]          bash tests/bypass/run-all.sh" >&2
			echo "[bypass]   ...or just run the witnesses in place: tests/bypass/run-all.sh --local" >&2
			_bd_fail=1
		fi
	fi

	# 4. $VM_WORKDIR's parent must exist on the VM (mkdir -p happens in
	#    vm_sync_repo, but a symlinked workdir is the dangerous case).
	if [ "$_bd_fail" -eq 0 ]; then
		if ssh $SSH_OPTS "${VM_USER}@${VM_HOST}" "test -L '$VM_WORKDIR'" >/dev/null 2>&1; then
			echo "[bypass] FAIL: $VM_WORKDIR is a SYMLINK on ${VM_HOST}." >&2
			echo "[bypass]   rsync --delete through a symlink into the working tree destroys it." >&2
			echo "[bypass]   Replace it with a real directory (sudo cp -a <tree> $VM_WORKDIR)." >&2
			_bd_fail=1
		fi
	fi

	return "$_bd_fail"
}

if ! bypass_driver_preflight; then
	echo "[bypass] FAIL — driver preconditions not met (see above); nothing was run." >&2
	exit 1
fi
if [ "$BYPASS_MODE" = check ]; then
	echo "[bypass] preflight OK: ${VM_USER}@${VM_HOST}:${VM_WORKDIR} reachable, workdir distinct from $REPO"
	exit 0
fi

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
	# 180s for the self-protection witnesses: they pin and unpin a real
	# policy and wait for the drain, and a kill mid-cycle leaves a
	# self-protected pin tree behind. Same rule as run-local.sh.
	case "$name" in
		2[2-6]-*) wcap=180s ;;
		*)        wcap=60s ;;
	esac
	vm_run "cd ${VM_WORKDIR} && REPO=${VM_WORKDIR} timeout --kill-after=5s ${wcap} bash tests/bypass/$name 2>&1" \
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
