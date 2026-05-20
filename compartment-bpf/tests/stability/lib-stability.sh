# SPDX-License-Identifier: Apache-2.0
# tests/stability/lib-stability.sh — shared helpers for the kernel stability
# stress suite. Sourced by pin-unpin-churn.sh and every corner-cases/CC-*.sh
# script. POSIX-ish; runs on the host (for static checks) and on the Resolute
# smoke VM (for live runs).
#
# Why this exists: synthetic-reviewer cohorts (V-6) cannot exercise sustained
# kernel-state lifecycle stress against a real BPF substrate. This harness is
# the operator-domain (kernel-work) gate that complements the V-6 drill; both
# gates clear independently before a release-rc-* tag.
#
# Conventions:
#   - STAB_DIR is the per-run capture directory; caller sets it before sourcing
#     (the harness itself creates a UTC-stamped subdir under tests/stability/results).
#   - All checks emit "PASS ..."/"FAIL ..."/"SKIP ..." lines to stdout and bump
#     STAB_PASS/STAB_FAIL/STAB_SKIP. They never `exit` on their own — the
#     caller decides overall verdict in stab_summary.
#   - On any unexpected condition that prevents a check from running (e.g.
#     dmesg unreadable, /sys/fs/bpf missing), the helper logs a stab_skip line
#     so an empty FAIL count is not interpreted as health.

: "${REPO:=$(pwd)}"
: "${STAB_DIR:=/tmp/stab-$$}"
: "${STAB_PROFILE:=$REPO/tests/stability/baseline-profile.conf}"
: "${STAB_CYCLES:=64}"

STAB_PASS=${STAB_PASS:-0}
STAB_FAIL=${STAB_FAIL:-0}
STAB_SKIP=${STAB_SKIP:-0}

mkdir -p "$STAB_DIR" 2>/dev/null || true

stab_log() {
	echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
}

stab_pass() { stab_log "PASS: $*"; STAB_PASS=$((STAB_PASS+1)); }
stab_fail() { stab_log "FAIL: $*"; STAB_FAIL=$((STAB_FAIL+1)); }
stab_skip() { stab_log "SKIP: $*"; STAB_SKIP=$((STAB_SKIP+1)); }

# Capture a baseline snapshot for delta comparisons after the run.
# Records: dmesg tail line count, taint value, BPF prog/map counts, RSS of
# compartment-bpf daemon (if running), MemAvailable, bpf_* slab totals.
stab_snapshot_baseline() {
	out="$STAB_DIR/baseline.snap"
	{
		echo "# stability baseline snapshot"
		echo "ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "uname=$(uname -r)"
		# dmesg may need CAP_SYSLOG; tolerate failure.
		if dmesg --read-clear >/dev/null 2>&1; then
			# We cleared the ring; record 0 as the baseline-line count
			# and use dmesg from this point forward.
			echo "dmesg_baseline_lines=0"
			echo "dmesg_cleared=1"
		elif dmesg >/dev/null 2>&1; then
			n=$(dmesg | wc -l)
			echo "dmesg_baseline_lines=$n"
			echo "dmesg_cleared=0"
			# Also save the literal tail so stab_check_dmesg can diff.
			dmesg > "$STAB_DIR/dmesg-baseline.txt" 2>/dev/null || true
		else
			echo "dmesg_baseline_lines=NA"
			echo "dmesg_cleared=NA"
		fi
		if [ -r /proc/sys/kernel/tainted ]; then
			echo "taint=$(cat /proc/sys/kernel/tainted)"
		else
			echo "taint=NA"
		fi
		# BPF prog/map counts — bpftool may be missing on the host
		if command -v bpftool >/dev/null 2>&1; then
			echo "bpf_progs=$(bpftool prog show 2>/dev/null | grep -c '^[0-9]*:')"
			echo "bpf_maps=$(bpftool map show 2>/dev/null | grep -c '^[0-9]*:')"
		else
			echo "bpf_progs=NA"
			echo "bpf_maps=NA"
		fi
		if [ -r /proc/meminfo ]; then
			echo "mem_available_kb=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
		fi
		# RSS of any running compartment-bpf daemon. Multiple PIDs ok;
		# we sum them so the post-run delta is meaningful.
		pids=$(pgrep -x compartment-bpf 2>/dev/null || true)
		if [ -n "$pids" ]; then
			rss=0
			for p in $pids; do
				r=$(awk '/^VmRSS:/ {print $2}' /proc/$p/status 2>/dev/null || echo 0)
				rss=$((rss + r))
			done
			echo "compartment_bpf_rss_kb=$rss"
		else
			echo "compartment_bpf_rss_kb=0"
		fi
		# bpf_* slab totals (best-effort; needs CAP_SYS_ADMIN).
		if [ -r /proc/slabinfo ]; then
			awk '/^bpf_/ {n+=$2} END {print "bpf_slab_objs="n}' /proc/slabinfo
		fi
	} > "$out"
	stab_log "baseline snapshot written: $out"
}

# Re-read taint and compare to baseline. T-STAB-1 component.
stab_check_taint() {
	base="$STAB_DIR/baseline.snap"
	if [ ! -r "$base" ]; then
		stab_skip "T-STAB-1 taint: baseline snapshot missing"
		return 0
	fi
	bt=$(awk -F= '/^taint=/ {print $2}' "$base")
	if [ "$bt" = "NA" ] || [ -z "$bt" ]; then
		stab_skip "T-STAB-1 taint: /proc/sys/kernel/tainted unreadable"
		return 0
	fi
	if [ ! -r /proc/sys/kernel/tainted ]; then
		stab_skip "T-STAB-1 taint: /proc/sys/kernel/tainted unreadable post-run"
		return 0
	fi
	nt=$(cat /proc/sys/kernel/tainted)
	if [ "$bt" = "$nt" ]; then
		stab_pass "T-STAB-1 taint unchanged ($bt)"
	else
		stab_fail "T-STAB-1 taint changed: baseline=$bt now=$nt"
	fi
}

# Scan dmesg for new kernel-level signals. T-STAB-1 component.
stab_check_dmesg() {
	out="$STAB_DIR/dmesg-new.txt"
	: > "$out"
	if ! command -v dmesg >/dev/null 2>&1 || ! dmesg >/dev/null 2>&1; then
		stab_skip "T-STAB-1 dmesg: not readable"
		return 0
	fi
	base="$STAB_DIR/baseline.snap"
	cleared=0
	[ -r "$base" ] && cleared=$(awk -F= '/^dmesg_cleared=/ {print $2}' "$base")
	if [ "$cleared" = "1" ]; then
		# We --read-clear'd at baseline, so the current dmesg is the delta.
		dmesg > "$out" 2>/dev/null || true
	elif [ -r "$STAB_DIR/dmesg-baseline.txt" ]; then
		# Diff vs the recorded baseline.
		dmesg > "$STAB_DIR/dmesg-end.txt" 2>/dev/null || true
		comm -13 \
			<(sort "$STAB_DIR/dmesg-baseline.txt") \
			<(sort "$STAB_DIR/dmesg-end.txt") > "$out" 2>/dev/null || true
	else
		dmesg > "$out" 2>/dev/null || true
	fi
	# Pattern set: kernel oops, BUG, WARNING, soft lockup, hung_task,
	# RCU stall. Match anchored on log levels / well-known token prefixes
	# so an unrelated user-space "warning" in a daemon log doesn't trip us.
	pattern='BUG:|kernel BUG|Oops:|Call Trace:|WARNING:|soft lockup|hung_task|rcu_sched self-detected stall|RCU.*stall|general protection fault|unable to handle|stack guard page'
	if grep -E "$pattern" "$out" >/dev/null 2>&1; then
		n=$(grep -Ec "$pattern" "$out")
		stab_fail "T-STAB-1 dmesg: $n new kernel error line(s); see $out"
		grep -E "$pattern" "$out" | head -20
	else
		stab_pass "T-STAB-1 dmesg: no new BUG/Oops/WARNING/hung_task/RCU stall"
	fi
}

# T-STAB-3: bpffs cleanup after final unpin.
stab_check_bpffs_clean() {
	pin_root=/sys/fs/bpf/compartment
	if [ ! -d "$pin_root" ]; then
		stab_pass "T-STAB-3 bpffs: $pin_root absent (clean)"
		return 0
	fi
	# Allow PIN_ROOT itself to exist but be empty of compartment-bpf state.
	# Per compartment-bpf.c (Sec-9/F14 + unpin lifecycle), --unpin removes
	# pin *files* but intentionally preserves PIN_ROOT and its
	# substructure (links/, maps/) so a subsequent --pin reuses the
	# directory tree. Count actual pinned bpf objects (files), not the
	# empty subdirs.
	residue=$(find "$pin_root" -mindepth 1 ! -type d 2>/dev/null | wc -l)
	if [ "$residue" -eq 0 ]; then
		stab_pass "T-STAB-3 bpffs: $pin_root has 0 pinned objects (PIN_ROOT substructure preserved by design)"
	else
		stab_fail "T-STAB-3 bpffs: $residue pinned object(s) remain under $pin_root"
		find "$pin_root" -mindepth 1 ! -type d >> "$STAB_DIR/bpffs-residue.txt" 2>&1 || true
	fi
}

# Snapshot the RSS of a single PID (kB) to a file. Returns the value to stdout.
stab_snapshot_rss() {
	pid=$1; out=$2
	if [ -r "/proc/$pid/status" ]; then
		r=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")
		echo "$r" > "$out"
		echo "$r"
	else
		echo "0" > "$out"
		echo "0"
	fi
}

# Capture user-space stack (best-effort; needs /proc/$1/wchan + stack).
stab_capture_stack() {
	pid=$1
	out="$STAB_DIR/stack-$pid.txt"
	{
		echo "# stack capture for pid=$pid at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "## /proc/$pid/status"
		cat "/proc/$pid/status" 2>/dev/null || echo "(unreadable)"
		echo "## /proc/$pid/wchan"
		cat "/proc/$pid/wchan" 2>/dev/null || echo "(unreadable)"
		echo "## /proc/$pid/stack"
		cat "/proc/$pid/stack" 2>/dev/null || echo "(unreadable)"
	} > "$out"
	stab_log "stack captured: $out"
}

# T-STAB-2 memory growth comparison.
# Recomputes a snapshot of the same fields as baseline and writes a diff.
stab_check_memory_growth() {
	base="$STAB_DIR/baseline.snap"
	end="$STAB_DIR/end.snap"
	if [ ! -r "$base" ]; then
		stab_skip "T-STAB-2: baseline snapshot missing"
		return 0
	fi
	{
		echo "ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		if [ -r /proc/meminfo ]; then
			echo "mem_available_kb=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
		fi
		pids=$(pgrep -x compartment-bpf 2>/dev/null || true)
		rss=0
		if [ -n "$pids" ]; then
			for p in $pids; do
				r=$(awk '/^VmRSS:/ {print $2}' /proc/$p/status 2>/dev/null || echo 0)
				rss=$((rss + r))
			done
		fi
		echo "compartment_bpf_rss_kb=$rss"
		if [ -r /proc/slabinfo ]; then
			awk '/^bpf_/ {n+=$2} END {print "bpf_slab_objs="n}' /proc/slabinfo
		fi
	} > "$end"
	# Compare. A "passing" RSS growth budget is 50 MB (51200 kB).
	rss_base=$(awk -F= '/^compartment_bpf_rss_kb=/ {print $2}' "$base")
	rss_end=$(awk -F= '/^compartment_bpf_rss_kb=/ {print $2}' "$end")
	rss_base=${rss_base:-0}; rss_end=${rss_end:-0}
	growth=$((rss_end - rss_base))
	if [ "$growth" -lt 51200 ]; then
		stab_pass "T-STAB-2 RSS: baseline=${rss_base}kB end=${rss_end}kB growth=${growth}kB (<50MB)"
	else
		stab_fail "T-STAB-2 RSS: baseline=${rss_base}kB end=${rss_end}kB growth=${growth}kB (>=50MB)"
	fi
	# Slab plateau check: emit informational line. We don't FAIL on slab
	# growth alone (slabs are kernel-wide and noisy); record the values.
	slab_base=$(awk -F= '/^bpf_slab_objs=/ {print $2}' "$base")
	slab_end=$(awk -F= '/^bpf_slab_objs=/ {print $2}' "$end")
	stab_log "T-STAB-2 slab bpf_*: baseline=${slab_base:-NA} end=${slab_end:-NA}"
}

# T-STAB-4 ancillary: BPF prog/map counts return to baseline (post-unpin).
stab_check_bpf_count_consistency() {
	base="$STAB_DIR/baseline.snap"
	if [ ! -r "$base" ] || ! command -v bpftool >/dev/null 2>&1; then
		stab_skip "T-STAB-4 BPF count: baseline or bpftool missing"
		return 0
	fi
	pb=$(awk -F= '/^bpf_progs=/ {print $2}' "$base")
	mb=$(awk -F= '/^bpf_maps=/ {print $2}' "$base")
	[ "$pb" = "NA" ] && { stab_skip "T-STAB-4 BPF count: bpftool unavailable at baseline"; return 0; }
	pe=$(bpftool prog show 2>/dev/null | grep -c '^[0-9]*:')
	me=$(bpftool map show 2>/dev/null | grep -c '^[0-9]*:')
	# Allow a small +N drift from kernel-internal programs that may load
	# during the run. Hard-fail if the delta exceeds 4 (tunable).
	dp=$((pe - pb)); dm=$((me - mb))
	[ "$dp" -lt 0 ] && dp=$((-dp))
	[ "$dm" -lt 0 ] && dm=$((-dm))
	if [ "$dp" -le 4 ] && [ "$dm" -le 4 ]; then
		stab_pass "T-STAB-4 BPF count: prog=$pb→$pe map=$mb→$me (within ±4)"
	else
		stab_fail "T-STAB-4 BPF count: prog=$pb→$pe map=$mb→$me (drift >4)"
	fi
}

# Print final tally + write a RESULTS.md-shaped file to STAB_DIR.
stab_summary() {
	total=$((STAB_PASS + STAB_FAIL + STAB_SKIP))
	stab_log "=== stability summary: pass=$STAB_PASS fail=$STAB_FAIL skip=$STAB_SKIP total=$total ==="
	{
		echo "# Stability run summary"
		echo "ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "cycles=${STAB_CYCLES:-?}"
		echo "pass=$STAB_PASS fail=$STAB_FAIL skip=$STAB_SKIP"
	} > "$STAB_DIR/summary.txt"
	[ "$STAB_FAIL" -eq 0 ]
}
