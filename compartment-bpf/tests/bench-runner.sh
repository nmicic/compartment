#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bench-runner.sh — VM-side benchmark suite. Emits CSV on stdout
# in the schema suggested by file 2:
#   test,kernel,n,workers,duration_s,ops,ops_sec,denies,loader_ms,result
#
# Suites:
#   bench-load                profile size sweep, daemon load time
#   bench-open-empty          hot-path open(O_RDONLY) miss with no seals
#   bench-open-full-miss      hot-path open(O_RDONLY) miss with N seals (different path)
#   bench-open-full-miss-write hot-path open(O_WRONLY) miss with N seals; exercises hash lookup
#   bench-deny                open(O_WRONLY) on a sealed path (deny throughput)
#   bench-load-actor          profile load time with N actor-bound seals (R2-F3)
#   bench-deny-actor-match    sealed-with-actor file written by the actor binary
#                             (caller_id matches — write allowed; measures the
#                             actor-scan match path; R2-F3)
#   bench-deny-actor-mismatch sealed-with-actor file written by a non-actor
#                             binary (ACTION_DENY_ACTOR_MISMATCH; measures the
#                             actor-scan mismatch + actor_mismatch_total++ path;
#                             R2-F3)
#
# bench-open-full-miss-write addresses the testing-followup item from the
# Codex synthesis review (2026-05-13 §"Left Open Deliberately" #1): the
# original full-miss row uses O_RDONLY, so comp_file_open returns before
# the map lookup (FMODE_WRITE early-exit) and the row measures syscall
# overhead, not hash miss cost. The -write row opens the decoy O_WRONLY
# so the LSM hook does the map lookup and misses.
#
# MODE=A skips daemon attach — emits no-daemon baselines for every mode-B
# row with the -modeA suffix, loader_ms=0, denies=0. The bench-load-modeA
# rows are degenerate (ops=0). The other rows measure raw kernel/syscall
# cost without the LSM hook chain.
#
# Worker-output parsing (fail-closed): each worker writes a single line
# matching ^elapsed_us=<n> ops=<n> ops_sec=<n> denies=<n>$. The runner
# (a) waits on each worker pid and records its exit code,
# (b) refuses any line that does not match the schema, and
# (c) emits a FAIL row for the suite if any worker exited non-zero,
#     produced an unparseable line, or produced no output at all. A row
#     emitted as FAIL never carries ops_sec/denies derived from partial
#     output. Addresses the testing-followup item from the Codex
#     synthesis review §"Left Open Deliberately" #2.
set -u

MODE=${MODE:-B}

REPO=${REPO:-/root/compartment-bpf}
SEALPROBE="$REPO/tests/sealprobe"
DAEMON="$REPO/compartment-bpf"
KERNEL=$(uname -r)

[ "$(id -u)" -eq 0 ] || { echo "bench-runner: needs root" >&2; exit 2; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| { echo "bench-runner: bpf not in LSM" >&2; exit 2; }

WORK=$(mktemp -d /tmp/bench.XXXXXX)
DAEMON_PID=
cleanup() {
	if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
		kill "$DAEMON_PID" 2>/dev/null || true
		wait "$DAEMON_PID" 2>/dev/null || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# Header
echo "test,kernel,n,workers,duration_s,ops,ops_sec,denies,loader_ms,result"

start_daemon() {
	policy=$1
	logf=$2
	t0=$(date +%s%N)
	"$DAEMON" "$policy" >"$logf" 2>&1 &
	DAEMON_PID=$!
	for _ in $(seq 1 200); do
		grep -q '\[run\] compartment-bpf live' "$logf" 2>/dev/null && break
		if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
			echo "(daemon died early)" >&2
			DAEMON_PID=
			return 1
		fi
		sleep 0.05
	done
	t1=$(date +%s%N)
	LOADER_MS=$(( (t1 - t0) / 1000000 ))
	grep -q '\[run\] compartment-bpf live' "$logf" 2>/dev/null
}

stop_daemon() {
	if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
		kill "$DAEMON_PID" 2>/dev/null || true
		wait "$DAEMON_PID" 2>/dev/null || true
	fi
	DAEMON_PID=
}

stage_seal_dir() {
	# stage N empty sealed files, write a profile, echo the unsealed
	# decoy path on stdout (a path NOT in the seal set).
	#
	# NOTE (R2-F3): bench rows fed from this stager hit the
	# actor_count==0 uniform-deny early-exit inside actor_check_or_deny.
	# They measure the non-actor path only — they do NOT exercise the
	# /proc/self/exe caller_id resolve, the actor[] scan loop, or the
	# actor_mismatch_total counter. The bench-*-actor family below
	# (stage_seal_actor_dir) covers those.
	count=$1
	dir="$WORK/seal_$count"
	rm -rf "$dir"
	mkdir -p "$dir"
	pol="$WORK/policy_$count.conf"
	: > "$pol"
	i=0
	while [ "$i" -lt "$count" ]; do
		t="$dir/f$i"
		: > "$t"
		echo "seal $t no-write,no-unlink" >> "$pol"
		i=$((i+1))
	done
	# Decoy outside the seal set
	echo unsealed > "$dir/decoy"
	echo "$pol|$dir/decoy"
}

# R2-F3 (Review-2 HIGH): actor-bound bench fixture. Adds three rows
# that measure the actor_check_or_deny hot path (caller_id resolve +
# actor[] scan). actor_bin == $SEALPROBE so the bench worker itself
# matches; mismatch_bin is any unrelated binary on the box.
#
# Echos "<policy>|<sealed_target>|<unsealed_decoy>".
stage_seal_actor_dir() {
	count=$1
	actor_bin=$2
	dir="$WORK/seal_actor_$count"
	rm -rf "$dir"
	mkdir -p "$dir"
	pol="$WORK/policy_actor_$count.conf"
	: > "$pol"
	echo "actor bench-actor = $actor_bin" >> "$pol"
	# ED-5 strict-mode requires the actor binary itself to be sealed
	# `full` at its declared path. Without this line the daemon load
	# fails with 'actor binary ... is not sealed at its declared path'.
	echo "seal $actor_bin full" >> "$pol"
	i=0
	while [ "$i" -lt "$count" ]; do
		t="$dir/f$i"
		: > "$t"
		echo "seal $t no-write,no-unlink actor=bench-actor" >> "$pol"
		i=$((i+1))
	done
	echo unsealed > "$dir/decoy"
	echo "$pol|$dir/f0|$dir/decoy"
}

# Wait on workers and parse their outputs strictly. Sets:
#   PARSE_OK           1 on success, 0 if any worker failed or output was bad
#   PARSE_OPS_TOTAL    summed ops_sec across workers (0 when PARSE_OK=0)
#   PARSE_DEN_TOTAL    summed denies across workers (0 when PARSE_OK=0)
#   PARSE_REASON       short tag describing the failure (for stderr)
#
# Args:
#   $1 = glob pattern matching the worker output files (no quoting; shell
#        expands on the for-loop)
#   $2 = whitespace-separated worker pids
#   $3 = expected number of workers
parse_worker_outputs() {
	pattern=$1
	pids=$2
	expected=$3

	PARSE_OK=1
	PARSE_REASON=
	PARSE_OPS_TOTAL=0
	PARSE_DEN_TOTAL=0

	# (a) wait on each worker; any nonzero rc → fail-closed.
	bad_rc=0
	for p in $pids; do
		if wait "$p"; then
			:
		else
			rc=$?
			bad_rc=$((bad_rc+1))
			PARSE_REASON="${PARSE_REASON}rc=$rc;"
		fi
	done
	if [ "$bad_rc" -ne 0 ]; then
		PARSE_OK=0
		PARSE_REASON="worker_bad_rc(${bad_rc}):${PARSE_REASON}"
	fi

	# (b) strict line-format check on each output file.
	n_files=0
	# shellcheck disable=SC2086
	for f in $pattern; do
		[ -f "$f" ] || continue
		n_files=$((n_files+1))
		line=$(head -1 "$f" 2>/dev/null)
		# Accept exactly the schema; any extra/missing fields → fail.
		if printf '%s\n' "$line" | \
		   grep -qE '^elapsed_us=[0-9]+ ops=[0-9]+ ops_sec=[0-9]+ denies=[0-9]+$'
		then
			ops=$(printf '%s\n' "$line" | \
			      sed -n 's/.*ops_sec=\([0-9]\+\).*/\1/p')
			den=$(printf '%s\n' "$line" | \
			      sed -n 's/.*denies=\([0-9]\+\).*/\1/p')
			PARSE_OPS_TOTAL=$((PARSE_OPS_TOTAL + ${ops:-0}))
			PARSE_DEN_TOTAL=$((PARSE_DEN_TOTAL + ${den:-0}))
		else
			PARSE_OK=0
			PARSE_REASON="${PARSE_REASON}bad_line:$f;"
		fi
	done

	# (c) every expected worker must have produced a file.
	if [ "$n_files" -ne "$expected" ]; then
		PARSE_OK=0
		PARSE_REASON="${PARSE_REASON}missing_files(got=$n_files,expected=$expected);"
	fi

	# fail-closed: zero out totals on any failure so partial output cannot
	# bias the CSV consumer.
	if [ "$PARSE_OK" -eq 0 ]; then
		PARSE_OPS_TOTAL=0
		PARSE_DEN_TOTAL=0
	fi
}

# Helper: emit a row in the canonical schema. Encodes the PARSE_OK
# result into the result column (PASS|FAIL) and prints PARSE_REASON to
# stderr on FAIL.
emit_row() {
	test_name=$1; n=$2; workers=$3; secs=$4; ops=$5; ops_sec=$6
	denies=$7; loader_ms=$8
	if [ "$PARSE_OK" -eq 1 ]; then
		echo "$test_name,$KERNEL,$n,$workers,$secs,$ops,$ops_sec,$denies,$loader_ms,PASS"
	else
		echo "bench-runner: $test_name: $PARSE_REASON" >&2
		echo "$test_name,$KERNEL,$n,$workers,$secs,$ops,$ops_sec,$denies,$loader_ms,FAIL"
	fi
}

# ============================================================
# MODE=A — no compartment-bpf daemon attached. Mirrors mode-B's
# row shape with -modeA suffix; bench-load-modeA is degenerate
# (ops=0) since there is no daemon to load. denies is read from
# sealprobe so a stale daemon attached during a mode-A rep would
# surface as denies>0 (a halt class per the V-2 brief).
# ============================================================
if [ "$MODE" = "A" ]; then
	# A1-A3) bench-load-modeA — degenerate; stage the seal dir so
	# inode/dcache state mirrors mode-B's, then emit a zero row.
	for n in 1 100 1000; do
		stage_seal_dir "$n" >/dev/null
		echo "bench-load-modeA,$KERNEL,$n,0,0,0,0,0,0,PASS"
	done

	# A4) bench-open-empty-modeA — RDONLY on unsealed file, no daemon.
	out=$(stage_seal_dir 1); pol=${out%|*}; decoy=${out#*|}
	echo content > "$WORK/unsealed"
	WORKERS=4
	OPS=200000
	worker_pids=
	for w in 1 2 3 4; do
		"$SEALPROBE" bench-open ro "$WORK/unsealed" "$OPS" \
			> "$WORK/empty_modeA_$w.out" &
		worker_pids="$worker_pids $!"
	done
	parse_worker_outputs "$WORK/empty_modeA_*.out" "$worker_pids" "$WORKERS"
	emit_row "bench-open-empty-modeA" 1 "$WORKERS" 5 "$OPS" \
		"$PARSE_OPS_TOTAL" "$PARSE_DEN_TOTAL" 0

	# A5) bench-open-full-miss-modeA — RDONLY on decoy under N=1000 dir, no daemon.
	out=$(stage_seal_dir 1000); pol=${out%|*}; decoy=${out#*|}
	WORKERS=4
	OPS=200000
	worker_pids=
	for w in 1 2 3 4; do
		"$SEALPROBE" bench-open ro "$decoy" "$OPS" \
			> "$WORK/fmiss_modeA_$w.out" &
		worker_pids="$worker_pids $!"
	done
	parse_worker_outputs "$WORK/fmiss_modeA_*.out" "$worker_pids" "$WORKERS"
	emit_row "bench-open-full-miss-modeA" 1000 "$WORKERS" 5 "$OPS" \
		"$PARSE_OPS_TOTAL" "$PARSE_DEN_TOTAL" 0

	# A5w) bench-open-full-miss-write-modeA — WRONLY on decoy under
	# N=1000 dir, no daemon. Mirror of mode-B's hash-miss-with-
	# write-intent baseline so the LSM hook overhead can be subtracted.
	out=$(stage_seal_dir 1000); pol=${out%|*}; decoy=${out#*|}
	WORKERS=4
	OPS=200000
	worker_pids=
	for w in 1 2 3 4; do
		"$SEALPROBE" bench-open wronly "$decoy" "$OPS" \
			> "$WORK/fmissw_modeA_$w.out" &
		worker_pids="$worker_pids $!"
	done
	parse_worker_outputs "$WORK/fmissw_modeA_*.out" "$worker_pids" "$WORKERS"
	emit_row "bench-open-full-miss-write-modeA" 1000 "$WORKERS" 5 "$OPS" \
		"$PARSE_OPS_TOTAL" "$PARSE_DEN_TOTAL" 0

	# A6) bench-deny-modeA — WRONLY on sealed target path, no daemon enforcing.
	out=$(stage_seal_dir 1); pol=${out%|*}
	sealed_target="$WORK/seal_1/f0"
	echo content > "$sealed_target"
	WORKERS=4
	OPS=100000
	worker_pids=
	for w in 1 2 3 4; do
		"$SEALPROBE" bench-open wronly "$sealed_target" "$OPS" \
			> "$WORK/deny_modeA_$w.out" &
		worker_pids="$worker_pids $!"
	done
	parse_worker_outputs "$WORK/deny_modeA_*.out" "$worker_pids" "$WORKERS"
	emit_row "bench-deny-modeA" 1 "$WORKERS" 5 "$OPS" \
		"$PARSE_OPS_TOTAL" "$PARSE_DEN_TOTAL" 0

	exit 0
fi

# 1) bench-load — profile sizes 1, 100, 1000.
for n in 1 100 1000; do
	out=$(stage_seal_dir "$n"); pol=${out%|*}
	if start_daemon "$pol" "$WORK/load.err"; then
		echo "bench-load,$KERNEL,$n,0,0,0,0,0,$LOADER_MS,PASS"
		stop_daemon
	else
		echo "bench-load,$KERNEL,$n,0,0,0,0,0,$LOADER_MS,FAIL"
	fi
done

# 2) bench-open-empty — empty policy, open(O_RDONLY) hot path.
out=$(stage_seal_dir 1); pol=${out%|*}; decoy=${out#*|}
if start_daemon "$pol" "$WORK/empty.err"; then
	echo content > "$WORK/unsealed"
	WORKERS=4
	OPS=200000
	worker_pids=
	for w in 1 2 3 4; do
		"$SEALPROBE" bench-open ro "$WORK/unsealed" "$OPS" \
			> "$WORK/empty_$w.out" &
		worker_pids="$worker_pids $!"
	done
	parse_worker_outputs "$WORK/empty_*.out" "$worker_pids" "$WORKERS"
	emit_row "bench-open-empty" 1 "$WORKERS" 5 "$OPS" \
		"$PARSE_OPS_TOTAL" "$PARSE_DEN_TOTAL" "$LOADER_MS"
	stop_daemon
else
	PARSE_OK=0; PARSE_REASON=daemon_not_live
	emit_row "bench-open-empty" 1 0 0 0 0 0 "$LOADER_MS"
fi

# 3) bench-open-full-miss — N=1000 seals, hammer an unsealed decoy with O_RDONLY.
# Note: O_RDONLY hits the FMODE_WRITE early-exit in comp_file_open, so this
# row measures syscall overhead, NOT map miss cost. See bench-open-full-miss-write
# below for the write-intent variant that actually exercises the hash lookup.
out=$(stage_seal_dir 1000); pol=${out%|*}; decoy=${out#*|}
if start_daemon "$pol" "$WORK/full.err"; then
	WORKERS=4
	OPS=200000
	worker_pids=
	for w in 1 2 3 4; do
		"$SEALPROBE" bench-open ro "$decoy" "$OPS" \
			> "$WORK/fmiss_$w.out" &
		worker_pids="$worker_pids $!"
	done
	parse_worker_outputs "$WORK/fmiss_*.out" "$worker_pids" "$WORKERS"
	emit_row "bench-open-full-miss" 1000 "$WORKERS" 5 "$OPS" \
		"$PARSE_OPS_TOTAL" "$PARSE_DEN_TOTAL" "$LOADER_MS"
	stop_daemon
else
	PARSE_OK=0; PARSE_REASON=daemon_not_live
	emit_row "bench-open-full-miss" 1000 0 0 0 0 0 "$LOADER_MS"
fi

# 3w) bench-open-full-miss-write — N=1000 seals, hammer the decoy with
# O_WRONLY. Unlike row #3, this passes the FMODE_WRITE early-exit in
# comp_file_open, so the LSM hook DOES execute the (dev, ino) hash lookup
# against sealed_inodes and sealed_dirs and MISSES. The expected denies
# count is 0 (decoy is unsealed). ops_sec measures hot-path lookup+miss
# cost; subtract the mode-A baseline to isolate the LSM overhead.
out=$(stage_seal_dir 1000); pol=${out%|*}; decoy=${out#*|}
if start_daemon "$pol" "$WORK/fullw.err"; then
	WORKERS=4
	OPS=200000
	worker_pids=
	for w in 1 2 3 4; do
		"$SEALPROBE" bench-open wronly "$decoy" "$OPS" \
			> "$WORK/fmissw_$w.out" &
		worker_pids="$worker_pids $!"
	done
	parse_worker_outputs "$WORK/fmissw_*.out" "$worker_pids" "$WORKERS"
	emit_row "bench-open-full-miss-write" 1000 "$WORKERS" 5 "$OPS" \
		"$PARSE_OPS_TOTAL" "$PARSE_DEN_TOTAL" "$LOADER_MS"
	stop_daemon
else
	PARSE_OK=0; PARSE_REASON=daemon_not_live
	emit_row "bench-open-full-miss-write" 1000 0 0 0 0 0 "$LOADER_MS"
fi

# 4) bench-deny — workers hammer open(O_WRONLY) on sealed file.
# NOTE (R2-F3): uniform-deny path — no actor allowlist. actor_count==0 in
# the seal_value, so actor_check_or_deny short-circuits before
# caller_id_resolve. See bench-deny-actor-* below for the actor-scan rows.
out=$(stage_seal_dir 1); pol=${out%|*}
sealed_target="$WORK/seal_1/f0"
echo content > "$sealed_target"
if start_daemon "$pol" "$WORK/deny.err"; then
	WORKERS=4
	OPS=100000
	worker_pids=
	for w in 1 2 3 4; do
		"$SEALPROBE" bench-open wronly "$sealed_target" "$OPS" \
			> "$WORK/deny_$w.out" &
		worker_pids="$worker_pids $!"
	done
	parse_worker_outputs "$WORK/deny_*.out" "$worker_pids" "$WORKERS"
	emit_row "bench-deny" 1 "$WORKERS" 5 "$OPS" \
		"$PARSE_OPS_TOTAL" "$PARSE_DEN_TOTAL" "$LOADER_MS"
	stop_daemon
else
	PARSE_OK=0; PARSE_REASON=daemon_not_live
	emit_row "bench-deny" 1 0 0 0 0 0 "$LOADER_MS"
fi

# ============================================================
# R2-F3 (Review-2 HIGH): actor-bound rows. Exercise the actor_check_or_deny
# hot path (caller_id resolve via /proc/self/exe → (dev,ino) → actor[] scan
# → match or actor_mismatch_total++). Without these rows the ED-13 bench
# under-reads — every existing row hits the actor_count==0 early-exit.
# ============================================================

# ED-5 strict-mode requires the actor binary's parent dir to be
# mode 0755 or stricter (Sec-2 / DEC-ED2-A: no world/group writable
# parent — an unprivileged user with write to the parent could swap
# the binary before path resolution). $SEALPROBE lives under
# $REPO/tests/ which on most build setups is mode 0775 (group-
# writable) and fails the load with 'parent dir is world- or
# group-writable'. Copy sealprobe into $WORK (which mktemp created
# as mode 0700) so the parent dir passes the check.
BENCH_ACTOR_BIN="$WORK/bench-actor"
cp "$SEALPROBE" "$BENCH_ACTOR_BIN" || { echo "bench-runner: failed to stage actor bin under $WORK" >&2; exit 2; }
chmod 0755 "$BENCH_ACTOR_BIN" || { echo "bench-runner: failed to chmod actor bin" >&2; exit 2; }

# Discover a non-sealprobe binary on the box for the mismatch row.
# Same parent-dir-mode constraint — copy into $WORK rather than
# pointing at /usr/bin/* directly (whose parents are mode 0755 on
# Resolute and fine, but symmetric staging keeps the test
# self-contained and reproducible).
MISMATCH_SRC=
for cand in /usr/bin/true /bin/true /usr/bin/cat /bin/cat; do
	if [ -x "$cand" ]; then
		MISMATCH_SRC="$cand"
		break
	fi
done
if [ -z "$MISMATCH_SRC" ]; then
	echo "bench-runner: no candidate mismatch binary; skipping actor-bound rows" >&2
	exit 0
fi
MISMATCH_BIN="$WORK/bench-mismatch"
cp "$MISMATCH_SRC" "$MISMATCH_BIN" || { echo "bench-runner: failed to stage mismatch bin" >&2; exit 2; }
chmod 0755 "$MISMATCH_BIN" || { echo "bench-runner: failed to chmod mismatch bin" >&2; exit 2; }

# 5) bench-load-actor — profile sizes 1, 100, 1000, each seal actor-bound.
# Loader has to stat the actor binary once + resolve (dev,ino), then
# every seal references the actor group by name (cheap symbol lookup).
for n in 1 100 1000; do
	out=$(stage_seal_actor_dir "$n" "$BENCH_ACTOR_BIN"); pol=${out%|*|*}
	if start_daemon "$pol" "$WORK/load_actor_$n.err"; then
		echo "bench-load-actor,$KERNEL,$n,0,0,0,0,0,$LOADER_MS,PASS"
		stop_daemon
	else
		echo "bench-load-actor,$KERNEL,$n,0,0,0,0,0,$LOADER_MS,FAIL"
	fi
done

# 6) bench-deny-actor-match — BENCH_ACTOR_BIN (== sealprobe) IS the
# actor and hammers a sealed file. caller_id resolve → match → write
# permitted. Measures the actor-scan + match throughput.
out=$(stage_seal_actor_dir 1 "$BENCH_ACTOR_BIN")
pol=${out%%|*}
rest=${out#*|}; sealed_target=${rest%|*}
if start_daemon "$pol" "$WORK/deny_actor_match.err"; then
	WORKERS=4
	OPS=100000
	worker_pids=
	for w in 1 2 3 4; do
		# Use BENCH_ACTOR_BIN as the worker so /proc/self/exe
		# resolves to the actor inode, matching the seal's actor=
		# clause.
		"$BENCH_ACTOR_BIN" bench-open wronly "$sealed_target" "$OPS" \
			> "$WORK/deny_actor_match_$w.out" &
		worker_pids="$worker_pids $!"
	done
	parse_worker_outputs "$WORK/deny_actor_match_*.out" "$worker_pids" "$WORKERS"
	emit_row "bench-deny-actor-match" 1 "$WORKERS" 5 "$OPS" \
		"$PARSE_OPS_TOTAL" "$PARSE_DEN_TOTAL" "$LOADER_MS"
	stop_daemon
else
	PARSE_OK=0; PARSE_REASON=daemon_not_live
	emit_row "bench-deny-actor-match" 1 0 0 0 0 0 "$LOADER_MS"
fi

# 7) bench-deny-actor-mismatch — actor binary is MISMATCH_BIN (not
# sealprobe); sealprobe attempts to write the sealed file. caller_id
# resolve → mismatch → ACTION_DENY_ACTOR_MISMATCH + actor_mismatch_total++.
# Measures the actor-scan + mismatch path throughput. denies expected
# ≈ ops (every write hits the deny).
out=$(stage_seal_actor_dir 1 "$MISMATCH_BIN")
pol=${out%%|*}
rest=${out#*|}; sealed_target=${rest%|*}
if start_daemon "$pol" "$WORK/deny_actor_mismatch.err"; then
	WORKERS=4
	OPS=100000
	worker_pids=
	for w in 1 2 3 4; do
		"$SEALPROBE" bench-open wronly "$sealed_target" "$OPS" \
			> "$WORK/deny_actor_mismatch_$w.out" &
		worker_pids="$worker_pids $!"
	done
	parse_worker_outputs "$WORK/deny_actor_mismatch_*.out" "$worker_pids" "$WORKERS"
	emit_row "bench-deny-actor-mismatch" 1 "$WORKERS" 5 "$OPS" \
		"$PARSE_OPS_TOTAL" "$PARSE_DEN_TOTAL" "$LOADER_MS"
	stop_daemon
else
	PARSE_OK=0; PARSE_REASON=daemon_not_live
	emit_row "bench-deny-actor-mismatch" 1 0 0 0 0 0 "$LOADER_MS"
fi
