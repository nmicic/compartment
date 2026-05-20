#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# tests/counter-smoke.sh — V-4b deny/audit-drop counter smoke suite.
#
# Four tests:
#   T4b.1 deny_total counts exactly 1000 denied writes.
#   T4b.2 audit_drop_total increases under ringbuf pressure; denies still
#         all return -EACCES.
#   T4b.3 --stats with no enforcement activity is idempotent across 10 reads.
#   T4b.4 actor_mismatch_total counts exactly 500 actor-mismatch denies
#         (F7, Review-1).
#
# Designed to run inside the same VM as tests/pin-regression.sh. Requires
# CAP_BPF / CAP_SYS_ADMIN (in practice: run as root). The harness pins to
# PIN_ROOT and ALWAYS --unpins on the way out, including on error, so the
# VM is left in the same state as it started.
#
# Outputs ${RESULTS}/counter-smoke.csv -- one row per test:
#   test,outcome,detail
#
# Exits non-zero unless all 3 tests pass.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"

if [ -z "${RESULTS:-}" ]; then
	DATE="$(date -u +%Y%m%dT%H%M%SZ)"
	RESULTS="${REPO}/tests/results/counter-smoke-${DATE}"
fi
mkdir -p "${RESULTS}"
CSV="${RESULTS}/counter-smoke.csv"
echo "test,outcome,detail" > "${CSV}"

BIN="${REPO}/compartment-bpf"
PIN_ROOT="/sys/fs/bpf/compartment"

if [ ! -x "${BIN}" ]; then
	echo "fatal: ${BIN} not present or not executable (run make first)" >&2
	exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "fatal: counter-smoke.sh requires root (CAP_BPF + bpffs mutation)" >&2
	exit 1
fi

# Scratch dir + sealed target file. Use a private tmpfs-like path under
# /tmp so we never touch anything system-owned.
SCRATCH="$(mktemp -d /tmp/v4b-counter-smoke.XXXXXX)"
SEALED="${SCRATCH}/sealed.txt"
PROFILE="${SCRATCH}/profile.conf"
echo "stay-sealed" > "${SEALED}"
cat > "${PROFILE}" <<EOF
seal ${SEALED} no-write
EOF

# F7: T4b.4 actor-mismatch counter fixture. Separate profile with an
# `actor` directive pointing at a real binary; the shared subshell that
# issues the writes is /bin/sh (or similar), which does NOT match the
# allowlist (dev, ino). Every write must increment
# actor_mismatch_total exactly once.
SEALED_AM="${SCRATCH}/sealed-actor-mismatch.txt"
ACTOR_BIN="${SCRATCH}/actor-bin"
PROFILE_AM="${SCRATCH}/profile-actor-mismatch.conf"
echo "stay-sealed-am" > "${SEALED_AM}"
cp /bin/dd "${ACTOR_BIN}"
chmod 0755 "${ACTOR_BIN}"
cat > "${PROFILE_AM}" <<EOF
actor allowed = ${ACTOR_BIN}

seal ${ACTOR_BIN} full
seal ${SEALED_AM} no-write actor=allowed
EOF

DAEMON_PID=""
DAEMON_LOG=""

cleanup() {
	local rc=$?
	if [ -n "${DAEMON_PID}" ] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
		kill -TERM "${DAEMON_PID}" 2>/dev/null || true
		# Daemon may take a beat to exit; pinned links keep policy live
		# without the daemon, so we don't depend on it.
		wait "${DAEMON_PID}" 2>/dev/null || true
	fi
	# Always sweep pins on the way out, regardless of test outcome.
	"${BIN}" --unpin >/dev/null 2>&1 || true
	rm -rf "${SCRATCH}"
	if [ -n "${DAEMON_LOG}" ] && [ -f "${DAEMON_LOG}" ]; then
		cp "${DAEMON_LOG}" "${RESULTS}/" 2>/dev/null || true
	fi
	exit $rc
}
trap cleanup EXIT INT TERM

# start_daemon <log-file> [env-prefix...]
#   Launches compartment-bpf --pin in background. Waits for "[run]" sentinel
#   in the log so callers know enforcement is live before exercising denies.
start_daemon() {
	local log=$1; shift
	DAEMON_LOG="${log}"
	# Pre-flight: no stale pins from a previous run.
	"${BIN}" --unpin >/dev/null 2>&1 || true
	# Background daemon. Caller passes env via the variadic args.
	"$@" "${BIN}" --pin "${PROFILE}" > "${log}" 2>&1 &
	DAEMON_PID=$!
	# Wait up to 15s for the daemon to advertise it is live.
	local i
	for i in $(seq 1 75); do
		if grep -q "^\[run\] compartment-bpf live" "${log}" 2>/dev/null; then
			return 0
		fi
		if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
			echo "fatal: daemon died during startup. log:" >&2
			cat "${log}" >&2
			return 1
		fi
		sleep 0.2
	done
	echo "fatal: daemon did not become live within 15s. log:" >&2
	cat "${log}" >&2
	return 1
}

stop_daemon() {
	if [ -n "${DAEMON_PID}" ] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
		kill -TERM "${DAEMON_PID}" 2>/dev/null || true
		wait "${DAEMON_PID}" 2>/dev/null || true
	fi
	DAEMON_PID=""
}

# stats_value <log-file> <field>
#   Run `compartment-bpf --stats`, log it, parse a value out of the
#   "[stats] deny_total=N audit_drop_total=M" line.
#
# Fields: deny | drop | amisma  (F7 added amisma for T4b.4)
stats_value() {
	local log=$1
	local field=$2
	local out
	out=$("${BIN}" --stats 2>&1)
	echo "${out}" >> "${log}"
	case "${field}" in
	deny) echo "${out}" | sed -n 's/.*deny_total=\([0-9][0-9]*\).*/\1/p' ;;
	drop) echo "${out}" | sed -n 's/.*audit_drop_total=\([0-9][0-9]*\).*/\1/p' ;;
	amisma) echo "${out}" | sed -n 's/.*actor_mismatch_total=\([0-9][0-9]*\).*/\1/p' ;;
	*) echo "bad field ${field}" >&2; return 1 ;;
	esac
}

record() {
	echo "$1,$2,$3" >> "${CSV}"
	echo "[$1] $2  $3" >&2
}

failed=0
pass_count=0

# ============================================================
# T4b.1: deny_total counts exactly 1000 denied writes.
# ============================================================
log_t1="${RESULTS}/t4b1-daemon.log"
stats_log_t1="${RESULTS}/t4b1-stats.log"
: > "${stats_log_t1}"

if ! start_daemon "${log_t1}"; then
	record T4b.1 FAIL "daemon-failed-to-start"
	failed=1
else
	# Baseline read. With a freshly-pinned daemon and only the sealed
	# file in the policy, deny_total should be 0 -- but record the
	# actual value and compare deltas to be robust against any
	# incidental early denies.
	deny_before=$(stats_value "${stats_log_t1}" deny)
	drop_before=$(stats_value "${stats_log_t1}" drop)

	# 1000 denied writes. `: > FILE` is open(O_WRONLY|O_TRUNC), which
	# triggers file_open with FMODE_WRITE -- exactly one deny per
	# invocation. Run inside a subshell with stderr silenced because
	# bash's redirect-failure message goes to its own stderr, not the
	# inner command's, so a per-redirect `2>/dev/null` would not work.
	# `set +e` because we EXPECT each redirect to fail; with the parent
	# script's `set -e` in effect the first failed redirect would abort.
	(
		set +e
		exec 2>/dev/null
		for _ in $(seq 1 1000); do
			: > "${SEALED}"
		done
		# Force a zero exit so the parent's `set -e` does not abort
		# on the subshell's last-command status, which is the final
		# (expected-to-fail) redirect.
		exit 0
	)
	t1_attempts=1000

	# Brief settle so any in-flight audit emission completes; the
	# counter increment itself happens synchronously in the deny path,
	# but stats_value rebinds bpf_obj_get on each call -- one second
	# is comfortable margin.
	sleep 1

	deny_after=$(stats_value "${stats_log_t1}" deny)
	drop_after=$(stats_value "${stats_log_t1}" drop)
	deny_delta=$((deny_after - deny_before))
	drop_delta=$((drop_after - drop_before))

	if [ "${deny_delta}" -eq 1000 ]; then
		record T4b.1 PASS "deny_delta=1000 drop_delta=${drop_delta} attempts=${t1_attempts}"
		pass_count=$((pass_count + 1))
	else
		record T4b.1 FAIL "deny_delta=${deny_delta} expected=1000 drop_delta=${drop_delta} attempts=${t1_attempts}"
		failed=1
	fi

	stop_daemon
	"${BIN}" --unpin >/dev/null 2>&1 || true
fi

# ============================================================
# T4b.2: audit_drop_total increases under ringbuf pressure.
# ============================================================
log_t2="${RESULTS}/t4b2-daemon.log"
stats_log_t2="${RESULTS}/t4b2-stats.log"
: > "${stats_log_t2}"

# Tiny audit ringbuf so a small burst exhausts it. 4096 bytes is the
# minimum (one page); ringbuf entry size is ~64 bytes including header,
# so ~60 entries before reserve fails. We will issue ~5000 denies in
# parallel -- the producer rate dominates the consumer rate and forces
# at least one drop. This env knob is read by the daemon at open() time;
# see "T4b.2" comment near getenv() in compartment-bpf.c.
if ! start_daemon "${log_t2}" env COMPARTMENT_BPF_AUDIT_RB_BYTES=4096; then
	record T4b.2 FAIL "daemon-failed-to-start"
	failed=1
else
	deny_before=$(stats_value "${stats_log_t2}" deny)
	drop_before=$(stats_value "${stats_log_t2}" drop)

	# Spawn 50 parallel writers, each attempting 100 denies, for 5000
	# total. Run them all in background and wait. The kernel sees a
	# burst of file_open calls; userspace ringbuf consumer wakes on
	# poll(1000ms) and cannot keep up at 4096-byte capacity.
	denial_failures=0
	t2_attempts=5000
	worker_pids=()
	for _w in $(seq 1 50); do
		(
			# Suppress bash redirect-failure stderr from the
			# subshell -- bash prints to its own stderr, not the
			# inner command's, so a per-redirect `2>/dev/null`
			# does not silence it. We do not care about the per
			# attempt diagnostic; we only care that the redirect
			# failed (== open denied).
			exec 2>/dev/null
			for _ in $(seq 1 100); do
				if : > "${SEALED}"; then
					# write SUCCEEDED -- that is a bypass.
					exit 1
				fi
			done
			exit 0
		) &
		worker_pids+=($!)
	done
	# Collect each worker's exit code; any non-zero means a write was
	# allowed which means denies are not all reaching the deny path.
	# IMPORTANT: do NOT use `jobs -p` here -- it would include the
	# pinned daemon's background pid, which only exits on SIGTERM.
	for pid in "${worker_pids[@]}"; do
		if ! wait "${pid}"; then
			denial_failures=$((denial_failures + 1))
		fi
	done

	sleep 1

	deny_after=$(stats_value "${stats_log_t2}" deny)
	drop_after=$(stats_value "${stats_log_t2}" drop)
	deny_delta=$((deny_after - deny_before))
	drop_delta=$((drop_after - drop_before))

	if [ "${denial_failures}" -ne 0 ]; then
		record T4b.2 FAIL "denial_failures=${denial_failures} deny_delta=${deny_delta} drop_delta=${drop_delta}"
		failed=1
	elif [ "${drop_delta}" -le 0 ]; then
		# Per V-4b brief: if drops cannot be induced even under the
		# test-only pressure mechanism, halt as INCONCLUSIVE rather
		# than silently passing.
		record T4b.2 INCONCLUSIVE "drop_delta=0 deny_delta=${deny_delta} attempts=${t2_attempts}"
		failed=1
	elif [ "${deny_delta}" -ne "${t2_attempts}" ]; then
		# Every attempt should have hit the deny path exactly once.
		# drop_delta > 0 is fine (it means some failed to audit, not
		# that they were allowed) but deny_delta must EQUAL attempts.
		# Codex 2026-05-13 M5: previously `-lt` (≥-equivalent pass),
		# which let over-counts slip through; tighten to strict
		# equality so a deny-side double-count surfaces as FAIL too.
		record T4b.2 FAIL "deny_delta=${deny_delta} expected=${t2_attempts} drop_delta=${drop_delta}"
		failed=1
	else
		record T4b.2 PASS "deny_delta=${deny_delta} drop_delta=${drop_delta} attempts=${t2_attempts}"
		pass_count=$((pass_count + 1))
	fi

	stop_daemon
	"${BIN}" --unpin >/dev/null 2>&1 || true
fi

# ============================================================
# T4b.3: --stats is idempotent across 10 reads with no activity.
# ============================================================
log_t3="${RESULTS}/t4b3-daemon.log"
stats_log_t3="${RESULTS}/t4b3-stats.log"
: > "${stats_log_t3}"

if ! start_daemon "${log_t3}"; then
	record T4b.3 FAIL "daemon-failed-to-start"
	failed=1
else
	# No enforcement activity from this harness. Read --stats 10 times
	# and require every read to be byte-identical.
	first=""
	identical=1
	for i in $(seq 1 10); do
		out=$("${BIN}" --stats 2>&1)
		echo "${i}: ${out}" >> "${stats_log_t3}"
		if [ -z "${first}" ]; then
			first="${out}"
		elif [ "${out}" != "${first}" ]; then
			identical=0
			break
		fi
	done

	if [ "${identical}" -eq 1 ]; then
		record T4b.3 PASS "10/10 identical reads: ${first}"
		pass_count=$((pass_count + 1))
	else
		record T4b.3 FAIL "reads diverged; see ${stats_log_t3}"
		failed=1
	fi

	stop_daemon
	"${BIN}" --unpin >/dev/null 2>&1 || true
fi

# ============================================================
# F7 / T4b.4: actor_mismatch_total counts exactly N actor-mismatch denies.
# Mirrors T4b.1's exactness pattern, but the writes come from a shell
# subshell rather than the allowlisted ACTOR_BIN — so every deny is on
# the ACTION_DENY_ACTOR_MISMATCH path and bumps actor_mismatch_total.
# ============================================================
log_t4="${RESULTS}/t4b4-daemon.log"
stats_log_t4="${RESULTS}/t4b4-stats.log"
: > "${stats_log_t4}"

# Use the actor-mismatch profile rather than the uniform-deny one. The
# simplest way to swap profile without refactoring start_daemon is to
# point the global PROFILE at it for this sub-test.
PROFILE_SAVED="${PROFILE}"
PROFILE="${PROFILE_AM}"
if ! start_daemon "${log_t4}"; then
	record T4b.4 FAIL "daemon-failed-to-start"
	failed=1
else
	amisma_before=$(stats_value "${stats_log_t4}" amisma)
	# 500 denied writes from /bin/sh (not the allowlisted ACTOR_BIN).
	# Each must trip ACTION_DENY_ACTOR_MISMATCH and bump the counter
	# by exactly 1.
	(
		set +e
		exec 2>/dev/null
		for _ in $(seq 1 500); do
			: > "${SEALED_AM}"
		done
		exit 0
	)
	t4_attempts=500
	sleep 1
	amisma_after=$(stats_value "${stats_log_t4}" amisma)
	amisma_delta=$((amisma_after - amisma_before))
	if [ "${amisma_delta}" -eq 500 ]; then
		record T4b.4 PASS "amisma_delta=500 attempts=${t4_attempts}"
		pass_count=$((pass_count + 1))
	else
		record T4b.4 FAIL "amisma_delta=${amisma_delta} expected=500 attempts=${t4_attempts}"
		failed=1
	fi
	stop_daemon
	"${BIN}" --unpin >/dev/null 2>&1 || true
fi
PROFILE="${PROFILE_SAVED}"

echo >&2
echo "counter-smoke: ${pass_count}/4 passed, $((4 - pass_count)) failed" >&2
echo "csv: ${CSV}" >&2

[ "${failed}" -eq 0 ]
