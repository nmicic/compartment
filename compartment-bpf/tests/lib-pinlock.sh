# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=sh
# tests/lib-pinlock.sh — advisory mutex over PIN_ROOT for concurrent suites.
#
# Why this exists
# ---------------
# PIN_ROOT (/sys/fs/bpf/compartment) is a single global namespace and
# `compartment-bpf --unpin` sweeps ALL of it, not just the pins the calling
# process created. Two suites want it at the same time:
#
#   * tests/stability/pin-unpin-churn.sh Loop A — 64 pin/unpin cycles;
#   * tests/mesh/run-mesh.sh ME-10 — pins a daemon and reads deny_total /
#     actor_mismatch_total deltas back through `--stats`.
#
# and the stability harness runs the mesh harness inside Loop B, so they
# overlap by construction. Every observed failure of `make check-stability-quick`
# on a healthy box was this collision: the churn's --unpin removed the pinned
# counter maps ME-10 was measuring, and ME-10 reported
# `deny_total-delta(exp=1,got=0)` for the rest of its block. Enforcement never
# diverged — every other ME block stayed at 0 FAIL — it was two harnesses
# fighting over one namespace.
#
# The product already refuses to race itself (compartment-bpf.c takes an
# exclusive flock on /run/lock/compartment-bpf-pin.lock for the pin window),
# but that lock covers a single --pin or --unpin, not a caller's whole
# pin-use-unpin transaction. This is the harness-level equivalent: hold it
# around a transaction that must own PIN_ROOT end to end.
#
# Deliberately advisory and best-effort: a suite that cannot take the lock
# (no flock(1), read-only /run/lock) proceeds unlocked rather than skipping,
# which is exactly the pre-existing behaviour.
#
# Usage:
#   . "$REPO/tests/lib-pinlock.sh"
#   pinlock_acquire 120 || echo "warning: proceeding without the PIN_ROOT lock"
#   ... --pin ... use ... --unpin ...
#   pinlock_release

: "${COMPARTMENT_TEST_PINLOCK:=/run/lock/compartment-bpf-testsuite-pin.lock}"

# pinlock_acquire [timeout-seconds]
#   0 = lock held (or unobtainable-and-skipped); 1 = timed out waiting, which
#   the caller should treat as a real problem (someone is wedged holding it).
pinlock_acquire() {
	_pl_to=${1:-120}
	PINLOCK_HELD=0
	command -v flock >/dev/null 2>&1 || return 0
	if ! exec 9>"$COMPARTMENT_TEST_PINLOCK" 2>/dev/null; then
		COMPARTMENT_TEST_PINLOCK=/tmp/.compartment-bpf-testsuite-pin.lock
		exec 9>"$COMPARTMENT_TEST_PINLOCK" 2>/dev/null || return 0
	fi
	if flock -w "$_pl_to" 9 2>/dev/null; then
		PINLOCK_HELD=1
		return 0
	fi
	exec 9>&- 2>/dev/null || true
	return 1
}

# pinlock_release
#   Idempotent. The lock is also released implicitly when the holding shell
#   exits (fd 9 closes), so an aborted suite cannot wedge the other one.
pinlock_release() {
	[ "${PINLOCK_HELD:-0}" = "1" ] || return 0
	flock -u 9 2>/dev/null || true
	exec 9>&- 2>/dev/null || true
	PINLOCK_HELD=0
}
