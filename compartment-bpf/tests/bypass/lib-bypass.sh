# SPDX-License-Identifier: Apache-2.0
# tests/bypass/lib-bypass.sh — shared scaffolding for VM-side bypass tests.
# Each tests/bypass/<name>.sh sources this, calls bypass_setup() to bring
# up a daemon over a fresh sealed file, runs the attack, and emits one of
#
#   PASS  <name>: <one-line summary>
#   FAIL  <name>: <one-line summary>            (loud bypass / unexpected)
#   SKIP  <name>: <reason>                       (env doesn't support it)
#
# The VM-side runner driver (tests/bypass/run-all.sh on the host) ssh's
# in, runs each script, and aggregates results.

# Caller must have set REPO before sourcing.
: "${REPO:=/root/compartment-bpf}"
SEALPROBE="$REPO/tests/sealprobe"
BYPASS_REAL_DAEMON="$REPO/compartment-bpf"

# ── Probe-integrity guard ───────────────────────────────────────────
#
# A witness that prints PASS without running anything satisfies the
# runner's one-label-per-script invariant while asserting nothing: put
# `bypass_pass "..."` straight after bypass_check_env in any witness here
# and the whole suite still reports "44 PASS / 0 FAIL / 0 SKIP", rc=0.
# Nothing in the corpus could tell the difference.
#
# $DAEMON is therefore a per-witness wrapper that records every
# invocation and exec's the real loader, and bypass_pass refuses when the
# count is zero. It is a wrapper rather than a counter the witnesses call
# because all 39 invoke "$DAEMON" directly — foreground, backgrounded,
# --dry-run, --pin — and none of them needs to change. exec() keeps
# argv[0] and the pid, so $DAEMON_PID, pkill and the audit output are
# unaffected.
#
# A witness that genuinely has nothing to run must call bypass_skip with
# a reason; one that exercises the kernel without the loader (none today)
# can declare it with bypass_evidence.
BYPASS_WRAPDIR=$(mktemp -d /tmp/bypass-wrap.XXXXXX)
BYPASS_RUNS="$BYPASS_WRAPDIR/daemon-runs"
: > "$BYPASS_RUNS"
DAEMON="$BYPASS_WRAPDIR/compartment-bpf"
{
	printf '#!/bin/sh\n'
	printf 'echo run >> %s\n' "$BYPASS_RUNS"
	printf 'exec %s "$@"\n' "$BYPASS_REAL_DAEMON"
} > "$DAEMON"
chmod 755 "$DAEMON"

# Declare evidence that is not a loader invocation.
bypass_evidence() {
	echo "evidence: $*" >> "$BYPASS_RUNS"
}

bypass_evidence_count() {
	wc -l < "$BYPASS_RUNS" 2>/dev/null | tr -d ' \t' || echo 0
}

bypass_die() {
	echo "FAIL ${BYPASS_NAME:-?}: $*" >&2
	exit 1
}
bypass_skip() {
	echo "SKIP ${BYPASS_NAME:-?}: $*" >&2
	exit 77
}
bypass_pass() {
	if [ "$(bypass_evidence_count)" -lt 1 ]; then
		echo "FAIL ${BYPASS_NAME:-?}: witness reported PASS without running a probe" \
		     "(the loader was never invoked) — claimed: $*" >&2
		exit 1
	fi
	echo "PASS ${BYPASS_NAME:-?}: $*"
	exit 0
}
bypass_fail() {
	echo "FAIL ${BYPASS_NAME:-?}: $*"
	exit 1
}

bypass_check_env() {
	[ "$(id -u)" -eq 0 ] || bypass_skip "needs root"
	grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
		|| bypass_skip "bpf not in active LSM"
	[ -x "$SEALPROBE" ] || bypass_skip "sealprobe not built"
	[ -x "$BYPASS_REAL_DAEMON" ] || bypass_skip "daemon not built"
}

# bypass_setup <flags> [extra-seal-line ...]
#   Creates $TMP/target with content, writes a profile sealing it with
#   the given flags, plus any extra `seal …` lines passed verbatim.
#   Starts the daemon and waits for `[run] live`. Sets $TARGET globally.
bypass_setup() {
	flags=$1; shift
	TMP=$(mktemp -d /tmp/bypass.XXXXXX)
	TARGET="$TMP/target"
	echo content > "$TARGET"
	{
		printf 'seal %s %s\n' "$TARGET" "$flags"
		while [ "$#" -gt 0 ]; do printf '%s\n' "$1"; shift; done
	} > "$TMP/policy.conf"
	DAEMON_LOG="$TMP/daemon.err"
	"$DAEMON" "$TMP/policy.conf" >"$DAEMON_LOG" 2>&1 &
	DAEMON_PID=$!
	for _ in $(seq 1 100); do
		grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null && break
		kill -0 "$DAEMON_PID" 2>/dev/null || { cat "$DAEMON_LOG" >&2; bypass_die "daemon died during attach"; }
		sleep 0.1
	done
	grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null \
		|| { cat "$DAEMON_LOG" >&2; bypass_die "daemon did not go live"; }
}

bypass_teardown() {
	if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
		kill "$DAEMON_PID" 2>/dev/null || true
		wait "$DAEMON_PID" 2>/dev/null || true
	fi
	[ -n "${TMP:-}" ] && rm -rf "$TMP"
	[ -n "${BYPASS_WRAPDIR:-}" ] && rm -rf "$BYPASS_WRAPDIR"
	return 0
}
trap bypass_teardown EXIT INT TERM
