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
DAEMON="$REPO/compartment-bpf"

bypass_die() {
	echo "FAIL ${BYPASS_NAME:-?}: $*" >&2
	exit 1
}
bypass_skip() {
	echo "SKIP ${BYPASS_NAME:-?}: $*" >&2
	exit 77
}
bypass_pass() {
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
	[ -x "$DAEMON" ]   || bypass_skip "daemon not built"
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
}
trap bypass_teardown EXIT INT TERM
