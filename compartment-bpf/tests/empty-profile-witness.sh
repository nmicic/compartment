#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/empty-profile-witness.sh — regression test for Codex finding 2,
# previously documented as finding 2.14.
#
# Pre-fix: an empty profile or comment-only profile reached "[run] live"
# with zero rules in the maps -- a fail-OPEN load that an operator could
# not distinguish from "policy not loaded yet."
#
# Post-fix: load_conf rejects sealed == 0 and the daemon exits non-zero
# with a clear message. --allow-empty opts back into the prior soak-only
# behavior.
#
# Asserts:
#   1. Empty profile, no flag       -> daemon EXITS, never reaches live
#   2. Comment-only profile, no flag -> daemon EXITS, never reaches live
#   3. Empty profile, --allow-empty  -> daemon REACHES live (prior behavior)
set -u

REPO=${REPO:-/root/compartment-bpf}
DAEMON="$REPO/compartment-bpf"

[ "$(id -u)" -eq 0 ] || { echo "SKIP empty-profile-witness: needs root" >&2; exit 77; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| { echo "SKIP empty-profile-witness: bpf not in active LSM" >&2; exit 77; }
[ -x "$DAEMON" ] || { echo "SKIP empty-profile-witness: missing $DAEMON" >&2; exit 77; }

TMP=$(mktemp -d /tmp/emptyprof.XXXXXX)
trap 'rm -rf "$TMP"; pkill -P $$ compartment-bpf 2>/dev/null || true' EXIT INT TERM

# state_after_run <profile> [extra-arg...]
#   Runs the daemon against the profile, with optional extra args, and
#   echoes one of:
#     LIVE_NO_OP  daemon reached "[run] live"
#     REFUSED     daemon exited before going live
state_after_run() {
	prof=$1; shift
	log="$TMP/$(basename "$prof").err"
	"$DAEMON" "$@" "$prof" >"$log" 2>&1 &
	pid=$!
	for _ in $(seq 1 50); do
		grep -q '\[run\] compartment-bpf live' "$log" 2>/dev/null && break
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	if grep -q '\[run\] compartment-bpf live' "$log" 2>/dev/null; then
		echo LIVE_NO_OP
	else
		echo REFUSED
	fi
	kill "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null || true
}

# Stage three profiles.
: > "$TMP/empty.conf"
printf '# only a comment\n' > "$TMP/cmt.conf"
: > "$TMP/empty-allow.conf"

empty_state=$(state_after_run "$TMP/empty.conf")
cmt_state=$(state_after_run "$TMP/cmt.conf")
allow_state=$(state_after_run "$TMP/empty-allow.conf" --allow-empty)

# Assert. Default: REFUSED. With flag: LIVE_NO_OP.
fail=0
if [ "$empty_state" != "REFUSED" ]; then
	echo "FAIL empty-profile-witness: empty profile expected REFUSED, got $empty_state"
	cat "$TMP/empty.conf.err" >&2 || true
	fail=1
fi
if [ "$cmt_state" != "REFUSED" ]; then
	echo "FAIL empty-profile-witness: comment-only profile expected REFUSED, got $cmt_state"
	cat "$TMP/cmt.conf.err" >&2 || true
	fail=1
fi
if [ "$allow_state" != "LIVE_NO_OP" ]; then
	echo "FAIL empty-profile-witness: --allow-empty profile expected LIVE_NO_OP, got $allow_state"
	cat "$TMP/empty-allow.conf.err" >&2 || true
	fail=1
fi

if [ "$fail" -eq 0 ]; then
	echo "PASS empty-profile-witness: empty=$empty_state comment=$cmt_state allow_empty=$allow_state"
	exit 0
fi
exit 1
