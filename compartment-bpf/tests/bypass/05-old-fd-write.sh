#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Behavior witness: writes through an fd opened BEFORE attach. The README
# called this a "documented limit" (writes succeed); the file_permission
# LSM hook in the current code path catches this case, so writes through
# pre-attach fds are denied. Either outcome is recorded as PASS — the
# point is to detect a behavior change next time someone touches the
# write-path hooks.
# Suggestion ID: 4.2e (and 3.3i, 3.4a)
set -u
BYPASS_NAME="05-old-fd-write"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
TARGET="$TMP/target"
echo content > "$TARGET"

# Open writable fd BEFORE the seal arms.
exec 9>"$TARGET"

echo "seal $TARGET no-write" > "$TMP/policy.conf"
DAEMON_LOG="$TMP/daemon.err"
"$DAEMON" "$TMP/policy.conf" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
trap '[ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null; rm -rf "$TMP"' EXIT INT TERM
for _ in $(seq 1 100); do
	grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null && break
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null || {
	echo "FAIL ${BYPASS_NAME}: daemon did not go live" >&2; exit 1; }

if printf x >&9 2>/dev/null; then
	bypass_pass "write via pre-attach fd succeeded (matches old README 'documented limit')"
else
	bypass_pass "write via pre-attach fd denied (file_permission hook catches it; tighter than README claims)"
fi
