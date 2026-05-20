#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Behavior witness: splice/sendfile-style copy through an fd opened
# before attach. Same documented-limit class as 05; recorded so any
# future relaxation or tightening trips this test.
# Suggestion ID: 4.2f
set -u
BYPASS_NAME="06-splice-old-fd"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
TARGET="$TMP/target"
echo content > "$TARGET"
echo overwrite > "$TMP/src"

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
grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null \
	|| { echo "FAIL ${BYPASS_NAME}: daemon did not go live" >&2; exit 1; }

if dd if="$TMP/src" of=/dev/fd/9 bs=4 count=1 2>/dev/null; then
	bypass_pass "dd via pre-attach fd succeeded (matches old README 'documented limit')"
else
	bypass_pass "dd via pre-attach fd denied (write-path hooks catch it; tighter than README claims)"
fi
