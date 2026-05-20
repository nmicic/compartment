#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Documented (admitted) limit: without --pin, killing the daemon removes
# enforcement. This test verifies the admitted behavior so a future
# change (e.g. accidental pinning) is loud.
# Suggestion ID: 4.2j
set -u
BYPASS_NAME="10-detach-by-kill"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env
bypass_setup "no-unlink"

# While daemon is up, unlink must DENY.
"$SEALPROBE" unlink "$TARGET" >/dev/null 2>&1; rc_before=$?
[ "$rc_before" = 1 ] || bypass_fail "pre-detach unlink expected DENY, got rc=$rc_before"

# Kill the daemon; without --pin, links go away and the seal map empties.
kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=

# After daemon exit (no --pin), unlink should now succeed.
"$SEALPROBE" unlink "$TARGET" >/dev/null 2>&1; rc_after=$?
case $rc_after in
	0) bypass_pass "unpinned daemon kill removes enforcement (documented)" ;;
	1) bypass_fail "DOCUMENTED LIMIT CHANGED: enforcement persisted after unpinned-kill" ;;
	*) bypass_fail "unexpected post-detach rc=$rc_after" ;;
esac
