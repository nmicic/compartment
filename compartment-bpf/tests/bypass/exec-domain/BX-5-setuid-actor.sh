#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-5-setuid-actor.sh
# Correct-behavior witness: the setuid bit on a non-actor binary does
# NOT make it satisfy the actor allowlist. mm->exe_file is the on-disk
# inode of the exec'd binary; the setuid bit influences only the
# credential transition. A setuid root binary that isn't in the actor
# group must still be DENIED at the actor check.
# Suggestion ID: SPEC §8 BX-5
set -u
BYPASS_NAME="BX-5-setuid-actor"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
ACTOR=$(ed_create_actor actor)                # in actor group
NONACTOR_SUID=$(ed_create_actor nonactor-suid)

# Toggle setuid bit on the NON-actor binary. The bit is preserved by cp
# across most filesystems; we set it explicitly to be deterministic.
chmod 4755 "$NONACTOR_SUID" || bypass_skip "filesystem refused setuid bit on tmpfs/$TMP"

# Daemon resolves actor → ACTOR's inode. NONACTOR_SUID is a distinct
# inode, never declared.
ed_setup_actor_seal myactor "$ACTOR" "no-write"

# R2-F7 (Review-2 HIGH): snapshot actor_mismatch_total BEFORE the
# attempted deny. --stats reads PINNED counters under PIN_ROOT/maps;
# BX-5 does not pin its daemon, so --stats may exit 2 with no
# counters available. Skip the counter assertion in that case
# with an [info] marker — the ringbuf actor=myactor is the
# load-bearing R2-F7 evidence either way.
STATS_OUT=$("$DAEMON" --stats 2>/dev/null); STATS_RC=$?
stats_before=$(printf '%s\n' "$STATS_OUT" | sed -n 's/.*actor_mismatch_total=\([0-9?]*\).*/\1/p' | head -1)
[ "$stats_before" = "?" ] && stats_before=0
: "${stats_before:=0}"
HAVE_STATS=1
[ "$STATS_RC" -ne 0 ] && HAVE_STATS=0

# Invoke the setuid non-actor. mm->exe_file = NONACTOR_SUID's inode (NOT
# the actor's). The setuid bit must not affect the (dev, ino) compared
# in actor_check_or_deny.
"$NONACTOR_SUID" open-write "$TARGET" >/dev/null 2>&1; rc=$?
case $rc in
	1) : ;;  # DENY — expected
	0) bypass_fail "BYPASS: setuid non-actor write succeeded — setuid bit influenced actor check?" ;;
	*) bypass_fail "unexpected rc=$rc (expected 1=DENY)" ;;
esac

# ringbuf__poll runs at 1s cadence; wait long enough for the event to
# land in DAEMON_LOG so the assertions below see it.
sleep 2

# R2-F7 assertion (a): actor_name=myactor in kernel audit emit.
# emit_audit_actor copies the actor-group name into the ABI v0.3
# audit_event slot; audit_handler renders it as `actor=<name>` on
# DENY_ACTOR_MISMATCH lines.
if ! grep -qE '\[audit\] DENY_ACTOR_MISMATCH .* actor=myactor' "$DAEMON_LOG"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "audit emit missing 'actor=myactor' on DENY_ACTOR_MISMATCH (R2-F7 ringbuf assertion)"
fi

# R2-F7 assertion (b): actor_mismatch_total strictly incremented
# (conditional on pinned counters being present — BX-5's daemon
# does not pin).
if [ "$HAVE_STATS" = "1" ]; then
	stats_after=$(
		"$DAEMON" --stats 2>/dev/null \
		| sed -n 's/.*actor_mismatch_total=\([0-9?]*\).*/\1/p' \
		| head -1
	)
	[ "$stats_after" = "?" ] && stats_after=0
	: "${stats_after:=0}"
	if [ "$stats_after" -le "$stats_before" ]; then
		bypass_fail "actor_mismatch_total did not increment ($stats_before → $stats_after)"
	fi
else
	stats_after="(no pinned counters; --stats rc=$STATS_RC; counter assertion skipped)"
fi

bypass_pass "setuid non-actor denied + actor=myactor in audit ringbuf + counter $stats_before → $stats_after (R2-F7 evidence)"
