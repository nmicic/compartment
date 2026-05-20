#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-9-version-mismatch.sh
# R2-F7 (Review-2 HIGH): synthetic witness for the ABI version-mismatch
# warn-skip branch in audit_handler (compartment-bpf.c, ~line 1538).
# The original ED-13 evidence pyramid did not exercise this branch;
# the elephant verdict (F-ELE-3) flagged the gap.
#
# Mechanism: compartment-bpf, when run with the test env knob
# COMPARTMENT_BPF_TEST_EMIT_BAD_VERSION=1, fabricates one audit_event
# with version=0xFFFE on the stack and feeds it through audit_handler
# once at startup. The handler's version-mismatch branch fires and
# emits a `warn: audit event version mismatch (got 0xfffe, ...)` line
# on stderr. We assert that warn line appears in daemon stderr and
# that the daemon still goes live (the branch fail-closed-skips the
# event, not the whole daemon).
#
# Userspace cannot inject into BPF_MAP_TYPE_RINGBUF (see DEC-LDR7-B),
# so this synthetic stack-event path is the only feasible witness.
set -u
BYPASS_NAME="BX-9-version-mismatch"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
ACTOR=$(ed_create_actor actor)

# Launch the daemon with the test knob. ed_setup_actor_seal already
# starts a daemon; instead of using it, run our own daemon launch so
# we control env vars.
TARGET="$TMP/target"
echo content > "$TARGET"
cat > "$TMP/policy.conf" <<EOF
actor myactor = $ACTOR
seal $ACTOR full
seal $TARGET no-write actor=myactor
EOF

DAEMON_LOG="$TMP/daemon.err"
COMPARTMENT_BPF_TEST_EMIT_BAD_VERSION=1 \
	"$DAEMON" "$TMP/policy.conf" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do
	grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null && break
	kill -0 "$DAEMON_PID" 2>/dev/null \
		|| { cat "$DAEMON_LOG" >&2; bypass_die "daemon died during attach"; }
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null \
	|| { cat "$DAEMON_LOG" >&2; bypass_die "daemon did not go live"; }

# Assertion 1: the synthetic-emit marker landed.
if ! grep -q '\[test\] BX-9 synthetic bad-version event emitted' "$DAEMON_LOG"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "synthetic-emit marker missing (test env knob not honoured?)"
fi

# Assertion 2: audit_handler's version-mismatch warn branch fired.
if ! grep -qE 'warn: audit event version mismatch \(got 0xfffe' "$DAEMON_LOG"; then
	cat "$DAEMON_LOG" >&2
	bypass_fail "version-mismatch warn line missing in daemon stderr"
fi

# Assertion 3: the daemon kept running (fail-closed-skip the event, not
# the daemon).
if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
	bypass_fail "daemon died after synthetic bad-version event (expected: skip event, stay live)"
fi

bypass_pass "audit_handler version-mismatch branch emits warn + daemon stays live (R2-F7 BX-9)"
