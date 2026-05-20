#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/smoke-actor.sh — Sec-3 / F8 runtime coverage of the actor-allowlist BPF path.
#
# Exercises end-to-end:
#   actor_check_or_deny + ACTION_DENY_ACTOR_MISMATCH + caller_dev/caller_ino audit
#   ED-5 path-equivalence strict-mode (the actor binary is sealed at its
#   declared path so strict-mode passes the load)
#   actor_mismatch_total counter increment (ED-7)
#
# Detect-and-skip on a host without BPF LSM / sudo, mirroring smoke.sh.
# Idempotent: --unpins on the way out regardless of outcome.

set -eu

if [ "$(uname -s)" != Linux ]; then
	echo "[skip] smoke-actor: not Linux"
	exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "[skip] smoke-actor: requires root for BPF LSM load"
	exit 0
fi

if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
	echo "[skip] smoke-actor: BPF not in /sys/kernel/security/lsm"
	exit 0
fi

BIN="$(cd "$(dirname "$0")/.." && pwd)/compartment-bpf"
if [ ! -x "$BIN" ]; then
	echo "[skip] smoke-actor: $BIN missing"
	exit 0
fi

tmp=$(mktemp -d /tmp/compartment-bpf-smoke-actor.XXXXXX)
pid=

cleanup() {
	if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
		kill -TERM "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	"$BIN" --unpin >/dev/null 2>&1 || true
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

# Build a real ELF actor binary as a copy of tests/sealprobe. Sealprobe
# does not dispatch on argv[0] (so a renamed copy still works), and gives
# us a stable 0=ALLOW / 1=DENY contract on a single write op. Older
# revisions of this test used `cp /bin/dd`, but uutils coreutils (the
# default on Ubuntu Resolute) is a multicall binary that refuses on any
# argv[0] not in its built-in table — a renamed copy aborts before the
# kernel ever sees the write. Same actor-binary pattern as
# tests/bypass/exec-domain/lib-exec-domain.sh.
SEALPROBE="$(cd "$(dirname "$0")" && pwd)/sealprobe"
if [ ! -x "$SEALPROBE" ]; then
	echo "[skip] smoke-actor: $SEALPROBE missing; run 'make test-tools'"
	exit 0
fi
ACTOR="$tmp/actor-writer"
INTRUDER="$tmp/intruder-writer"
cp "$SEALPROBE" "$ACTOR"
cp "$SEALPROBE" "$INTRUDER"
chmod 0755 "$ACTOR" "$INTRUDER"

SEALED="$tmp/sealed-target"
printf 'initial\n' > "$SEALED"

PROFILE="$tmp/profile.conf"
cat > "$PROFILE" <<EOF
actor allowed = $ACTOR

seal $ACTOR full
seal $SEALED no-write actor=allowed
EOF

# Start the daemon with --pin so policy survives daemon teardown.
DAEMON_LOG="$tmp/daemon.log"
"$BIN" --pin "$PROFILE" >"$DAEMON_LOG" 2>&1 &
pid=$!

# Wait up to 5s for the [run] sentinel.
for i in 1 2 3 4 5 6 7 8 9 10; do
	if grep -q '\[run\]' "$DAEMON_LOG" 2>/dev/null; then
		break
	fi
	sleep 0.5
done
if ! grep -q '\[run\]' "$DAEMON_LOG"; then
	echo "[FAIL] smoke-actor: daemon never reached [run]" >&2
	cat "$DAEMON_LOG" >&2
	exit 1
fi

# Test 1: write via $ACTOR (allowed actor) MUST succeed.
# sealprobe exit codes: 0=ALLOW, 1=DENY, anything else = staging error.
rc=0; "$ACTOR" open-write "$SEALED" || rc=$?
if [ "$rc" -ne 0 ]; then
	echo "[FAIL] smoke-actor: allowed actor write rc=$rc (expected 0=ALLOW)" >&2
	exit 1
fi
echo "[PASS] smoke-actor: allowed actor write succeeded"

# Test 2: write via $INTRUDER (not in allowlist) MUST be denied.
rc=0; "$INTRUDER" open-write "$SEALED" || rc=$?
if [ "$rc" -ne 1 ]; then
	echo "[FAIL] smoke-actor: intruder write rc=$rc (expected 1=DENY)" >&2
	exit 1
fi
echo "[PASS] smoke-actor: intruder write denied (ACTION_DENY_ACTOR_MISMATCH)"

# Test 3: actor_mismatch_total MUST be > 0.
STATS="$("$BIN" --stats 2>&1 || true)"
if ! echo "$STATS" | grep -Eq 'actor_mismatch_total=([1-9][0-9]*)'; then
	echo "[FAIL] smoke-actor: actor_mismatch_total counter did not increment" >&2
	echo "$STATS" >&2
	exit 1
fi
echo "[PASS] smoke-actor: actor_mismatch_total counter incremented"

echo "[OK] smoke-actor: 3/3 tests passed"
exit 0
