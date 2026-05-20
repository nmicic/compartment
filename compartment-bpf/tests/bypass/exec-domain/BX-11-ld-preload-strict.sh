#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-11-ld-preload-strict.sh
#
# v0.4 promotion: convert the spike's SPEC §1 headline gap into a
# permanent regression witness. With a `strict-launch` seal on
# /tmp/sealed.db bound to an `actor-strict` declaration, a direct
# `LD_PRELOAD=evil.so $ACTOR write $SEALED` must DENY at the kernel
# layer (ACTION_DENY_STRICT_LAUNCH_MISSING). The same operation with
# v0.3 `actor=` alone would ALLOW because LD_PRELOAD does not change
# the exe inode — that is precisely the gap the strict-launch marker
# closes.
#
# Skips cleanly when spike fixtures aren't built (the in-tree
# strict-launch test owns the fixture build path; this bypass witness
# only verifies the LSM-layer DENY when the fixtures exist).

set -u
BYPASS_NAME="BX-11-ld-preload-strict"
. "$(dirname "$0")/../lib-bypass.sh"

bypass_check_env

SPIKE_DIR="$(dirname "$0")/../../../experimental/strict-launch-marker"
LAUNCHER="$SPIKE_DIR/build/slm-launcher"
ACTOR="$SPIKE_DIR/build/slm-actor"

if [ ! -x "$LAUNCHER" ] || [ ! -x "$ACTOR" ]; then
    bypass_skip "spike fixtures missing ($LAUNCHER / $ACTOR); run \`make check-strict-launch\` to build them"
fi

LAUNCHER_ABS=$(readlink -f "$LAUNCHER")
ACTOR_ABS=$(readlink -f "$ACTOR")

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
TARGET="$TMP/sealed.db"
: >"$TARGET"

# Build a no-op LD_PRELOAD .so
cat >"$TMP/preload.c" <<'EOF'
__attribute__((constructor)) static void slm_pre(void) {}
EOF
gcc -shared -fPIC -o "$TMP/preload.so" "$TMP/preload.c" 2>/dev/null \
    || bypass_die "cannot build LD_PRELOAD stub"

cat >"$TMP/policy.conf" <<EOF
actor-strict bx11 = $ACTOR_ABS launcher=$LAUNCHER_ABS

seal $LAUNCHER_ABS full
seal $ACTOR_ABS full
seal $TARGET no-write actor=bx11 strict-launch
EOF

# Review-1 HIGH-14 (2026-05-15): the original BX-11 PASS condition was
# `rc != 0` only, which is satisfied by ANY deny on this path (no-write,
# actor-mismatch, strict-launch — they all return non-zero). The spike's
# original BX-11 also read `strict_launch_missing_total` exactly to
# distinguish strict-launch from any-other-deny; the in-tree lift
# dropped that read. Use --pin so the counters land at PIN_ROOT for
# readback, and assert the counter delta.
PIN_ROOT=/sys/fs/bpf/compartment

# lib-bypass.sh's bypass_pass / bypass_fail call exit, which skips any
# inline cleanup. Chain --unpin onto the existing teardown trap so the
# next test in run-all.sh starts with a clean PIN_ROOT regardless of
# this script's exit path.
bx11_cleanup() {
    "$DAEMON" --unpin >/dev/null 2>&1 || true
    bypass_teardown
}
trap bx11_cleanup EXIT INT TERM

rm -rf "$PIN_ROOT" 2>/dev/null || true
DAEMON_LOG="$TMP/daemon.log"
"$DAEMON" --pin "$TMP/policy.conf" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 60); do
    grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null && break
    kill -0 "$DAEMON_PID" 2>/dev/null || { cat "$DAEMON_LOG" >&2; bypass_die "daemon died"; }
    sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null \
    || { cat "$DAEMON_LOG" >&2; bypass_die "daemon did not go live"; }

read_strict_missing() {
    local pin="$PIN_ROOT/maps/strict_launch_missing_total"
    [ -e "$pin" ] || { echo 0; return; }
    bpftool -j map dump pinned "$pin" 2>/dev/null | python3 -c '
import json, sys
d=json.load(sys.stdin)
total=0
for e in d:
    if "values" in e:
        for cpu in e["values"]:
            v=cpu["value"]
            if isinstance(v, list):
                acc=0
                for i,b in enumerate(v):
                    if isinstance(b,str): b=int(b,16)
                    acc |= b << (8*i)
                v=acc
            total += int(v)
    else:
        v=e["value"]
        if isinstance(v, list):
            acc=0
            for i,b in enumerate(v):
                if isinstance(b,str): b=int(b,16)
                acc |= b << (8*i)
            v=acc
        total += int(v)
print(total)' 2>/dev/null || echo 0
}

pre_missing=$(read_strict_missing)

# The bypass attempt: LD_PRELOAD against the actor target, direct
# exec (no launcher → no marker → strict-launch check denies).
LD_PRELOAD=$TMP/preload.so "$ACTOR_ABS" write "$TARGET" 2>>"$DAEMON_LOG"
rc=$?

# Brief grace period to let the BPF percpu counter settle.
sleep 0.2
post_missing=$(read_strict_missing)
d_missing=$((post_missing - pre_missing))

if [ "$rc" -eq 0 ]; then
    bypass_fail "BYPASS: LD_PRELOAD direct exec wrote to a strict-launch-sealed file (kernel marker check did not fire); strict_launch_missing delta=$d_missing"
elif [ "$d_missing" -ge 1 ]; then
    bypass_pass "LD_PRELOAD direct exec denied at LSM (strict_launch_missing); rc=$rc miss+$d_missing"
else
    # HIGH-14: rc!=0 alone is INSUFFICIENT. Could be no-write or
    # actor-mismatch denying for an adjacent reason while the
    # strict-launch hook silently degrades to no-op. Fail loud.
    bypass_fail "FALSE-GREEN: rc=$rc but strict_launch_missing_total delta=$d_missing (expected >=1); strict-launch hook did not fire"
fi

kill -TERM "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
# --unpin happens via the bx11_cleanup trap above.
