#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-14-actor-self-mod.sh
# P1-C (V-6 re-run #3, 2026-05-16) + P1-B (V-6 re-run #4, 2026-05-16):
# assert the loader rejects an actor-binary seal that carries `actor=NAME`
# AND that an actor-strict launcher seal carrying `actor=NAME` is
# rejected with a launcher-specific diagnostic.
#
# enforce_actor_binaries_sealed previously checked only that the actor
# binary seal carried the four required flags. If the operator wrote
# `seal /opt/actor full actor=myactor`, the actor process would appear
# in its own seal's allowlist and actor_check_or_deny would return ALLOW
# for writes/renames/etc to its own binary, defeating SPEC §7.1 E-6 (the
# actor can overwrite its own bytes in-place, preserving (dev,ino)).
#
# Witnesses:
#   1. Profile with `actor=myactor` on the actor binary's own seal →
#      `--dry-run` exits non-zero with the diagnostic naming the actor +
#      binary path + "prevents self-modification gate".
#   2. The correctly-shaped profile (actor binary seal with no `actor=`,
#      data-dir seal with `actor=myactor`) → `--dry-run` exits 0.
#   3. V-6 re-run #4 P1-B (symmetric for launchers): strict-launch profile
#      with `actor=a_target` on the launcher seal → `--dry-run` exits
#      non-zero with "prevents launcher self-modification gate".
#   4. The correctly-shaped strict-launch profile (launcher seal with no
#      `actor=`) → `--dry-run` either accepts the profile OR fails for an
#      unrelated reason (e.g. dynamic-launcher ELF rejection), as long
#      as the launcher self-mod diagnostic is NOT emitted.
set -u
BYPASS_NAME="BX-14-actor-self-mod"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

ACTOR=$(ed_create_actor actor)
DATADIR="$TMP/data"
mkdir -p "$DATADIR"
echo content > "$DATADIR/file"

# ----- Witness 1: actor= on the actor binary's own seal is rejected. -----
cat > "$TMP/bad.conf" <<EOF
actor myactor = $ACTOR
seal $ACTOR no-write,no-unlink,no-rename,no-chmod actor=myactor
seal $DATADIR no-write,no-unlink,no-rename,no-chmod actor=myactor
EOF

OUT1="$TMP/w1.err"
"$DAEMON" --dry-run "$TMP/bad.conf" >"$OUT1" 2>&1
rc1=$?
if [ "$rc1" -eq 0 ]; then
	cat "$OUT1" >&2
	bypass_fail "loader accepted actor= on actor binary seal (self-modification gap)"
fi
if ! grep -q "prevents self-modification gate" "$OUT1"; then
	cat "$OUT1" >&2
	bypass_fail "loader rejected but without the expected self-mod diagnostic"
fi
if ! grep -q "myactor" "$OUT1"; then
	cat "$OUT1" >&2
	bypass_fail "self-mod diagnostic did not name the actor"
fi

# ----- Witness 2: correct asymmetric profile loads. -----
cat > "$TMP/good.conf" <<EOF
actor myactor = $ACTOR
seal $ACTOR no-write,no-unlink,no-rename,no-chmod
seal $DATADIR no-write,no-unlink,no-rename,no-chmod actor=myactor
EOF

OUT2="$TMP/w2.err"
"$DAEMON" --dry-run "$TMP/good.conf" >"$OUT2" 2>&1
rc2=$?
if [ "$rc2" -ne 0 ]; then
	cat "$OUT2" >&2
	bypass_fail "correct asymmetric profile rejected (rc=$rc2)"
fi
if grep -q "prevents self-modification gate" "$OUT2"; then
	cat "$OUT2" >&2
	bypass_fail "good profile triggered self-mod diagnostic"
fi

# ----- Witness 3 (P1-B): actor= on launcher seal is rejected. -----
# enforce_actor_binaries_sealed runs before strict_validate_launchers, so
# its path-based launcher check fires first — the launcher need not be a
# valid statically-linked ELF for this witness; we only assert the loader
# emits the launcher self-modification gate diagnostic.
LAUNCHER=$(ed_create_actor launcher_w3)
TARGET3=$(ed_create_actor target_w3)
cat > "$TMP/strict_bad.conf" <<EOF
actor a_target = $TARGET3
actor-strict st = $TARGET3 launcher=$LAUNCHER
seal $LAUNCHER no-write,no-unlink,no-rename,no-chmod actor=a_target
seal $TARGET3 no-write,no-unlink,no-rename,no-chmod
EOF

OUT3="$TMP/w3.err"
"$DAEMON" --dry-run "$TMP/strict_bad.conf" >"$OUT3" 2>&1
rc3=$?
if [ "$rc3" -eq 0 ]; then
	cat "$OUT3" >&2
	bypass_fail "loader accepted actor= on actor-strict launcher seal (P1-B launcher self-mod gap)"
fi
if ! grep -q "launcher.*must not carry actor=" "$OUT3"; then
	cat "$OUT3" >&2
	bypass_fail "loader rejected but without the expected launcher self-mod diagnostic (P1-B)"
fi
# Match the exact actor name (quoted in the diagnostic) — bare "st" would
# false-positive against the substring of "actor-strict".
if ! grep -q "'st'" "$OUT3"; then
	cat "$OUT3" >&2
	bypass_fail "launcher self-mod diagnostic did not name the actor-strict actor 'st' (P1-B)"
fi

# ----- Witness 4 (P1-B): correct strict-launch profile does not trip the gate. -----
# The launcher in this fixture is a dynamically-linked sealprobe copy, so
# strict_validate_launchers will reject it for being dynamic. That is
# unrelated to P1-B — what we assert here is that the launcher
# self-modification diagnostic is NOT emitted when the launcher seal
# carries no `actor=`.
cat > "$TMP/strict_good.conf" <<EOF
actor a_target = $TARGET3
actor-strict st = $TARGET3 launcher=$LAUNCHER
seal $LAUNCHER no-write,no-unlink,no-rename,no-chmod
seal $TARGET3 no-write,no-unlink,no-rename,no-chmod
EOF

OUT4="$TMP/w4.err"
"$DAEMON" --dry-run "$TMP/strict_good.conf" >"$OUT4" 2>&1
if grep -q "launcher.*must not carry actor=" "$OUT4"; then
	cat "$OUT4" >&2
	bypass_fail "good strict-launch profile incorrectly tripped the launcher self-mod gate (P1-B false positive)"
fi

bypass_pass "actor-self-mod gate rejects actor= on binary seal (P1-C) and on launcher seal (P1-B v6-rerun4); correct shapes do not trip"
