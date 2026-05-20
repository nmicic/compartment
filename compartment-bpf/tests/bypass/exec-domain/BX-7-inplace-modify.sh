#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-7-inplace-modify.sh
# Bypass class: in-place modification of the actor binary + path-swap.
# This is the case ED-5 (E-6) strict-mode exists to defend. Two
# sub-attacks, both must DENY:
#
#   #1 in-place write: dd / open-write the actor binary at its declared
#      path. Without E-6, the inode survives, the actor group still
#      "matches", but the bytes the kernel exec's are now the attacker's.
#      With E-6, the actor binary carries no-write,no-unlink,no-rename,
#      no-chmod (loader-enforced strict mode) and the open-for-write
#      fails before any byte is written.
#
#   #2 path-swap: rename the actor binary aside and drop a different
#      binary at its declared path. Strict mode also requires
#      no-rename on the actor binary, so the rename itself is denied —
#      and even if it weren't, the new inode at the path is not in the
#      actor group, so the impostor would be denied at next exec
#      (overlap with BX-1 in spirit; covered there).
#
# A-2 (2026-05-15): consolidated to a single PASS/FAIL label per script.
# Previously emitted two PASS lines (7a + 7b) which broke the runner's
# "exactly one label per script" invariant — a 7a→FAIL while 7b passed
# would still leave one PASS in the stream and look green at the suite
# tally. Fix shape: track each sub-attack outcome silently; emit one
# consolidated bypass_pass at the end. bypass_fail fail-fast still gives
# specific 7a / 7b diagnostics on the failure path.
# Suggestion ID: SPEC §8 BX-7
set -u
BYPASS_NAME="BX-7-inplace-modify"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
ACTOR=$(ed_create_actor actor)

# ed_setup_actor_seal already seals $ACTOR `full` per ED-5 strict mode.
ed_setup_actor_seal myactor "$ACTOR" "no-write"

# --- Sub-attack #1: in-place write to the actor binary ----------------
# sub-attack: in-place write to actor binary at its declared path.
"$SEALPROBE" open-write "$ACTOR" >/dev/null 2>&1; rc1=$?
case $rc1 in
	1) : ;;  # denied as expected
	0) bypass_fail "7a BYPASS: in-place write to actor binary succeeded — E-6 not enforced" ;;
	*) bypass_fail "7a unexpected rc=$rc1 (expected 1=DENY)" ;;
esac

# --- Sub-attack #2: rename the actor binary aside ---------------------
# sub-attack: rename actor binary aside (path-swap precursor).
"$SEALPROBE" rename "$ACTOR" "$TMP/actor.attacker-stash" >/dev/null 2>&1; rc2=$?
case $rc2 in
	1) : ;;  # denied as expected
	0) bypass_fail "7b BYPASS: rename of actor binary succeeded — path-swap attack possible" ;;
	*) bypass_fail "7b unexpected rc=$rc2 (expected 1=DENY)" ;;
esac

bypass_pass "7a in-place write + 7b rename of actor binary both denied (ED-5 strict-mode seal)"
