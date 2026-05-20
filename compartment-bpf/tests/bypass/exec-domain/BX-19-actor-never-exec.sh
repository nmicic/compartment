#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-19-actor-never-exec.sh
#
# GAP-H-7 (coverage audit 2026-05-16): silent-DENY semantics has no
# positive witness when the declared actor never executes. The contract
# is "seal-rule-driven enforcement", not "actor-process-driven"; the
# BPF hooks consult the per-inode seal map at every protected op
# regardless of which actor processes have been observed. A regression
# that lazily registered an actor's seals only after the actor's first
# exec would silently defeat protection until the actor first ran.
#
# Witnesses:
#   W1 — Load policy with `actor mute = $ACTOR` and a sealed target
#        carrying `actor=mute`. Without ever exec'ing $ACTOR, a
#        non-actor process (sealprobe at a distinct inode) attempts
#        open-WRONLY against $TARGET. Must DENY.
#   W2 — Same policy, same non-actor; attempts unlink against $TARGET.
#        Must DENY. (Defense-in-depth across two op-classes — proves
#        the seal map is populated and consulted, not that one specific
#        hook was patched in lazily.)
#
# The witness deliberately spawns a NEW shell with `sh -c` to invoke
# the non-actor probe so the probe binary (sealprobe) is exec'd fresh;
# the parent shell's process has never executed the actor binary either,
# but we want a clean separate process to make the "non-actor" identity
# unambiguous.
set -u
BYPASS_NAME="BX-19-actor-never-exec"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)

# Create the actor binary fixture but DO NOT execute it. The point of
# this witness is that the seal rules apply even when the actor has
# never been seen by the BPF hooks.
ACTOR=$(ed_create_actor mute_actor)

# Seal $TARGET with full op-class coverage and bind to actor=mute so
# only `mute` exec'd processes would be allowed. ed_setup_actor_seal
# passes "no-write" only; we want the full set to also gate unlink.
ed_setup_actor_seal mute "$ACTOR" "no-write,no-unlink"

# Sanity: actor binary has never been run. (If a prior leak ever exec'd
# it, exit code 4 would indicate stage error — confirm via stat that the
# fixture is the same inode we sealed and that no PID currently has it
# as its exe.) The check is best-effort; the main assertion is the
# DENY below.
[ -x "$ACTOR" ] || bypass_die "actor binary missing post-setup"

# ----- W1: non-actor open-WRONLY → DENY -----
# Use sealprobe directly (NOT the actor binary). sealprobe has a
# distinct inode (Makefile-built tests/sealprobe vs. ed_create_actor's
# fresh copy), so the BPF hook sees a non-actor task. open-WRONLY
# under a `no-write actor=mute` seal must deny with rc=1.
"$SEALPROBE" open-write "$TARGET" >/dev/null 2>&1; rc1=$?
case "$rc1" in
    1) ;;  # DENY — expected
    0) bypass_fail "W1 BYPASS: non-actor process allowed to write to sealed target while actor 'mute' was never exec'd (silent-DENY contract violated)" ;;
    *) bypass_fail "W1 unexpected rc=$rc1 (want 1=DENY)" ;;
esac

# ----- W2: non-actor unlink → DENY -----
"$SEALPROBE" unlink "$TARGET" >/dev/null 2>&1; rc2=$?
case "$rc2" in
    1) ;;  # DENY — expected
    0) bypass_fail "W2 BYPASS: non-actor process allowed to unlink sealed target while actor 'mute' was never exec'd" ;;
    *) bypass_fail "W2 unexpected rc=$rc2 (want 1=DENY)" ;;
esac

# Sanity: confirm $TARGET is still on disk (W2 must have been denied).
[ -f "$TARGET" ] \
    || bypass_fail "W2 post-check: $TARGET vanished — unlink was NOT denied"

bypass_pass "actor 'mute' never executed, yet sealed target is DENY for non-actor writes (W1) and unlinks (W2) — enforcement is seal-driven, not actor-presence-driven"
