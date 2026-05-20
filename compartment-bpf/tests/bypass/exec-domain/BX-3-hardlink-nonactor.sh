#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-3-hardlink-nonactor.sh
# Bypass class: hardlink-of-non-actor-binary at a misleading path. The
# attacker creates a directory entry whose NAME looks like the actor
# path but whose INODE points to a non-actor binary. Identity is keyed
# on (dev, ino), not on path — so the misleading name does not matter.
# Actor check must DENY.
#
# NOTE: a hardlink TO the actor binary's inode (i.e. another path
# pointing to the SAME inode the daemon resolved) IS allowed by design.
# Inode-identity is the contract — see SPEC §8 BX-3 italics. This
# witness verifies the converse: same NAME-looks, different INODE → DENY.
# Suggestion ID: SPEC §8 BX-3
set -u
BYPASS_NAME="BX-3-hardlink-nonactor"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
ACTOR=$(ed_create_actor actor)        # the real actor, declared inode
DECOY=$(ed_create_actor decoy)        # distinct non-actor inode

# Misleading path: an alternate directory entry pointing at DECOY's inode.
# `actor.hl` looks like a hardlink-alias of the actor, but it's actually
# linked to the decoy.
MISLEADING="$TMP/actor.hl"
ln "$DECOY" "$MISLEADING" || bypass_die "could not hardlink decoy (fs-level)"

ed_setup_actor_seal myactor "$ACTOR" "no-write"

# Invoke via the misleading path. exe_inode is DECOY's. Not in actor
# group → DENY.
"$MISLEADING" open-write "$TARGET" >/dev/null 2>&1; rc=$?
case $rc in
	1) bypass_pass "hardlink-to-non-actor at misleading path denied (inode-identity wins over path)" ;;
	0) bypass_fail "BYPASS: write via misleading-name hardlink succeeded — path-derived identity bug?" ;;
	*) bypass_fail "unexpected rc=$rc (expected 1=DENY)" ;;
esac
