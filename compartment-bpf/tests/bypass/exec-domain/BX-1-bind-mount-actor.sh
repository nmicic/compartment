#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-1-bind-mount-actor.sh
# Bypass class: bind-mount-over-actor — attacker uses `mount --bind` to
# overlay a non-actor binary at the declared actor path, then exec's the
# path. The caller's mm->exe_file inode is the decoy's, NOT the actor's
# inode the daemon resolved at load time. Actor check must DENY.
# Suggestion ID: SPEC §8 BX-1
set -u
BYPASS_NAME="BX-1-bind-mount-actor"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
ACTOR=$(ed_create_actor actor)
DECOY=$(ed_create_actor decoy)   # distinct sealprobe-copy inode, NOT in actor group

# Start daemon AFTER both files exist; before any bind-mount. Daemon
# resolves actor → ACTOR's real inode at load time (O_PATH+fstat).
ed_setup_actor_seal myactor "$ACTOR" "no-write"

# Now bind-mount the decoy over the actor path. Daemon's resolved (dev,
# ino) is unaffected (it captured the original inode). Any exec via the
# ACTOR path now runs DECOY's bytes; the running process's mm->exe_file
# is the DECOY inode.
mount --bind "$DECOY" "$ACTOR" 2>/dev/null \
	|| bypass_skip "bind-mount of regular file failed (need privileged mount)"

# Ensure we umount on every exit path — runs before lib-bypass.sh's
# teardown so $DAEMON gets killed cleanly with no live bind-mount.
_bx1_cleanup() { umount "$ACTOR" 2>/dev/null || true; }
trap '_bx1_cleanup; bypass_teardown' EXIT INT TERM

# Invoke the actor path. Kernel exec resolves the bind-mounted inode
# (= DECOY), so the running sealprobe-copy is the decoy. Its exe_inode
# is NOT in the actor group → write must DENY.
"$ACTOR" open-write "$TARGET" >/dev/null 2>&1; rc=$?
case $rc in
	1) bypass_pass "open-write via bind-mounted decoy denied (exe_inode != actor inode)" ;;
	0) bypass_fail "BYPASS: open-write succeeded after bind-mount-over-actor" ;;
	*) bypass_fail "unexpected rc=$rc (expected 1=DENY)" ;;
esac
