#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-8-exec-then-fork-exec.sh
# Bypass class: exec-followed-by-fork-to-different-binary. Models the
# SPEC §8 BX-8 chain: `/usr/sbin/aide` exec's, then forks a child that
# exec's `/bin/sh -c 'cat /var/lib/aide/aide.db'`. After the child's
# exec, mm->exe_file is /bin/sh's inode (or cat's after the next exec) —
# NOT in `actor aide`. Actor check on the child must DENY.
#
# Implementation: we model the chain with `sh -c "$NONACTOR ..."`.
# - The starting sh exec replaces our process image with sh.
# - sh forks a child to run NONACTOR; child execs NONACTOR.
# - The grandchild's mm->exe_file is NONACTOR's inode, not the actor's.
# That grandchild does the seal-gated op; the actor check fires on
# NONACTOR's inode → DENY.
# Suggestion ID: SPEC §8 BX-8
set -u
BYPASS_NAME="BX-8-exec-then-fork-exec"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
ACTOR=$(ed_create_actor actor)
NONACTOR=$(ed_create_actor non-actor)   # distinct inode, NOT in actor group

ed_setup_actor_seal myactor "$ACTOR" "no-write"

# Chain: this script's shell forks an sh child; sh forks-and-execs
# NONACTOR. The final process's exe inode is NONACTOR's. Capture rc.
sh -c "'$NONACTOR' open-write '$TARGET' >/dev/null 2>&1"; rc=$?
case $rc in
	1) bypass_pass "fork+exec to non-actor binary denied (exe inode = non-actor)" ;;
	0) bypass_fail "BYPASS: non-actor child exec'd through sh succeeded" ;;
	*) bypass_fail "unexpected rc=$rc (expected 1=DENY)" ;;
esac
