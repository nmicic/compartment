#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-2-mount-namespace.sh
# Bypass class: mount-namespace-decoy — attacker creates a private mount
# namespace with a different binary bind-mounted at the actor path, then
# exec's. The (dev, ino) the kernel sees at exec time is the decoy's,
# regardless of which namespace performed the mount; mm->exe_file is the
# decoy inode. Actor check must DENY identically across mount namespaces.
# Suggestion ID: SPEC §8 BX-2
set -u
BYPASS_NAME="BX-2-mount-namespace"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env

command -v unshare >/dev/null 2>&1 || bypass_skip "unshare not present"

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
ACTOR=$(ed_create_actor actor)
DECOY=$(ed_create_actor decoy)

ed_setup_actor_seal myactor "$ACTOR" "no-write"

# Pre-flight: unshare -m may be blocked by user_namespaces sysctl or
# CAP_SYS_ADMIN gating. SKIP cleanly instead of false-failing.
unshare -m true 2>/dev/null || bypass_skip "unshare -m not permitted in this environment"

# Inside a private mount namespace: bind-mount decoy over ACTOR, then
# invoke ACTOR (which now resolves to DECOY's inode). Propagate the
# inner sealprobe's rc as the unshare process exit. Sentinel 100 means
# the mount itself failed (env limitation → SKIP).
unshare -m sh -c "
	mount --bind '$DECOY' '$ACTOR' 2>/dev/null || exit 100
	'$ACTOR' open-write '$TARGET' >/dev/null 2>&1
	exit \$?
"
rc=$?

[ "$rc" = "100" ] && bypass_skip "bind-mount inside unshare -m failed"

case $rc in
	1) bypass_pass "open-write in mount-ns decoy denied (exe_inode != actor inode)" ;;
	0) bypass_fail "BYPASS: open-write succeeded via mount-namespace decoy" ;;
	*) bypass_fail "unexpected rc=$rc (expected 1=DENY)" ;;
esac
