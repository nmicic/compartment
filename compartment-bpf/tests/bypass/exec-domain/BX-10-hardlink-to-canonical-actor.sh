#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-10-hardlink-to-canonical-actor.sh
# Bypass class: hardlink TO the canonical actor binary's inode. An
# unprivileged user on a box with fs.protected_hardlinks=0 (or where
# the relevant policy doesn't fire — e.g. links inside an unsealed
# tmp dir) could `link("/usr/sbin/aide", "/tmp/myactor")` and then
# `exec /tmp/myactor`; current->mm->exe_file resolves to the SAME
# (dev, ino) as the canonical actor binary, inheriting actor identity.
#
# R2-F10 + R2-F11 (Review-2 HIGH) bracket the class at two layers:
#   R2-F11: LSM hook comp_inode_link denies the link if the source
#           inode has SEAL_NO_WRITE — strict-mode requires the actor
#           binary to be `full` sealed, so this fires uniformly.
#   R2-F10: loader emits a `[loader] WARNING` if fs.protected_hardlinks=0
#           at startup + LIMITATIONS.md row.
#
# This witness validates the LSM-layer property: the link syscall must
# DENY when the source is the canonical actor binary, regardless of
# whether the new link path is inside a sealed dir.
set -u
BYPASS_NAME="BX-10-hardlink-to-canonical-actor"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
ACTOR=$(ed_create_actor canonical-actor)

# ed_setup_actor_seal seals the actor binary `full` (ED-5 strict mode).
# `full` = no-write,no-unlink,no-rename,no-chmod — SEAL_NO_WRITE is set.
ed_setup_actor_seal myactor "$ACTOR" "no-write"

# Attempt: unprivileged-style hardlink from the canonical actor binary
# to a NEW path. R2-F11's comp_inode_link source-inode check must
# refuse the operation.
ALIAS="$TMP/aliased-actor"
ln "$ACTOR" "$ALIAS" 2>/dev/null
rc=$?
if [ "$rc" -eq 0 ]; then
	# link() returned success — the LSM didn't intercept. Verify
	# the alias really lives on disk (sanity: not a phantom).
	if [ -e "$ALIAS" ]; then
		bypass_fail "BYPASS: hardlink to SEAL_NO_WRITE actor binary succeeded (R2-F11 LSM check did not fire)"
	else
		bypass_fail "ln rc=0 but $ALIAS missing (test invariant violated)"
	fi
else
	bypass_pass "hardlink to canonical actor binary denied at the LSM layer (R2-F11)"
fi

# Side-check: confirm the loader emitted its hardlink-sysctl warning
# when fs.protected_hardlinks=0. Soft assertion (informational; the
# LSM-layer DENY above is the load-bearing property).
PROT=$(cat /proc/sys/fs/protected_hardlinks 2>/dev/null || echo unknown)
if [ "$PROT" = "0" ]; then
	if grep -q 'protected_hardlinks=0' "$DAEMON_LOG" 2>/dev/null; then
		printf '[info] %s: R2-F10 loader warn observed (sysctl=0)\n' "$BYPASS_NAME" >&2
	else
		printf '[info] %s: R2-F10 loader warn NOT in $DAEMON_LOG (sysctl=0); check daemon stderr capture\n' "$BYPASS_NAME" >&2
	fi
elif [ "$PROT" = "1" ]; then
	printf '[info] %s: fs.protected_hardlinks=1 on test VM; sysctl side already hardened (R2-F10 warn intentionally silent)\n' "$BYPASS_NAME" >&2
fi
