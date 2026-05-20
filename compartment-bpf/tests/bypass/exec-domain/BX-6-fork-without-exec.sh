#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-6-fork-without-exec.sh
# Correct-behavior witness, PASS-on-ALLOW: fork() copies mm->exe_file
# into the child. A child of the actor that has NOT exec'd is still
# identified as the actor (same exe inode). The seal-gated op in the
# child must be ALLOWED.
#
# This is the ONE BX test whose expected sealprobe-style rc is 0 (ALLOW),
# not 1 (DENY). If actor_check_or_deny mishandled the fork-inheritance
# case (e.g. cleared mm->exe_file on fork) the child would be wrongly
# denied — that would be the bug this witness guards against.
# Suggestion ID: SPEC §8 BX-6
set -u
BYPASS_NAME="BX-6-fork-without-exec"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env

command -v cc >/dev/null 2>&1 || bypass_skip "cc not present (needed to build fork-actor helper)"

TMP=$(mktemp -d /tmp/bypass.XXXXXX)

# Build a tiny ELF helper that fork()s and lets the child do open-WRONLY.
# Lives in $TMP so it has a fresh, predictable inode. Used as the actor.
cat > "$TMP/fork-actor.c" <<'EOF'
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
int main(int argc, char **argv) {
	if (argc != 3) return 2;            /* usage */
	pid_t p = fork();
	if (p < 0) return 4;                /* stage error */
	if (p == 0) {
		int fd = open(argv[2], O_WRONLY);
		if (fd >= 0) { close(fd); _exit(0); }   /* ALLOW */
		_exit(1);                                /* DENY (EACCES or other) */
	}
	int s;
	if (waitpid(p, &s, 0) < 0) return 4;
	return WIFEXITED(s) ? WEXITSTATUS(s) : 4;
}
EOF
ACTOR="$TMP/fork-actor"
cc -O1 -o "$ACTOR" "$TMP/fork-actor.c" \
	|| bypass_skip "cc failed to build fork-actor helper"
chmod 0755 "$ACTOR"

ed_setup_actor_seal myactor "$ACTOR" "no-write"

# Invoke. The parent fork-actor process is in the actor group; the child
# inherits mm->exe_file → child's exe inode == actor's. open-WRONLY in
# the child must be ALLOWED.
"$ACTOR" probe "$TARGET" >/dev/null 2>&1; rc=$?
case $rc in
	0) bypass_pass "fork-without-exec child allowed (exe inode preserved across fork)" ;;
	1) bypass_fail "actor's forked child was DENIED — fork-inheritance regression" ;;
	*) bypass_fail "unexpected rc=$rc (expected 0=ALLOW)" ;;
esac
