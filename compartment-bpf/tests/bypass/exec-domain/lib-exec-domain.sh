# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/lib-exec-domain.sh — actor-allowlist test helpers.
#
# Sourced by each tests/bypass/exec-domain/BX-*.sh after lib-bypass.sh. The
# parent lib provides bypass_die/skip/pass/fail + bypass_check_env. This
# adds the actor-binary fixture creation + actor-bound daemon setup.
#
# Design choice: actor binaries are copies of $SEALPROBE. That gives every
# BX script a deterministic exit code (sealprobe's 0=ALLOW / 1=DENY) when
# the actor (or an impostor at the actor path) invokes the read/write op
# against the sealed target. The (dev, ino) check fires on the copy's
# inode, which is distinct from the original SEALPROBE inode and from any
# other copy — exactly the property under test.
#
# Globals after ed_setup_actor_seal: $TMP, $TARGET, $ACTOR, $DAEMON_PID,
# $DAEMON_LOG. Cleanup is inherited from lib-bypass.sh's trap.

# ed_create_actor <relname>
#   Copy $SEALPROBE to $TMP/$relname, chmod 0755. Echo the new path.
#   Each invocation produces a NEW inode (cp creates a fresh file). The
#   inode-identity property of the actor check is what we want to verify:
#   two copies of the same bytes have distinct inodes.
ed_create_actor() {
	_ed_relname=$1
	[ -n "${TMP:-}" ] || bypass_die "ed_create_actor: TMP not set (call mktemp first)"
	_ed_out="$TMP/$_ed_relname"
	cp "$SEALPROBE" "$_ed_out" || bypass_die "ed_create_actor: cp failed"
	chmod 0755 "$_ed_out" || bypass_die "ed_create_actor: chmod failed"
	printf '%s\n' "$_ed_out"
}

# ed_setup_actor_seal <actor_name> <actor_path> <target_flags> [extra-seal-lines...]
#   Create $TMP/target, write a policy with:
#     actor <actor_name> = <actor_path>
#     seal <actor_path> full                            (ED-5 strict mode)
#     seal $TMP/target <target_flags> actor=<actor_name>
#   plus any verbatim extra lines, then launch the daemon and wait live.
#   Sets globals $TARGET, $DAEMON_PID, $DAEMON_LOG.
#
#   Caller must have created $TMP via mktemp -d /tmp/bypass.XXXXXX (so
#   bypass_teardown's `rm -rf $TMP` cleans up correctly).
ed_setup_actor_seal() {
	_ed_actor=$1
	_ed_actor_path=$2
	_ed_flags=$3
	shift 3
	[ -n "${TMP:-}" ] || bypass_die "ed_setup_actor_seal: TMP not set"
	[ -x "$_ed_actor_path" ] || bypass_die "ed_setup_actor_seal: actor not executable: $_ed_actor_path"

	TARGET="$TMP/target"
	echo content > "$TARGET"
	{
		printf 'actor %s = %s\n' "$_ed_actor" "$_ed_actor_path"
		# ED-5 strict mode: actor binary must be sealed full at its
		# declared path. `full` expands to no-write,no-unlink,
		# no-rename,no-chmod — exactly what strict-mode requires.
		printf 'seal %s full\n' "$_ed_actor_path"
		printf 'seal %s %s actor=%s\n' "$TARGET" "$_ed_flags" "$_ed_actor"
		while [ "$#" -gt 0 ]; do printf '%s\n' "$1"; shift; done
	} > "$TMP/policy.conf"

	DAEMON_LOG="$TMP/daemon.err"
	"$DAEMON" "$TMP/policy.conf" >"$DAEMON_LOG" 2>&1 &
	DAEMON_PID=$!
	for _ in $(seq 1 100); do
		grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null && break
		kill -0 "$DAEMON_PID" 2>/dev/null \
			|| { cat "$DAEMON_LOG" >&2; bypass_die "daemon died during attach"; }
		sleep 0.1
	done
	grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null \
		|| { cat "$DAEMON_LOG" >&2; bypass_die "daemon did not go live"; }
}

# ed_invoke <actor-path> <sealprobe-op> [args...]
#   Run "$actor_path $op ..." (the actor-as-sealprobe convention). Echoes
#   the rc to stdout (so $(ed_invoke ...) captures it) and never exits the
#   caller — leaves PASS/FAIL/SKIP decisions to the BX script.
ed_invoke() {
	_ed_actor=$1; shift
	"$_ed_actor" "$@" >/dev/null 2>&1
	printf '%s\n' "$?"
}
