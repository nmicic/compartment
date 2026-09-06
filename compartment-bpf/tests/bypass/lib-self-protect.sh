# shellcheck shell=bash
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/lib-self-protect.sh — shared scaffolding for the
# --self-protect witnesses (22..26).
#
# Why these four do not use bypass_setup(): --self-protect only means anything
# for a PINNED policy, and bypass_setup() starts an unpinned daemon. They also
# need the loader to be a root-owned, non-group-writable image, because
# --self-protect refuses to arm against a maintenance binary anyone in the
# build group could overwrite (that refusal is itself part of the design, and
# BX-style witnesses run out of a group-writable checkout). So each witness
# installs its own root:root 0755 copy of the tree's loader into its private
# $TMP and drives that. The copy is a faithful image of the binary under test:
# same bytes, different inode, which is exactly what an upgrade produces.
#
# The probe-integrity guard in lib-bypass.sh still applies: every witness runs
# the wrapped $DAEMON at least once (a --dry-run of the same profile) so a
# witness that silently stopped exercising the loader cannot print PASS.

SP_PASS='compartment-self-protect-witness-passphrase'
SP_PIN=/sys/fs/bpf/compartment

sp_n_comp() { bpftool prog show 2>/dev/null | grep -c 'name comp_'; }
sp_npins()  { ls "$SP_PIN/links" 2>/dev/null | wc -l; }

# Wait for the kernel to free every compartment program. --unpin's own drain
# proof does this, but a witness that re-pins needs it too: two overlapping
# instances make every count in the witness ambiguous.
sp_drain() {
	for _ in $(seq 1 90); do
		[ "$(sp_n_comp)" -eq 0 ] && return 0
		sleep 1
	done
	return 1
}

sp_check_env() {
	[ "$(id -u)" -eq 0 ] || bypass_skip "needs root"
	grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
		|| bypass_skip "bpf not in active LSM"
	[ -x "$BYPASS_REAL_DAEMON" ] || bypass_skip "daemon not built"
	command -v bpftool >/dev/null 2>&1 || bypass_skip "bpftool not installed"
	mountpoint -q /sys/fs/bpf 2>/dev/null || bypass_skip "/sys/fs/bpf is not mounted"
	[ "$(sp_n_comp)" -eq 0 ] \
		|| bypass_skip "another compartment-bpf instance is loaded ($(sp_n_comp) programs); refusing to measure against a dirty box"
	# The loader must know --self-protect, or every witness below would be
	# measuring pre-feature behaviour and passing for the wrong reason.
	# usage() lists it, and an unknown flag exits 2 with usage on stderr, so
	# grep the usage text rather than relying on an exit code.
	"$BYPASS_REAL_DAEMON" --not-a-flag 2>&1 | grep -q -- '--self-protect' \
		|| bypass_skip "loader has no --self-protect (pre-feature build)"
}

# sp_install <dest> — a root-owned 0755 image of the loader under test.
sp_install() {
	cp "$BYPASS_REAL_DAEMON" "$1" || bypass_die "cannot copy loader to $1"
	chown 0:0 "$1" 2>/dev/null || bypass_die "cannot chown $1"
	chmod 0755 "$1" || bypass_die "cannot chmod $1"
}

# sp_pin <image> <profile> <logfile> [extra args...]
# Starts a --pin --self-protect daemon and waits for it to go live. The daemon
# is kept RUNNING so it drains the audit ringbuf: without a consumer the deny
# events are produced and dropped, and the audit half of every witness below
# would be unobservable.
sp_pin() {
	_img=$1; _prof=$2; _log=$3; shift 3
	COMPARTMENT_BPF_PASSPHRASE="$SP_PASS" \
		"$_img" --pin --self-protect "$@" "$_prof" >"$_log" 2>&1 &
	SP_PID=$!
	for _ in $(seq 1 400); do
		grep -q '\[run\] compartment-bpf live' "$_log" 2>/dev/null && return 0
		kill -0 "$SP_PID" 2>/dev/null || break
		sleep 0.1
	done
	if grep -q 'no usable bpf_lsm_bpf_map hook' "$_log" 2>/dev/null; then
		bypass_skip "kernel has no bpf_lsm_bpf_map hook; --self-protect refuses to load here (by design)"
	fi
	cat "$_log" >&2
	bypass_die "--pin --self-protect did not go live"
}

sp_kill_daemon() {
	if [ -n "${SP_PID:-}" ] && kill -0 "$SP_PID" 2>/dev/null; then
		kill "$SP_PID" 2>/dev/null || true
		wait "$SP_PID" 2>/dev/null || true
	fi
	SP_PID=""
}

# sp_unpin <image> — --unpin with the witness passphrase. Returns the rc.
sp_unpin() {
	COMPARTMENT_BPF_PASSPHRASE="$SP_PASS" "$1" --unpin >"${2:-/dev/null}" 2>&1
}

# sp_audit_wait <logfile> <token> — the ringbuf consumer is asynchronous.
sp_audit_wait() {
	for _ in $(seq 1 30); do
		grep -q "$2" "$1" 2>/dev/null && return 0
		sleep 0.1
	done
	return 1
}

# Teardown shared by all four: stop the daemon, unpin with the image that
# pinned (recorded in $SP_OWNER), drain, then hand back to lib-bypass.
sp_teardown() {
	sp_kill_daemon
	[ -n "${SP_OWNER:-}" ] && sp_unpin "$SP_OWNER" >/dev/null 2>&1
	sp_drain
	for m in ${SP_MOUNTS:-}; do
		umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null || true
	done
	bypass_teardown
}

# sp_expect_links — the ARMED pin set, name by name, against
# tests/expected-links.txt. pin-regression T4.6 asserts the default 28-link set
# (it pins without the flag); nothing asserted the armed one, so a future edit
# that stopped pinning comp_bpf_map would leave every deny in witnesses 22..25
# lasting exactly as long as the first `rm`. Rows marked `self-protect` are
# expected here and only here.
sp_expect_links() {
	_exp="$REPO/tests/expected-links.txt"
	[ -f "$_exp" ] || bypass_fail "tests/expected-links.txt is missing"
	_compat=absent
	grep -q '\[probe\] file_ioctl_compat hook: present' "$1" && _compat=present
	grep -q 'self-protection ARMED' "$1" \
		|| bypass_fail "the loader did not report self-protection ARMED; the witness would be measuring the default build"
	_want=$(mktemp /tmp/sp-links-want.XXXXXX)
	_got=$(mktemp /tmp/sp-links-got.XXXXXX)
	awk -v compat="$_compat" '
		/^[[:space:]]*(#|$)/ { next }
		{
			if ($2 == "conditional") { if (compat == "present") print $1; next }
			print $1
		}' "$_exp" | sort > "$_want"
	ls "$SP_PIN/links" 2>/dev/null | sort > "$_got"
	if ! _diff=$(diff "$_want" "$_got" 2>&1); then
		rm -f "$_want" "$_got"
		bypass_fail "armed pin set differs from expected-links.txt (< expected > actual): $(printf '%s' "$_diff" | tr '\n' ' ' | cut -c1-300)"
	fi
	# shellcheck disable=SC2034  # read by the calling witness's bypass_pass line
	SP_NLINKS=$(wc -l < "$_got" | tr -d ' \t')
	rm -f "$_want" "$_got"
}
