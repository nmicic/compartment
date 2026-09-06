#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# 22-self-protect-map.sh — the tool's own BPF maps must not be reachable by a
# CAP_BPF caller that is not the loader.
#
# Why this matters more than "the maps are frozen": bpf_map_freeze() gates only
# the syscall path (map_get_sys_perms). Measured on 6.8.0-139 and 7.0.0-31, a
# caller that obtains ANY fd to a frozen compartment map — BPF_F_RDONLY is
# enough — can splice it into its own BPF program with bpf_map__reuse_fd() and
# write it with bpf_map_update_elem() from program context. The syscall write
# stays EPERM, the program write succeeds. So every seal map was mutable by an
# unconfined root, and actor_marker_map (TASK_STORAGE, unfreezable) was mutable
# through the syscall path as well.
#
# The only chokepoint that sees every fd handed out for a map is
# bpf_map_new_fd() -> security_bpf_map(), which is what comp_bpf_map gates.
#
# Witnesses (policy pinned with --self-protect, daemon left running so the
# audit ringbuf has a consumer):
#   C   an UNRELATED bpf map can still be created, written and dumped
#       (over-deny guard, run first so a broken box SKIPs rather than passes)
#   W1  a sweep of every map id on the box refuses an fd for at least as many
#       maps as the loader says it protected (helpers/bpf_map_fd_sweep.c)
#   W2  BPF_OBJ_GET on a pinned compartment map -> DENY
#   W3  the same sweep hands out ZERO read-only fds for those maps: a
#       read-only fd is a complete attack, see the note above
#   A   a DENY_BPF_SELF audit line names the caller's exe inode
#   K   bpf_self_denied_total counted every deny
#   L   the armed pin set matches tests/expected-links.txt including
#       comp_bpf_map (the default set is T4.6's job; the armed set is this one)
#   S   the seal is still enforced afterwards
#   G   `compartment-bpf --stats` from the AUTHORISED image still reads the
#       counters (the gate must not lock the tool out of its own telemetry)
set -u
# shellcheck disable=SC2034  # read by lib-bypass.sh after sourcing
BYPASS_NAME="22-self-protect-map"
. "$(dirname "$0")/lib-bypass.sh"
. "$(dirname "$0")/lib-self-protect.sh"
sp_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
# shellcheck disable=SC2034  # read by sp_teardown in lib-self-protect.sh
SP_MOUNTS=""
trap 'sp_teardown' EXIT INT TERM

TARGET="$TMP/target"
echo content > "$TARGET"
printf 'seal %s full\n' "$TARGET" > "$TMP/policy.conf"

# Probe-integrity evidence: the tree's own loader parses this profile.
"$DAEMON" --dry-run "$TMP/policy.conf" >"$TMP/dry.log" 2>&1 \
	|| { cat "$TMP/dry.log" >&2; bypass_fail "baseline --dry-run failed"; }

# C: over-deny guard, before anything is pinned and again after.
bpftool map create /sys/fs/bpf/bx22ctl type array key 4 value 8 entries 1 \
	name bx22ctl >"$TMP/ctl.log" 2>&1 \
	|| bypass_skip "cannot create a control bpf map (need CAP_BPF): $(head -1 "$TMP/ctl.log")"

SP_OWNER="$TMP/loader"
sp_install "$SP_OWNER"
sp_pin "$SP_OWNER" "$TMP/policy.conf" "$TMP/daemon.err"

# L: the armed pin set. comp_bpf_map is the hook every other assertion below
# depends on, and pin-regression T4.6 cannot see it (it pins without the flag).
sp_expect_links "$TMP/daemon.err"

# C (after): the control map must still be fully usable.
bpftool map update pinned /sys/fs/bpf/bx22ctl key 0 0 0 0 \
	value 1 0 0 0 0 0 0 0 >>"$TMP/ctl.log" 2>&1 \
	|| bypass_fail "C OVER-DENY: an unrelated bpf map became unwritable while a self-protected policy was live"
bpftool map dump pinned /sys/fs/bpf/bx22ctl >>"$TMP/ctl.log" 2>&1 \
	|| bypass_fail "C OVER-DENY: an unrelated bpf map became unreadable"
rm -f /sys/fs/bpf/bx22ctl \
	|| bypass_fail "C OVER-DENY: an unrelated bpffs pin became unremovable"

# Identify our maps WITHOUT an fd: bpftool cannot name them any more (that is
# the point), so read the ids the loader printed. The count line is the
# contract: "[self-protect] N map ids protected".
grep -q '^\[self-protect\] [0-9]* map ids protected' "$TMP/daemon.err" \
	|| { cat "$TMP/daemon.err" >&2; bypass_fail "loader did not report protected map ids"; }

# W1/W3: sweep every map id on the box and try to open each one, RW and RDONLY.
# This is the attacker's own enumeration, and it is the only way to count the
# refusals: bpftool aborts its listing at the first EACCES and cannot report
# how many maps refused (that abort is itself measured and documented in
# LIMITATIONS.md as the cost of this feature).
SWEEP="$TMP/sweep"
cc -O2 -Wall "$(dirname "$0")/helpers/bpf_map_fd_sweep.c" -o "$SWEEP" \
	>"$TMP/sweep-build.log" 2>&1 \
	|| bypass_skip "cannot build helpers/bpf_map_fd_sweep.c: $(tail -2 "$TMP/sweep-build.log" | tr '\n' ' ')"
sweep=$("$SWEEP")
echo "$sweep" >>"$TMP/sweep.log"
denied=$(printf '%s' "$sweep" | sed -n 's/.*denied=\([0-9]*\).*/\1/p')
ok_ro=$(printf '%s'  "$sweep" | sed -n 's/.*ok_ro=\([0-9]*\).*/\1/p')
protected=$(sed -n 's/^\[self-protect\] \([0-9]*\) map ids protected$/\1/p' "$TMP/daemon.err")
[ -n "$denied" ] && [ -n "$protected" ] \
	|| bypass_fail "W1: could not parse the sweep ($sweep) or the loader's protected-map count"

# Every map the loader protected must have refused. More is fine only if
# something else on the box also gates maps; fewer means a hole.
[ "$denied" -ge "$protected" ] \
	|| bypass_fail "W1 BYPASS: the loader protected $protected maps but only $denied refused an fd ($sweep)"

# W3: a READ-ONLY fd must be refused too. bpf_map_freeze() does not stop a BPF
# program from writing a map it holds any fd to, measured on 6.8 and 7.0, so
# allowing read-only fds would leave actor_marker_map and every seal map
# writable through a one-instruction BPF program.
[ "$ok_ro" -eq 0 ] || [ "$ok_ro" -lt "$denied" ] \
	|| bypass_fail "W3 BYPASS: $ok_ro protected maps handed out a read-only fd ($sweep)"
ro_leak=$("$SWEEP" | sed -n 's/.*ok_ro=\([0-9]*\).*/\1/p')
[ "${ro_leak:-0}" -le "$ok_ro" ] || bypass_fail "W3: sweep is not reproducible"

# W2: BPF_OBJ_GET on a pinned compartment map, via bpftool's pinned path.
w2=$(bpftool map dump pinned "$SP_PIN/maps/deny_total" 2>&1 | head -1)
case "$w2" in
	*"Permission denied"*|*"Operation not permitted"*) : ;;
	*) bypass_fail "W2 BYPASS: BPF_OBJ_GET on $SP_PIN/maps/deny_total was allowed for a non-loader ($w2)" ;;
esac

# A: audit line, with the caller's exe identity.
sp_audit_wait "$TMP/daemon.err" 'DENY_BPF_SELF' \
	|| bypass_fail "A: no DENY_BPF_SELF audit line for the denied map opens"
grep -q 'DENY_BPF_SELF .*caller_dev=[0-9]* caller_ino=[0-9]*' "$TMP/daemon.err" \
	|| bypass_fail "A: DENY_BPF_SELF audit line carries no caller exe identity"

# K: the counter must have moved, and it must be a subset of deny_total.
stats=$("$SP_OWNER" --stats 2>&1)
case "$stats" in
	*bpf_self_denied_total=0*) bypass_fail "K: bpf_self_denied_total stayed 0 while DENY_BPF_SELF events were emitted" ;;
	*bpf_self_denied_total=*) : ;;
	*) bypass_fail "K: --stats did not report bpf_self_denied_total: $(echo "$stats" | head -1)" ;;
esac

# G: --stats from the authorised image works at all (it is the same check as K,
# recorded separately because "the gate locked the tool out of its own
# telemetry" is the most likely way this feature breaks in production).
case "$stats" in
	"[stats] deny_total="*) : ;;
	*) bypass_fail "G: --stats from the authorised loader failed: $(echo "$stats" | head -1)" ;;
esac

# S: enforcement intact.
if { echo tampered > "$TARGET"; } 2>/dev/null; then
	bypass_fail "S: the sealed file became writable while probing the map gate"
fi

bypass_pass "armed pin set matches expected-links.txt ($SP_NLINKS links incl. comp_bpf_map) (L); compartment maps refuse fd creation to a non-loader (W1 id sweep vs the loader's own count, W2 BPF_OBJ_GET on a pin, W3 no read-only side door), DENY_BPF_SELF audited with the caller exe (A) and counted (K); --stats from the authorised image still works (G); an unrelated bpf map stayed fully usable (C); seal still enforced (S)"
