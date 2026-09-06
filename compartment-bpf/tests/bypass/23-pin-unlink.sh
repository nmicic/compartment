#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# 23-pin-unlink.sh — the bpffs pins are the real removal path; --self-protect
# must close it without closing --unpin.
#
# bpf(BPF_LINK_DETACH) returns -EOPNOTSUPP for a BPF-LSM link on both 6.8 and
# 7.0 (bpf_tracing_link_lops has no .detach), so `unlink()` of the pin plus
# dropping the last fd is the only way to take a hook off. Measured on stock
# v0.8: `rm /sys/fs/bpf/compartment/links/comp_file_open` succeeded and that
# one hook detached within a second, and `rm -rf /sys/fs/bpf/compartment`
# removed enforcement entirely.
#
# Witnesses (policy pinned with --self-protect, daemon left running):
#   C   an unrelated pin on the SAME bpffs is still removable (over-deny guard)
#   W1  rm of one link pin        -> DENY, hook stays attached
#   W2  mv of one link pin        -> DENY
#   W3  rm of one map pin         -> DENY
#   W4  rm -rf of the whole tree  -> DENY, link count unchanged
#   W5  rmdir of the pin dirs     -> DENY
#   W6  rm of the comp_bpf_map pin itself -> DENY (the gate protects its own
#       enforcement point; without this every other deny lasts one syscall)
#   A   DENY_PIN_TAMPER audit line present, naming the caller exe
#   K   pin_tamper_denied_total counted the denies
#   U   --unpin by the image that pinned still removes everything
set -u
# shellcheck disable=SC2034  # read by lib-bypass.sh after sourcing
BYPASS_NAME="23-pin-unlink"
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
"$DAEMON" --dry-run "$TMP/policy.conf" >"$TMP/dry.log" 2>&1 \
	|| { cat "$TMP/dry.log" >&2; bypass_fail "baseline --dry-run failed"; }

SP_OWNER="$TMP/loader"
sp_install "$SP_OWNER"
sp_pin "$SP_OWNER" "$TMP/policy.conf" "$TMP/daemon.err"

before=$(sp_npins)
[ "$before" -ge 20 ] || bypass_fail "expected a pinned tree, found $before link pins"

# C: an unrelated object on the same bpffs must stay removable. If the gate
# keyed on the filesystem instead of the individual inodes, this would fail.
bpftool map create /sys/fs/bpf/bx23ctl type array key 4 value 8 entries 1 \
	name bx23ctl >"$TMP/ctl.log" 2>&1 \
	|| bypass_skip "cannot create a control bpf map: $(head -1 "$TMP/ctl.log")"
rm -f /sys/fs/bpf/bx23ctl \
	|| bypass_fail "C OVER-DENY: an unrelated pin on the pin bpffs became unremovable"

# W1
if rm -f "$SP_PIN/links/comp_file_open" 2>/dev/null; then
	bypass_fail "W1 BYPASS: unlink of a link pin succeeded — the enforcement hook was removed"
fi
[ -e "$SP_PIN/links/comp_file_open" ] || bypass_fail "W1: the pin is gone despite rm reporting failure"

# W2
if mv "$SP_PIN/links/comp_file_permission" "$SP_PIN/links/bx23" 2>/dev/null; then
	mv "$SP_PIN/links/bx23" "$SP_PIN/links/comp_file_permission" 2>/dev/null
	bypass_fail "W2 BYPASS: a link pin could be renamed out of the name --unpin sweeps"
fi

# W3
if rm -f "$SP_PIN/maps/deny_total" 2>/dev/null; then
	bypass_fail "W3 BYPASS: a map pin could be unlinked"
fi

# W6: the self-protection hook's OWN pin. If comp_bpf_map could be unlinked,
# every other deny in this file would evaporate one syscall later.
if rm -f "$SP_PIN/links/comp_bpf_map" 2>/dev/null; then
	bypass_fail "W6 BYPASS: the comp_bpf_map pin — the hook that enforces all of this — could be unlinked"
fi
[ -e "$SP_PIN/links/comp_bpf_map" ] \
	|| bypass_fail "W6: no comp_bpf_map pin exists; --self-protect cannot be armed"

# W4
rm -rf "$SP_PIN" 2>/dev/null
after=$(sp_npins)
[ "$after" -eq "$before" ] \
	|| bypass_fail "W4 BYPASS: rm -rf of the pin root removed $((before - after)) pins (was $before, now $after)"

# W5
if rmdir "$SP_PIN/links" 2>/dev/null; then
	bypass_fail "W5 BYPASS: the links pin directory could be removed"
fi

# S: still enforcing.
if { echo tampered > "$TARGET"; } 2>/dev/null; then
	bypass_fail "S: the sealed file became writable after the pin-removal attempts"
fi

# A
sp_audit_wait "$TMP/daemon.err" 'DENY_PIN_TAMPER' \
	|| bypass_fail "A: no DENY_PIN_TAMPER audit line for the denied pin removals"
grep -q 'DENY_PIN_TAMPER .*caller_dev=[0-9]* caller_ino=[0-9]*' "$TMP/daemon.err" \
	|| bypass_fail "A: DENY_PIN_TAMPER audit line carries no caller exe identity"

# K
stats=$("$SP_OWNER" --stats 2>&1)
case "$stats" in
	*pin_tamper_denied_total=0*) bypass_fail "K: pin_tamper_denied_total stayed 0" ;;
	*pin_tamper_denied_total=*) : ;;
	*) bypass_fail "K: --stats did not report pin_tamper_denied_total: $(echo "$stats" | head -1)" ;;
esac

# U: the authorised image can still take the policy down. This is the half that
# a mistake here would break, and breaking it strands the box until reboot.
sp_kill_daemon
sp_unpin "$SP_OWNER" "$TMP/unpin.log" \
	|| { cat "$TMP/unpin.log" >&2; bypass_fail "U: --unpin by the pinning image FAILED — self-protection stranded its own policy"; }
sp_drain || bypass_fail "U: compartment programs did not drain after --unpin"
[ "$(sp_npins)" -eq 0 ] || bypass_fail "U: $(sp_npins) pins survived --unpin"
{ echo probe > "$TARGET"; } 2>/dev/null \
	|| bypass_fail "U: the seal is still enforced after a successful --unpin"

bypass_pass "unlink (W1), rename (W2), map-pin unlink (W3), rm -rf (W4), rmdir (W5) and the comp_bpf_map pin itself (W6) all denied with DENY_PIN_TAMPER, audited with the caller exe (A) and counted (K); an unrelated pin on the same bpffs stayed removable (C); --unpin by the pinning image still tore the policy down cleanly (U)"
