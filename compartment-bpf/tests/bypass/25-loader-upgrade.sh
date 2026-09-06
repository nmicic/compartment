#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# 25-loader-upgrade.sh — the upgrade/recovery semantics, both directions.
#
# --self-protect keys the maintenance right on the loader's (dev, ino). A
# rebuild or a package upgrade produces a new inode, so the new binary is NOT
# the loader that pinned the policy. That is the whole cost of the feature and
# it must be exercised in both directions, or the first operator to run
# `make && sudo make check` on a pinned host discovers it the hard way.
#
# The documented flows are:
#   RIGHT (a) --unpin with the running image, then replace the binary, then
#             --pin again with the new one.
#   RIGHT (b) pre-authorise the successor at pin time:
#             --pin --self-protect --authorize-loader /path/to/next
#   WRONG     replace the binary and expect the new image to --unpin. It must
#             fail LOUDLY, name ACTION_DENY_PIN_TAMPER, and say what to do.
#
# Witnesses:
#   W1  a byte-identical copy at a different inode CANNOT --unpin, and the
#       failure names --self-protect, the authorised set and the reboot escape
#   W2  ...and the policy is still fully enforced after that failed attempt
#   W3  --stats from the unauthorised copy fails too (no telemetry side door)
#   W4  the pinning image CAN --unpin (flow a)
#   W5  a successor pre-authorised with --authorize-loader CAN --unpin (flow b)
#   W6  --authorize-loader refuses a group/world-writable successor
#   W7  --self-protect is rejected on --unpin/--stats (the authorised set is
#       fixed at pin time and must not look changeable afterwards)
set -u
# shellcheck disable=SC2034  # read by lib-bypass.sh after sourcing
BYPASS_NAME="25-loader-upgrade"
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

SP_OWNER="$TMP/loader-a"
NEXT="$TMP/loader-b"
sp_install "$SP_OWNER"
sp_install "$NEXT"
[ "$(stat -c %i "$SP_OWNER")" != "$(stat -c %i "$NEXT")" ] \
	|| bypass_fail "the two loader images share an inode; the test cannot distinguish them"

# W7 first: it is a pure argument check and needs no policy.
w7=$("$SP_OWNER" --unpin --self-protect 2>&1 | head -1)
case "$w7" in
	*"apply to --pin only"*) : ;;
	*) bypass_fail "W7: --unpin --self-protect was not rejected ($w7)" ;;
esac

# W6: a group-writable successor must be refused at pin time.
cp "$SP_OWNER" "$TMP/loader-bad"; chown 0:0 "$TMP/loader-bad"; chmod 0775 "$TMP/loader-bad"
w6=$(COMPARTMENT_BPF_PASSPHRASE="$SP_PASS" "$SP_OWNER" --pin --self-protect \
     --authorize-loader "$TMP/loader-bad" "$TMP/policy.conf" 2>&1 | head -20)
case "$w6" in
	*"group- or world-writable"*) : ;;
	*) bypass_fail "W6: a group-writable --authorize-loader target was accepted: $(echo "$w6" | tail -2 | tr '\n' ' ')" ;;
esac
sp_drain || bypass_fail "W6: the refused --pin left programs loaded"
[ "$(sp_npins)" -eq 0 ] || bypass_fail "W6: the refused --pin left $(sp_npins) pins behind"

# --- flow (a): pin with A, try to unpin with B, then unpin with A. ---
sp_pin "$SP_OWNER" "$TMP/policy.conf" "$TMP/daemon.err"
before=$(sp_npins)

sp_kill_daemon
if sp_unpin "$NEXT" "$TMP/w1.log"; then
	bypass_fail "W1 BYPASS: an unauthorised image at a different inode removed the policy"
fi
for phrase in "self-protect" "authorised loader set" "DENY_PIN_TAMPER" "reboot"; do
	grep -qi -- "$phrase" "$TMP/w1.log" \
		|| { cat "$TMP/w1.log" >&2; bypass_fail "W1: the refusal does not mention '$phrase' — an operator cannot act on it"; }
done

# W2
[ "$(sp_npins)" -eq "$before" ] \
	|| bypass_fail "W2: the failed unpin removed $((before - $(sp_npins))) pins"
if { echo tampered > "$TARGET"; } 2>/dev/null; then
	bypass_fail "W2: the seal stopped being enforced after the refused unpin"
fi

# W3
w3=$("$NEXT" --stats 2>&1 | head -1)
case "$w3" in
	*"Permission denied"*|*"Operation not permitted"*) : ;;
	*) bypass_fail "W3: --stats from the unauthorised image was not refused ($w3)" ;;
esac

# W4
sp_unpin "$SP_OWNER" "$TMP/w4.log" \
	|| { cat "$TMP/w4.log" >&2; bypass_fail "W4: the pinning image could not --unpin its own policy"; }
sp_drain || bypass_fail "W4: programs did not drain after --unpin"
[ "$(sp_npins)" -eq 0 ] || bypass_fail "W4: $(sp_npins) pins survived --unpin by the pinning image"

# --- flow (b): pin with A pre-authorising B, then unpin with B. ---
echo content > "$TARGET"
sp_pin "$SP_OWNER" "$TMP/policy.conf" "$TMP/daemon2.err" --authorize-loader "$NEXT"
grep -q "authorised loader $NEXT" "$TMP/daemon2.err" \
	|| { cat "$TMP/daemon2.err" >&2; bypass_fail "W5: the loader did not report the pre-authorised successor"; }
sp_kill_daemon
sp_unpin "$NEXT" "$TMP/w5.log" \
	|| { cat "$TMP/w5.log" >&2; bypass_fail "W5: the pre-authorised successor could NOT --unpin — the documented upgrade flow does not work"; }
sp_drain || bypass_fail "W5: programs did not drain after the successor unpinned"
[ "$(sp_npins)" -eq 0 ] || bypass_fail "W5: $(sp_npins) pins survived the successor's --unpin"
SP_OWNER=""   # nothing left to tear down

bypass_pass "an unauthorised image cannot unpin and says why (W1), the policy survives the attempt (W2) and gives it no telemetry side door (W3); the pinning image can unpin (W4); a successor pre-authorised with --authorize-loader can unpin (W5); a group-writable successor is refused (W6); --self-protect is rejected outside --pin (W7)"
