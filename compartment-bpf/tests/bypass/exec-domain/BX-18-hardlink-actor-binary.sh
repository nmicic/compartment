#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-18-hardlink-actor-binary.sh
#
# GAP-H-6 (coverage audit 2026-05-16): hardlink-of-actor-binary used as
# the target of a second actor's `actor=` seal. The defense lives in
# DEC-ED3-B (cross-actor seal merge-refusal — `seal_path` at
# compartment-bpf.c:1893-1913 / 2024-2046): if two seal lines share
# (dev, ino) and either carries `actor=`, the loader refuses with a
# merge-refusal diagnostic. The gap doc flagged this surface as
# "conceptually covered by DEC-ED3-B" but lacking an explicit witness.
# This script pins the hardlink twist so a regression that softened
# the (dev, ino) match (e.g. a path-only key) would slip through the
# existing same-path H-5 witness yet still fail H-6.
#
# Witnesses:
#   W1 — Two seals at DIFFERENT paths but SAME (dev, ino); second
#        carries `actor=actor_B` whose declared binary is unrelated.
#        DEC-ED3-B fires; loader exits non-zero with the merge-refusal
#        diagnostic.
#   W2 — Same hardlink topology but the second seal does NOT carry
#        `actor=` (no actor anywhere on either seal). DEC-ED3-B must
#        NOT fire (the (dev, ino) merge is a legitimate flag union).
#        Confirms W1 isn't a false positive on the hardlink alone.
#   W3 — Runtime no-bypass: even if an operator tried to use the
#        hardlink to declare a SECOND actor on the same inode (allowed
#        per DEC-ED2-C, inode-keyed dedup applies), strict-mode still
#        requires both declared paths to be sealed `full`; an unsealed
#        hardlink-path declared as actor_B's binary fails the strict-
#        mode "not sealed at its declared path" check.
set -u
BYPASS_NAME="BX-18-hardlink-actor-binary"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

ACTOR_A=$(ed_create_actor actor_A_bin)
ACTOR_B=$(ed_create_actor actor_B_bin)
HARDLINK_OF_A="$TMP/actor_A_hardlink"
ln "$ACTOR_A" "$HARDLINK_OF_A" \
    || bypass_die "setup: ln $ACTOR_A $HARDLINK_OF_A failed (need same-fs hardlink)"

# Sanity: confirm the hardlink and actor_A share (dev, ino).
A_INO=$(stat -c '%d:%i' "$ACTOR_A")
HL_INO=$(stat -c '%d:%i' "$HARDLINK_OF_A")
[ "$A_INO" = "$HL_INO" ] \
    || bypass_die "setup: hardlink ino mismatch (A=$A_INO HL=$HL_INO)"

# ----- W1: two seals on same inode, second carries actor= → DEC-ED3-B -----
DATA_W1="$TMP/data_w1"
echo content > "$DATA_W1"
cat > "$TMP/w1.conf" <<EOF
actor actor_A = $ACTOR_A
actor actor_B = $ACTOR_B
seal $ACTOR_A no-write,no-unlink,no-rename,no-chmod
seal $HARDLINK_OF_A no-write,no-unlink,no-rename,no-chmod actor=actor_B
seal $ACTOR_B no-write,no-unlink,no-rename,no-chmod
seal $DATA_W1 no-write actor=actor_A
EOF
OUT1="$TMP/w1.err"
"$DAEMON" --dry-run "$TMP/w1.conf" >"$OUT1" 2>&1
rc1=$?
if [ "$rc1" -eq 0 ]; then
    cat "$OUT1" >&2
    bypass_fail "W1: loader accepted cross-actor seal collision on hardlinked inode (H-6 / DEC-ED3-B gap)"
fi
if ! grep -q "refusing to merge seal lines" "$OUT1"; then
    cat "$OUT1" >&2
    bypass_fail "W1: rejected without the 'refusing to merge seal lines' verb"
fi

# ----- W2: hardlink seals with NO actor= anywhere → must accept -----
# Confirms W1 fires on the actor= bit, not on the hardlink topology.
# Two seals at different paths sharing (dev, ino), neither with actor=,
# is a legitimate flag-union case (Sec-2/F5 path-merge handles it).
cat > "$TMP/w2.conf" <<EOF
actor actor_A = $ACTOR_A
seal $ACTOR_A no-write,no-unlink
seal $HARDLINK_OF_A no-rename,no-chmod
seal $TMP/dummy_data no-write actor=actor_A
EOF
echo content > "$TMP/dummy_data"
OUT2="$TMP/w2.err"
"$DAEMON" --dry-run "$TMP/w2.conf" >"$OUT2" 2>&1
rc2=$?
if [ "$rc2" -ne 0 ]; then
    cat "$OUT2" >&2
    bypass_fail "W2: loader rejected two-seal-no-actor-merge on shared inode (should be the legitimate flag-union case)"
fi
if grep -q "refusing to merge seal lines" "$OUT2"; then
    cat "$OUT2" >&2
    bypass_fail "W2: merge-refusal fired on no-actor seal merge (false positive)"
fi

# ----- W3: declare actor_B at the hardlink path, but DON'T seal that path.
# Strict-mode requires every actor binary to be sealed at its declared
# path. Even though the inode happens to be sealed (via actor_A's seal),
# /tmp/actor_A_hardlink is NOT in the seal entry's declared-path list
# (Sec-2/F5 path-equivalence), so strict-mode refuses.
cat > "$TMP/w3.conf" <<EOF
actor actor_A = $ACTOR_A
actor actor_B = $HARDLINK_OF_A
seal $ACTOR_A no-write,no-unlink,no-rename,no-chmod
seal $TMP/dummy_data no-write actor=actor_B
EOF
OUT3="$TMP/w3.err"
"$DAEMON" --dry-run "$TMP/w3.conf" >"$OUT3" 2>&1
rc3=$?
if [ "$rc3" -eq 0 ]; then
    cat "$OUT3" >&2
    bypass_fail "W3: loader accepted actor_B at hardlink path without seal at that path (Sec-2/F5 gap)"
fi
if ! grep -Eq "(is not sealed at its declared path|hardlink-equivalent path does NOT satisfy)" "$OUT3"; then
    cat "$OUT3" >&2
    bypass_fail "W3: rejected but missing the Sec-2/F5 declared-path diagnostic"
fi
if ! grep -q "actor_B" "$OUT3"; then
    cat "$OUT3" >&2
    bypass_fail "W3: diagnostic did not name actor_B"
fi

bypass_pass "H-6 hardlink-of-actor-binary: DEC-ED3-B fires when second seal carries actor= (W1); no false positive when neither carries actor= (W2); Sec-2/F5 path-equivalence refuses hardlink-as-actor-binary without seal at declared path (W3)"
