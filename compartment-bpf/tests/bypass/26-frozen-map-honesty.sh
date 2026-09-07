#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# 26-frozen-map-honesty.sh — with self-protection OFF, a BPF program still
# writes a frozen compartment map. This witness exists to keep that recorded.
#
# The honest-witness pattern (same as tests/limitations-witness.sh L2-L4 for
# fallocate): a limitation that only lives in prose rots. LIMITATIONS.md used
# to say the seal maps were immune because freeze_seal_maps() freezes them.
# They are not. bpf_map_freeze() gates map_get_sys_perms() on the SYSCALL path
# only; a caller holding any fd — BPF_F_RDONLY is enough — splices the map into
# a BPF program of its own with bpf_map__reuse_fd() and writes it from program
# context.
#
# So this witness asserts the GAP, not its absence. It runs in the DEFAULT
# build (no --self-protect anywhere) and passes when the attack still works,
# because that is what the shipped documentation says. If a future kernel or a
# future default closes it, this witness FAILS — loudly, with the text to fix
# — rather than letting the tree quietly keep a limitation it no longer has.
#
# Witnesses (default build, unpinned daemon, nothing armed):
#   C   the syscall-path write to the same frozen map is refused (EPERM), so
#       the freeze is doing what it does do and the measurement is not just
#       "the map was never frozen"
#   W1  a READ-ONLY fd to the frozen map is granted (comp_bpf_map is not
#       loaded in the default build — that is the opt-in half)
#   W2  the in-program bpf_map_update_elem() returns 0
#   W3  the written key reads back, so the map really was mutated
#   D   LIMITATIONS.md still documents this as open, in the row this witness
#       measures
#   Z   no DENY_BPF_SELF was emitted and no self-protection link was pinned:
#       the default build is unarmed
set -u
# shellcheck disable=SC2034  # read by lib-bypass.sh after sourcing
BYPASS_NAME="26-frozen-map-honesty"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env
command -v bpftool >/dev/null 2>&1 || bypass_skip "bpftool not installed"
command -v clang   >/dev/null 2>&1 || bypass_skip "clang not installed (needed to build the attacker BPF object)"
command -v python3 >/dev/null 2>&1 || bypass_skip "python3 not installed (needed to read the map id out of bpftool -j)"
[ -r "$REPO/vmlinux.h" ] || bypass_skip "vmlinux.h not generated in $REPO"
# This witness picks a map by NAME out of a host-wide listing, so a second
# compartment instance would make it ambiguous which sealed_devs it measured.
[ "$(bpftool prog show 2>/dev/null | grep -c 'name comp_')" -eq 0 ] \
	|| bypass_skip "another compartment-bpf instance is loaded; refusing to measure against a dirty box"

PROBE=$(mktemp -d /tmp/bx26-probe.XXXXXX)
echo 'int main(void){return 0;}' > "$PROBE/p.c"
cc -o "$PROBE/p" "$PROBE/p.c" -lbpf 2>/dev/null \
	|| { rm -rf "$PROBE"; bypass_skip "libbpf development files not available (need -lbpf to build the runner)"; }
rm -rf "$PROBE"

bypass_setup full

H="$(dirname "$0")/helpers"
OBJ="$TMP/fw.bpf.o"
RUN="$TMP/fw"
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I"$REPO" \
	-c "$H/frozen_map_write.bpf.c" -o "$OBJ" >"$TMP/build.log" 2>&1 \
	|| bypass_skip "cannot build the attacker BPF object: $(tail -2 "$TMP/build.log" | tr '\n' ' ')"
cc -O2 -Wall -o "$RUN" "$H/frozen_map_write.c" -lbpf -lelf -lz \
	>>"$TMP/build.log" 2>&1 \
	|| bypass_skip "cannot build the runner: $(tail -2 "$TMP/build.log" | tr '\n' ' ')"

# Z: the default build must be unarmed, or this witness measures the wrong
# thing and would "pass" by describing a build nobody ships.
grep -q 'self-protection ARMED' "$DAEMON_LOG" \
	&& bypass_fail "Z: the default daemon armed self-protection; this witness only describes the default build"
if [ -e /sys/fs/bpf/compartment/links/comp_bpf_map ]; then
	bypass_fail "Z: a comp_bpf_map link is pinned in the default build; the gap this witness records may already be closed"
fi

# The target is sealed_devs: a frozen HASH(__u64 -> __u32), populated by the
# loader for every sealed superblock, so wiping it disarms comp_sb_umount.
ID=$(bpftool -j map show 2>/dev/null | python3 -c '
import json,sys
try: d = json.load(sys.stdin)
except Exception: sys.exit(0)
ids = [m["id"] for m in d if m.get("name") == "sealed_devs"]
print(ids[0] if ids else "")' 2>/dev/null)
[ -n "$ID" ] || bypass_skip "could not resolve the sealed_devs map id from bpftool"

out=$("$RUN" "$OBJ" "$ID" 2>"$TMP/run.err")
rc=$?
[ "$rc" -eq 0 ] || { cat "$TMP/run.err" >&2; bypass_skip "the measurement could not be taken (runner rc=$rc)"; }
echo "$out" >"$TMP/fw.out"
bypass_evidence "frozen-map program-write measurement: $out"

case "$out" in
	*"fd=denied"*)
		bypass_fail "W1: a read-only fd to the frozen sealed_devs map was refused in the DEFAULT build. Something already gates bpf_map_new_fd() here. If that is now the shipped behaviour, this witness and the CAP_BPF map-mutation row in LIMITATIONS.md both need rewriting ($out)" ;;
	*"prog=failed"*)
		bypass_fail "W2: the attacker program would not load with the frozen map spliced in ($out); the LIMITATIONS row claims it does — re-measure and update the row" ;;
esac

write_rc=$(printf '%s' "$out" | sed -n 's/.*write=\(-\{0,1\}[0-9]*\).*/\1/p')
[ "${write_rc:-1}" = "0" ] \
	|| bypass_fail "W2: the in-program bpf_map_update_elem() on a FROZEN map returned $write_rc, not 0. If the kernel now refuses program-context writes to frozen maps, the CAP_BPF map-mutation row in LIMITATIONS.md is obsolete and must be rewritten to say so, naming this kernel ($(uname -r)) ($out)"

case "$out" in
	*"readback=yes"*) : ;;
	*) bypass_fail "W3: the program write reported success but the value did not read back ($out); the measurement is not trustworthy — investigate before touching the docs" ;;
esac

# C: the syscall path on the very same fd must still be refused. Without this
# the whole witness could be satisfied by a map that was never frozen.
sysrc=$(printf '%s' "$out" | sed -n 's/.*syscall=\(-\{0,1\}[0-9]*\)\/\([0-9]*\).*/\1/p')
syserr=$(printf '%s' "$out" | sed -n 's/.*syscall=\(-\{0,1\}[0-9]*\)\/\([0-9]*\).*/\2/p')
[ "${sysrc:-0}" != "0" ] \
	|| bypass_fail "C: the SYSCALL-path write to sealed_devs succeeded too — the map is not frozen at all, so this run measures nothing about freeze semantics ($out)"
[ "${syserr:-0}" = "1" ] \
	|| bypass_fail "C: the syscall-path write failed with errno=$syserr, expected 1 (EPERM) from bpf_map_freeze ($out)"

# Z (audit half): no self-protection deny can have been emitted.
grep -q 'DENY_BPF_SELF' "$DAEMON_LOG" \
	&& bypass_fail "Z: DENY_BPF_SELF appeared in the default build's audit stream"

# D: the documentation this witness measures must still say the gap is open.
LIM="$REPO/LIMITATIONS.md"
[ -r "$LIM" ] || bypass_fail "D: LIMITATIONS.md not present at $LIM"
grep -qE 'CAP_BPF \+ direct map mutation.*bpf_map_freeze.*syscall.*program' "$LIM" \
	|| bypass_fail "D: the CAP_BPF map-mutation row no longer distinguishes the syscall path from the program path, but the program-context write still works on this kernel"

bypass_pass "with self-protection OFF (the default build), a BPF program still writes a FROZEN compartment map: read-only fd granted (W1), in-program bpf_map_update_elem()=0 (W2), value reads back (W3), while the syscall path on the same fd stays EPERM (C); no comp_bpf_map link and no DENY_BPF_SELF (Z); LIMITATIONS.md still records the gap (D) — kernel $(uname -r), sealed_devs id=$ID"
