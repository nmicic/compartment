#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# tests/bench/bpf-syscall-overhead.sh — the cost of --self-protect on bpf(2).
#
# Three legs, same box, same loop, back to back:
#   baseline   no compartment policy loaded at all
#   flag off   policy pinned with plain --pin (comp_bpf_map is NOT autoloaded)
#   flag on    policy pinned with --pin --self-protect
#
# The loop is BPF_MAP_GET_FD_BY_ID + close on one unrelated map, the thinnest
# syscall that still reaches bpf_map_new_fd(): the hook runs on every iteration
# and exits on its first branch, with almost no other kernel work to hide its
# fixed entry cost behind.
#
# rc=0 with the three numbers on stdout; rc=77 if the environment cannot run it.
set -u
REPO=${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}
BIN="$REPO/compartment-bpf"
ITERS=${BPFBENCH_ITERS:-200000}
REPS=${BPFBENCH_REPS:-7}
PASS=${BPFBENCH_PASS:-bench-self-protect-passphrase}
PIN=/sys/fs/bpf/compartment

[ "$(id -u)" -eq 0 ] || { echo "[bpf-bench] SKIP (needs root)"; exit 77; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null || { echo "[bpf-bench] SKIP (bpf not in active LSM)"; exit 77; }
[ -x "$BIN" ] || { echo "[bpf-bench] SKIP (daemon not built)"; exit 77; }

TMP=$(mktemp -d /tmp/bpfbench.XXXXXX)
cleanup() {
	[ -n "${DPID:-}" ] && kill "$DPID" 2>/dev/null
	COMPARTMENT_BPF_PASSPHRASE="$PASS" "${OWNER:-$BIN}" --unpin >/dev/null 2>&1
	for _ in $(seq 1 60); do
		[ "$(bpftool prog show 2>/dev/null | grep -c 'name comp_')" -eq 0 ] && break
		sleep 1
	done
	rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

cc -O2 -Wall -o "$TMP/bench" "$(dirname "$0")/bpf-syscall-overhead.c" 2>"$TMP/cc.log" \
	|| { echo "[bpf-bench] SKIP (cannot build the probe: $(tail -1 "$TMP/cc.log"))"; exit 77; }

# Median of $REPS runs: a single sample on a 2-vCPU guest is noise.
run_leg() {
	for _ in $(seq 1 "$REPS"); do
		"$TMP/bench" "$ITERS" | sed -n 's/.*ns_per_call=\([0-9.]*\).*/\1/p'
	done | sort -n | awk '{v[NR]=$1} END{printf "%.1f\n", v[int((NR+1)/2)]}'
}

drain() {
	for _ in $(seq 1 90); do
		[ "$(bpftool prog show 2>/dev/null | grep -c 'name comp_')" -eq 0 ] && return 0
		sleep 1
	done
	return 1
}

[ "$(bpftool prog show 2>/dev/null | grep -c 'name comp_')" -eq 0 ] \
	|| { echo "[bpf-bench] SKIP (another compartment instance is loaded)"; exit 77; }

echo content > "$TMP/target"
printf 'seal %s full\n' "$TMP/target" > "$TMP/policy.conf"

base=$(run_leg)

OWNER="$TMP/loader"
cp "$BIN" "$OWNER"; chown 0:0 "$OWNER"; chmod 0755 "$OWNER"

COMPARTMENT_BPF_PASSPHRASE="$PASS" "$OWNER" --pin "$TMP/policy.conf" >"$TMP/off.log" 2>&1 &
DPID=$!
for _ in $(seq 1 400); do grep -q '\[run\] compartment-bpf live' "$TMP/off.log" 2>/dev/null && break; sleep 0.1; done
grep -q '\[run\] compartment-bpf live' "$TMP/off.log" || { cat "$TMP/off.log" >&2; echo "[bpf-bench] SKIP (plain --pin did not go live)"; exit 77; }
off=$(run_leg)
off_links=$(ls "$PIN/links" 2>/dev/null | wc -l)
kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; DPID=""
COMPARTMENT_BPF_PASSPHRASE="$PASS" "$OWNER" --unpin >/dev/null 2>&1
drain || { echo "[bpf-bench] SKIP (programs did not drain between legs)"; exit 77; }

COMPARTMENT_BPF_PASSPHRASE="$PASS" "$OWNER" --pin --self-protect "$TMP/policy.conf" >"$TMP/on.log" 2>&1 &
DPID=$!
for _ in $(seq 1 400); do grep -q '\[run\] compartment-bpf live' "$TMP/on.log" 2>/dev/null && break; sleep 0.1; done
grep -q '\[run\] compartment-bpf live' "$TMP/on.log" || { cat "$TMP/on.log" >&2; echo "[bpf-bench] SKIP (--pin --self-protect did not go live)"; exit 77; }
on=$(run_leg)
on_links=$(ls "$PIN/links" 2>/dev/null | wc -l)

echo "[bpf-bench] kernel=$(uname -r) iters=$ITERS reps=$REPS (median ns per BPF_MAP_GET_FD_BY_ID+close)"
echo "[bpf-bench] baseline=${base} flag_off=${off} flag_on=${on} links_off=${off_links} links_on=${on_links}"
awk -v b="$base" -v f="$off" -v o="$on" 'BEGIN{
  printf "[bpf-bench] delta_off=%+.1f ns (%+.2f%%)  delta_on=%+.1f ns (%+.2f%%)  hook_cost=%+.1f ns\n",
         f-b, (f-b)*100/b, o-b, (o-b)*100/b, o-f
}'
