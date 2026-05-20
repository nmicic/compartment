#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/fuzz-runner.sh — VM-side runner for the property/fuzz oracle.
#
# Stages N files in a workdir, samples K of them with random non-zero
# flagspecs, writes a policy.conf and the matching CSV oracle, brings
# up the daemon, runs tests/fuzz_oracle for ITERS iterations, prints
# the JSON summary on stdout. Exits non-zero on divergence or stage
# error.
#
# Pre: REPO points at a built repo on the VM (compartment-bpf and
# tests/fuzz_oracle and tests/sealprobe present), root, bpf in LSM list.

set -u

REPO=${REPO:-/root/compartment_ebpf-tests}
DAEMON="$REPO/compartment-bpf"
ORACLE="$REPO/tests/fuzz_oracle"
N_FILES=${N_FILES:-200}
N_SEALED=${N_SEALED:-150}
ITERS=${ITERS:-10000}
SEED=${SEED:-$$}

if [ "$(id -u)" -ne 0 ]; then
	echo "fuzz-runner: must run as root" >&2
	exit 2
fi
if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
	echo "fuzz-runner: bpf not in LSM list" >&2
	exit 2
fi
[ -x "$DAEMON" ] || { echo "fuzz-runner: missing $DAEMON" >&2; exit 2; }
[ -x "$ORACLE" ] || { echo "fuzz-runner: missing $ORACLE" >&2; exit 2; }

TMP=$(mktemp -d /tmp/fuzz.XXXXXX)
DAEMON_PID=
cleanup() {
	if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
		kill "$DAEMON_PID" 2>/dev/null || true
		wait "$DAEMON_PID" 2>/dev/null || true
	fi
	rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

mkdir "$TMP/files"
i=0
while [ "$i" -lt "$N_FILES" ]; do
	echo "content-$i" > "$TMP/files/f$i"
	i=$((i+1))
done

# Sample N_SEALED files, assign a non-zero u4 flag mask each.
# awk produces "path,0xN" lines for fuzz_oracle's CSV, plus matching
# "seal path flagspec" lines for the daemon's policy.conf.
awk -v N="$N_FILES" -v K="$N_SEALED" -v dir="$TMP/files" -v seed="$SEED" '
BEGIN {
	srand(seed);
	for (i = 0; i < N; i++) idx[i] = i;
	# Fisher-Yates
	for (i = N - 1; i > 0; i--) {
		j = int(rand() * (i + 1));
		t = idx[i]; idx[i] = idx[j]; idx[j] = t;
	}
	for (i = 0; i < K; i++) {
		# random non-zero 4-bit mask
		m = int(rand() * 15) + 1;
		path = dir "/f" idx[i];
		printf("%s,0x%x\n", path, m) > "/dev/stderr";  # CSV
		# build flagspec from bits
		spec = "";
		if (m % 2)        spec = spec (spec ? "," : "") "no-unlink";
		if (int(m/2) % 2) spec = spec (spec ? "," : "") "no-rename";
		if (int(m/4) % 2) spec = spec (spec ? "," : "") "no-write";
		if (int(m/8) % 2) spec = spec (spec ? "," : "") "no-chmod";
		printf("seal %s %s\n", path, spec);  # policy
	}
}
' > "$TMP/policy.conf" 2> "$TMP/oracle.csv"

DAEMON_LOG="$TMP/daemon.err"
"$DAEMON" "$TMP/policy.conf" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 200); do
	grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null && break
	if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
		echo "fuzz-runner: daemon died during attach" >&2
		cat "$DAEMON_LOG" >&2
		exit 4
	fi
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null \
	|| { echo "fuzz-runner: daemon never live" >&2; cat "$DAEMON_LOG" >&2; exit 4; }

"$ORACLE" --csv "$TMP/oracle.csv" --iters "$ITERS" --seed "$SEED"
rc=$?
exit $rc
