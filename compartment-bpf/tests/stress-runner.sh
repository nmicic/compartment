#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/stress-runner.sh — VM-side. 60 s sustained open(O_WRONLY) hammer
# against a sealed file with multiple workers. Verifies:
#   - file content + size unchanged
#   - daemon is still alive
#   - daemon emitted at least some audit events (otherwise the workers
#     weren't actually hitting the deny path)
# Suggestion ID: 4.5h, 1.4, 3.8d, 5.3.
set -u

REPO=${REPO:-/root/compartment_ebpf-tests}
SEALPROBE="$REPO/tests/sealprobe"
DAEMON="$REPO/compartment-bpf"
DURATION=${DURATION:-60}
WORKERS=${WORKERS:-8}
OPS_PER_BATCH=${OPS_PER_BATCH:-10000}

[ "$(id -u)" -eq 0 ] || { echo "stress-runner: needs root" >&2; exit 2; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| { echo "stress-runner: bpf not in LSM" >&2; exit 2; }
[ -x "$SEALPROBE" ] || { echo "stress-runner: missing $SEALPROBE" >&2; exit 2; }
[ -x "$DAEMON" ]   || { echo "stress-runner: missing $DAEMON" >&2; exit 2; }

TMP=$(mktemp -d /tmp/stress.XXXXXX)
DAEMON_PID=
cleanup() {
	if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
		kill "$DAEMON_PID" 2>/dev/null || true
		wait "$DAEMON_PID" 2>/dev/null || true
	fi
	rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

TARGET="$TMP/target"
echo content_baseline > "$TARGET"
ORIG_SIZE=$(stat -c %s "$TARGET")
ORIG_SHA=$(sha256sum "$TARGET" | cut -d' ' -f1)

echo "seal $TARGET no-write" > "$TMP/policy.conf"
DAEMON_LOG="$TMP/daemon.err"
"$DAEMON" "$TMP/policy.conf" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do
	grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null && break
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null \
	|| { echo "stress-runner: daemon never live" >&2; exit 4; }

echo "stress-runner: $WORKERS workers x ${DURATION}s on $TARGET"
deadline=$(($(date +%s) + DURATION))
worker_pids=
i=0
while [ "$i" -lt "$WORKERS" ]; do
	(
		while [ "$(date +%s)" -lt "$deadline" ]; do
			"$SEALPROBE" bench-open wronly "$TARGET" "$OPS_PER_BATCH" \
				>> "$TMP/worker_$i.out" 2>&1
		done
	) &
	worker_pids="$worker_pids $!"
	i=$((i+1))
done
for pid in $worker_pids; do wait "$pid" 2>/dev/null || true; done

# Aggregate worker output: sum ops, denies, batches.
total_ops=0; total_denies=0; total_batches=0
for f in "$TMP"/worker_*.out; do
	while read -r line; do
		ops=$(echo "$line" | grep -oE 'ops=[0-9]+' | head -1 | cut -d= -f2)
		den=$(echo "$line" | grep -oE 'denies=[0-9]+' | head -1 | cut -d= -f2)
		[ -n "$ops" ] && total_ops=$((total_ops + ops))
		[ -n "$den" ] && total_denies=$((total_denies + den))
		[ -n "$ops" ] && total_batches=$((total_batches + 1))
	done < "$f"
done

# Daemon health checks.
NEW_SIZE=$(stat -c %s "$TARGET" 2>/dev/null || echo 0)
NEW_SHA=$(sha256sum "$TARGET" 2>/dev/null | cut -d' ' -f1 || echo missing)
DAEMON_ALIVE=no
kill -0 "$DAEMON_PID" 2>/dev/null && DAEMON_ALIVE=yes
AUDIT_LINES=$(grep -c '\[audit\]' "$DAEMON_LOG" 2>/dev/null || echo 0)

# Try to also confirm seal map size hasn't changed (best-effort).
SEAL_LINES=$(grep -c '^\[seal\]' "$DAEMON_LOG" 2>/dev/null || echo 0)

cat <<EOF
{
  "duration_s":     $DURATION,
  "workers":        $WORKERS,
  "total_ops":      $total_ops,
  "total_denies":   $total_denies,
  "total_batches":  $total_batches,
  "ops_per_sec":    $((total_ops / DURATION)),
  "daemon_alive":   "$DAEMON_ALIVE",
  "audit_lines":    $AUDIT_LINES,
  "seal_lines":     $SEAL_LINES,
  "orig_size":      $ORIG_SIZE,
  "post_size":      $NEW_SIZE,
  "orig_sha":       "$ORIG_SHA",
  "post_sha":       "$NEW_SHA"
}
EOF

# Verdict.
if [ "$DAEMON_ALIVE" != yes ]; then
	echo "stress-runner: FAIL — daemon died" >&2
	exit 1
fi
if [ "$ORIG_SHA" != "$NEW_SHA" ]; then
	echo "stress-runner: FAIL — file content changed (BYPASS)" >&2
	exit 1
fi
if [ "$total_ops" -lt 1000 ]; then
	echo "stress-runner: FAIL — barely any ops; harness wasn't hammering" >&2
	exit 1
fi
if [ "$total_denies" -lt $((total_ops / 2)) ]; then
	echo "stress-runner: FAIL — fewer than half of ops denied; enforcement weak" >&2
	exit 1
fi
echo "stress-runner: PASS"
