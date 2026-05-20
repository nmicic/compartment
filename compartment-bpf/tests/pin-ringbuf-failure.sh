#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/pin-ringbuf-failure.sh — regression test for Codex finding 4.
#
# Pre-fix the daemon called pin_links() BEFORE ring_buffer__new(). If
# the ringbuf failed (ENOMEM, RLIMIT_MEMLOCK, etc.), the daemon exited 1
# but the pinned program persisted under /sys/fs/bpf/compartment/links/
# with no audit reader, leaving enforcement live and silent.
#
# Post-fix: ring_buffer__new() runs FIRST. A ringbuf failure means we
# never reach pin_links(), so there is no pinned link to leak.
#
# Forces ringbuf failure via an LD_PRELOAD shim that returns NULL from
# ring_buffer__new with errno=ENOMEM. Asserts:
#   1. daemon exits non-zero
#   2. /sys/fs/bpf/compartment/links/ is empty (or absent)
set -u

REPO=${REPO:-/root/compartment-bpf-fixes}
DAEMON="$REPO/compartment-bpf"
PIN_ROOT=/sys/fs/bpf/compartment

[ "$(id -u)" -eq 0 ] || { echo "SKIP pin-ringbuf-failure: needs root" >&2; exit 77; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| { echo "SKIP pin-ringbuf-failure: bpf not in active LSM" >&2; exit 77; }
[ -x "$DAEMON" ] || { echo "SKIP pin-ringbuf-failure: daemon not built" >&2; exit 77; }
command -v cc >/dev/null 2>&1 \
	|| { echo "SKIP pin-ringbuf-failure: cc not available for shim build" >&2; exit 77; }

TMP=$(mktemp -d /tmp/ringbuf-fail.XXXXXX)
TARGET="$TMP/file"
PROFILE="$TMP/policy.conf"
SHIM_C="$TMP/shim.c"
SHIM_SO="$TMP/shim.so"
LOG="$TMP/daemon.err"

# Pre-clean any stale pins from prior runs of THIS test or aborted daemons.
# We must not falsely PASS because someone else left the dir empty already;
# verify by recording the pre-state.
if [ -e "$PIN_ROOT/links" ]; then
	# Try to clean. If files are pinned by a live daemon we abort the test.
	for p in "$PIN_ROOT/links"/*; do
		[ -e "$p" ] || continue
		rm -f "$p" 2>/dev/null || true
	done
	rmdir "$PIN_ROOT/links" 2>/dev/null || true
	rmdir "$PIN_ROOT" 2>/dev/null || true
fi

cleanup() {
	if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
		kill "$PID" 2>/dev/null || true
		wait "$PID" 2>/dev/null || true
	fi
	# Sweep any pins we may have created (post-fix should leave none).
	if [ -d "$PIN_ROOT/links" ]; then
		for p in "$PIN_ROOT/links"/*; do
			[ -e "$p" ] || continue
			rm -f "$p" 2>/dev/null || true
		done
		rmdir "$PIN_ROOT/links" 2>/dev/null || true
		rmdir "$PIN_ROOT" 2>/dev/null || true
	fi
	rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

# Stage a profile that resolves -- daemon will reach the ringbuf step.
echo content > "$TARGET"
printf 'seal %s no-write\n' "$TARGET" > "$PROFILE"

# Build LD_PRELOAD shim that fails ring_buffer__new.
cat > "$SHIM_C" <<'EOF'
#include <errno.h>
#include <stddef.h>

/* Override libbpf's ring_buffer__new(). The daemon calls it exactly
 * once on startup; returning NULL triggers the daemon's "ringbuf:"
 * error path and exit. */
struct ring_buffer;
typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, unsigned long size);
struct ring_buffer_opts;

struct ring_buffer *
ring_buffer__new(int map_fd,
                 ring_buffer_sample_fn sample_cb,
                 void *ctx,
                 const struct ring_buffer_opts *opts)
{
	(void)map_fd; (void)sample_cb; (void)ctx; (void)opts;
	errno = ENOMEM;
	return NULL;
}
EOF

cc -shared -fPIC -O0 -o "$SHIM_SO" "$SHIM_C" \
	|| { echo "FAIL pin-ringbuf-failure: shim build failed"; exit 1; }

# Run daemon with --pin under the shim.
LD_PRELOAD="$SHIM_SO" "$DAEMON" --pin "$PROFILE" >"$LOG" 2>&1 &
PID=$!
# Daemon should exit quickly (ringbuf fails after attach). Give it 3 s max.
for _ in $(seq 1 30); do
	kill -0 "$PID" 2>/dev/null || break
	sleep 0.1
done
wait "$PID" 2>/dev/null
rc=$?

if [ "$rc" -eq 0 ]; then
	echo "FAIL pin-ringbuf-failure: daemon exited 0 despite forced ringbuf failure"
	cat "$LOG" >&2
	exit 1
fi

# Daemon should have logged the ringbuf error.
if ! grep -q 'ringbuf:' "$LOG"; then
	echo "FAIL pin-ringbuf-failure: no ringbuf error in daemon log"
	cat "$LOG" >&2
	exit 1
fi

# Critical assertion: no pinned links left behind.
leaked=""
if [ -d "$PIN_ROOT/links" ]; then
	leaked=$(ls -A "$PIN_ROOT/links" 2>/dev/null || true)
fi
if [ -n "$leaked" ]; then
	echo "FAIL pin-ringbuf-failure: orphan pins after ringbuf failure: $leaked"
	exit 1
fi

echo "PASS pin-ringbuf-failure: ringbuf failure → exit $rc, no orphan pins"
exit 0
