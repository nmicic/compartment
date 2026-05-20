#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-16-anon-bdev-refuse.sh
#
# Coverage-gaps 2026-05-16 GAP-H-3 (Angle 1 + Angle 3 cross-flag):
# anon_bdev_refuse() (compartment-bpf.c:765-794) is the load-bearing
# fail-closed gate against silent fail-open on btrfs / overlayfs / FUSE.
# The mesh test treats these filesystems as KNOWN-GAP and SKIPs them,
# but never positively asserts the loader emits the refuse diagnostic
# with rc!=0. A regression that swapped the magic numbers in
# compartment-abi.h or the case arms in lines 776-779 would pass the
# mesh SKIP check and ship.
#
# Witnesses (3 sub-tests, one per call site):
#   W1 — seal target path inside an overlayfs merged tree
#        → anon_bdev_refuse() at compartment-bpf.c:seal_path call site.
#   W2 — actor binary inside an overlayfs merged tree
#        → anon_bdev_refuse() at compartment-bpf.c:actor_resolve_paths.
#   W3 — strict-launch launcher inside an overlayfs merged tree
#        → anon_bdev_refuse() at compartment-bpf.c:1154 strict_validate_launchers.
#
# Each witness runs --dry-run (no daemon attach needed; the gate fires
# during resolve / seal_path before any BPF program loads). The assertion
# is rc != 0 AND the diagnostic mentions "anon_bdev" or "overlayfs".
#
# Environment requirements: mount(2) overlay support + ability to mount
# overlay from a tmp dir. Most production Linux kernels support overlay
# unprivileged-or-privileged; this test runs as root anyway.

set -u
BYPASS_NAME="BX-16-anon-bdev-refuse"
. "$(dirname "$0")/../lib-bypass.sh"

bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
trap 'umount "$TMP/merged" 2>/dev/null || true; rm -rf "$TMP" 2>/dev/null || true' EXIT

mkdir -p "$TMP/lower" "$TMP/upper" "$TMP/work" "$TMP/merged"
echo "lower-content" > "$TMP/lower/file"
chmod 0755 "$TMP/lower/file"

# Provide a real (non-overlay) anchor seal so the profile is not empty
# when we comment out the overlay one. Avoids the empty-profile-fail-closed
# code path firing for a different reason.
ANCHOR="$TMP/anchor"; echo anchor > "$ANCHOR"

# Mount overlay. If mount fails (kernel without overlay support, or
# nested in a container that prohibits overlay), SKIP cleanly.
if ! mount -t overlay overlay \
	-o "lowerdir=$TMP/lower,upperdir=$TMP/upper,workdir=$TMP/work" \
	"$TMP/merged" 2>"$TMP/mount.err"; then
	bypass_skip "overlayfs mount unavailable: $(cat "$TMP/mount.err")"
fi

# Cross-check: confirm we actually got an anon_bdev. /proc/mounts will
# list "overlay overlay" as fs type and `stat -c %d` returns a synthetic
# dev. Skip if for some reason the kernel surfaced a real bdev.
OVERLAY_DEV=$(stat -c %d "$TMP/merged/file" 2>/dev/null || echo 0)
if [ "$OVERLAY_DEV" = "0" ]; then
	bypass_skip "overlay merge stat returned dev=0; environment unusual"
fi

# --- W1: seal target on overlayfs ---
cat > "$TMP/w1.conf" <<EOF
seal $ANCHOR no-write
seal $TMP/merged/file no-write
EOF
W1_LOG="$TMP/w1.log"
set +e
"$DAEMON" --dry-run "$TMP/w1.conf" >"$W1_LOG" 2>&1
W1_RC=$?
set -e

if [ "$W1_RC" -eq 0 ]; then
	echo "----- W1 stderr -----"
	cat "$W1_LOG"
	bypass_fail "W1 seal-on-overlay: --dry-run rc=0 but anon_bdev fail-closed required"
fi
if ! grep -Eq 'anon_bdev|overlayfs|filesystem type 0x' "$W1_LOG"; then
	echo "----- W1 stderr -----"
	cat "$W1_LOG"
	bypass_fail "W1 seal-on-overlay: rc=$W1_RC but anon_bdev diagnostic missing"
fi

# --- W2: actor binary on overlayfs ---
cat > "$TMP/w2.conf" <<EOF
actor olactor = $TMP/merged/file

seal $ANCHOR no-write actor=olactor
EOF
W2_LOG="$TMP/w2.log"
set +e
"$DAEMON" --dry-run "$TMP/w2.conf" >"$W2_LOG" 2>&1
W2_RC=$?
set -e

if [ "$W2_RC" -eq 0 ]; then
	echo "----- W2 stderr -----"
	cat "$W2_LOG"
	bypass_fail "W2 actor-on-overlay: --dry-run rc=0 but anon_bdev fail-closed required"
fi
if ! grep -Eq 'anon_bdev|overlayfs|filesystem type 0x' "$W2_LOG"; then
	echo "----- W2 stderr -----"
	cat "$W2_LOG"
	bypass_fail "W2 actor-on-overlay: rc=$W2_RC but anon_bdev diagnostic missing"
fi

# --- W3: strict-launch launcher on overlayfs ---
# Need a real target binary off-overlay so the only overlay-resident
# path is the launcher. The strict_validate_launchers refuse fires
# specifically at the launcher resolve step.
TARGET="$TMP/target-bin"; cp /bin/true "$TARGET"; chmod 0755 "$TARGET"
cat > "$TMP/w3.conf" <<EOF
actor-strict s = $TARGET launcher=$TMP/merged/file

seal $TARGET full
seal $TMP/merged/file full
seal $ANCHOR no-write
EOF
W3_LOG="$TMP/w3.log"
set +e
"$DAEMON" --dry-run "$TMP/w3.conf" >"$W3_LOG" 2>&1
W3_RC=$?
set -e

if [ "$W3_RC" -eq 0 ]; then
	echo "----- W3 stderr -----"
	cat "$W3_LOG"
	bypass_fail "W3 launcher-on-overlay: --dry-run rc=0 but anon_bdev fail-closed required"
fi
if ! grep -Eq 'anon_bdev|overlayfs|filesystem type 0x' "$W3_LOG"; then
	echo "----- W3 stderr -----"
	cat "$W3_LOG"
	bypass_fail "W3 launcher-on-overlay: rc=$W3_RC but anon_bdev diagnostic missing"
fi

bypass_pass "W1 seal + W2 actor + W3 launcher all anon_bdev fail-closed on overlayfs"
