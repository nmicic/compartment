#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/pin-passphrase.sh — ED-11 unpin-passphrase witness.
#
# Verifies the Argon2id-sentinel gate on the --unpin path
# (SPEC §7.2 Shape A):
#
#   T11.1 Pin with COMPARTMENT_BPF_PASSPHRASE → sentinel exists,
#         mode 0600, root-owned.
#   T11.2 --unpin without the env var (and non-tty stdin) → FAIL
#         with ACTION_DENY_UNPIN_AUTH_FAIL audit event; sentinel intact.
#   T11.3 --unpin with the WRONG passphrase → FAIL with
#         ACTION_DENY_UNPIN_AUTH_FAIL; sentinel intact.
#   T11.4 --unpin with the CORRECT passphrase → SUCCESS, sentinel gone.
#   T11.5 Pin WITHOUT a passphrase → no sentinel written
#         (legacy v0.x compat).
#   T11.6 --unpin on a legacy pin (no sentinel) → SUCCESS without prompt
#         (backward compatible).
#
# Exit: 0 = all pass, 1 = any failure, 77 = SKIP (env unsupported).
set -u

NAME="pin-passphrase"
REPO="${REPO:-$(realpath "$(dirname "$0")/..")}"
BIN="${BIN:-${REPO}/compartment-bpf}"
SENTINEL="/run/compartment-bpf/unpin-sentinel"
PIN_ROOT="/sys/fs/bpf/compartment"

# ABI v0.3 ACTION_DENY_UNPIN_AUTH_FAIL = 7. Mirror compartment-abi.h.
ACTION_CODE=7

# A-1: bind passphrase to a single variable shared between the test body
# and cleanup (was: cleanup used a hard-coded literal that did not match
# what the test exported, so an abort mid-flow left the pin tree behind).
PASSPHRASE="compartment-ed11-test-passphrase"

skip()   { echo "SKIP ${NAME}: $*" >&2; exit 77; }
fail()   { echo "[FAIL] ${NAME}: $*" >&2; FAILED=1; }
pass()   { echo "[PASS] ${NAME}: $*"; }

# Returns 0 if anything is pinned under $PIN_ROOT/{links,maps}.
pins_present() {
	if [ -d "$PIN_ROOT/links" ]; then
		for p in "$PIN_ROOT/links"/*; do
			[ -e "$p" ] && return 0
		done
	fi
	if [ -d "$PIN_ROOT/maps" ]; then
		for p in "$PIN_ROOT/maps"/*; do
			[ -e "$p" ] && return 0
		done
	fi
	return 1
}

# --- pre-flight -------------------------------------------------------
[ "$(id -u)" -eq 0 ] || skip "needs root (BPF LSM load)"
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| skip "bpf not in active LSM"
[ -x "$BIN" ] || skip "daemon not built ($BIN)"
# Sentinel needs libsodium-linked binary; smoke that:
ldd "$BIN" 2>/dev/null | grep -q libsodium || skip "compartment-bpf not linked against libsodium"

TMP=$(mktemp -d /tmp/pin-passphrase.XXXXXX)
DAEMON_PID=""
# A-1: tracks whether a pin lifecycle is in-flight; set to 1 once a
# `--pin` daemon has gone live and cleared once `--unpin` succeeds.
policy_pinned=0
cleanup() {
	rc=$?
	if [ -n "${DAEMON_PID}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
		kill -TERM "$DAEMON_PID" 2>/dev/null || true
		wait "$DAEMON_PID" 2>/dev/null || true
	fi
	# Primary teardown: use $PASSPHRASE — the variable the test actually
	# set, not a stale literal. Works for both passphrase-gated pins
	# (T11.1 path) and legacy / no-sentinel pins (T11.5 path; the env
	# var is ignored when no sentinel is present).
	if [ "$policy_pinned" -eq 1 ]; then
		COMPARTMENT_BPF_PASSPHRASE="$PASSPHRASE" \
			"$BIN" --unpin </dev/null >/dev/null 2>&1 && policy_pinned=0
	fi
	# Recovery: if pins still exist (passphrase mismatch, sentinel write
	# raced the abort, etc.) nuke the sentinel and retry --unpin so a
	# stuck pin tree cannot bleed into a subsequent test.
	if pins_present; then
		rm -f "$SENTINEL" 2>/dev/null || true
		"$BIN" --unpin </dev/null >/dev/null 2>&1 || true
	fi
	rm -f "$SENTINEL" 2>/dev/null || true
	rm -rf "$TMP"
	# Fail loud if any pin remains — CI must see the cross-test leak.
	if pins_present; then
		echo "[FAIL] ${NAME}: pins still present under $PIN_ROOT after cleanup; cross-test leak risk" >&2
		exit 1
	fi
	exit "$rc"
}
trap cleanup EXIT INT TERM

# Stale-state sweep so the test starts deterministic.
"$BIN" --unpin >/dev/null 2>&1 || true
rm -f "$SENTINEL" 2>/dev/null || true

echo "stay-sealed" > "$TMP/sealed"
cat > "$TMP/profile.conf" <<EOF
seal $TMP/sealed no-write
EOF

start_daemon_with_pass() {
	# $1 = passphrase ("" → legacy / no-passphrase pin)
	rm -f "$TMP/daemon.log"
	if [ -n "$1" ]; then
		COMPARTMENT_BPF_PASSPHRASE="$1" "$BIN" --pin "$TMP/profile.conf" </dev/null \
			>"$TMP/daemon.log" 2>&1 &
	else
		"$BIN" --pin "$TMP/profile.conf" </dev/null \
			>"$TMP/daemon.log" 2>&1 &
	fi
	DAEMON_PID=$!
	# Poll up to ~15s: the passphrase path runs memory-hard Argon2id (libsodium
	# crypto_pwhash, intentionally slow) and startup also loads vmlinux BTF +
	# attaches 21 LSM links, which on slower / older kernels (e.g. Noble 6.8)
	# can exceed a tight few-second budget. The daemon liveness is startup, not
	# a hot path, so a generous wait is correct (matches the bench-script poll).
	for i in $(seq 1 50); do
		if grep -q '\[run\] compartment-bpf live' "$TMP/daemon.log" 2>/dev/null; then
			# A-1: daemon is live → policy is now pinned. Cleanup needs
			# to know this so it can teardown using $PASSPHRASE if the
			# test aborts mid-flow.
			policy_pinned=1
			return 0
		fi
		# If the daemon process already exited, stop waiting — it failed fast.
		kill -0 "$DAEMON_PID" 2>/dev/null || break
		sleep 0.3
	done
	cat "$TMP/daemon.log" >&2
	return 1
}

stop_daemon() {
	if [ -n "${DAEMON_PID}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
		kill -TERM "$DAEMON_PID" 2>/dev/null || true
		wait "$DAEMON_PID" 2>/dev/null || true
	fi
	DAEMON_PID=""
}

FAILED=0

# --- T11.1: pin with passphrase writes sentinel -----------------------
if ! start_daemon_with_pass "$PASSPHRASE"; then
	fail "T11.1 daemon did not become live"
else
	if [ ! -e "$SENTINEL" ]; then
		fail "T11.1 sentinel was not created at $SENTINEL"
	else
		# Inspect mode + owner.
		mode=$(stat -c '%a' "$SENTINEL")
		owner=$(stat -c '%u' "$SENTINEL")
		if [ "$mode" != "600" ]; then
			fail "T11.1 sentinel mode is $mode (expected 600)"
		elif [ "$owner" != "0" ]; then
			fail "T11.1 sentinel uid is $owner (expected 0)"
		else
			pass "T11.1 pin with passphrase: sentinel created mode 0600 root-owned"
		fi
	fi
fi
# Stop the daemon but leave the pinned policy + sentinel in place.
stop_daemon

# --- T11.2: --unpin without env, non-tty stdin → FAIL -----------------
# /dev/null on stdin guarantees isatty()==0, so the loader can't
# fall back to interactive getpass.
T112_OUT="$TMP/t11.2.log"
"$BIN" --unpin </dev/null >"$T112_OUT" 2>&1; rc=$?
if [ "$rc" -eq 0 ]; then
	fail "T11.2 --unpin without passphrase returned 0 (expected nonzero)"
elif ! grep -qE "\[audit\] DENY_UNPIN_AUTH_FAIL" "$T112_OUT"; then
	fail "T11.2 --unpin without passphrase: no ACTION_DENY_UNPIN_AUTH_FAIL audit emit"
	cat "$T112_OUT" >&2
elif [ ! -e "$SENTINEL" ]; then
	fail "T11.2 sentinel removed after a failing --unpin (should be intact)"
else
	pass "T11.2 --unpin without passphrase denied + audit + sentinel intact"
fi

# --- T11.3: --unpin with WRONG passphrase → FAIL ----------------------
T113_OUT="$TMP/t11.3.log"
COMPARTMENT_BPF_PASSPHRASE="this-is-not-the-right-passphrase" \
	"$BIN" --unpin </dev/null >"$T113_OUT" 2>&1; rc=$?
if [ "$rc" -eq 0 ]; then
	fail "T11.3 --unpin with wrong passphrase returned 0 (expected nonzero)"
elif ! grep -qE "\[audit\] DENY_UNPIN_AUTH_FAIL" "$T113_OUT"; then
	fail "T11.3 --unpin with wrong passphrase: no ACTION_DENY_UNPIN_AUTH_FAIL audit emit"
	cat "$T113_OUT" >&2
elif [ ! -e "$SENTINEL" ]; then
	fail "T11.3 sentinel removed after a failing --unpin (should be intact)"
else
	pass "T11.3 --unpin with wrong passphrase denied + audit + sentinel intact"
fi

# --- T11.4: --unpin with CORRECT passphrase → SUCCESS -----------------
T114_OUT="$TMP/t11.4.log"
COMPARTMENT_BPF_PASSPHRASE="$PASSPHRASE" \
	"$BIN" --unpin </dev/null >"$T114_OUT" 2>&1; rc=$?
if [ "$rc" -ne 0 ]; then
	fail "T11.4 --unpin with correct passphrase rc=$rc (expected 0)"
	cat "$T114_OUT" >&2
elif [ -e "$SENTINEL" ]; then
	fail "T11.4 sentinel still present after successful --unpin (should be unlinked)"
else
	policy_pinned=0
	pass "T11.4 --unpin with correct passphrase: success; sentinel removed"
fi

# --- T11.5: pin WITHOUT passphrase (legacy) writes no sentinel --------
if ! start_daemon_with_pass ""; then
	fail "T11.5 legacy daemon did not become live"
elif [ -e "$SENTINEL" ]; then
	fail "T11.5 sentinel created on legacy pin (passphrase env unset); should be absent"
else
	pass "T11.5 pin without passphrase: no sentinel (legacy compat preserved)"
fi
stop_daemon

# --- T11.6: --unpin on legacy pin (no sentinel) → SUCCESS no prompt ---
T116_OUT="$TMP/t11.6.log"
"$BIN" --unpin </dev/null >"$T116_OUT" 2>&1; rc=$?
if [ "$rc" -ne 0 ]; then
	fail "T11.6 legacy --unpin rc=$rc (expected 0)"
	cat "$T116_OUT" >&2
elif grep -qE "\[audit\] DENY_UNPIN_AUTH_FAIL" "$T116_OUT"; then
	fail "T11.6 legacy --unpin emitted ACTION_DENY_UNPIN_AUTH_FAIL (no sentinel: should be silent)"
else
	policy_pinned=0
	pass "T11.6 legacy --unpin (no sentinel) succeeded without auth (backward-compat)"
fi

# --- ACTION_DENY_UNPIN_AUTH_FAIL numeric stability --------------------
# R2-F2 + R2-M23: the userspace audit emit now uses the unified
# `[audit] DENY_UNPIN_AUTH_FAIL ts=… pid=… …` format (action_name()
# symbolic, matches the kernel-side handler). Numeric stability still
# matters for the SIEM correlation contract — assert it directly
# against compartment-abi.h instead of fishing it back out of the
# audit string.
if grep -qE "^#define[[:space:]]+ACTION_DENY_UNPIN_AUTH_FAIL[[:space:]]+${ACTION_CODE}\b" "${REPO}/compartment-abi.h"; then
	pass "ABI action code stable at ${ACTION_CODE} (compartment-abi.h)"
else
	fail "ABI action code drift: expected #define ACTION_DENY_UNPIN_AUTH_FAIL ${ACTION_CODE} in compartment-abi.h"
	grep -E "ACTION_DENY_UNPIN_AUTH_FAIL" "${REPO}/compartment-abi.h" 2>/dev/null
fi
# Cross-check the symbolic-name audit line landed in both T11.2 + T11.3:
if grep -qE "\[audit\] DENY_UNPIN_AUTH_FAIL\b" "$T112_OUT" "$T113_OUT" 2>/dev/null; then
	pass "audit emit uses unified [audit] DENY_UNPIN_AUTH_FAIL format"
else
	fail "audit emit missing unified symbolic format in T11.2/T11.3 output"
	grep -E "audit|ACTION" "$T112_OUT" "$T113_OUT" 2>/dev/null
fi

if [ "$FAILED" -ne 0 ]; then
	echo "${NAME}: FAIL" >&2
	exit 1
fi
echo "${NAME}: OK (8/8)"
exit 0
