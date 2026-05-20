#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/profile-e2e/aide.sh — ED-9 AIDE actor-bound profile witness.
#
# Verifies that profiles/aide.conf:
#   1. parses + loads cleanly when AIDE is installed (the load-time
#      ED-5 strict-mode check passes against the actor binary's seal),
#   2. denies a non-aide caller writing the sealed baseline DB,
#   3. allows aide --version to run (positive smoke: the actor binary
#      itself is not over-sealed; aide can still be invoked).
#
# Exit convention follows tests/bypass/lib-bypass.sh:
#   0 = PASS
#   1 = FAIL
#  77 = SKIP (env doesn't support — e.g. AIDE not installed)
#
# Intentionally NOT in the NONCE / WORKFLOW_OUTPUT_HASH / E2E_VERDICT
# style used by the V-3b orchestrator: AIDE is an actor-allowlist
# witness, more closely related to the bypass suite than the workflow
# round-trip tests. The V-3b orchestrator (tests/profile-e2e.sh) will
# auto-SKIP aide via its UNIT[aide] guard.
set -u

NAME="aide-e2e"
REPO="${REPO:-$(realpath "$(dirname "$0")/../..")}"
DAEMON="${DAEMON:-${REPO}/compartment-bpf}"
SEALPROBE="${SEALPROBE:-${REPO}/tests/sealprobe}"
PROFILE="${PROFILE:-${REPO}/profiles/aide.conf}"

skip() { echo "SKIP ${NAME}: $*" >&2; exit 77; }
fail() { echo "FAIL ${NAME}: $*" >&2; exit 1; }
pass() { echo "PASS ${NAME}: $*"; exit 0; }

# --- pre-flight -------------------------------------------------------
[ "$(id -u)" -eq 0 ] || skip "needs root (LSM hooks require CAP_BPF)"
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
	|| skip "bpf not in active LSM"
[ -x "$DAEMON" ]    || skip "daemon not built ($DAEMON)"
[ -x "$SEALPROBE" ] || skip "sealprobe not built ($SEALPROBE)"
[ -f "$PROFILE" ]   || skip "profile missing ($PROFILE)"

command -v aide >/dev/null 2>&1 || skip "aide not installed"
# Distro paths: Debian historically /usr/sbin/aide; usr-merged distros
# (Ubuntu Resolute) ship aide at /usr/bin/aide. Discover the actual
# absolute path, then below we splice it into a tmp copy of the profile
# so the shipped profile (documented at /usr/sbin/aide) stays canonical
# while the test runs on whichever distro is in front of us.
AIDE_BIN="$(command -v aide)"
[ -x "$AIDE_BIN" ] || skip "aide reported by command -v but not executable: $AIDE_BIN"

# The seal targets in aide.conf must exist or the loader fails at
# O_PATH+fstat. Initialize a baseline DB if one doesn't exist. `aide
# --init` writes /var/lib/aide/aide.db.new — we copy it to aide.db so
# both paths exist for the seal load. SKIP loudly if init fails.
need_init=0
[ -f /var/lib/aide/aide.db ]     || need_init=1
[ -f /var/lib/aide/aide.db.new ] || need_init=1
TMP_INIT_ERR=$(mktemp /tmp/aide-init-err.XXXXXX)
if [ "$need_init" = "1" ]; then
	mkdir -p /var/lib/aide /etc/aide /etc/aide/aide.conf.d
	[ -f /etc/aide/aide.conf ] || {
		# Minimal config compatible with aide >= 0.18 (database_in= form).
		# aide on Ubuntu Resolute (0.19.2) rejects the older bare
		# `database=file:` shorthand. Hash group `p+i+u+g` is enough
		# to exercise an --init scan without picking heavy checksums.
		cat > /etc/aide/aide.conf <<'EOF'
database_in=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
gzip_dbout=no
report_url=stdout
/etc p+i+u+g
EOF
	}
	# Explicit --config so we don't depend on aide's built-in default
	# (which on Resolute is <none>). Suppress stdout (verbose=5 is loud)
	# but capture stderr so a SKIP can diagnose what went wrong.
	if ! aide --init --config=/etc/aide/aide.conf >/dev/null 2>"$TMP_INIT_ERR"; then
		skip "aide --init failed: $(head -1 "$TMP_INIT_ERR" 2>/dev/null)"
	fi
	[ -f /var/lib/aide/aide.db.new ] || skip "aide --init produced no aide.db.new: $(head -1 "$TMP_INIT_ERR" 2>/dev/null)"
	cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
fi

# --- daemon launch with profiles/aide.conf ----------------------------
TMP=$(mktemp -d /tmp/aide-e2e.XXXXXX)
trap '
	[ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null
	[ -n "${DAEMON_PID:-}" ] && wait "$DAEMON_PID" 2>/dev/null
	rm -rf "$TMP"
' EXIT INT TERM

DAEMON_LOG="$TMP/daemon.err"
# Splice the discovered AIDE_BIN into a per-run profile copy so the test
# works on both /usr/sbin/aide (Debian / pre-usr-merge) and
# /usr/bin/aide (Ubuntu Resolute usr-merge) without forking the shipped
# profile. If AIDE_BIN is already /usr/sbin/aide the substitution is a
# no-op.
PROFILE_RUN="$TMP/aide.run.conf"
sed "s|/usr/sbin/aide|${AIDE_BIN}|g" "$PROFILE" > "$PROFILE_RUN"
"$DAEMON" "$PROFILE_RUN" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do
	grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null && break
	kill -0 "$DAEMON_PID" 2>/dev/null \
		|| { cat "$DAEMON_LOG" >&2; fail "daemon died loading aide.conf"; }
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null \
	|| { cat "$DAEMON_LOG" >&2; fail "daemon did not go live with aide.conf"; }

# R2-F7 (Review-2 HIGH): snapshot actor_mismatch_total before the
# attempted deny so we can assert strict increment after. `--stats`
# reads PINNED counter maps under PIN_ROOT/maps; this e2e test
# does NOT pin (the daemon is launched in the background and torn
# down at exit). When no pinned counters exist `--stats` exits 2;
# we detect that and skip the counter assertion with an [info]
# marker — the actor_name ringbuf assertion below is the load-
# bearing evidence either way.
STATS_OUT=$("$DAEMON" --stats 2>/dev/null); STATS_RC=$?
stats_before=$(printf '%s\n' "$STATS_OUT" | sed -n 's/.*actor_mismatch_total=\([0-9?]*\).*/\1/p' | head -1)
[ "$stats_before" = "?" ] && stats_before=0
: "${stats_before:=0}"
HAVE_STATS=1
[ "$STATS_RC" -ne 0 ] && HAVE_STATS=0

# --- negative: non-aide write to baseline DB must DENY ----------------
# sealprobe's exe inode is /usr/local/bin/sealprobe (or wherever it's
# built), NOT in actor `aide` → no-write actor=aide must reject.
"$SEALPROBE" open-write /var/lib/aide/aide.db >/dev/null 2>&1; rc=$?
case $rc in
	1) : ;;  # DENY — expected
	0) fail "BYPASS: non-aide caller wrote /var/lib/aide/aide.db" ;;
	*) fail "non-aide write rc=$rc (expected 1=DENY)" ;;
esac

# ringbuf__poll cadence is 1s; allow the event to land in DAEMON_LOG.
sleep 2

# R2-F7 assertion (a): actor_name=aide in kernel audit ringbuf.
if ! grep -qE '\[audit\] DENY_ACTOR_MISMATCH .* actor=aide' "$DAEMON_LOG"; then
	cat "$DAEMON_LOG" >&2
	fail "audit emit missing 'actor=aide' on DENY_ACTOR_MISMATCH (R2-F7 ringbuf assertion)"
fi

# R2-F7 assertion (b): actor_mismatch_total strictly incremented.
# Conditional on the pinned-counters being present (see HAVE_STATS).
if [ "$HAVE_STATS" = "1" ]; then
	stats_after=$(
		"$DAEMON" --stats 2>/dev/null \
		| sed -n 's/.*actor_mismatch_total=\([0-9?]*\).*/\1/p' \
		| head -1
	)
	[ "$stats_after" = "?" ] && stats_after=0
	: "${stats_after:=0}"
	if [ "$stats_after" -le "$stats_before" ]; then
		fail "actor_mismatch_total did not increment ($stats_before → $stats_after)"
	fi
else
	stats_after="(no pinned counters; --stats rc=$STATS_RC; counter assertion skipped, ringbuf actor= is the load-bearing R2-F7 evidence)"
fi

# --- positive smoke: aide itself can be invoked -----------------------
# --version (no scan, no DB read) ensures the strict-mode seal on the
# aide binary doesn't accidentally prevent runtime invocation.
aide --version >/dev/null 2>&1; rc=$?
[ "$rc" -eq 0 ] \
	|| fail "aide --version failed under aide.conf seal (rc=$rc)"

# R2-F7 assertion (c): positive actor-ALLOW path via aide --update.
# aide --update writes aide.db.new from aide.db; the actor (aide
# binary's own exe inode) is the writer, so the LSM hook permits
# the write. Cap at 120s.
#
# aide --update exit codes are a bitfield, NOT pass/fail:
#   bit 0 (=1) new files added
#   bit 1 (=2) files removed
#   bit 2 (=4) files changed
#   bit 3 (=8) write error
#   bit 4 (=16) other I/O error
#   ...
# A normal run on a slightly-modified /etc tree returns 5
# (NF+CF) — that means the scan completed AND the new DB was
# successfully written. The load-bearing R2-F7 actor-ALLOW
# witness is "did aide.db.new get written?" (i.e. did the LSM
# permit the actor's write), NOT "did aide return zero?". Check
# the mtime; flag actual LSM-style failures via the upper bits
# (8 = write error, 16 = I/O error, etc.).
PRE_NEW_MTIME=$(stat -c %Y /var/lib/aide/aide.db.new 2>/dev/null || echo 0)
TMP_UPDATE_ERR=$(mktemp /tmp/aide-update-err.XXXXXX)
timeout 120 aide --update --config=/etc/aide/aide.conf >/dev/null 2>"$TMP_UPDATE_ERR"
aide_rc=$?
POST_NEW_MTIME=$(stat -c %Y /var/lib/aide/aide.db.new 2>/dev/null || echo 0)
# Fail-closed on bits indicating an actual I/O / write error
# (bit3=8, bit4=16) — that is the LSM-blocked-the-write signature.
# Diff-only bits (NF=1, RF=2, CF=4) are normal scan output.
if [ $((aide_rc & 24)) -ne 0 ]; then
	fail "aide --update failed under aide.conf seal (rc=$aide_rc, bits 8/16 indicate write/I-O error): $(head -1 "$TMP_UPDATE_ERR" 2>/dev/null)"
fi
if [ "$POST_NEW_MTIME" -le "$PRE_NEW_MTIME" ]; then
	fail "aide --update did not advance aide.db.new mtime ($PRE_NEW_MTIME → $POST_NEW_MTIME); LSM may have blocked the actor's write (rc=$aide_rc)"
fi

pass "non-aide write denied + actor=aide in audit ringbuf + counter $stats_before → $stats_after + aide --update permitted (positive actor-ALLOW)"
