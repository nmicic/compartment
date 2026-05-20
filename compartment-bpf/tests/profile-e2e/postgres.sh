#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/profile-e2e/postgres.sh — ED-10 PostgreSQL actor-bound profile
# witness.
#
# Verifies that profiles/postgres.conf:
#   1. parses + loads cleanly when PostgreSQL is installed (the load-time
#      ED-5 strict-mode check passes against the actor binary's seal),
#   2. denies a non-postgres caller writing PG_VERSION under the data dir,
#      with the kernel emitting ACTION_DENY_ACTOR_MISMATCH,
#   3. allows the postgres server itself to keep running (positive smoke:
#      `pg_isready` succeeds against the live cluster while the profile is
#      pinned).
#
# Same shape as tests/profile-e2e/aide.sh (ED-9). Substitutes the postgres
# major version literal (default 18 = Resolute) into a per-run profile
# copy so the shipped profile (anchored at version 18) stays canonical
# while the test works on any deployed cluster.
#
# Exit convention follows tests/bypass/lib-bypass.sh:
#   0 = PASS
#   1 = FAIL
#  77 = SKIP (env doesn't support — postgres not installed / cluster down)
set -u

NAME="postgres-e2e"
REPO="${REPO:-$(realpath "$(dirname "$0")/../..")}"
DAEMON="${DAEMON:-${REPO}/compartment-bpf}"
SEALPROBE="${SEALPROBE:-${REPO}/tests/sealprobe}"
PROFILE="${PROFILE:-${REPO}/profiles/postgres.conf}"

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

# Discover the installed cluster + version via pg_lsclusters. The profile
# is anchored at version 18 (Ubuntu Resolute default); we splice the
# discovered version into a per-run profile copy below. pg_lsclusters is
# part of postgresql-common, present on every Debian-family install where
# postgres is packaged.
command -v pg_lsclusters >/dev/null 2>&1 \
	|| skip "pg_lsclusters not present (postgresql-common missing)"
LS="$(pg_lsclusters --no-header 2>/dev/null | head -1 || true)"
[ -n "$LS" ] || skip "no postgres clusters configured"
PG_VER="$(echo "$LS" | awk '{print $1}')"
PG_CLUS="$(echo "$LS" | awk '{print $2}')"
PG_STATUS="$(echo "$LS" | awk '{print $4}')"
[ -n "$PG_VER" ] && [ -n "$PG_CLUS" ] || skip "could not parse pg_lsclusters: $LS"
[ "$PG_STATUS" = "online" ] || skip "cluster $PG_VER/$PG_CLUS not online (status=$PG_STATUS)"

PG_BIN="/usr/lib/postgresql/${PG_VER}/bin/postgres"
PG_DATA="/var/lib/postgresql/${PG_VER}/${PG_CLUS}"
PG_VERSION_FILE="${PG_DATA}/PG_VERSION"
[ -x "$PG_BIN" ]            || skip "postgres binary missing: $PG_BIN"
[ -f "$PG_VERSION_FILE" ]   || skip "PG_VERSION sentinel missing: $PG_VERSION_FILE"

command -v pg_isready >/dev/null 2>&1 \
	|| skip "pg_isready not on PATH (postgresql-client missing)"

# --- daemon launch with postgres.conf ---------------------------------
TMP=$(mktemp -d /tmp/postgres-e2e.XXXXXX)
trap '
	[ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null
	[ -n "${DAEMON_PID:-}" ] && wait "$DAEMON_PID" 2>/dev/null
	rm -rf "$TMP"
' EXIT INT TERM

# Splice cluster name + major version into a per-run profile so the test
# works against any deployed cluster, not just the canonical 18/main.
PROFILE_RUN="$TMP/postgres.run.conf"
sed -e "s|/usr/lib/postgresql/18/|/usr/lib/postgresql/${PG_VER}/|g" \
    -e "s|/etc/postgresql/18/main/|/etc/postgresql/${PG_VER}/${PG_CLUS}/|g" \
    -e "s|/var/lib/postgresql/18/main|/var/lib/postgresql/${PG_VER}/${PG_CLUS}|g" \
    "$PROFILE" > "$PROFILE_RUN"

DAEMON_LOG="$TMP/daemon.err"
"$DAEMON" "$PROFILE_RUN" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do
	grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null && break
	kill -0 "$DAEMON_PID" 2>/dev/null \
		|| { cat "$DAEMON_LOG" >&2; fail "daemon died loading postgres.conf"; }
	sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null \
	|| { cat "$DAEMON_LOG" >&2; fail "daemon did not go live with postgres.conf"; }

# --- negative: non-postgres write to PG_VERSION sentinel must DENY ----
# sealprobe's exe is /root/compartment_ebpf/tests/sealprobe, NOT in actor
# `postgres` → no-write,no-unlink,no-rename actor=postgres must reject.
# We target PG_VERSION specifically (rather than the data dir itself)
# because the dir seal blocks create/unlink/rename of entries; opening
# the existing sentinel file for write hits the file-seal hook and is the
# stronger ACTION_DENY_ACTOR_MISMATCH witness.
#
# R2-F5 SCOPE NOTE: this assertion witnesses v0.x's actual coverage —
# per-file sentinel write protection + structural mutation guard. It
# does NOT witness "every file under data dir write-protected" because
# v0.x has no recursive-subtree-seal primitive; heap files / WAL
# segments are still writable by root. v1.x scope.
# R2-F7 (Review-2 HIGH): snapshot actor_mismatch_total before the
# attempted deny. --stats reads PINNED counters under PIN_ROOT/maps;
# this e2e test does not pin, so --stats may exit 2. Skip the
# counter assertion in that case with an [info] marker.
STATS_OUT=$("$DAEMON" --stats 2>/dev/null); STATS_RC=$?
stats_before=$(printf '%s\n' "$STATS_OUT" | sed -n 's/.*actor_mismatch_total=\([0-9?]*\).*/\1/p' | head -1)
[ "$stats_before" = "?" ] && stats_before=0
: "${stats_before:=0}"
HAVE_STATS=1
[ "$STATS_RC" -ne 0 ] && HAVE_STATS=0

"$SEALPROBE" open-write "$PG_VERSION_FILE" >/dev/null 2>&1; rc=$?
case $rc in
	1) : ;;  # DENY — expected
	0) fail "BYPASS: non-postgres caller wrote $PG_VERSION_FILE" ;;
	*) fail "non-postgres write rc=$rc (expected 1=DENY)" ;;
esac

# ringbuf__poll cadence is 1s; allow event to land in DAEMON_LOG.
sleep 2

# R2-F7 assertion (a): actor_name=postgres in kernel audit ringbuf.
if ! grep -qE '\[audit\] DENY_ACTOR_MISMATCH .* actor=postgres' "$DAEMON_LOG"; then
	cat "$DAEMON_LOG" >&2
	fail "audit emit missing 'actor=postgres' on DENY_ACTOR_MISMATCH (R2-F7 ringbuf assertion)"
fi

# R2-F7 assertion (b): actor_mismatch_total strictly incremented
# (conditional on pinned counters).
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

# --- positive smoke: the live cluster keeps responding ----------------
# The cluster was already online before we loaded the profile (we
# require status=online above). Sealing must not have wedged the
# already-running backend. pg_isready connects to the listening socket
# and verifies the cluster accepts a TCP handshake — cheap, no auth.
pg_isready -q >/dev/null 2>&1; rc=$?
[ "$rc" -eq 0 ] \
	|| fail "pg_isready failed under postgres.conf seal (rc=$rc; cluster wedged?)"

# R2-F7 assertion (c): positive actor-ALLOW path via psql write to a
# scratch object. pg_isready is TCP-handshake only; psql exercises the
# backend's actual write path (heap + WAL). The backend's exe inode is
# the postgres actor binary, so the LSM hook must ALLOW these writes
# (writes inside the data dir to NON-PG_VERSION files are not
# protected anyway in v0.x — see R2-F5 SCOPE NOTE — but the assertion
# below specifically verifies the postgres backend keeps serving with
# the actor-bound profile pinned).
SCRATCH_TBL="compartment_bpf_r2f7_scratch_$$"
psql_out=$(sudo -u postgres psql -tA -X -v ON_ERROR_STOP=1 -c \
	"CREATE TABLE IF NOT EXISTS ${SCRATCH_TBL} (x int); \
	 INSERT INTO ${SCRATCH_TBL} VALUES (1); \
	 SELECT count(*) FROM ${SCRATCH_TBL}; \
	 DROP TABLE ${SCRATCH_TBL};" 2>&1)
prc=$?
if [ "$prc" -ne 0 ]; then
	echo "$psql_out" >&2
	fail "psql write-permit smoke failed under postgres.conf seal (rc=$prc); backend ALLOW path broken"
fi

pass "non-postgres PG_VERSION write denied + actor=postgres in audit ringbuf + counter $stats_before → $stats_after + psql write-permit OK ($PG_VER/$PG_CLUS) [v0.x scope; heap-file write-protection deferred to v1.x]"
