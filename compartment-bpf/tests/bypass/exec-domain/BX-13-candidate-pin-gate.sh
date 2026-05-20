#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-13-candidate-pin-gate.sh
# P1-C (V-6 re-run #1, 2026-05-16): assert the `--pin` path refuses a
# candidate-marked profile unless the operator opts in with
# `--allow-candidate`.
#
# Before this fix, `compartment-bpf --pin` against a profile carrying
# `#@compartment-bpf-profile-status: candidate` printed a WARNING and
# proceeded into strict-mode enforcement + freeze + pin. The warn-only
# behaviour was trivially silenced by `2>/dev/null`, so a draft profile
# emitted by `compartment-bpf observe` could be promoted to live
# enforcement without operator review.
#
# Witnesses:
#   1. `--dry-run` against a candidate profile: rc=0 + WARNING line.
#      The warn-only path is preserved for non-enforcement modes
#      (load_conf is called with pin_enforce_path=0 in dry-run).
#   2. `--pin candidate.conf` (no override): rc!=0 + "refusing to
#      --pin without --allow-candidate" diagnostic; pin tree must
#      NOT have been created (the gate is fail-closed before freeze
#      + attach, but after BPF __load — so we sanity-check the pin
#      paths under PIN_ROOT did not appear).
#   3. `--allow-candidate --pin candidate.conf`: daemon goes live;
#      WARNING line still present (override is auditable); refusal
#      diagnostic absent. We tear down via SIGTERM + --unpin so the
#      test does not leave a live pin behind.
set -u
BYPASS_NAME="BX-13-candidate-pin-gate"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

# Build a candidate profile that would otherwise be a valid load.
ACTOR=$(ed_create_actor actor)
TARGET="$TMP/target"
echo content > "$TARGET"
cat > "$TMP/candidate.conf" <<EOF
#@compartment-bpf-profile-status: candidate
actor myactor = $ACTOR
seal $ACTOR full
seal $TARGET no-write actor=myactor
EOF

# Build an identical non-candidate profile for the override witness.
cat > "$TMP/promoted.conf" <<EOF
actor myactor = $ACTOR
seal $ACTOR full
seal $TARGET no-write actor=myactor
EOF

# ----- Witness 1: dry-run candidate is warn-only (preserved). -----
OUT1="$TMP/w1.err"
"$DAEMON" --dry-run "$TMP/candidate.conf" >"$OUT1" 2>&1
rc1=$?
if [ "$rc1" -ne 0 ]; then
	cat "$OUT1" >&2
	bypass_fail "dry-run candidate must be warn-only (got rc=$rc1)"
fi
if ! grep -q "profile-status: candidate" "$OUT1"; then
	cat "$OUT1" >&2
	bypass_fail "dry-run candidate did not emit the candidate-marker WARNING"
fi
if grep -q "refusing to --pin" "$OUT1"; then
	cat "$OUT1" >&2
	bypass_fail "dry-run candidate emitted the --pin refusal (should be warn-only)"
fi

# ----- Witness 2: --pin candidate refused with rc!=0. -----
# Pre-flight: clear any stale pin contents from a prior --pin daemon.
# Other BX tests run un-pinned; the empty PIN_ROOT directory structure
# (links/, maps/) is created lazily by libbpf and can persist as empty
# dirs across runs. Only the presence of actual *entries* under those
# dirs is what would interfere with our witness.
"$DAEMON" --unpin >/dev/null 2>&1 || true
links_n=$(ls -A /sys/fs/bpf/compartment/links 2>/dev/null | wc -l)
maps_n=$(ls -A /sys/fs/bpf/compartment/maps 2>/dev/null | wc -l)
if [ "$links_n" -gt 0 ] || [ "$maps_n" -gt 0 ]; then
	bypass_skip "stale pin entries present after --unpin (links=$links_n maps=$maps_n); refusing --pin witness"
fi
OUT2="$TMP/w2.err"
"$DAEMON" --pin "$TMP/candidate.conf" >"$OUT2" 2>&1
rc2=$?
if [ "$rc2" -eq 0 ]; then
	# Worst case: we may have created a real pin tree. Unpin best-effort
	# so the suite does not contaminate downstream tests.
	"$DAEMON" --unpin >/dev/null 2>&1 || true
	cat "$OUT2" >&2
	bypass_fail "--pin candidate.conf succeeded (rc=0); gate did not fire"
fi
if ! grep -q "refusing to --pin without --allow-candidate" "$OUT2"; then
	cat "$OUT2" >&2
	bypass_fail "--pin candidate.conf failed but without the expected diagnostic"
fi
# Sanity: the gate is fail-closed before freeze + attach, so no pin
# entries should have been created (empty PIN_ROOT subdirs may persist
# from a prior run — that is libbpf bookkeeping, not a gate breach).
links_after=$(ls -A /sys/fs/bpf/compartment/links 2>/dev/null | wc -l)
maps_after=$(ls -A /sys/fs/bpf/compartment/maps 2>/dev/null | wc -l)
if [ "$links_after" -gt 0 ] || [ "$maps_after" -gt 0 ]; then
	"$DAEMON" --unpin >/dev/null 2>&1 || true
	bypass_fail "--pin candidate.conf was refused but pin entries appeared (links=$links_after maps=$maps_after); gate ran too late"
fi

# ----- Witness 3: --allow-candidate --pin candidate is accepted. -----
# The daemon runs in foreground; we run it in the background, wait
# for the live marker, then SIGTERM + --unpin to clean up.
OUT3="$TMP/w3.err"
"$DAEMON" --allow-candidate --pin "$TMP/candidate.conf" >"$OUT3" 2>&1 &
DPID3=$!
live=0
for _ in $(seq 1 100); do
	if grep -q '\[run\] compartment-bpf live' "$OUT3" 2>/dev/null; then
		live=1
		break
	fi
	kill -0 "$DPID3" 2>/dev/null || break
	sleep 0.1
done
if [ "$live" -ne 1 ]; then
	kill "$DPID3" 2>/dev/null || true
	wait "$DPID3" 2>/dev/null || true
	"$DAEMON" --unpin >/dev/null 2>&1 || true
	cat "$OUT3" >&2
	bypass_fail "--allow-candidate --pin did not bring the daemon live"
fi
# Even on the override path, the WARNING line must still appear so
# the override is auditable.
if ! grep -q "profile-status: candidate" "$OUT3"; then
	cat "$OUT3" >&2
	kill "$DPID3" 2>/dev/null || true
	"$DAEMON" --unpin >/dev/null 2>&1 || true
	bypass_fail "--allow-candidate --pin: candidate WARNING missing (override must still audit)"
fi
# Refusal diagnostic must NOT appear on the override path.
if grep -q "refusing to --pin without --allow-candidate" "$OUT3"; then
	kill "$DPID3" 2>/dev/null || true
	"$DAEMON" --unpin >/dev/null 2>&1 || true
	bypass_fail "--allow-candidate --pin: refusal diagnostic fired (override did not suppress)"
fi
# Teardown: kill daemon, wait, unpin, confirm.
kill "$DPID3" 2>/dev/null || true
wait "$DPID3" 2>/dev/null || true
"$DAEMON" --unpin >/dev/null 2>&1 || true

bypass_pass "candidate-pin gate fail-closed; --allow-candidate override works (P1-C v6-rerun1)"
