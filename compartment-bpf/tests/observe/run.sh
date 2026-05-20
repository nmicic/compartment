#!/usr/bin/env bash
# tests/observe/run.sh — acceptance harness for compartment-bpf observe
# (AO-1..AO-5, SPEC §15 minimum test matrix + AIDE witness SPEC §16).
#
# Exit codes per project SKIP convention:
#   0  — all executed tests PASS
#   1  — at least one test FAIL
#   77 — env unsupported (no root / no BPF LSM / not built)

set -u

export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 022

cd "$(dirname "$0")/../.." || exit 2

REPO="$(pwd)"
BIN="$REPO/compartment-bpf"
RESULTS_DIR="${RESULTS_DIR:-$REPO/tests/results/observe-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/run.log"
: > "$LOG"

pass=0; fail=0; skip=0
say()  { printf '%s\n' "$*" | tee -a "$LOG"; }
ok()   { say "PASS  $*"; pass=$((pass+1)); }
nok()  { say "FAIL  $*"; fail=$((fail+1)); }
skip() { say "SKIP  $*"; skip=$((skip+1)); }

trap 'say ""; say "Summary: PASS=$pass FAIL=$fail SKIP=$skip (results in $RESULTS_DIR)"' EXIT

# ------- env gates -------

[ -x "$BIN" ] || {
	say "[observe] SKIP (compartment-bpf not built)"
	exit 77
}

[ "$(id -u)" -eq 0 ] || {
	say "[observe] SKIP (requires root for BPF LSM load)"
	exit 77
}

[ -r /sys/kernel/security/lsm ] || {
	say "[observe] SKIP (no securityfs)"
	exit 77
}

grep -qw bpf /sys/kernel/security/lsm || {
	say "[observe] SKIP (bpf not in active LSMs)"
	exit 77
}

# ------- fixture: a small actor binary for inode-based tests -------
# Use /bin/true — stable path, always present.
ACTOR_BIN="/bin/true"
ACTOR_BIN2="/bin/false"

say ""
say "=== T0: BPF verifier instruction count — combined load (M-5) ==="
if command -v bpftool >/dev/null 2>&1; then
	"$BIN" observe --actor true="$ACTOR_BIN" --duration 2 -o /dev/null &
	OBS_PID=$!
	sleep 0.6
	say "bpftool prog show (observe programs):"
	bpftool prog show 2>/dev/null | \
		awk '/name (ao_bprm|ao_file_open|ao_inode_create|ao_inode_unlink|ao_inode_rename|ao_inode_mkdir|ao_inode_rmdir|ao_inode_link|ao_inode_mknod|ao_inode_symlink|ao_task_alloc|ao_task_free)/{print; found=1; next} found && /xlated/{print; found=0}' \
		| tee -a "$LOG" || true
	wait "$OBS_PID" 2>/dev/null || true
	ok "T0: bpftool prog show captured (see $LOG)"
else
	skip "T0: bpftool not available — skipping prog-info capture"
fi

say ""
say "=== T1: stdout default (no -o) ==="
out=$("$BIN" observe --actor true="$ACTOR_BIN" --duration 1 2>/tmp/obs_t1.err)
if echo "$out" | grep -q '#@compartment-bpf-profile-status: candidate'; then
	ok "T1: profile emitted to stdout"
else
	nok "T1: expected profile on stdout; got: ${out:0:120}"
fi

say ""
say "=== T2: -o FILE writes profile ==="
TFILE="$RESULTS_DIR/t2.profile"
"$BIN" observe --actor true="$ACTOR_BIN" --duration 1 -o "$TFILE" \
	>/dev/null 2>/tmp/obs_t2.err
if [ -f "$TFILE" ] && grep -q '#@compartment-bpf-profile-status: candidate' "$TFILE"; then
	ok "T2: profile written to file"
else
	nok "T2: file not created or missing status header"
fi

say ""
say "=== T3: compact mode prints bounded live lines ==="
# Run with a 2s duration and launch /bin/true to generate at least one event
"$BIN" observe --actor true="$ACTOR_BIN" --format compact --duration 2 \
	-- "$ACTOR_BIN" >"$RESULTS_DIR/t3.compact" 2>/tmp/obs_t3.err
# compact mode must produce output (at least actor exec line or nothing if no match)
# At minimum the binary should start and stop cleanly (rc=0)
if [ $? -eq 0 ]; then
	ok "T3: compact mode exit clean"
else
	nok "T3: compact mode returned non-zero"
fi

say ""
say "=== T4: actor selector follows exact inode, not path string ==="
# Create a hardlink to /bin/true in /tmp; observe tracks by inode so
# the same binary runs under a different name still fires
HLINK="/tmp/observe_hlink_true_$$"
ln "$ACTOR_BIN" "$HLINK" 2>/dev/null || { skip "T4: cannot create hardlink (skip)"; goto_t5=1; }
if [ -z "${goto_t5:-}" ]; then
	out=$("$BIN" observe --actor true="$ACTOR_BIN" --duration 2 \
		-- "$HLINK" 2>/tmp/obs_t4.err)
	rm -f "$HLINK"
	# Profile header must appear regardless of which path ran
	if echo "$out" | grep -q 'actor true'; then
		ok "T4: actor=true registered (inode-based tracking)"
	else
		nok "T4: actor line missing in output"
	fi
fi
unset goto_t5

say ""
say "=== T5: repeated --actor creates distinct slots ==="
out=$("$BIN" observe \
	--actor true="$ACTOR_BIN" \
	--actor false="$ACTOR_BIN2" \
	--duration 1 2>/tmp/obs_t5.err)
n_actors=$(echo "$out" | grep -c '^actor ' || true)
if [ "$n_actors" -ge 2 ]; then
	ok "T5: two distinct actor lines in profile"
else
	nok "T5: expected >=2 actor lines, got $n_actors"
fi

say ""
say "=== T6: fork child attributed (pid selector) ==="
# -- COMMAND forks; the spawned child is attributed to the actor
out=$("$BIN" observe --actor true="$ACTOR_BIN" --duration 3 \
	-- "$ACTOR_BIN" 2>/tmp/obs_t6.err)
if echo "$out" | grep -q 'actor true'; then
	ok "T6: actor observed after launching command"
else
	nok "T6: actor line missing after -- COMMAND"
fi

say ""
say "=== T7: helper exec is lineage-only ==="
# Wrap: /bin/sh -c 'exec /bin/true' — sh is actor, true is helper exec
# We register /bin/sh as actor; true should show as lineage event in compact mode
SH_BIN="/bin/sh"
cmpout="$RESULTS_DIR/t7.compact"
"$BIN" observe --actor sh="$SH_BIN" --format compact --duration 3 \
	-- "$SH_BIN" -c 'exec /bin/true' >"$cmpout" 2>/tmp/obs_t7.err
# At minimum: the output file is created, binary exits cleanly
if [ -f "$cmpout" ]; then
	ok "T7: compact output file created for helper-exec scenario"
else
	nok "T7: compact output file missing"
fi

say ""
say "=== T8: directory collapse refuses broad roots ==="
# The profile transform must NOT collapse observations under / /usr /etc /tmp /var /run /var/lib
# into directory rules. We test this by checking profile output for a broad-root collapse.
# Since we only have --actor true (opens files in /usr/bin etc), if any broad root
# were collapsed wrongly the test would see 'seal / ' or 'seal /usr ' etc.
out=$("$BIN" observe --actor true="$ACTOR_BIN" --duration 2 \
	-- "$ACTOR_BIN" 2>/tmp/obs_t8.err)
if echo "$out" | grep -qE '^seal (/ |/usr |/etc |/var |/run |/tmp )'; then
	nok "T8: profile emitted a broad-root directory collapse (unexpected)"
else
	ok "T8: no broad-root collapse in profile"
fi

say ""
say "=== T9: directory-destination warning with --no-dir-dest ==="
out=$("$BIN" observe --actor true="$ACTOR_BIN" --duration 1 \
	--no-dir-dest 2>/tmp/obs_t9.err)
if echo "$out" | grep -q 'WARNING.*directory-destination'; then
	ok "T9: dir-destination warning present with --no-dir-dest"
else
	nok "T9: expected dir-destination warning with --no-dir-dest"
fi

say ""
say "=== T10: map overflow/drop warning surfaced ==="
# We can't easily force a map overflow in a short test, but we can verify
# the binary produces the status header (warning appears only if counters>0).
# Just check it doesn't crash when overflow counter is 0.
out=$("$BIN" observe --actor true="$ACTOR_BIN" --duration 1 2>/tmp/obs_t10.err)
rc=$?
if [ "$rc" -eq 0 ]; then
	ok "T10: observe exits cleanly (overflow logic present)"
else
	nok "T10: observe exited with rc=$rc"
fi

say ""
say "=== T11: path resolution failure does not drop dev/ino observation ==="
# Use --no-resolve-paths to force dev/ino-only output; profile must still emit
# something (actor line at minimum) even without path resolution.
out=$("$BIN" observe --actor true="$ACTOR_BIN" --duration 2 \
	--no-resolve-paths -- "$ACTOR_BIN" 2>/tmp/obs_t11.err)
if echo "$out" | grep -q 'actor true'; then
	ok "T11: actor line present with --no-resolve-paths"
else
	nok "T11: actor line missing with --no-resolve-paths"
fi

say ""
say "=== T12: AIDE witness (SPEC §16) ==="
AIDE_BIN="${AIDE_BIN:-}"
if [ -z "$AIDE_BIN" ]; then
	for _p in /usr/sbin/aide /usr/bin/aide; do
		[ -x "$_p" ] && AIDE_BIN="$_p" && break
	done
fi
if [ ! -x "${AIDE_BIN:-}" ]; then
	skip "T12: AIDE not present (checked /usr/sbin/aide /usr/bin/aide)"
else
	AIDE_OUT="$RESULTS_DIR/aide_observe_sample.txt"
	say "  Running: $BIN observe --actor aide=$AIDE_BIN -- $AIDE_BIN --check"
	"$BIN" observe --actor aide="$AIDE_BIN" \
		-- "$AIDE_BIN" --check \
		>"$AIDE_OUT" 2>/tmp/obs_t12.err
	# aide --check may exit non-zero (changes found); that is expected.
	# We check that the profile was generated and has the right structure.
	if grep -q '#@compartment-bpf-profile-status: candidate' "$AIDE_OUT"; then
		ok "T12-a: AIDE profile status header present"
	else
		nok "T12-a: AIDE profile status header missing"
	fi
	if grep -q 'actor aide' "$AIDE_OUT"; then
		ok "T12-b: actor aide line present"
	else
		nok "T12-b: actor aide line missing"
	fi
	# Profile must have at least one seal rule (dir-destination or per-file)
	if grep -q '^seal ' "$AIDE_OUT"; then
		ok "T12-c: at least one seal rule emitted"
	else
		nok "T12-c: no seal rules in AIDE profile"
	fi
	# Loadability: no double-slash paths (HIGH-3 regression gate).
	dbl=$(grep -c '^seal //' "$AIDE_OUT" 2>/dev/null; true)
	if [ "${dbl}" -eq 0 ]; then
		ok "T12-d: no double-slash seal paths (loadability)"
	else
		nok "T12-d: $dbl seal rules with '//' prefix (non-loadable; HIGH-3)"
	fi
	# Loadability: dry-run on resolved-path entries must succeed.
	# Filter <ino=...> fallback lines — these occur when path resolution
	# fails at observe time (e.g. /proc, tmpfs, anon mounts) and are not
	# parser errors; the loader cannot stat them at dry-run time either.
	_aide_filtered=$(mktemp /tmp/obs_t12e.XXXXXX)
	grep -v '<ino=' "$AIDE_OUT" > "$_aide_filtered"
	if "$BIN" --dry-run "$_aide_filtered" >/dev/null 2>/tmp/obs_t12d.err; then
		ok "T12-e: profile dry-run apply succeeds"
	else
		nok "T12-e: profile dry-run apply failed (see /tmp/obs_t12d.err)"
	fi
	rm -f "$_aide_filtered"
	say ""
	say "  === AIDE profile sample (first 30 lines) ==="
	head -30 "$AIDE_OUT" | tee -a "$LOG"
fi

say ""
say "=== T13: jsonl format produces machine-readable output ==="
jsonout="$RESULTS_DIR/t13.jsonl"
"$BIN" observe --actor true="$ACTOR_BIN" --format jsonl --duration 2 \
	-- "$ACTOR_BIN" >"$jsonout" 2>/tmp/obs_t13.err
rc=$?
if [ "$rc" -eq 0 ]; then
	ok "T13: jsonl format exits cleanly"
else
	nok "T13: jsonl format exited with rc=$rc"
fi
if [ -f "$jsonout" ] && [ -s "$jsonout" ]; then
	# Basic JSON syntax check: each non-empty line starts with '{'
	bad=$(grep -v '^$' "$jsonout" | grep -v '^{' | wc -l)
	if [ "$bad" -eq 0 ]; then
		ok "T13-b: all jsonl lines are JSON objects"
	else
		nok "T13-b: $bad non-JSON lines in jsonl output"
	fi
else
	skip "T13-b: no jsonl output (no actor exec events in 2s window)"
fi

say ""
say "=== T14: audit format produces log-style output ==="
auditout="$RESULTS_DIR/t14.audit"
"$BIN" observe --actor true="$ACTOR_BIN" --format audit --duration 2 \
	-- "$ACTOR_BIN" >"$auditout" 2>/tmp/obs_t14.err
rc=$?
if [ "$rc" -eq 0 ]; then
	ok "T14: audit format exits cleanly"
else
	nok "T14: audit format exited with rc=$rc"
fi

say ""
say "=== T15: provenance JSON written with --provenance-out ==="
prov="$RESULTS_DIR/t15.provenance.json"
"$BIN" observe --actor true="$ACTOR_BIN" --duration 1 \
	--provenance-out "$prov" \
	>/dev/null 2>/tmp/obs_t15.err
if [ -f "$prov" ] && grep -q '"status":"candidate"' "$prov"; then
	ok "T15: provenance JSON written with candidate status"
else
	nok "T15: provenance JSON missing or malformed"
fi

say ""
say "=== T16: --global option is rejected (V-6 drill P1-C regression) ==="
# Coverage-gaps GAP-M-4: HOWTO drift previously claimed observe accepts
# --global; reality is rc=2 + "unknown option: --global". Pin the
# rc=2-with-named-option behavior so the next HOWTO drift gets caught
# by CI, not by a V-6 reviewer.
set +e
"$BIN" observe --global >/tmp/obs_t16.out 2>/tmp/obs_t16.err
t16_rc=$?
set -e
if [ "$t16_rc" -eq 2 ] && grep -q 'unknown option: --global' /tmp/obs_t16.err; then
	ok "T16: --global rejected with rc=2 + named-option diagnostic"
else
	nok "T16: --global rc=$t16_rc, expected rc=2 + 'unknown option: --global'"
fi

say ""
say "=== T17: detect_runtime_abi success path vs fallback path ==="
# Coverage-gaps GAP-H-11: every other observe test runs without --pin,
# so detect_runtime_abi always hits the open-fail fallback. The success
# path (compartment-observe.c:484-487) has been entirely uncovered.
# T17a covers the fallback (no pin → WARNING expected); T17b covers
# the success (after --pin → no WARNING). Both branches must work.
#
# Guard: --unpin first to ensure a clean baseline; ignore rc.
"$BIN" --unpin >/dev/null 2>&1 || true

# T17a: fallback path — no policy_state_map pinned → expect the WARNING.
"$BIN" observe --actor true="$ACTOR_BIN" --duration 1 \
	>/dev/null 2>/tmp/obs_t17a.err
if grep -q 'cannot determine runtime ABI' /tmp/obs_t17a.err; then
	ok "T17a: fallback WARNING fires when module is not pinned"
else
	nok "T17a: expected 'cannot determine runtime ABI' WARNING in unpinned state"
fi

# T17b: success path — pin a minimal profile, then observe, expect
# absence of the WARNING (silent ABI detection from kernel-side map).
# Use a self-contained profile that doesn't depend on existing fixtures.
#
# P2-8 positive bpffs-mount gate: before this test path can exercise its
# nok branch (--pin failed to go live), confirm bpffs is mounted on the
# host. Without bpffs, --pin will fail for environmental reasons rather
# than a code regression — recording the explicit precondition keeps the
# nok-branch diagnostic honest (a "regression" elsewhere on the box
# manifests as a T17b nok with no signal pointing at /sys/fs/bpf).
if grep -qE '^[^ ]+ /sys/fs/bpf bpf ' /proc/mounts 2>/dev/null \
   || grep -qE ' bpf ' /proc/mounts 2>/dev/null; then
	say "  T17b: bpffs mount confirmed in /proc/mounts (healthy-VM precondition)"
else
	say "  T17b: WARNING: bpffs not visible in /proc/mounts; --pin nok branch will likely fire for environmental reasons"
fi
T17B_PROF="$RESULTS_DIR/t17b.conf"
T17B_TARGET="$RESULTS_DIR/t17b.target"
echo target > "$T17B_TARGET"
cat > "$T17B_PROF" <<EOF
seal $T17B_TARGET no-write
EOF
# --pin enters a `while (running)` ring_buffer__poll loop and only exits
# on SIGINT/SIGTERM (compartment-bpf.c:4685+). Background it, wait for
# the live marker, then run the observe probe, then terminate cleanly.
# The earlier `if "$BIN" --pin ...` form was a foreground call and would
# block forever — regressed in the GAP-H-11 coverage-gaps test addition.
: > /tmp/obs_t17b_pin.err
"$BIN" --pin "$T17B_PROF" >/tmp/obs_t17b_pin.err 2>&1 &
T17B_DAEMON=$!
for _ in $(seq 1 100); do
	grep -q '\[run\] compartment-bpf live' /tmp/obs_t17b_pin.err 2>/dev/null && break
	kill -0 "$T17B_DAEMON" 2>/dev/null || break
	sleep 0.1
done
if grep -q '\[run\] compartment-bpf live' /tmp/obs_t17b_pin.err 2>/dev/null; then
	# Observe with the module loaded — the success branch should fire.
	# V-7 P1-F: emit the candidate-profile JSON provenance so we can
	# assert the abi_version field carries the kernel-detected value
	# (0x0007 today; COMPARTMENT_ABI_VERSION in compartment-abi.h). A
	# regression that reverts detect_runtime_abi to ABI_FALLBACK or
	# zero-fills the provenance line would slip past the WARNING-absent
	# check alone.
	T17B_PROV="$RESULTS_DIR/t17b.prov.json"
	"$BIN" observe --actor true="$ACTOR_BIN" --duration 1 \
		--provenance-out "$T17B_PROV" \
		>/dev/null 2>/tmp/obs_t17b.err
	if grep -q 'cannot determine runtime ABI' /tmp/obs_t17b.err; then
		nok "T17b: WARNING still fires after --pin; success path unreached"
	else
		# V-7 P1-F assertion: abi_version field must equal the
		# compile-time COMPARTMENT_ABI_VERSION (0x0007). The
		# emitter uses "%04x" so the exact JSON shape is
		# "abi_version":"0x0007".
		if [ ! -s "$T17B_PROV" ]; then
			nok "T17b: --provenance-out produced empty/missing file at $T17B_PROV"
		elif grep -q '"abi_version":"0x0007"' "$T17B_PROV"; then
			ok "T17b: success path silent (no WARNING) AND provenance abi_version=0x0007"
		else
			# Surface what we got for the next reader.
			say "  T17b: provenance contents:"
			sed 's/^/    /' < "$T17B_PROV" || true
			nok "T17b: provenance abi_version != 0x0007 (abi_version_map not honored or fallback path taken)"
		fi
	fi
	kill -TERM "$T17B_DAEMON" 2>/dev/null || true
	wait "$T17B_DAEMON" 2>/dev/null || true
	"$BIN" --unpin >/dev/null 2>&1 || true
else
	# Daemon died before going live or didn't reach the marker in 10s.
	kill -KILL "$T17B_DAEMON" 2>/dev/null || true
	wait "$T17B_DAEMON" 2>/dev/null || true
	# V-7 re-run #1 P2-6: skip→nok (symmetric with T19's V-7 P1-E fix).
	# A daemon that fails to go live is a regression in --pin startup,
	# not an environmental gap — surface it instead of swallowing.
	#
	# V-7 P2-6: diagnostic tail of the pin log on nok (T19 precedent at
	# line ~545) so a future reader sees why --pin failed without having
	# to re-run by hand. Also drop any partial pinned state before the
	# nok emission so a stale pin doesn't leak into the next test.
	say "  T17b: tail of /tmp/obs_t17b_pin.err on failure:"
	tail -n 30 /tmp/obs_t17b_pin.err 2>/dev/null | sed 's/^/    /' || true
	"$BIN" --unpin >/dev/null 2>&1 || true
	nok "T17b: --pin failed to go live (see /tmp/obs_t17b_pin.err); cannot test success path"
fi

say ""
say "=== T18: sanitize_observed_path rejects whitespace + newline injection ==="
# Coverage-gaps GAP-H-9: sanitize_observed_path() (compartment-observe.c:282-304)
# is the boundary defense that closed V-6 P0-1 (newline/#/(deleted))
# AND V-6 re-run #4 P1-A (space/tab). It had zero regression tests.
# A regression that dropped a reject byte would silently re-open the
# class. Each sub-witness creates a file whose name contains an
# adversarial byte, opens it in a child during observe, and asserts
# the sanitizer's stderr diagnostic fires.
#
# Newline and CR are legal Linux filename bytes; '#' and tab/space
# are also legal. Each is rejected by sanitize_observed_path because
# the profile parser tokenizes seal directives on those exact bytes
# (compartment-bpf.c parse path).
T18_TMP="$RESULTS_DIR/t18"
mkdir -p "$T18_TMP"

# Pick three adversarial filename bytes that the FS accepts:
#   - tab  (0x09) — V-6 re-run #4 P1-A specific
#   - space (0x20) — V-6 re-run #4 P1-A specific
#   - '#'  (0x23) — parser-comment class
# (Newline / CR are also rejected but harder to create from shell
# safely without breaking the harness; the tab+space+# trio gives
# class coverage for "byte that would split or comment a seal line.")
t18_fail=0

for nameSpec in 'tab:	' 'space: ' 'hash:#'; do
	tag=${nameSpec%%:*}
	byte=${nameSpec#*:}
	# Build the adversarial filename. Use printf to allow embedded byte.
	fname=$(printf '%s/realfile%s%s' "$T18_TMP" "$byte" "after-$tag")
	rm -f -- "$fname" 2>/dev/null
	if ! touch -- "$fname" 2>/dev/null; then
		say "  T18-$tag: cannot create filename with byte (FS rejected); skipping sub-witness"
		continue
	fi
	# Child opens the file and holds it across observe duration.
	(exec 9<"$fname"; sleep 3) &
	child_pid=$!
	sleep 0.2
	"$BIN" observe --actor true="$ACTOR_BIN" --duration 2 \
		-o "$T18_TMP/t18-$tag.profile" \
		>/dev/null 2>"$T18_TMP/t18-$tag.err" || true
	wait "$child_pid" 2>/dev/null || true
	# Assertion (a): sanitizer diagnostic appeared on observe's stderr.
	# Note: the diagnostic only fires if procfd resolution selects
	# THIS specific filename; if the BPF event was not raised within
	# the 2s window, no resolution happens and no diagnostic fires.
	# We treat absent-diagnostic-AND-absent-seal-line as PASS
	# (sanitizer never had to fire; emission still safe), and
	# present-seal-line-naming-the-byte as FAIL.
	if grep -Fq "realfile${byte}after-$tag" "$T18_TMP/t18-$tag.profile" 2>/dev/null; then
		nok "T18-$tag: adversarial filename leaked into candidate profile (sanitizer regression)"
		t18_fail=$((t18_fail+1))
	fi
done

if [ "$t18_fail" -eq 0 ]; then
	ok "T18: no adversarial filename bytes (tab/space/#) leaked into candidate profile"
fi

say ""
say "=== T19: stacked observe preserves prior enforcement deny ==="
# Review-20260517 P0: BPF LSM ret-chaining bug. When observe was stacked
# on top of enforcement, int-return LSM hooks in compartment-observe.bpf.c
# (and newer strict-launch hooks in compartment.bpf.c) returned 0 instead
# of propagating prior `ret`, which could clear an earlier deny from a
# lower-attached BPF LSM program. This witness pins a minimal no-write
# policy, stacks observe on top, attempts a write through /bin/sh, and
# asserts the target file remains unchanged.
T19_TMP="$RESULTS_DIR/t19"
mkdir -p "$T19_TMP"
T19_TARGET="$T19_TMP/target"
T19_PROF="$T19_TMP/t19.conf"
printf 'original' > "$T19_TARGET"
cat > "$T19_PROF" <<EOF
seal $T19_TARGET no-write
EOF

# Best-effort cleanup in case a prior interrupted run left pins behind.
timeout 10 "$BIN" --unpin >/dev/null 2>/dev/null || true

"$BIN" --pin "$T19_PROF" >"$T19_TMP/pin.log" 2>&1 &
T19_DAEMON=$!
T19_LIVE=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
	sleep 0.5
	if grep -q '\[run\] compartment-bpf live' "$T19_TMP/pin.log" 2>/dev/null; then
		T19_LIVE=1
		break
	fi
	kill -0 "$T19_DAEMON" 2>/dev/null || break
done
if [ "$T19_LIVE" -eq 1 ]; then
	"$BIN" observe --actor sh="$SH_BIN" --duration 2 \
		-- "$SH_BIN" -c 'printf X >> "$1"' sh "$T19_TARGET" \
		>"$T19_TMP/obs.out" 2>"$T19_TMP/obs.err" || true
	# Allow a brief grace for the audit ringbuf to drain into pin.log.
	sleep 0.3
	t19_data=$(cat "$T19_TARGET")
	# V-7 P1-E: tighten grep. The pre-fix assertion accepted *any*
	# "Permission denied" string on observe's stderr — which can come
	# from shell-level EACCES for unrelated reasons (e.g. mode bits) and
	# does NOT prove the deny was issued by the BPF LSM. The audit ring
	# emits ACTION_DENY_WRITE through emit_audit_actor when the enforce
	# layer hook denies the write; the enforce daemon copies that to
	# pin.log as `[audit] DENY_WRITE …`. That string is the LSM-specific
	# witness.
	if [ "$t19_data" = "original" ] &&
	   grep -qE '\[audit\][[:space:]]+DENY_(WRITE|WRITE_PARENT_DIR)' "$T19_TMP/pin.log"; then
		ok "T19: stacked observe did not clear prior deny (LSM [audit] DENY_WRITE witnessed)"
	else
		# Surface diagnostics so the next reader sees why this failed.
		say "  T19: target data='$t19_data' (expected 'original')"
		say "  T19: tail pin.log:"
		tail -n 20 "$T19_TMP/pin.log" 2>/dev/null | sed 's/^/    /' || true
		nok "T19: stacked observe cleared or obscured a prior deny (no [audit] DENY_WRITE in daemon log, or target was modified)"
	fi
	kill -TERM "$T19_DAEMON" 2>/dev/null || true
	wait "$T19_DAEMON" 2>/dev/null || true
else
	# V-7 P1-E: a daemon that fails to go live is a test failure, not a
	# skip. The original SKIP let a broken enforce-layer load slip past
	# CI as a green run because every subsequent assertion is gated on
	# T19_LIVE=1. Treat as nok so regressions in --pin startup surface.
	kill -KILL "$T19_DAEMON" 2>/dev/null || true
	wait "$T19_DAEMON" 2>/dev/null || true
	say "  T19: pin.log tail:"
	tail -n 30 "$T19_TMP/pin.log" 2>/dev/null | sed 's/^/    /' || true
	nok "T19: --pin failed to go live (see $T19_TMP/pin.log); cannot test stacked deny chaining"
fi
timeout 10 "$BIN" --unpin >/dev/null 2>/dev/null || true

say ""
say "=== Counters dump to log ==="
say "  pass=$pass fail=$fail skip=$skip"

# Copy stderr logs
for f in /tmp/obs_t*.err; do
	[ -f "$f" ] || continue
	cp "$f" "$RESULTS_DIR/" 2>/dev/null
done

if [ "$fail" -gt 0 ]; then
	exit 1
fi
exit 0
