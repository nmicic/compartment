#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# tests/pin-regression.sh -- V-4 pin/unpin regression suite.
#
# Four tests:
#   T4.1 Killed daemon, pinned links: enforcement survives.
#   T4.2 --unpin removes owned pins, enforcement stops, PIN_ROOT preserved.
#   T4.3 --unpin <foreign bpffs object> refused; sentinel intact.
#   T4.4 Reload sshd.conf -> chronyd.conf via (dry-run|unpin|pin) composition:
#        no stale sshd denial, chronyd denial active.
#
# Run only inside a dedicated VM. The probe uses sealprobe's
# truncate-to-same-size operation, which triggers the truncate hooks
# without changing file contents and reports non-LSM errno separately.
#
# Outputs ${RESULTS}/pin-regression.csv -- one row per test:
#   test,outcome,detail
#
# Exits non-zero unless all 4 tests pass.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"

# Allow callers (Makefile or local harnesses) to direct the CSV
# elsewhere; default to a timestamped scratch dir under tests/results/
# so a bare `bash tests/pin-regression.sh` invocation still works.
if [ -z "${RESULTS:-}" ]; then
	DATE="$(date -u +%Y%m%dT%H%M%SZ)"
	RESULTS="${REPO}/tests/results/pin-regression-${DATE}"
fi
mkdir -p "${RESULTS}"
CSV="${RESULTS}/pin-regression.csv"
echo "test,outcome,detail" > "${CSV}"

BIN="${REPO}/compartment-bpf"
SEALPROBE="${REPO}/tests/sealprobe"
PIN_ROOT="/sys/fs/bpf/compartment"
SENTINEL="/sys/fs/bpf/sentinel_v4"

DAEMON_PID=""
DAEMON_LOG=""

if [ ! -x "${BIN}" ]; then
	echo "fatal: ${BIN} not present or not executable (run make first)" >&2
	exit 1
fi
if [ ! -x "${SEALPROBE}" ]; then
	echo "fatal: ${SEALPROBE} not present or not executable (run make test-tools first)" >&2
	exit 1
fi

# Probe helper: try truncate(2) to the file's CURRENT size. The kernel
# fires security_file_truncate (or security_inode_setattr with ATTR_SIZE)
# unconditionally; the BPF program's deny_file_write path denies with
# EACCES when SEAL_NO_WRITE is set. On a regular file, truncating to the
# existing size leaves byte content unchanged, so the probe is
# non-destructive whether the seal denies or not.
#
# Stdout is exactly one of "DENIED" or "ALLOWED" on a single line. Other
# outcomes (stat failure) print "ERROR:<reason>" so the harness fails
# loud rather than misclassifying.
#
# A note on what we did NOT pick:
#   chmod-to-same-mode: coreutils' chmod skips fchmodat(2) when the new
#                       mode matches stat()'s current mode, so the BPF
#                       inode_setattr hook is never invoked and the
#                       probe yields ALLOWED regardless of seal state.
#   open-for-append on a running ELF: kernel returns ETXTBSY before the
#                                     LSM hook runs, so the result is
#                                     not attributable to compartment-bpf.
# truncate-to-same-size avoids both pitfalls.
probe_seal()
{
	local p=$1
	local rc
	"${SEALPROBE}" truncate-same "$p" >/dev/null 2>&1 && rc=0 || rc=$?
	case "${rc}" in
		0) echo "ALLOWED" ;;
		1) echo "DENIED" ;;
		*) echo "ERROR:rc=${rc}" ;;
	esac
}

# Wait for the daemon to print its "live" sentinel on stderr. The daemon
# writes "[run] compartment-bpf live." after attach()+pin(); polling for
# that line avoids races where the test issues a probe before the LSM
# hooks are reachable.
wait_for_live()
{
	local log=$1
	local i
	for i in $(seq 1 60); do
		if grep -q '\[run\] compartment-bpf live' "${log}" 2>/dev/null; then
			return 0
		fi
		sleep 0.5
	done
	echo "fatal: daemon did not reach live state in 30s; log:" >&2
	cat "${log}" >&2 || true
	return 1
}

# Wait for the kernel to drain compartment-bpf BPF programs after --unpin
# completes. Unlinking a bpffs pin only decrements the link refcount;
# the actual link release runs through bpf_link_put_deferred (a kernel
# workqueue) and on a 7.0 kernel takes a few hundred ms to seconds
# depending on RCU grace periods. Until the workqueue runs, the LSM
# hooks remain attached to the still-living program and enforcement
# continues even though `--unpin` has returned. Tests that probe
# enforcement-after-unpin must poll for this drain or they race the
# kernel and misreport DENIED.
#
# Polls `bpftool prog show` for any program whose name begins with
# "comp_" (every compartment-bpf BPF program is named that way by the
# skeleton). Returns 0 once the count reaches zero, 1 on timeout.
wait_for_kernel_drain()
{
	local i
	for i in $(seq 1 120); do
		if ! bpftool prog show 2>/dev/null | grep -q 'name comp_'; then
			return 0
		fi
		sleep 0.25
	done
	echo "warn: kernel did not drain comp_* progs in 30s" >&2
	bpftool prog show 2>/dev/null | grep 'name comp_' >&2 || true
	return 1
}

start_daemon()
{
	local profile=$1
	# Defensive sweep: a prior test that failed mid-flight may have left
	# pin files behind. bpf_link__pin returns -EEXIST on a stale pin and
	# kills the daemon during attach; clearing first keeps each test
	# independent of the previous test's exit shape.
	"${BIN}" --unpin >/dev/null 2>&1 || true
	DAEMON_LOG="${RESULTS}/daemon-$(date -u +%H%M%S%N).log"
	"${BIN}" --pin "${profile}" >"${DAEMON_LOG}" 2>&1 &
	DAEMON_PID=$!
	wait_for_live "${DAEMON_LOG}"
}

stop_daemon()
{
	if [ -n "${DAEMON_PID}" ] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
		kill "${DAEMON_PID}" || true
		# Daemon SIGTERM handler sets running=0 then exits the ringbuf loop.
		wait "${DAEMON_PID}" 2>/dev/null || true
	fi
	DAEMON_PID=""
}

# Best-effort teardown so a failed test does not leave stale pins or
# the daemon running. Each individual test still cleans up its own
# successful path; this handler is the safety net for failures.
cleanup()
{
	local rc=$?
	stop_daemon || true
	"${BIN}" --unpin >/dev/null 2>&1 || true
	rm -f "${SENTINEL}" >/dev/null 2>&1 || true
	# bpftool-created pins are unlinkable as root; do not chase non-root.
	exit "${rc}"
}
trap cleanup EXIT INT TERM

record()
{
	# record <test> <outcome> <detail>
	# Quote detail to keep commas in messages from splitting columns.
	printf '%s,%s,"%s"\n' "$1" "$2" "$3" >> "${CSV}"
}

# Build a synthetic seal profile under /tmp that seals a throwaway file
# we own. Decouples T4.1/T4.2 from real system targets (sshd, chronyd)
# and lets us use unlink-style and write-style probes without risking
# data on the host. The file is created with a known size so the
# truncate-to-same-size probe has a deterministic baseline.
SYNTHETIC_TARGET=""
SYNTHETIC_PROFILE=""
synthetic_setup()
{
	SYNTHETIC_TARGET="$(mktemp /tmp/v4-canary.XXXXXX)"
	# Non-empty so truncate-to-same-size has a real size to confirm.
	printf 'v4-canary-payload\n' > "${SYNTHETIC_TARGET}"
	# World-writable so the truncate probe is gated by the BPF LSM and
	# nothing else. When the seal is gone the file mode allows any
	# truncate to succeed; when the seal is active the BPF program
	# rejects with EACCES regardless of mode. Decouples the probe from
	# UID-mismatch confounders.
	chmod 0666 "${SYNTHETIC_TARGET}" 2>/dev/null || true
	SYNTHETIC_PROFILE="$(mktemp /tmp/v4-synthetic.XXXXXX.conf)"
	printf 'seal %s full\n' "${SYNTHETIC_TARGET}" > "${SYNTHETIC_PROFILE}"
}
synthetic_teardown()
{
	rm -f "${SYNTHETIC_TARGET}" "${SYNTHETIC_PROFILE}" 2>/dev/null || true
	SYNTHETIC_TARGET=""
	SYNTHETIC_PROFILE=""
}

# ---------- T4.1 -------------------------------------------------------
# Start --pin <synthetic profile>, verify the sealed canary denies a
# write-probe, SIGTERM the daemon, then verify the same probe still
# denies. The kernel-side link pin is what makes this work:
# bpf_link__destroy on daemon exit closes the userspace fd, but the
# bpffs pin keeps the link object alive, so the LSM hooks continue to
# consult the still-frozen seal maps.
test_t41()
{
	synthetic_setup
	start_daemon "${SYNTHETIC_PROFILE}"
	local before after
	before="$(probe_seal "${SYNTHETIC_TARGET}")"
	if [ "${before}" != "DENIED" ]; then
		record T4.1 FAIL "pre-kill probe=${before} on ${SYNTHETIC_TARGET}"
		stop_daemon
		"${BIN}" --unpin >/dev/null 2>&1 || true
		synthetic_teardown
		return 1
	fi

	stop_daemon
	# Probe AFTER daemon exit: the pin keeps enforcement live.
	after="$(probe_seal "${SYNTHETIC_TARGET}")"
	"${BIN}" --unpin >/dev/null 2>&1 || true
	synthetic_teardown

	if [ "${after}" = "DENIED" ]; then
		record T4.1 PASS "post-kill probe=DENIED on canary"
		return 0
	fi
	record T4.1 FAIL "post-kill probe=${after} on canary (expected DENIED)"
	return 1
}

# ---------- T4.2 -------------------------------------------------------
# Start --pin <synthetic profile>, stop daemon, run --unpin, verify
# enforcement stops AND PIN_ROOT directory itself is still present.
# The Claude appendix to the V-4 brief makes the directory-preservation
# point explicit: a subsequent --pin must be able to reuse PIN_ROOT
# without mkdir gymnastics, so --unpin removes contents only.
test_t42()
{
	synthetic_setup
	start_daemon "${SYNTHETIC_PROFILE}"
	local pre
	pre="$(probe_seal "${SYNTHETIC_TARGET}")"
	if [ "${pre}" != "DENIED" ]; then
		record T4.2 FAIL "pre-unpin probe=${pre} on canary"
		stop_daemon
		"${BIN}" --unpin >/dev/null 2>&1 || true
		synthetic_teardown
		return 1
	fi
	stop_daemon

	"${BIN}" --unpin >"${RESULTS}/t42-unpin.log" 2>&1
	local rc=$?
	if [ "${rc}" -ne 0 ]; then
		record T4.2 FAIL "--unpin exit=${rc}"
		synthetic_teardown
		return 1
	fi

	# Critical: PIN_ROOT directory itself must remain.
	if [ ! -d "${PIN_ROOT}" ]; then
		record T4.2 FAIL "${PIN_ROOT} removed by --unpin (must be preserved)"
		synthetic_teardown
		return 1
	fi

	# Wait for kernel deferred-work to actually tear down the LSM links.
	# --unpin returns as soon as the bpffs pin files are unlink()'d but
	# the program-detach happens via a workqueue; probing too early
	# observes pre-drain enforcement and misreports a still-live seal.
	wait_for_kernel_drain || true

	# Diagnostic snapshot before the probe -- captured into the results
	# dir so a failing run shows whether the kernel had actually drained.
	{
		echo "--- t42 post-unpin diagnostic ---"
		echo "comp_* progs:"
		bpftool prog show 2>/dev/null | grep 'name comp_' || echo "(none)"
		echo "canary stat: $(stat -c '%a %U:%G %s' "${SYNTHETIC_TARGET}" 2>&1)"
		echo "running as uid=$(id -u)"
	} > "${RESULTS}/t42-post-unpin-diag.txt" 2>&1

	# Enforcement must be gone.
	local post
	post="$(probe_seal "${SYNTHETIC_TARGET}")"
	synthetic_teardown
	if [ "${post}" = "ALLOWED" ]; then
		record T4.2 PASS "post-unpin probe=ALLOWED; ${PIN_ROOT} preserved"
		return 0
	fi
	record T4.2 FAIL "post-unpin probe=${post} on canary (expected ALLOWED)"
	return 1
}

# ---------- T4.3 -------------------------------------------------------
# Plant a foreign bpffs object at /sys/fs/bpf/sentinel_v4 via bpftool,
# capture its inode, run --unpin /sys/fs/bpf/sentinel_v4, expect refusal
# and the sentinel intact (same inode).
test_t43()
{
	# Clean any stale sentinel from a prior failed run.
	rm -f "${SENTINEL}" 2>/dev/null || true

	# Create a dummy hash map and pin it at the sentinel path. The map
	# itself is irrelevant -- only the bpffs pin file matters for the test.
	if ! bpftool map create "${SENTINEL}" type hash key 4 value 4 \
		entries 1 name sentinel_v4 >"${RESULTS}/t43-create.log" 2>&1; then
		record T4.3 FAIL "could not create sentinel via bpftool"
		return 1
	fi
	if [ ! -e "${SENTINEL}" ]; then
		record T4.3 FAIL "bpftool map create did not produce sentinel"
		return 1
	fi
	local ino_before
	ino_before="$(stat -c '%i' "${SENTINEL}")"

	# Run --unpin against the sentinel. Expect non-zero exit, sentinel intact.
	local out rc
	out="$("${BIN}" --unpin "${SENTINEL}" 2>&1)" && rc=0 || rc=$?
	echo "${out}" > "${RESULTS}/t43-unpin.log"

	if [ "${rc}" -eq 0 ]; then
		record T4.3 FAIL "--unpin ${SENTINEL} exit=0 (must refuse)"
		rm -f "${SENTINEL}" 2>/dev/null || true
		return 1
	fi
	if [ ! -e "${SENTINEL}" ]; then
		record T4.3 FAIL "--unpin removed sentinel (must leave intact)"
		return 1
	fi
	local ino_after
	ino_after="$(stat -c '%i' "${SENTINEL}")"
	if [ "${ino_before}" != "${ino_after}" ]; then
		record T4.3 FAIL "sentinel inode changed: ${ino_before} -> ${ino_after}"
		rm -f "${SENTINEL}" 2>/dev/null || true
		return 1
	fi

	# Cleanup the sentinel ourselves. The daemon refused, as designed.
	rm -f "${SENTINEL}" 2>/dev/null || true
	record T4.3 PASS "refusal (exit=${rc}); sentinel ino=${ino_after} preserved"
	return 0
}

# ---------- T4.4 -------------------------------------------------------
# Reload sshd.conf -> chronyd.conf using the V-4 documented composition:
#   1) --dry-run chronyd.conf (parse + stat first; fail-closed)
#   2) --unpin                (remove old owned pins)
#   3) --pin chronyd.conf     (load + attach + pin new)
# Verify: a sshd-only sealed path is ALLOWED after reload, a chronyd-only
# sealed path is DENIED after reload.
test_t44()
{
	local prof_sshd="${REPO}/profiles/sshd.conf"
	local prof_chrony="${REPO}/profiles/chronyd.conf"
	# Pick targets that exist in EXACTLY one profile, to keep the
	# before/after states unambiguous.
	local sshd_target chrony_target
	sshd_target="/etc/ssh/sshd_config"
	chrony_target="/etc/chrony/chrony.conf"
	for p in "${sshd_target}" "${chrony_target}"; do
		if [ ! -e "$p" ]; then
			record T4.4 SKIP "missing fixture: $p"
			return 1
		fi
	done

	# Phase 1: sshd policy live.
	start_daemon "${prof_sshd}"
	local s1 c1
	s1="$(probe_seal "${sshd_target}")"
	c1="$(probe_seal "${chrony_target}")"
	if [ "${s1}" != "DENIED" ] || [ "${c1}" != "ALLOWED" ]; then
		record T4.4 FAIL "phase1 sshd=${s1} chrony=${c1} (want DENIED,ALLOWED)"
		stop_daemon
		"${BIN}" --unpin >/dev/null 2>&1 || true
		return 1
	fi
	stop_daemon

	# Phase 2: reload composition.
	if ! "${BIN}" --dry-run "${prof_chrony}" >"${RESULTS}/t44-dryrun.log" 2>&1; then
		record T4.4 FAIL "dry-run chronyd.conf failed; old pins NOT removed"
		"${BIN}" --unpin >/dev/null 2>&1 || true
		return 1
	fi
	if ! "${BIN}" --unpin >"${RESULTS}/t44-unpin.log" 2>&1; then
		record T4.4 FAIL "--unpin failed mid-reload"
		return 1
	fi
	start_daemon "${prof_chrony}"

	# Phase 3: post-reload probes.
	local s2 c2
	s2="$(probe_seal "${sshd_target}")"
	c2="$(probe_seal "${chrony_target}")"
	stop_daemon
	"${BIN}" --unpin >/dev/null 2>&1 || true

	if [ "${s2}" = "ALLOWED" ] && [ "${c2}" = "DENIED" ]; then
		record T4.4 PASS "phase1 sshd=DENIED,chrony=ALLOWED phase3 sshd=ALLOWED,chrony=DENIED"
		return 0
	fi
	record T4.4 FAIL "phase3 sshd=${s2} chrony=${c2} (want ALLOWED,DENIED)"
	return 1
}

# Sec-11/F19 v0→v0.2 pinned-map shape mismatch fixture. Pre-pins a
# wrong-shape hash map at PIN_ROOT/maps/sealed_inodes and asserts the
# loader refuses to start. Mirrors the V-4b counter-map schema check.
# Requires bpftool to be on PATH (the smoke VM already has it via
# check-env).
test_t45()
{
	"${BIN}" --unpin >/dev/null 2>&1 || true
	if ! command -v bpftool >/dev/null 2>&1; then
		record T4.5 SKIP "bpftool not on PATH"
		return 0
	fi
	mkdir -p "${PIN_ROOT}/maps"
	# Create a HASH map with the OLD v0 shape (key=struct inode_key
	# i.e. 16 bytes, value=__u32 i.e. 4 bytes). Pin it at the
	# sealed_inodes name — this is the exact adversarial layout v0
	# leftover crud would have.
	if ! bpftool map create "${PIN_ROOT}/maps/sealed_inodes" \
	     type hash key 16 value 4 entries 64 name fake_v0 \
	     >"${RESULTS}/t45-mkmap.log" 2>&1; then
		record T4.5 SKIP "bpftool map create failed (kernel may lack feature)"
		"${BIN}" --unpin >/dev/null 2>&1 || true
		return 0
	fi
	# Now attempt to start the loader; it MUST refuse before opening
	# the skeleton.
	local rc=0
	local prof_sshd="${REPO}/profiles/sshd.conf"
	"${BIN}" --dry-run "${prof_sshd}" \
		>"${RESULTS}/t45-loader.log" 2>&1 || rc=$?
	"${BIN}" --unpin >/dev/null 2>&1 || true
	if [ "${rc}" -ne 0 ] && \
	   grep -q "Sec-11/F19" "${RESULTS}/t45-loader.log"; then
		record T4.5 PASS "loader refused fake-shape pin with Sec-11/F19 diagnostic"
		return 0
	fi
	record T4.5 FAIL "loader rc=${rc}; expected nonzero with Sec-11/F19 diagnostic"
	return 1
}

# Each test must run with a known-clean BPF state. The trap'd cleanup
# above is the safety net; this leading sweep handles a leftover pin
# from a previous run that exited before its own cleanup.
"${BIN}" --unpin >/dev/null 2>&1 || true
rm -f "${SENTINEL}" 2>/dev/null || true

pass=0
fail=0
for t in test_t41 test_t42 test_t43 test_t44 test_t45; do
	if "$t"; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1))
	fi
done

# Final bpffs inspection -- record what is left under PIN_ROOT after the
# suite. A clean run leaves PIN_ROOT present but its subdirectories empty
# of compartment-bpf owned pins.
{
	echo "=== final bpffs state ==="
	ls -la "${PIN_ROOT}" 2>&1 || echo "(PIN_ROOT absent)"
	echo "--- links ---"
	ls -la "${PIN_ROOT}/links" 2>&1 || echo "(links absent)"
	echo "--- maps ---"
	ls -la "${PIN_ROOT}/maps" 2>&1 || echo "(maps absent)"
} > "${RESULTS}/final-bpffs.txt"

echo
echo "pin-regression: ${pass} passed, ${fail} failed"
echo "csv: ${CSV}"
echo "final-bpffs: ${RESULTS}/final-bpffs.txt"

if [ "${fail}" -ne 0 ]; then
	exit 1
fi
exit 0
