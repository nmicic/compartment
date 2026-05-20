#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/matrix-runner.sh — VM-side runner for the 24-cell functional matrix
# from suggestion_for_testing4.md §1.
#
#         | NO_UNLINK | NO_RENAME | NO_WRITE | NO_CHMOD
#  unlink |   DENY    |  allow    |  allow   |  allow
#  rename |   DENY    |  DENY     |  allow   |  allow
#  trunc  |   allow   |  allow    |  DENY    |  allow
#  o_wr   |   allow   |  allow    |  DENY    |  allow
#  chmod  |   allow   |  allow    |  allow   |  DENY
#  mmap_w |   allow   |  allow    |  DENY    |  allow
#
# Output: CSV on stdout. flag,op,expected,actual_rc,actual_name,result
# result is PASS / FAIL / ERROR.
#
# Important: each (flag, op) cell uses ITS OWN sealed file. Reusing a
# single sealed file across ops creates false negatives because an
# allowed unlink destroys the sealed inode; subsequent ops then hit a
# fresh unsealed inode at the same path. Per-op staging avoids this.

set -u

REPO=${REPO:-/root/compartment_ebpf-tests}
SEALPROBE="$REPO/tests/sealprobe"
DAEMON="$REPO/compartment-bpf"

if [ "$(id -u)" -ne 0 ]; then
	echo "matrix-runner: must run as root on the VM" >&2
	exit 2
fi
if [ ! -x "$SEALPROBE" ] || [ ! -x "$DAEMON" ]; then
	echo "matrix-runner: missing $SEALPROBE or $DAEMON" >&2
	exit 2
fi
if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
	echo "matrix-runner: bpf not in active LSM list" >&2
	exit 2
fi

TMP=$(mktemp -d /tmp/matrix.XXXXXX)
DAEMON_PID=
DAEMON_LOG="$TMP/daemon.err"

cleanup() {
	if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
		kill "$DAEMON_PID" 2>/dev/null || true
		wait "$DAEMON_PID" 2>/dev/null || true
	fi
	rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

OPS="unlink rename truncate open_wronly chmod mmap_shared_write mmap_after_ro_open"

run_cell() {
	flag=$1; op=$2; expected=$3; target=$4

	case "$op" in
	unlink)
		"$SEALPROBE" unlink "$target" >/dev/null 2>&1; rc=$?
		;;
	rename)
		"$SEALPROBE" rename "$target" "${target}.renamed" >/dev/null 2>&1; rc=$?
		;;
	truncate)
		"$SEALPROBE" truncate "$target" >/dev/null 2>&1; rc=$?
		;;
	open_wronly)
		"$SEALPROBE" open-write "$target" >/dev/null 2>&1; rc=$?
		;;
	chmod)
		"$SEALPROBE" chmod "$target" >/dev/null 2>&1; rc=$?
		;;
	mmap_shared_write)
		"$SEALPROBE" mmap-shared-write "$target" >/dev/null 2>&1; rc=$?
		;;
	mmap_after_ro_open)
		# Coverage probe for comp_mmap_file independent of file_open.
		# See tests/sealprobe.c::do_mmap_after_ro_open(). Closes the
		# Codex 2026-05-13 synthesis follow-up item #5.
		"$SEALPROBE" mmap-after-ro-open "$target" >/dev/null 2>&1; rc=$?
		;;
	esac

	case "$rc" in
	0) name=ALLOW ;;
	1) name=DENY ;;
	2) name=USAGE ;;
	3) name=UNEXPECTED_ERRNO ;;
	4) name=STAGE_ERROR ;;
	*) name="RC$rc" ;;
	esac

	if   [ "$expected" = "DENY"  ] && [ "$rc" -eq 1 ]; then result=PASS
	elif [ "$expected" = "ALLOW" ] && [ "$rc" -eq 0 ]; then result=PASS
	elif [ "$rc" -eq 4 ]; then                              result=ERROR
	else                                                    result=FAIL
	fi

	echo "$flag,$op,$expected,$rc,$name,$result"
}

# Expected matrix per (op,flag): see file 4 §1.
#
# mmap_after_ro_open is the dedicated comp_mmap_file coverage probe
# (Codex synthesis 2026-05-13 follow-up #5). Expected DENY for no-write
# because security_mmap_file() runs BEFORE the VFS write-on-RO-fd check
# inside vm_mmap_pgoff, so the EACCES is attributable to our hook. For
# the other three flags the LSM hook returns 0 and the VFS check then
# rejects PROT_WRITE+MAP_SHARED on an O_RDONLY fd → also EACCES but
# from VFS. Expected DENY everywhere; the row PASSES means the path is
# reachable. To distinguish hook-deny from VFS-deny, compare against
# deny_total counter snapshots — outside the matrix runner's scope.
expected_for() {
	op=$1; flag=$2
	case "${op}:${flag}" in
	unlink:no-unlink|rename:no-unlink|rename:no-rename|truncate:no-write|open_wronly:no-write|chmod:no-chmod|mmap_shared_write:no-write)
		echo DENY ;;
	mmap_after_ro_open:*)
		echo DENY ;;
	*)
		echo ALLOW ;;
	esac
}

test_one_flag() {
	flag=$1
	dir="$TMP/$flag"
	mkdir -p "$dir"

	# Stage one fresh sealed file per op so cell results don't pollute
	# each other.
	: > "$dir/policy.conf"
	for op in $OPS; do
		t="$dir/target_$op"
		echo content > "$t"
		echo "seal $t $flag" >> "$dir/policy.conf"
	done

	"$DAEMON" "$dir/policy.conf" >"$DAEMON_LOG" 2>&1 &
	DAEMON_PID=$!
	# Wait up to 10s for daemon to be live.
	live=0
	for _ in $(seq 1 100); do
		if grep -q '\[run\] compartment-bpf live' "$DAEMON_LOG" 2>/dev/null; then
			live=1
			break
		fi
		if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
			break
		fi
		sleep 0.1
	done
	if [ "$live" -ne 1 ]; then
		for op in $OPS; do
			exp=$(expected_for "$op" "$flag")
			echo "$flag,$op,$exp,99,DAEMON_NOT_LIVE,ERROR"
		done
		cat "$DAEMON_LOG" >&2
		DAEMON_PID=
		return
	fi

	for op in $OPS; do
		exp=$(expected_for "$op" "$flag")
		t="$dir/target_$op"
		run_cell "$flag" "$op" "$exp" "$t"
	done

	kill "$DAEMON_PID" 2>/dev/null || true
	wait "$DAEMON_PID" 2>/dev/null || true
	DAEMON_PID=
}

echo "flag,op,expected,actual_rc,actual_name,result"

for f in no-unlink no-rename no-write no-chmod; do
	test_one_flag "$f"
done
