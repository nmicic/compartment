#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/dir-matrix-runner.sh — VM-side runner for the M×N directory
# matrix (PHASE-0.md §3.V-3). Mirrors matrix-runner.sh against
# directory-applicable hooks (inode_create, inode_mkdir, inode_mknod,
# inode_symlink, inode_link, inode_rename, inode_rmdir + the
# declared superset: inode_unlink on child, inode_setattr on dir).
# Per-cell sealed parent directory ensures no cross-cell pollution.
# Predictions for every cell are derived from BOTH the implementation
# AND the policy intent; both must agree (per V-3 prompt D-V3.D).
#
#                  | NO_UNLINK | NO_RENAME | NO_WRITE | NO_CHMOD
#  dir_unlink_child|   DENY    |  allow    |  allow   |  allow
#  dir_create      |   allow   |  allow    |  DENY    |  allow
#  dir_mkdir       |   allow   |  allow    |  DENY    |  allow
#  dir_mknod       |   allow   |  allow    |  DENY    |  allow
#  dir_symlink     |   allow   |  allow    |  DENY    |  allow
#  dir_link        |   allow   |  allow    |  DENY    |  allow
#  dir_rename_in   |   allow   |  DENY     |  DENY    |  allow
#  dir_rename_out  |   DENY    |  DENY     |  allow   |  allow
#  dir_rmdir       |   DENY    |  allow    |  allow   |  allow
#  dir_chmod       |   allow   |  allow    |  allow   |  DENY
#
# Output: CSV on stdout. flag,op,expected,actual_rc,actual_name,result
# result is PASS / FAIL / ERROR.
#
# Important (same discipline as matrix-runner.sh lines 14-19): each
# (flag, op) cell uses ITS OWN sealed parent directory. Reusing a single
# sealed dir across ops creates false negatives because an allowed
# rmdir/unlink destroys the staged child; subsequent ops then hit a
# fresh tree at the same path.

set -u

REPO=${REPO:-/root/compartment-bpf}
SEALPROBE="$REPO/tests/sealprobe"
DAEMON="$REPO/compartment-bpf"

if [ "$(id -u)" -ne 0 ]; then
	echo "dir-matrix-runner: must run as root on the VM" >&2
	exit 2
fi
if [ ! -x "$SEALPROBE" ] || [ ! -x "$DAEMON" ]; then
	echo "dir-matrix-runner: missing $SEALPROBE or $DAEMON" >&2
	exit 2
fi
if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
	echo "dir-matrix-runner: bpf not in active LSM list" >&2
	exit 2
fi

TMP=$(mktemp -d /tmp/dir-matrix.XXXXXX)
DAEMON_PID=
DAEMON_LOG=""

cleanup() {
	if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
		kill "$DAEMON_PID" 2>/dev/null || true
		wait "$DAEMON_PID" 2>/dev/null || true
	fi
	rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

OPS="dir_unlink_child dir_create dir_mkdir dir_mknod dir_symlink dir_link dir_rename_in dir_rename_out dir_rmdir dir_chmod"

# Expected matrix per (op, flag): see V-3 predictions.md. Both impl and
# intent columns agree on every cell (Step 2 reconciliation).
expected_for() {
	op=$1; flag=$2
	case "${op}:${flag}" in
	dir_unlink_child:no-unlink|dir_rmdir:no-unlink) echo DENY ;;
	dir_create:no-write|dir_mkdir:no-write|dir_mknod:no-write|dir_symlink:no-write|dir_link:no-write|dir_rename_in:no-write) echo DENY ;;
	dir_rename_in:no-rename|dir_rename_out:no-unlink|dir_rename_out:no-rename) echo DENY ;;
	dir_chmod:no-chmod) echo DENY ;;
	*) echo ALLOW ;;
	esac
}

rc_to_name() {
	case "$1" in
	0) echo ALLOW ;;
	1) echo DENY ;;
	2) echo USAGE ;;
	3) echo UNEXPECTED_ERRNO ;;
	4) echo STAGE_ERROR ;;
	*) echo "RC$1" ;;
	esac
}

# Pre-stage cell-specific filesystem state BEFORE the daemon attaches.
# Anything created after attach inside a sealed dir would be subject to
# the seal — these prerequisites must exist first.
stage_cell() {
	op=$1; cell_dir=$2
	mkdir -p "$cell_dir/sealed"
	case "$op" in
	dir_unlink_child)
		: > "$cell_dir/sealed/child" ;;
	dir_link|dir_rename_in)
		: > "$cell_dir/donor" ;;
	dir_rename_out)
		: > "$cell_dir/sealed/child"
		mkdir -p "$cell_dir/dest" ;;
	dir_rmdir)
		mkdir -p "$cell_dir/sealed/emptysub" ;;
	esac
}

run_cell() {
	flag=$1; op=$2; expected=$3; cell_dir=$4

	sealed="$cell_dir/sealed"
	donor="$cell_dir/donor"
	dest="$cell_dir/dest"

	case "$op" in
	dir_unlink_child)
		"$SEALPROBE" unlink "$sealed/child" >/dev/null 2>&1; rc=$?
		;;
	dir_create)
		"$SEALPROBE" create-in "$sealed" >/dev/null 2>&1; rc=$?
		;;
	dir_mkdir)
		"$SEALPROBE" mkdir "$sealed/newsub" >/dev/null 2>&1; rc=$?
		;;
	dir_mknod)
		"$SEALPROBE" mknod-fifo "$sealed/newfifo" >/dev/null 2>&1; rc=$?
		;;
	dir_symlink)
		"$SEALPROBE" symlink /tmp "$sealed/newsym" >/dev/null 2>&1; rc=$?
		;;
	dir_link)
		"$SEALPROBE" link "$donor" "$sealed/newhard" >/dev/null 2>&1; rc=$?
		;;
	dir_rename_in)
		"$SEALPROBE" rename-into "$donor" "$sealed/arrived" >/dev/null 2>&1; rc=$?
		;;
	dir_rename_out)
		"$SEALPROBE" rename "$sealed/child" "$dest/departed" >/dev/null 2>&1; rc=$?
		;;
	dir_rmdir)
		"$SEALPROBE" rmdir "$sealed/emptysub" >/dev/null 2>&1; rc=$?
		;;
	dir_chmod)
		"$SEALPROBE" chmod "$sealed" >/dev/null 2>&1; rc=$?
		;;
	esac

	name=$(rc_to_name "$rc")
	if   [ "$expected" = "DENY"  ] && [ "$rc" -eq 1 ]; then result=PASS
	elif [ "$expected" = "ALLOW" ] && [ "$rc" -eq 0 ]; then result=PASS
	elif [ "$rc" -eq 4 ]; then                              result=ERROR
	else                                                    result=FAIL
	fi
	echo "$flag,$op,$expected,$rc,$name,$result"
}

test_one_flag() {
	flag=$1
	flag_dir="$TMP/$flag"
	mkdir -p "$flag_dir"
	policy="$flag_dir/policy.conf"
	: > "$policy"
	DAEMON_LOG="$flag_dir/daemon.err"

	# Pre-stage every cell's preconditions and one policy line per cell
	# (one seal per sealed parent dir). All staging happens BEFORE the
	# daemon attaches.
	for op in $OPS; do
		stage_cell "$op" "$flag_dir/$op"
		echo "seal $flag_dir/$op/sealed $flag" >> "$policy"
	done

	"$DAEMON" "$policy" >"$DAEMON_LOG" 2>&1 &
	DAEMON_PID=$!
	# Wait up to 10s for daemon to be live (same shape as matrix-runner.sh).
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
		run_cell "$flag" "$op" "$exp" "$flag_dir/$op"
	done

	kill "$DAEMON_PID" 2>/dev/null || true
	wait "$DAEMON_PID" 2>/dev/null || true
	DAEMON_PID=
}

echo "flag,op,expected,actual_rc,actual_name,result"

for f in no-unlink no-rename no-write no-chmod; do
	test_one_flag "$f"
done
