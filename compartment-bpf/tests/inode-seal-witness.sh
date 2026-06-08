#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# tests/inode-seal-witness.sh — deterministic regression witnesses for the two
# load-bearing security fixes that otherwise had NO assertion-level guardian
# (review OPEN-1 / Codex P1-2):
#
#   W1 inode_setattr variant : the [probe] line matches the running kernel
#                              (legacy/2-arg on <=6.8, modern/3-arg on >6.8).
#   W2 no-chmod enforcement  : chmod of a no-chmod-sealed file is DENIED — this
#                              EXERCISES the inode_setattr hook on EVERY kernel
#                              (smoke.sh never issues a chmod, so the legacy 6.8
#                              path was previously unexercised in the gate).
#   W3 held-fd lifetime      : the daemon logs `[seal] holding N O_PATH fd(s)`
#                              with N >= #seals, and the fds are visibly open in
#                              /proc/<pid>/fd while the daemon runs.
#   W4 EBUSY (held-fd proof) : a fs containing a seal returns EBUSY on umount
#                              while the daemon runs, and umounts cleanly after
#                              the daemon exits. This is the DETERMINISTIC,
#                              cross-kernel proof the O_PATH fd is held for the
#                              daemon lifetime (reverting the hold makes umount
#                              succeed while live -> W4 fails).
#   W5 inode-reuse           : after unlinking a no-write-sealed file (unlink is
#                              permitted), a freshly created file in the same dir
#                              is WRITABLE — the held fd kept the old inode
#                              allocated so its number cannot be reused by a new
#                              file inheriting the stale seal. BEST-EFFORT only:
#                              FAILs loud if reuse is ever observed, else reports
#                              INCONCLUSIVE (never a vacuous PASS). The held-fd
#                              property is proven DETERMINISTICALLY by W4 + ME-12.
#
# Root + BPF LSM required; SKIPs cleanly (rc=0) on a dev host without them so
# `make check` stays non-hostile. Any real assertion failure -> rc=1.

set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"
BIN="${REPO}/compartment-bpf"
PIN_ROOT="/sys/fs/bpf/compartment"

if [ "$(id -u)" -ne 0 ]; then
	echo "[inode-seal-witness] SKIP (requires root + BPF LSM)"; exit 0
fi
[ -x "${BIN}" ] || { echo "[inode-seal-witness] build compartment-bpf first" >&2; exit 2; }
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null || {
	echo "[inode-seal-witness] SKIP (bpf not in active LSM list)"; exit 0; }

SCR="$(mktemp -d /tmp/inode-witness.XXXXXX)"
DAEMON_PID=""
MNT=""
RTMP=""   # W5 scratch dir on a recycling fs; tracked here so a signal can't leak it (P2-7)
W6=""     # W6 dir-seal scratch dir; tracked for the same reason
cleanup() {
	[ -n "${DAEMON_PID}" ] && kill -0 "${DAEMON_PID}" 2>/dev/null && \
		{ kill -TERM "${DAEMON_PID}" 2>/dev/null; wait "${DAEMON_PID}" 2>/dev/null; }
	"${BIN}" --unpin >/dev/null 2>&1 || true
	[ -n "${MNT}" ] && mountpoint -q "${MNT}" && umount -l "${MNT}" 2>/dev/null || true
	[ -n "${RTMP}" ] && rm -rf "${RTMP}" 2>/dev/null || true
	[ -n "${W6}" ] && rm -rf "${W6}" 2>/dev/null || true
	rm -rf "${SCR}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

pass=0; fail=0
ok()  { echo "[inode-seal-witness] PASS $1"; pass=$((pass+1)); }
bad() { echo "[inode-seal-witness] FAIL $1"; fail=$((fail+1)); }

start_daemon() {  # $1 = profile
	rm -f "${SCR}/daemon.log"
	"${BIN}" --pin "$1" >"${SCR}/daemon.log" 2>&1 &
	DAEMON_PID=$!
	local i
	for i in $(seq 1 60); do
		grep -q '^\[run\] compartment-bpf live' "${SCR}/daemon.log" 2>/dev/null && return 0
		kill -0 "${DAEMON_PID}" 2>/dev/null || { echo "daemon died:" >&2; cat "${SCR}/daemon.log" >&2; return 1; }
		sleep 0.3
	done
	echo "daemon not live in 18s" >&2; cat "${SCR}/daemon.log" >&2; return 1
}
stop_daemon() {
	[ -n "${DAEMON_PID}" ] && { kill -TERM "${DAEMON_PID}" 2>/dev/null; wait "${DAEMON_PID}" 2>/dev/null; }
	DAEMON_PID=""
}

# Expected variant from the running kernel.
KREL="$(uname -r)"; KMAJ="${KREL%%.*}"; KREST="${KREL#*.}"; KMIN="${KREST%%.*}"
if [ "${KMAJ}" -lt 6 ] || { [ "${KMAJ}" -eq 6 ] && [ "${KMIN}" -le 8 ]; }; then
	EXPECT_VARIANT="legacy/no-idmap"
else
	EXPECT_VARIANT="modern/idmap"
fi

# ---- scratch tmpfs so W4 can umount a fs that contains a seal ----------------
MNT="${SCR}/mnt"; mkdir -p "${MNT}"
mount -t tmpfs tmpfs "${MNT}" 2>/dev/null || { echo "[inode-seal-witness] SKIP (cannot mount tmpfs)"; exit 0; }
echo seal-target > "${MNT}/sealed"
echo nochmod     > "${MNT}/nochmod"
echo nowrite     > "${MNT}/nowrite"
chmod 0666 "${MNT}/nochmod" "${MNT}/nowrite"
PROFILE="${SCR}/p.conf"
cat > "${PROFILE}" <<EOF
seal ${MNT}/sealed full
seal ${MNT}/nochmod no-chmod
seal ${MNT}/nowrite no-write
EOF
N_SEALS=3

"${BIN}" --unpin >/dev/null 2>&1 || true
start_daemon "${PROFILE}" || { echo "[inode-seal-witness] FAIL daemon-start"; exit 1; }

# ---- W1: probe line matches kernel ------------------------------------------
if grep -q "^\[probe\] inode_setattr hook: ${EXPECT_VARIANT}" "${SCR}/daemon.log"; then
	ok "W1 inode_setattr variant = ${EXPECT_VARIANT} (kernel ${KREL})"
else
	bad "W1 expected '${EXPECT_VARIANT}' probe line; got: $(grep 'inode_setattr hook' "${SCR}/daemon.log" || echo none)"
fi

# ---- W2: chmod of a no-chmod-sealed file is DENIED (exercises inode_setattr) -
if chmod 0640 "${MNT}/nochmod" 2>/dev/null; then
	bad "W2 chmod of no-chmod-sealed file SUCCEEDED (inode_setattr not enforcing!)"
else
	grep -q 'DENY_CHMOD' "${SCR}/daemon.log" && ok "W2 chmod denied + DENY_CHMOD audited (inode_setattr enforced on ${KREL})" \
		|| ok "W2 chmod denied (EACCES) on ${KREL}"
fi

# ---- W3: held fds point at the SEALED inodes (not just "some fds open") ------
# Strengthened (P2-e): the held O_PATH fds appear in /proc/<pid>/fd as symlinks
# whose targets are the sealed paths. Prove each sealed path is actually held,
# not merely that the daemon printed a count.
HELD_N="$(sed -n 's/^\[seal\] holding \([0-9]*\) O_PATH.*/\1/p' "${SCR}/daemon.log" | head -1)"
held_paths=0
for sp in "${MNT}/sealed" "${MNT}/nochmod" "${MNT}/nowrite"; do
	# O_PATH fd -> readlink resolves to the sealed path (deleted-suffix tolerated).
	ls -l "/proc/${DAEMON_PID}/fd" 2>/dev/null | grep -qF "${sp}" && held_paths=$((held_paths+1))
done
if [ -z "${HELD_N}" ] || [ "${HELD_N}" -lt "${N_SEALS}" ]; then
	bad "W3 expected '[seal] holding N>=${N_SEALS} O_PATH fd(s)'; got N='${HELD_N}'"
elif [ "${held_paths}" -lt "${N_SEALS}" ]; then
	bad "W3 only ${held_paths}/${N_SEALS} sealed paths are held as O_PATH fds in /proc/${DAEMON_PID}/fd (log claimed ${HELD_N})"
else
	ok "W3 all ${N_SEALS} sealed paths held as O_PATH fds in /proc/${DAEMON_PID}/fd (log: ${HELD_N})"
fi

# ---- W4: EBUSY while live, clean umount after exit (the held-fd proof) -------
uerr="$(umount "${MNT}" 2>&1)"; urc=$?
if [ "$urc" -eq 0 ]; then
	bad "W4 umount of a sealed-file fs SUCCEEDED while daemon live (held-fd NOT pinning the fs — inode-reuse fix reverted?)"
	mount -t tmpfs tmpfs "${MNT}" 2>/dev/null || true   # remount for cleanup symmetry
elif ! printf '%s' "$uerr" | grep -qiE 'busy|EBUSY'; then
	# A non-EBUSY failure (e.g. not-mounted, perms) doesn't prove the held-fd pin
	# (P2-e): don't credit it as the EBUSY witness.
	bad "W4 umount failed but NOT with EBUSY ('${uerr}') — does not prove the held-fd fs pin"
else
	# EBUSY confirmed; now prove it releases after the daemon (and its fds) exit.
	stop_daemon
	"${BIN}" --unpin >/dev/null 2>&1 || true
	if umount "${MNT}" 2>/dev/null; then
		ok "W4 umount EBUSY while daemon live, succeeds after exit (O_PATH fd held for daemon lifetime)"
		MNT=""   # already unmounted
	else
		bad "W4 umount still failed AFTER daemon exit (something else holds the mount)"
	fi
fi

# W5 needs the daemon live again on the original (non-tmpfs) fs for inode reuse.
# Use the repo /tmp fs (ext4 on most hosts) where inode recycling is observable.
RTMP="$(mktemp -d /tmp/inode-reuse.XXXXXX)"
echo victim > "${RTMP}/victim"; chmod 0666 "${RTMP}/victim"
VINO="$(stat -c %i "${RTMP}/victim")"
P2="${SCR}/p2.conf"; echo "seal ${RTMP}/victim no-write" > "${P2}"
"${BIN}" --unpin >/dev/null 2>&1 || true
if ! start_daemon "${P2}"; then
	# A failed 2nd daemon is a real failure, not a silent W5 skip (P2-e).
	bad "W5 second daemon (no-write victim) did not reach live state"
elif ! rm -f "${RTMP}/victim" 2>/dev/null || [ -e "${RTMP}/victim" ]; then
	# no-write permits unlink; if the unlink itself failed, W5's premise (freed
	# inode) does not hold — fail rather than test nothing (P2-e line-160).
	bad "W5 could not unlink the no-write-sealed victim (unlink should be permitted by no-write)"
	stop_daemon
else
	reuse_denied=0; made=0   # victim unlinked; its inode VINO is freed but the held fd pins it
	for n in $(seq 1 400); do
		f="${RTMP}/s${n}"
		if : > "$f" 2>/dev/null; then
			made=1
			[ "$(stat -c %i "$f" 2>/dev/null)" = "${VINO}" ] && reuse_denied=2  # got old inode AND write allowed -> fine
		else
			# create denied -> a new file reused VINO and inherited the stale seal
			reuse_denied=1; break
		fi
	done
	if [ "${reuse_denied}" -eq 1 ]; then
		bad "W5 a new file reused freed inode ${VINO} and inherited the stale seal (inode-reuse window OPEN)"
	else
		# With the held-fd pin, VINO cannot be recycled, so we usually do NOT
		# observe reuse here — that is EXPECTED, not positive proof, and must not
		# green vacuously (P2-1). The held-fd property is proven DETERMINISTICALLY
		# by W4 (umount-EBUSY) and mesh ME-12; W5 only ever fails LOUD (above) if
		# reuse is observed. Report INCONCLUSIVE, not PASS.
		echo "[inode-seal-witness] W5 INCONCLUSIVE: no inode reuse observed (held fd prevents recycling; deterministic proof = W4 + mesh ME-12)"
	fi
	stop_daemon
fi
"${BIN}" --unpin >/dev/null 2>&1 || true
rm -rf "${RTMP}" 2>/dev/null || true; RTMP=""

# ---- W6: recursive directory-seal blocks IN-PLACE writes to EXISTING files ---
# The coverage gap behind the dir-seal doc drift (README said recursive;
# postgres.conf/SPEC said structural-only). Empirically pin the truth: an
# in-place write (no create) to an EXISTING file under a no-write-sealed dir, by
# a NON-actor caller, is DENIED — directly under the dir AND in a subdir (the
# recursive ancestor walk, bounded by COMPARTMENT_MAX_DIR_ANCESTORS).
W6="$(mktemp -d /tmp/inode-w6.XXXXXX)"
W6DIR="${W6}/datadir"; mkdir -p "${W6DIR}/sub"; cp /bin/true "${W6}/actor"
echo orig  > "${W6DIR}/existing";  echo orig2 > "${W6DIR}/sub/deep"
chmod 0666 "${W6DIR}/existing" "${W6DIR}/sub/deep"
cat > "${SCR}/p6.conf" <<EOF6
actor a1 = ${W6}/actor
seal ${W6}/actor full
seal ${W6DIR} no-write actor=a1
EOF6
"${BIN}" --unpin >/dev/null 2>&1 || true
if ! start_daemon "${SCR}/p6.conf"; then
	bad "W6 dir-seal daemon did not reach live state"
else
	grep -q '^\[seal\] \[d\]' "${SCR}/daemon.log" || bad "W6 dir was not registered as a dir-seal ([d])"
	w6fail=""
	# in-place write (existing file, no create) by this shell (NOT actor a1):
	echo NEW > "${W6DIR}/existing" 2>/dev/null && w6fail="${w6fail} direct-existing-ALLOWED"
	echo NEW > "${W6DIR}/sub/deep" 2>/dev/null && w6fail="${w6fail} subdir-existing-ALLOWED"
	if [ -z "${w6fail}" ]; then
		ok "W6 recursive dir-seal DENIED in-place writes to existing files (direct + depth-2 subdir)"
	else
		bad "W6 dir-seal did NOT block in-place writes:${w6fail} — recursive write protection broken (docs claim it)"
	fi
	stop_daemon
fi
"${BIN}" --unpin >/dev/null 2>&1 || true
rm -rf "${W6}" 2>/dev/null || true; W6=""

echo "[inode-seal-witness] ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
