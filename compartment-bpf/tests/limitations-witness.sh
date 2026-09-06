#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# tests/limitations-witness.sh — honest witnesses for the LIMITATIONS.md
# residuals.
#
# Every row in LIMITATIONS.md that says "not enforced" is prose. Nothing
# under tests/ recorded today's behaviour for any of them, so a silent
# change in EITHER direction was invisible: an upstream hook appearing
# (good, but the docs would go stale) or the transitive coverage that
# currently compensates regressing (bad, and nothing would say so).
#
# Each witness therefore asserts the CURRENT documented behaviour and
# fails when it changes, with a message naming the row to update. A
# failure here is not necessarily a defect — it is a documentation
# obligation.
#
# Rows witnessed:
#   L1  pre-seal writable fd, ordinary write        -> DENIED
#       ("Pre-existing writable file descriptors": file_permission
#        catches it, which is tighter than the row's own history)
#   L2  pre-seal writable fd, FALLOC_FL_PUNCH_HOLE  -> ALLOWED, no audit
#       ("VFS write-class transitive coverage": vfs_fallocate() has no
#        security_* call; there is nothing to hook)
#   L3  the punch actually destroys content         -> zeroed
#   L4  mount -o remount,rw on a filesystem holding seals -> ALLOWED,
#       and the seal still denies afterwards
#       ("sb_remount is deliberately not attached ... defeats nothing")
#   L5  MAP_SHARED writable mapping established before the seal
#       -> writes through it still land
#
# Root + BPF LSM. SKIPs cleanly otherwise, like every sibling suite.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DAEMON="${REPO}/compartment-bpf"
SEALPROBE="${REPO}/tests/sealprobe"

PASS=0
FAIL=0
SKIP=0
pass() { PASS=$((PASS + 1)); echo "PASS limitations-${1}"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL limitations-${1}"; }
skipall() {
    echo "SKIP limitations-witness: $1"
    echo "RESULT check-limitations: pass=0 fail=0 skip=1"
    exit 77
}

[ "$(id -u)" -eq 0 ] || skipall "needs root"
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null || skipall "bpf not in active LSM"
[ -x "${DAEMON}" ] || skipall "daemon not built"
[ -x "${SEALPROBE}" ] || skipall "sealprobe not built"

TMP="$(mktemp -d /tmp/limitations.XXXXXX)"
MNT="${TMP}/mnt"
DAEMON_PID=""
cleanup() {
    [ -n "${DAEMON_PID}" ] && kill "${DAEMON_PID}" 2>/dev/null
    [ -n "${DAEMON_PID}" ] && wait "${DAEMON_PID}" 2>/dev/null
    mountpoint -q "${MNT}" 2>/dev/null && umount -l "${MNT}" 2>/dev/null
    rm -rf "${TMP}"
    return 0
}
trap cleanup EXIT INT TERM

mkdir -p "${MNT}"
mount -t tmpfs -o size=4m tmpfs "${MNT}" || skipall "cannot mount a scratch tmpfs"
TARGET="${MNT}/target"
head -c 8192 /dev/urandom > "${TARGET}"
BEFORE_SUM="$(md5sum < "${TARGET}")"

# The descriptor that predates the policy. Everything below uses it.
exec 9<>"${TARGET}"

DAEMON_LOG="${TMP}/daemon.err"
printf 'seal %s no-write\n' "${TARGET}" > "${TMP}/policy.conf"
"${DAEMON}" "${TMP}/policy.conf" > "${DAEMON_LOG}" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do
    grep -q '\[run\] compartment-bpf live' "${DAEMON_LOG}" 2>/dev/null && break
    kill -0 "${DAEMON_PID}" 2>/dev/null || { cat "${DAEMON_LOG}" >&2; skipall "daemon died during attach"; }
    sleep 0.1
done
grep -q '\[run\] compartment-bpf live' "${DAEMON_LOG}" 2>/dev/null \
    || { cat "${DAEMON_LOG}" >&2; skipall "daemon did not go live"; }

denies_before="$(grep -c 'DENY_' "${DAEMON_LOG}" 2>/dev/null || echo 0)"

# ── L1 ─────────────────────────────────────────────────────────────
"${SEALPROBE}" write-to-fd 9 >/dev/null 2>&1
rc=$?
if [ "${rc}" -eq 1 ]; then
    pass "L1-preseal-fd-write-denied: ordinary write through a pre-seal fd is denied (file_permission)"
else
    fail "L1-preseal-fd-write-denied: rc=${rc} (want 1=DENY). The transitive write coverage that LIMITATIONS.md 'Pre-existing writable file descriptors' relies on has changed — update the row."
fi

# ── L2 ─────────────────────────────────────────────────────────────
"${SEALPROBE}" punch-hole-via-fd 9 >/dev/null 2>&1
rc=$?
sleep 0.5
denies_after="$(grep -c 'DENY_' "${DAEMON_LOG}" 2>/dev/null || echo 0)"
if [ "${rc}" -eq 0 ] && [ "${denies_after}" -eq "${denies_before}" ]; then
    pass "L2-fallocate-punch-hole-unhooked: FALLOC_FL_PUNCH_HOLE through a pre-seal fd succeeds with no audit event (vfs_fallocate has no security_* call)"
elif [ "${rc}" -ne 0 ]; then
    fail "L2-fallocate-punch-hole-unhooked: the punch was refused (rc=${rc}). An upstream hook on fallocate would be good news — update the LIMITATIONS.md 'VFS write-class transitive coverage' and 'Pre-existing writable file descriptors' rows."
else
    fail "L2-fallocate-punch-hole-unhooked: the punch succeeded but produced $((denies_after - denies_before)) audit DENY line(s); the row says there is no deny and no audit event."
fi

# ── L3 ─────────────────────────────────────────────────────────────
AFTER_SUM="$(md5sum < "${TARGET}")"
ZEROES="$(head -c 4096 "${TARGET}" | tr -d '\0' | wc -c)"
if [ "${BEFORE_SUM}" != "${AFTER_SUM}" ] && [ "${ZEROES}" -eq 0 ]; then
    pass "L3-punch-hole-destroys-content: the first 4 KiB of the sealed file are now zero"
else
    fail "L3-punch-hole-destroys-content: content unchanged (nonzero bytes in the punched range: ${ZEROES}) — L2 may have measured nothing"
fi

# ── L4 ─────────────────────────────────────────────────────────────
mount -o remount,ro "${MNT}" 2>/dev/null
if mount -o remount,rw "${MNT}" 2>/dev/null; then
    sleep 0.3
    denies_now="$(grep -c 'DENY_' "${DAEMON_LOG}" 2>/dev/null || echo 0)"
    if [ "${denies_now}" -eq "${denies_after}" ]; then
        pass "L4-remount-not-attached: remount,rw on a filesystem holding seals is allowed and unaudited (sb_remount is deliberately not attached)"
    else
        fail "L4-remount-not-attached: remount produced an audit DENY line; sb_remount looks attached now — update LIMITATIONS.md"
    fi
else
    fail "L4-remount-not-attached: remount,rw was refused; either sb_remount is attached now or the scratch tmpfs is not remountable"
fi

# The seal must still be in force after the remount — that is the reason
# the row gives for not attaching sb_remount in the first place.
"${SEALPROBE}" open-write "${TARGET}" >/dev/null 2>&1
rc=$?
if [ "${rc}" -eq 1 ]; then
    pass "L4b-seal-survives-remount: the no-write seal still denies after remount,rw"
else
    fail "L4b-seal-survives-remount: rc=${rc} (want 1=DENY) — a remount now defeats a seal"
fi

# ── L5 ─────────────────────────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
    SKIP=$((SKIP + 1))
    echo "SKIP limitations-L5-preattach-shared-mmap: python3 not installed"
else
    MTARGET="${MNT}/mmaptarget"
    head -c 4096 /dev/zero > "${MTARGET}"
    READY="${TMP}/mmap.ready"
    GO="${TMP}/mmap.go"
    DONE="${TMP}/mmap.done"
    python3 - "${MTARGET}" "${READY}" "${GO}" "${DONE}" <<'PYEOF' &
import mmap, os, sys, time
target, ready, go, done = sys.argv[1:5]
f = open(target, "r+b")
m = mmap.mmap(f.fileno(), 4096, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
open(ready, "w").close()
for _ in range(600):
    if os.path.exists(go):
        break
    time.sleep(0.05)
try:
    m[0:4] = b"MMAP"
    m.flush()
    result = "ok"
except OSError as e:
    result = "errno=%d" % e.errno
with open(done, "w") as fh:
    fh.write(result)
m.close()
f.close()
PYEOF
    MMAP_PID=$!
    for _ in $(seq 1 100); do [ -f "${READY}" ] && break; sleep 0.05; done
    if [ ! -f "${READY}" ]; then
        fail "L5-preattach-shared-mmap: the mapping helper never became ready"
        kill "${MMAP_PID}" 2>/dev/null
    else
        # Seal the mapped file only now, with the mapping already live.
        printf 'seal %s no-write\n' "${MTARGET}" >> "${TMP}/policy.conf"
        kill "${DAEMON_PID}" 2>/dev/null; wait "${DAEMON_PID}" 2>/dev/null
        DAEMON_LOG2="${TMP}/daemon2.err"
        "${DAEMON}" "${TMP}/policy.conf" > "${DAEMON_LOG2}" 2>&1 &
        DAEMON_PID=$!
        for _ in $(seq 1 100); do
            grep -q '\[run\] compartment-bpf live' "${DAEMON_LOG2}" 2>/dev/null && break
            sleep 0.1
        done
        : > "${GO}"
        for _ in $(seq 1 200); do [ -f "${DONE}" ] && break; sleep 0.05; done
        wait "${MMAP_PID}" 2>/dev/null
        RESULT="$(cat "${DONE}" 2>/dev/null || echo missing)"
        if [ "${RESULT}" = "ok" ] && [ "$(head -c 4 "${MTARGET}")" = "MMAP" ]; then
            pass "L5-preattach-shared-mmap: a MAP_SHARED writable mapping made before the seal still writes through (documented: load policy before the protected services start)"
        else
            fail "L5-preattach-shared-mmap: the write through the pre-seal mapping did not land (${RESULT}) — the residual is closed; update the LIMITATIONS.md mmap row"
        fi
    fi
fi

echo "[limitations] ${PASS} PASS / ${FAIL} FAIL / ${SKIP} SKIP"
echo "RESULT check-limitations: pass=${PASS} fail=${FAIL} skip=${SKIP}"
[ "${FAIL}" -eq 0 ] || exit 1
exit 0
