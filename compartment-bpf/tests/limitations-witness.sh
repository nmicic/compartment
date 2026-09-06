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
#   L2  pre-seal writable fd, FALLOC_FL_PUNCH_HOLE, no policy -> ALLOWED
#   L3  the same punch with the policy live         -> DENIED + audited
#   L4  the same punch on an UNSEALED sibling       -> ALLOWED
#       L2-L4 together are the attribution chain for the
#       "VFS write-class transitive coverage" row, which claims
#       fallocate is an unhooked gap. Measured on 6.8.0-139 and
#       7.0.0-31, on tmpfs and on ext4: it is not. The row is wrong and
#       these three witnesses are what will say so if it ever becomes
#       right.
#   L5  mount -o remount,rw on a filesystem holding seals -> ALLOWED,
#       and the seal still denies afterwards
#       ("sb_remount is deliberately not attached ... defeats nothing")
#   L6  MAP_SHARED writable mapping established before the seal
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
mount -t tmpfs -o size=8m tmpfs "${MNT}" || skipall "cannot mount a scratch tmpfs"
TARGET="${MNT}/target"
CONTROL="${MNT}/control"
head -c 8192 /dev/urandom > "${TARGET}"
head -c 8192 /dev/urandom > "${CONTROL}"

# The descriptors that predate the policy. Everything below uses them.
exec 9<>"${TARGET}"
exec 8<>"${CONTROL}"

# ── L2 (baseline, before any policy) ───────────────────────────────
# Without this the deny in L3 is not attributable to compartment-bpf:
# fallocate can fail for filesystem reasons of its own.
"${SEALPROBE}" punch-hole-via-fd 9 >/dev/null 2>&1
rc=$?
if [ "${rc}" -eq 0 ]; then
    pass "L2-fallocate-baseline-allowed: FALLOC_FL_PUNCH_HOLE succeeds with no policy loaded"
else
    fail "L2-fallocate-baseline-allowed: rc=${rc} with no policy loaded — the filesystem under ${MNT} refuses PUNCH_HOLE, so L3 would prove nothing"
fi
head -c 8192 /dev/urandom > "${TARGET}"

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

denies_before="$(grep -c 'DENY_' "${DAEMON_LOG}" 2>/dev/null || true)"
denies_before="${denies_before:-0}"

# ── L1 ─────────────────────────────────────────────────────────────
"${SEALPROBE}" write-to-fd 9 >/dev/null 2>&1
rc=$?
if [ "${rc}" -eq 1 ]; then
    pass "L1-preseal-fd-write-denied: ordinary write through a pre-seal fd is denied (file_permission)"
else
    fail "L1-preseal-fd-write-denied: rc=${rc} (want 1=DENY). The transitive write coverage LIMITATIONS.md 'Pre-existing writable file descriptors' relies on has changed — update the row."
fi

# ── L3 ─────────────────────────────────────────────────────────────
# LIMITATIONS.md's "VFS write-class transitive coverage" row says
# vfs_fallocate() contains no security_* call, so FALLOC_FL_PUNCH_HOLE
# through a pre-seal writable fd zeroes a no-write sealed file "with no
# deny and no audit event". Measured on 6.8.0-139 and 7.0.0-31, on tmpfs
# and on ext4: the punch is denied with EACCES and a DENY_WRITE audit
# line, and it is allowed again the moment the policy goes away. The row
# is wrong. This witness is what will notice if it ever becomes right.
"${SEALPROBE}" punch-hole-via-fd 9 >/dev/null 2>&1
rc=$?
sleep 0.5
denies_after="$(grep -c 'DENY_' "${DAEMON_LOG}" 2>/dev/null || true)"
denies_after="${denies_after:-0}"
if [ "${rc}" -eq 1 ] && [ "${denies_after}" -gt "${denies_before}" ]; then
    pass "L3-fallocate-punch-hole-denied: FALLOC_FL_PUNCH_HOLE through a pre-seal fd is denied and audited"
elif [ "${rc}" -eq 0 ]; then
    fail "L3-fallocate-punch-hole-denied: the punch succeeded. fallocate has become an unhooked gap on this kernel — that IS the LIMITATIONS.md 'VFS write-class transitive coverage' row as written, so restore it and say which kernels it applies to."
else
    fail "L3-fallocate-punch-hole-denied: rc=${rc}, audit delta $((denies_after - denies_before)) — denied without an audit event, or refused for some other reason"
fi

# ── L4 ─────────────────────────────────────────────────────────────
"${SEALPROBE}" punch-hole-via-fd 8 >/dev/null 2>&1
rc=$?
if [ "${rc}" -eq 0 ]; then
    pass "L4-fallocate-control-allowed: the same punch on an unsealed sibling still succeeds"
else
    fail "L4-fallocate-control-allowed: rc=${rc} on an UNSEALED file — the write path is over-denying"
fi
denies_after="$(grep -c 'DENY_' "${DAEMON_LOG}" 2>/dev/null || true)"
denies_after="${denies_after:-0}"

# ── L5 ─────────────────────────────────────────────────────────────
# "sb_remount is deliberately NOT attached ... mount -o remount,rw on a
# filesystem holding seals defeats nothing, because compartment keys on
# (dev, ino) and its denies are LSM-layer." Both halves are asserted: the
# remount is allowed and unaudited, and the seal still bites after it. If
# the second ever stops being true the row's reasoning is gone.
mount -o remount,ro "${MNT}" 2>/dev/null
if mount -o remount,rw "${MNT}" 2>/dev/null; then
    sleep 0.3
    denies_now="$(grep -c 'DENY_' "${DAEMON_LOG}" 2>/dev/null || true)"
    denies_now="${denies_now:-0}"
    if [ "${denies_now}" -eq "${denies_after}" ]; then
        pass "L5-remount-not-attached: remount,rw on a filesystem holding seals is allowed and unaudited (sb_remount is deliberately not attached)"
    else
        fail "L5-remount-not-attached: remount produced an audit DENY line; sb_remount looks attached now — update LIMITATIONS.md"
    fi
else
    fail "L5-remount-not-attached: remount,rw was refused; either sb_remount is attached now or the scratch tmpfs is not remountable"
fi

"${SEALPROBE}" open-write "${TARGET}" >/dev/null 2>&1
rc=$?
if [ "${rc}" -eq 1 ]; then
    pass "L5b-seal-survives-remount: the no-write seal still denies after remount,rw"
else
    fail "L5b-seal-survives-remount: rc=${rc} (want 1=DENY) — a remount now defeats a seal"
fi

# ── L6 ─────────────────────────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
    SKIP=$((SKIP + 1))
    echo "SKIP limitations-L6-preattach-shared-mmap: python3 not installed"
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
        fail "L6-preattach-shared-mmap: the mapping helper never became ready"
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
            pass "L6-preattach-shared-mmap: a MAP_SHARED writable mapping made before the seal still writes through (documented: load policy before the protected services start)"
        else
            fail "L6-preattach-shared-mmap: the write through the pre-seal mapping did not land (${RESULT}) — the residual is closed; update the LIMITATIONS.md mmap row"
        fi
    fi
fi

echo "[limitations] ${PASS} PASS / ${FAIL} FAIL / ${SKIP} SKIP"
echo "RESULT check-limitations: pass=${PASS} fail=${FAIL} skip=${SKIP}"
[ "${FAIL}" -eq 0 ] || exit 1
exit 0
