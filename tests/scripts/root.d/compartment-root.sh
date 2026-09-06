#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# compartment-root.sh — root-only test suite for compartment-root
#
# Runs a real container on the machine it is invoked on, so it needs real
# root.  Everything it creates lives under one mktemp -d directory plus one
# cgroup directory, and both are removed on exit — including on failure.
#
# Standalone by design: it builds its own busybox rootdir and does not
# depend on tests/probes or tests/profiles.
#
# Usage: sudo ./tests/scripts/root.d/compartment-root.sh [--verbose]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CR="${REPO_DIR}/compartment-root"
VERBOSE="${1:-}"

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP: $1"; }

# ── Prerequisites ──────────────────────────────────────────────────

echo "=== compartment-root root test suite ==="
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: this suite must run as root (it creates real containers)."
    echo "  sudo $0"
    exit 1
fi

if [ ! -x "${CR}" ]; then
    echo "ERROR: ${CR} not found. Run 'make' first."
    exit 1
fi

BUSYBOX=""
for cand in /bin/busybox /usr/bin/busybox; do
    [ -x "$cand" ] && BUSYBOX="$cand" && break
done
if [ -z "${BUSYBOX}" ] && command -v apt-get >/dev/null 2>&1; then
    echo "busybox not found — installing busybox-static"
    DEBIAN_FRONTEND=noninteractive apt-get install -y busybox-static >/dev/null 2>&1 || true
    for cand in /bin/busybox /usr/bin/busybox; do
        [ -x "$cand" ] && BUSYBOX="$cand" && break
    done
fi
if [ -z "${BUSYBOX}" ]; then
    echo "ERROR: busybox not available and could not be installed."
    echo "  apt-get install busybox-static"
    exit 1
fi
if ldd "${BUSYBOX}" >/dev/null 2>&1; then
    echo "ERROR: ${BUSYBOX} is dynamically linked; the rootdir must stand alone."
    echo "  apt-get install busybox-static"
    exit 1
fi

echo "  compartment-root: ${CR}"
echo "  busybox:          ${BUSYBOX}"
echo "  kernel:           $(uname -r)"
echo ""

# ── Fixtures ───────────────────────────────────────────────────────

WORK="$(mktemp -d /tmp/compartment-root-tests.XXXXXX)"
JAIL="${WORK}/jail"
CGROUP_DIR=""

cleanup() {
    local rc=$?
    # Kill anything this suite left running, then unwind mounts.  The
    # container does all of its mounting inside its own mount namespace,
    # so nothing should be left on the host — but check anyway.
    pkill -9 -f "compartment-root -c ${JAIL}" 2>/dev/null || true
    sleep 0.2
    local mp
    while read -r mp; do
        [ -n "${mp}" ] && umount -l "${mp}" 2>/dev/null || true
    done < <(awk -v p="${WORK}" '$5 ~ "^"p {print $5}' /proc/self/mountinfo | sort -r)
    [ -n "${CGROUP_DIR}" ] && rmdir "${CGROUP_DIR}" 2>/dev/null
    # A container that is still tearing down can hold rootdir/.pivot_old
    # for a moment after its last process is gone; retry briefly.
    for _ in 1 2 3 4 5; do
        rm -rf "${WORK}" 2>/dev/null && break
        sleep 0.4
    done
    if [ -e "${WORK}" ]; then
        rm -rf "${WORK}" || echo "WARNING: could not remove ${WORK}"
    fi
    exit "${rc}"
}
trap cleanup EXIT INT TERM

mkdir -p "${JAIL}"/{bin,dev,proc,sys,tmp,etc,host}
cp "${BUSYBOX}" "${JAIL}/bin/busybox"
for applet in sh ls cat echo grep head wc id hostname sleep true ping mount \
              ps env printf sed cut tr sort dd stat; do
    ln -sf /bin/busybox "${JAIL}/bin/${applet}"
done
printf 'root:x:0:0::/:/bin/sh\nctsvc:x:60000:60000::/:/bin/sh\n' > "${JAIL}/etc/passwd"
printf 'root:x:0:\nctsvc:x:60000:\n' > "${JAIL}/etc/group"
chmod 755 "${JAIL}"
# mktemp -d gives 0700; a container whose uid map is shifted runs as an
# unmapped host uid and needs to traverse this directory.
chmod 755 "${WORK}"

# The service user is resolved with getpwnam() in the HOST passwd database
# (that lookup happens before clone), so use a name that is deliberately
# not there and pin the ids with -u/-g.  The name only has to exist in the
# container's own /etc/passwd, which is what the shell inside sees.
CRUSER=(-U ctsvc -u 60000 -g 60000)

# A setuid-root binary inside the rootdir, for the nosuid check.
cat > "${WORK}/suidtest.c" <<'EOF'
#include <stdio.h>
#include <unistd.h>
int main(void) { printf("uid=%u euid=%u\n", getuid(), geteuid()); return 0; }
EOF
HAVE_SUIDTEST=0
if command -v cc >/dev/null 2>&1 &&
   cc -static -O2 -o "${JAIL}/bin/suidtest" "${WORK}/suidtest.c" 2>/dev/null; then
    chown 0:0 "${JAIL}/bin/suidtest"
    chmod 4755 "${JAIL}/bin/suidtest"
    HAVE_SUIDTEST=1
fi

# Run compartment-root; sets RUN_OUT / RUN_RC.
# Usage: run_cr ARGS...
run_cr() {
    RUN_OUT=""
    RUN_RC=0
    if [ -n "${VERBOSE}" ]; then
        echo "    CMD: ${CR} $*"
    fi
    RUN_OUT="$("${CR}" "$@" 2>&1)" || RUN_RC=$?
    if [ -n "${VERBOSE}" ]; then
        echo "    OUT: ${RUN_OUT}"
        echo "    RC:  ${RUN_RC}"
    fi
}

expect_contains() {
    local label="$1" pattern="$2"
    if printf '%s\n' "${RUN_OUT}" | grep -q -- "${pattern}"; then
        pass "${label}"
    else
        fail "${label} (expected '${pattern}' in output; got: $(printf '%s' "${RUN_OUT}" | tr '\n' '|' | cut -c1-200))"
    fi
}

# A negative assertion is only meaningful if the container actually ran:
# a setup failure must not satisfy it.  (That is exactly how the pre-fix
# build produced false greens — every "not present" check passed while
# `mount proc` was failing and no probe ever executed.)
expect_not_contains() {
    local label="$1" pattern="$2"
    if [ "${RUN_RC}" -ne 0 ]; then
        fail "${label} (container did not run: rc=${RUN_RC})"
    elif printf '%s\n' "${RUN_OUT}" | grep -q -- "${pattern}"; then
        fail "${label} (unexpected '${pattern}' in output)"
    else
        pass "${label}"
    fi
}

expect_rc() {
    local label="$1" expected="$2"
    if [ "${RUN_RC}" -eq "${expected}" ]; then
        pass "${label}"
    else
        fail "${label} (expected rc=${expected}, got rc=${RUN_RC})"
    fi
}

expect_rc_not() {
    local label="$1" unexpected="$2"
    if [ "${RUN_RC}" -ne "${unexpected}" ]; then
        pass "${label}"
    else
        fail "${label} (expected rc != ${unexpected})"
    fi
}

# ── Test 1: container starts with a plain-directory rootdir ────────

echo "--- Test group: container start (H5) ---"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'echo INSIDE_OK'
expect_rc "plain rootdir: exit 0" 0
expect_contains "plain rootdir: command ran" "INSIDE_OK"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'exit 42'
expect_rc "exit status propagates" 42

echo ""

# ── Test 2: /dev device nodes ──────────────────────────────────────

echo "--- Test group: /dev device nodes (H4) ---"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'echo x > /dev/null && head -c1 /dev/urandom > /dev/null && echo DEVOK'
expect_contains "/dev/null writable and /dev/urandom readable" "DEVOK"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'for d in null zero full random urandom tty; do [ -c /dev/$d ] || echo "MISSING $d"; done; echo DEVSCAN'
expect_contains "device node scan ran" "DEVSCAN"
expect_not_contains "all six device nodes present" "MISSING"

echo ""

# ── Test 3: seccomp filter ─────────────────────────────────────────

echo "--- Test group: seccomp (H6) ---"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'grep ^Seccomp: /proc/self/status'
expect_contains "default filter installed (Seccomp: 2)" "Seccomp:	2"

run_cr --no-seccomp -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'grep ^Seccomp: /proc/self/status'
expect_contains "--no-seccomp really disables it (Seccomp: 0)" "Seccomp:	0"

run_cr --dry-run -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh
expect_contains "--dry-run reports the built-in deny-list" "built-in default"

echo ""

# ── Test 4: privilege drop and no-new-privs ────────────────────────

echo "--- Test group: privilege drop (M5) ---"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'grep ^NoNewPrivs /proc/self/status'
expect_contains "NoNewPrivs set" "NoNewPrivs:	1"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'grep ^CapEff /proc/self/status'
expect_contains "capabilities empty after drop" "CapEff:	0000000000000000"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'id -u'
expect_contains "dropped to the service uid" "60000"

if [ "${HAVE_SUIDTEST}" -eq 1 ]; then
    run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/suidtest
    expect_contains "setuid-root binary neutralised by nosuid" "euid=60000"
else
    skip "no C compiler: setuid-root binary check"
fi

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'head -1 /proc/self/mountinfo'
expect_contains "container root mounted nosuid,nodev" "nosuid,nodev"

NNP_CONF="${WORK}/nnp.conf"
printf 'rootdir %s\nusername ctsvc\nuid 60000\ngid 60000\nno-new-privs off\n' "${JAIL}" > "${NNP_CONF}"
run_cr --profile "${NNP_CONF}" -- /bin/sh -c 'grep ^NoNewPrivs /proc/self/status'
expect_contains "'no-new-privs off' refused by a profile" "NoNewPrivs:	1"
expect_contains "'no-new-privs off' diagnosed" "cannot be disabled"

echo ""

# ── Test 5: /proc and /sys masking ─────────────────────────────────

echo "--- Test group: /proc and /sys masking (M6) ---"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'for f in /proc/keys /proc/timer_list /proc/sched_debug /proc/kallsyms \
              /proc/modules /proc/kcore /proc/sysrq-trigger; do
       [ -s "$f" ] && echo "UNMASKED $f"
     done; echo MASKSCAN'
expect_contains "mask scan ran" "MASKSCAN"
expect_not_contains "no unmasked /proc entry" "UNMASKED"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'wc -c < /proc/kcore'
expect_contains "/proc/kcore is empty" "^0$"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'grep " /sys " /proc/self/mountinfo || echo NOSYS'
expect_contains "/sys mounted read-only" " ro,"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'ls /sys/firmware | wc -l'
expect_contains "/sys/firmware masked (empty)" "^0$"

echo ""

# ── Test 6: namespace isolation and escape attempts ────────────────

echo "--- Test group: namespace isolation ---"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'hostname'
expect_contains "UTS hostname isolated" "container"

# Only the container's own mounts must be visible: rootdir, /proc, /sys,
# /dev and the masks.  Any other host filesystem would show up as a
# separate mount source here.
run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'awk '"'"'$5 != "/" && $5 !~ /^\/(proc|sys|dev)(\/|$)/'"'"' /proc/self/mountinfo | wc -l'
expect_contains "no host mounts leaked into the container" "^0$"

# /proc/1/root is the container init's root: it must be the jail, not the host.
run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'ls /proc/1/root/ | tr "\n" " "; echo'
expect_not_contains "/proc/1/root does not reach the host root" "boot"
expect_contains "/proc/1/root is the container root or denied" "host\|Permission denied"

# A directory fd opened by the caller must not survive into the container.
run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'ls /proc/self/fd | tr "\n" " "; echo' 9< /
expect_not_contains "pre-opened host directory fd is closed" "^9$"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'ls /host | wc -l'
expect_contains "container root really is the jail" "^0$"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'grep ^Groups /proc/self/status'
expect_not_contains "supplementary groups cleared" "Groups:	0"

# A fresh pid namespace: only the reaper, the shell and its own children.
run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'n=$(ls /proc | grep -c "^[0-9][0-9]*$"); echo "pids=$n"; [ "$n" -lt 10 ] && echo PIDNS_OK'
expect_contains "host processes not visible in the pid namespace" "PIDNS_OK"

echo ""

# ── Test 7: init, signals and fd hygiene ───────────────────────────

echo "--- Test group: container init (L4, L5) ---"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'echo pid=$$'
expect_contains "target runs under a PID 1 reaper" "pid=2"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'ls /proc/self/fd | tr "\n" " "; echo' 8< /etc/hostname
expect_not_contains "inherited fd 8 closed before exec" "^8$"

# SIGTERM to compartment-root must reach the target through PID 1.
"${CR}" -c "${JAIL}" "${CRUSER[@]}" -- /bin/sleep 30 >/dev/null 2>&1 &
SIG_PID=$!
sleep 1
kill -TERM "${SIG_PID}" 2>/dev/null
SIG_RC=0
wait "${SIG_PID}" 2>/dev/null || SIG_RC=$?
if [ "${SIG_RC}" -eq 143 ]; then
    pass "SIGTERM forwarded to the target (rc=143)"
else
    fail "SIGTERM forwarded to the target (expected rc=143, got ${SIG_RC})"
fi

# Killing compartment-root must take the container down (PR_SET_PDEATHSIG).
"${CR}" -c "${JAIL}" "${CRUSER[@]}" -- /bin/sleep 29 >/dev/null 2>&1 &
PD_PID=$!
sleep 1
PD_BEFORE=$(pgrep -c -f "compartment-root -c ${JAIL} .* /bin/sleep 29" || true)
kill -9 "${PD_PID}" 2>/dev/null
wait "${PD_PID}" 2>/dev/null || true
sleep 1
PD_AFTER=$(pgrep -c -f "compartment-root -c ${JAIL} .* /bin/sleep 29" || true)
if [ "${PD_BEFORE}" -gt 0 ] && [ "${PD_AFTER}" -eq 0 ]; then
    pass "PR_SET_PDEATHSIG tears the container down with its parent"
else
    fail "PR_SET_PDEATHSIG (before=${PD_BEFORE} after=${PD_AFTER}, expected >0 then 0)"
fi

echo ""

# ── Test 8: networking ─────────────────────────────────────────────

echo "--- Test group: network namespace ---"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'ls /sys/class/net | tr "\n" " "; echo'
expect_contains "fresh netns has only loopback" "lo"
expect_not_contains "host interfaces not visible" "eth0"

# IFF_UP is bit 0 of /sys/class/net/lo/flags: 0x9 up, 0x8 down.  (ICMP is
# not usable as a probe here — ping needs CAP_NET_RAW or a permissive
# net.ipv4.ping_group_range, and the container has neither.)
run_cr -c "${JAIL}" "${CRUSER[@]}" -l -- /bin/sh -c 'cat /sys/class/net/lo/flags'
expect_contains "loopback is up with 'loopback on'" "0x9"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'cat /sys/class/net/lo/flags'
expect_contains "loopback probe ran without --loopback" "0x"
expect_not_contains "loopback is down without --loopback" "0x9"

echo ""

# ── Test 9: uid/gid map ────────────────────────────────────────────

echo "--- Test group: uid-map / gid-map (L3) ---"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'head -1 /proc/self/uid_map'
expect_contains "default is the identity map" "0          0      65536"

SHIFT_ROOT="${WORK}/shifted"
cp -a "${JAIL}" "${SHIFT_ROOT}"
chown -R 100000:100000 "${SHIFT_ROOT}"
chmod 755 "${SHIFT_ROOT}"
MAP_CONF="${WORK}/map.conf"
printf 'rootdir %s\nusername root\nuid-map 0 100000 65536\ngid-map 0 100000 65536\n' \
    "${SHIFT_ROOT}" > "${MAP_CONF}"
run_cr --profile "${MAP_CONF}" -- /bin/sh -c 'id -u; head -1 /proc/self/uid_map'
expect_rc "shifted uid map: container starts" 0
expect_contains "shifted uid map: container uid is 0" "^0$"
expect_contains "shifted uid map: host base is 100000" "100000"

BADMAP_CONF="${WORK}/badmap.conf"
printf 'rootdir %s\nusername ctsvc\nuid 60000\ngid 60000\nuid-map 0 100000\n' "${JAIL}" > "${BADMAP_CONF}"
run_cr --profile "${BADMAP_CONF}" -- /bin/sh -c true
expect_rc_not "malformed uid-map refused" 0
expect_contains "malformed uid-map diagnosed" "invalid uid-map"

echo ""

# ── Test 10: cgroup path confinement ───────────────────────────────

echo "--- Test group: cgroup confinement (L9) ---"

run_cr -c "${JAIL}" "${CRUSER[@]}" -C /etc/cron.d -- /bin/sh -c true
expect_rc_not "cgroup path outside /sys/fs/cgroup refused" 0
expect_contains "cgroup path outside /sys/fs/cgroup diagnosed" "must be under /sys/fs/cgroup"
if [ -e /etc/cron.d/cgroup.procs ]; then
    fail "cgroup path outside /sys/fs/cgroup created a file"
    rm -f /etc/cron.d/cgroup.procs
else
    pass "cgroup path outside /sys/fs/cgroup created nothing"
fi

if [ -d /sys/fs/cgroup ] && mkdir -p /sys/fs/cgroup/compartment-root-test 2>/dev/null; then
    CGROUP_DIR=/sys/fs/cgroup/compartment-root-test
    run_cr -c "${JAIL}" "${CRUSER[@]}" -C "${CGROUP_DIR}" -- /bin/sh -c 'echo CGOK'
    expect_contains "real cgroup path accepted" "CGOK"
else
    skip "cgroup v2 hierarchy not writable: real cgroup assignment"
fi

echo ""

# ── Test 11: dry-run and audit reporting ───────────────────────────

echo "--- Test group: reporting ---"

run_cr --dry-run -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh
DRY_PLAIN="${RUN_OUT}"
run_cr --dry-run --verbose -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh
if [ "${#RUN_OUT}" -gt "${#DRY_PLAIN}" ]; then
    pass "--dry-run --verbose prints more than --dry-run"
else
    fail "--dry-run --verbose prints nothing extra"
fi
expect_contains "--dry-run --verbose lists the built-in masks" "/proc/kallsyms"
expect_contains "--dry-run --verbose lists the blocked syscalls" "pivot_root"

run_cr --dry-run -c "${JAIL}" "${CRUSER[@]}" -L "${WORK}/audit" -- /bin/sh
expect_contains "audit banner names a directory and its file" "log dir:"

run_cr -c "${JAIL}" "${CRUSER[@]}" -L "${WORK}/audit" -- /bin/sh -c 'echo AUDITRUN'
expect_contains "audit run succeeds" "AUDITRUN"
if grep -qs CONTAINER_EXEC "${WORK}"/audit/*.log; then
    pass "audit log file records CONTAINER_EXEC"
else
    fail "no CONTAINER_EXEC record in ${WORK}/audit/*.log"
fi

echo ""

# ── Test 12: shipped allow-list profile end to end ─────────────────

echo "--- Test group: allow-list profile ---"

if [ -f "${REPO_DIR}/examples/container.conf" ]; then
    # Same syscall allow-list, pointed at this suite's rootdir and user.
    # Nothing in it mentions wait4/kill/rt_sigaction — which the PID 1
    # reaper needs — so this also proves the reaper is outside the filter.
    ALLOW_CONF="${WORK}/allow.conf"
    grep -vE '^(rootdir|uid|gid|username|audit-log|audit|loopback)[[:space:]]' \
        "${REPO_DIR}/examples/container.conf" > "${ALLOW_CONF}"
    printf 'rootdir %s\nusername ctsvc\nuid 60000\ngid 60000\n' "${JAIL}" \
        >> "${ALLOW_CONF}"

    run_cr --profile "${ALLOW_CONF}" -- /bin/sh -c 'echo ALLOWLIST_OK'
    expect_rc "allow-list profile: container starts" 0
    expect_contains "allow-list profile: command ran" "ALLOWLIST_OK"

    run_cr --profile "${ALLOW_CONF}" -- /bin/sh -c 'grep ^Seccomp: /proc/self/status'
    expect_contains "allow-list profile: filter enforced" "Seccomp:	2"
else
    skip "examples/container.conf not present: allow-list profile"
fi

echo ""

# ── Summary ────────────────────────────────────────────────────────

echo "=== Results ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  SKIP: ${SKIP}"
echo ""

if [ "${FAIL}" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
