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

# One skip standing in for a block of N assertions, so pass+fail+skip is
# the same number on every machine (tests/scripts/lib/harness.sh).
skip_group() {
    local n="$1" reason="$2"
    SKIP=$((SKIP + n))
    echo "  SKIP: ${reason} (${n} assertions)"
}

# The suite declares its own assertion count, counting this check, so a
# block that silently stops running fails instead of shrinking the total.
harness_expect_total() {
    local want="$1"
    local got=$((PASS + FAIL + SKIP + 1))
    if [ "${got}" -eq "${want}" ]; then
        pass "suite ran all ${want} assertions"
    else
        fail "suite ran ${got} assertions, declared ${want} — a block was added, removed or silently skipped"
    fi
}

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

# busybox-static is a documented precondition, not something a test
# suite installs. The previous version ran `apt-get install -y` on the
# host, unprompted, and never removed the package: a test suite that
# modifies the machine it is measuring is not a test suite.
SUITE_TOTAL=86
bail_skip() {
    skip_group "${SUITE_TOTAL}" "$1"
    echo ""
    echo "=== Results ==="
    echo "  PASS: ${PASS}"
    echo "  FAIL: ${FAIL}"
    echo "  SKIP: ${SKIP}"
    echo ""
    echo "SUMMARY compartment-root: pass=${PASS} fail=${FAIL} skip=${SKIP}"
    echo "ALL TESTS PASSED"
    exit 0
}

BUSYBOX=""
for cand in /bin/busybox /usr/bin/busybox; do
    [ -x "$cand" ] && BUSYBOX="$cand" && break
done
if [ -z "${BUSYBOX}" ]; then
    echo "busybox-static is a precondition of this suite:"
    echo "  apt-get install busybox-static"
    bail_skip "busybox-static is not installed (precondition, not installed by the suite)"
fi
if ldd "${BUSYBOX}" >/dev/null 2>&1; then
    echo "${BUSYBOX} is dynamically linked; the rootdir must stand alone:"
    echo "  apt-get install busybox-static"
    bail_skip "${BUSYBOX} is dynamically linked (need busybox-static)"
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
    # Matches both the -c ${JAIL} runs and the --profile ${WORK}/*.conf ones.
    pkill -9 -f "compartment-root .*${WORK}" 2>/dev/null || true
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

# cap-allow has to survive the fork into the PID 1 reaper and the exec:
# CAP_NET_BIND_SERVICE is bit 10, i.e. 0x400 in every cap set.
run_cr -c "${JAIL}" "${CRUSER[@]}" -A CAP_NET_BIND_SERVICE -- /bin/sh -c \
    'grep -E "^Cap(Eff|Bnd|Amb)" /proc/self/status'
expect_contains "cap-allow: effective set kept" "CapEff:	0000000000000400"
expect_contains "cap-allow: ambient set raised" "CapAmb:	0000000000000400"

# 'no-new-privs off' in a profile is a fatal parse error (a profile may only
# tighten policy), so the container never starts.  compartment-root also
# forces the flag back on in main() as a second line of defence, but the
# parser refuses first — assert the refusal, not the forced-on container.
NNP_CONF="${WORK}/nnp.conf"
printf 'rootdir %s\nusername ctsvc\nuid 60000\ngid 60000\nno-new-privs off\n' "${JAIL}" > "${NNP_CONF}"
run_cr --profile "${NNP_CONF}" -- /bin/sh -c 'grep ^NoNewPrivs /proc/self/status'
expect_rc_not "'no-new-privs off' refused by a profile" 0
expect_contains "'no-new-privs off' diagnosed" "cannot be disabled"
expect_contains "'no-new-privs off' names the one-way rule" \
    "may only tighten policy"

# The container itself is unconditionally no-new-privs, with or without a
# profile saying anything about it.
run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'grep ^NoNewPrivs /proc/self/status'
expect_contains "no-new-privs is on without any profile" "NoNewPrivs:	1"

echo ""

# ── Test 5: /proc and /sys masking ─────────────────────────────────

echo "--- Test group: /proc and /sys masking (M6) ---"

# The mask list is read from compartment-root's own --dry-run --verbose
# output, so a path added to or removed from default_proc_masks[] is
# scanned without editing this suite.
MASK_LIST="$("${CR}" --dry-run --verbose -c "${JAIL}" "${CRUSER[@]}" -- /bin/true 2>&1 |
             sed -n 's|^    \(/proc/[^ ]*\)$|\1|p')"
MASK_COUNT="$(printf '%s\n' "${MASK_LIST}" | grep -c '^/proc/')"
# The container-side scan takes the list as a single-line word list: a raw
# newline inside a `for f in ...` list is a syntax error in dash/ash.
MASK_LINE="$(printf '%s ' ${MASK_LIST})"

# The scan proves the masking *mechanism*, not the byte count.  The old
# predicate was `[ -s "$f" ]`, and procfs reports st_size == 0 for every
# one of these but /proc/kcore, masked or not — so it could only ever have
# detected an unmasked /proc/kcore, which the next assertion already
# covers.  A masked directory is an empty read-only tmpfs mounted over the
# path; a masked file is a bind of /dev/null.  Both are checked here, and
# /proc/version — deliberately not in the mask list — is scanned alongside
# them as a positive control, so a scanner that reports nothing is itself
# a failure.
run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'dn=$(stat -Lc %d:%i /dev/null)
     for f in '"${MASK_LINE}"' /proc/version; do
       tag=MASKED
       [ "$f" = /proc/version ] && tag=CONTROL
       if [ ! -e "$f" ]; then echo "ABSENT $f"; continue; fi
       if [ -d "$f" ]; then
         if grep -q " $f " /proc/self/mountinfo &&
            [ -z "$(ls -A "$f" 2>/dev/null)" ]; then
           echo "${tag} $f"
         else
           echo "UN${tag} $f"
         fi
       elif [ "$(stat -Lc %d:%i "$f" 2>/dev/null)" = "$dn" ]; then
         echo "${tag} $f"
       else
         echo "UN${tag} $f"
       fi
     done; echo MASKSCAN'
expect_contains "mask scan ran" "MASKSCAN"
# Positive control: the scanner must be able to say "not masked".  Without
# this a scanner that silently produced no output would satisfy every
# negative assertion below.
expect_contains "mask scan is live (an unmasked path is reported as such)" \
    "^UNCONTROL /proc/version$"
expect_not_contains "no unmasked /proc entry" "^UNMASKED "

if [ "${MASK_COUNT}" -ge 15 ]; then
    pass "mask list has all ${MASK_COUNT} built-in entries"
else
    fail "mask list has only ${MASK_COUNT} entries (want >= 15)"
fi

# One assertion per mask, so an unmasked path names itself.
for _m in ${MASK_LIST}; do
    if printf '%s\n' "${RUN_OUT}" | grep -q "^ABSENT ${_m}$"; then
        skip "/proc mask ${_m}: not present on this kernel"
    else
        expect_contains "/proc mask ${_m}" "^MASKED ${_m}$"
    fi
done

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'wc -c < /proc/kcore'
expect_contains "/proc/kcore is empty" "^0$"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'grep " /sys " /proc/self/mountinfo || echo NOSYS'
expect_contains "/sys mounted read-only" " ro,"

# `ls DIR | wc -l` prints 0 when DIR does not exist, so an absent
# /sys/firmware was scored as a masked one. Separate the two.
run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'if [ -d /sys/firmware ]; then
       echo "FW=[$(ls -A /sys/firmware | tr "\n" " ")]"
     else echo FW=ABSENT; fi'
if printf '%s\n' "${RUN_OUT}" | grep -q '^FW=ABSENT$'; then
    skip "/sys/firmware masked (this container got the empty-tmpfs /sys fallback)"
else
    expect_contains "/sys/firmware masked (an empty directory, not a missing one)" "^FW=\[\]$"
fi

echo ""

# ── Test 5b: user-namespace credential hardening ───────────────────

echo "--- Test group: user-namespace credentials (M6b) ---"

# man/compartment-root.8: "The parent writes deny to /proc/<pid>/setgroups
# before the gid map".  Nothing under tests/ used to mention setgroups at
# all, so removing the write left every root assertion green while
# /proc/self/setgroups flipped from deny to allow inside the container.
run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'echo "setgroups=$(cat /proc/self/setgroups 2>&1)"'
expect_contains "setgroups is denied in the user namespace" "^setgroups=deny$"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'echo "uidmap=$(tr -s " \t" " " < /proc/self/uid_map)";
     echo "gidmap=$(tr -s " \t" " " < /proc/self/gid_map)"'
expect_contains "uid_map is written" "^uidmap= *0 0 65536$"
expect_contains "gid_map is written" "^gidmap= *0 0 65536$"

# PR_SET_DUMPABLE(0) (man/compartment-root.8: "prevent ptrace from
# outside").  procfs hands the files under /proc/<pid> to uid 0 of the
# task's user namespace instead of its euid when the task is not
# dumpable — but only the files, not the /proc/<pid> directory itself,
# whose ownership the kernel deliberately keeps at the euid
# (task_dump_owner()).  execve() resets dumpable, so the process that
# still carries it is the PID 1 reaper, which never execs.  The target's
# own status file is the built-in positive control: it must be owned by
# the target uid, or the assertion above it would pass on any host where
# procfs stopped reporting euid at all.
run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'echo "reaper=$(stat -c %u /proc/1/status) target=$(stat -c %u /proc/$$/status)"'
expect_contains "PR_SET_DUMPABLE(0): the reaper is not dumpable" \
    "^reaper=0 "
expect_contains "dumpable control: the exec'd target is owned by its own uid" \
    " target=60000$"

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
# `ls | tr "\n" " "` collapses the listing to a single line, so the old
# `grep -q "^9$"` could not match whether the fd leaked or not. Emit a
# bracketed, space-delimited list and match " 9 " inside it.
run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'echo "FDS=[ $(ls /proc/self/fd | tr "\n" " ")]"' 9< /
expect_contains "fd listing captured (probe liveness)" "^FDS=\[ "
expect_not_contains "pre-opened host directory fd is closed" "FDS=\[.* 9 "

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'ls /host | wc -l'
expect_contains "container root really is the jail" "^0$"

# `expect_not_contains "Groups:\t0"` only fired when gid 0 happened to be
# the *first* supplementary group; a container that inherited
# `Groups: 1000 4 24` passed it.  Assert the list is empty instead.
run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'echo "groups=[$(grep ^Groups /proc/self/status | cut -f2- | tr -d " \t")]"'
expect_contains "supplementary groups cleared" "^groups=\[\]$"

# A fresh pid namespace: only the reaper, the shell and its own children.
run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'n=$(ls /proc | grep -c "^[0-9][0-9]*$"); echo "pids=$n"; [ "$n" -lt 10 ] && echo PIDNS_OK'
expect_contains "host processes not visible in the pid namespace" "PIDNS_OK"

echo ""

# ── Test 7: init, signals and fd hygiene ───────────────────────────

echo "--- Test group: container init (L4, L5) ---"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'echo pid=$$'
expect_contains "target runs under a PID 1 reaper" "pid=2"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'echo "FDS=[ $(ls /proc/self/fd | tr "\n" " ")]"' 8< /etc/hostname
expect_contains "fd listing captured (probe liveness)" "^FDS=\[ "
expect_not_contains "inherited fd 8 closed before exec" "FDS=\[.* 8 "

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

# `expect_not_contains "eth0"` passed on any host whose NIC is named
# enp0s3 — i.e. every modern one — so dropping CLONE_NEWNET was invisible.
# Assert the list is exactly "lo", with the host's own interface count as
# the control that makes the assertion attributable.
run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'echo "NETIF=[$(ls /sys/class/net | sort | tr "\n" " ")]"'
expect_contains "fresh netns has only loopback" "^NETIF=\[lo \]$"
HOST_IFCOUNT="$(ls /sys/class/net | wc -l)"
if [ "${HOST_IFCOUNT}" -gt 1 ]; then
    pass "control: the host has ${HOST_IFCOUNT} interfaces, so an empty netns is attributable"
else
    skip "control: the host itself has only one interface"
fi

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

# The suite declares its own assertion count. A block that stops
# running — a `skip` standing in for twenty assertions, a group
# guarded by a tool that is not installed — changes the total, and a
# changed total is a failure rather than a smaller number nobody
# compares against anything.
harness_expect_total "${SUITE_TOTAL}"

echo "=== Results ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  SKIP: ${SKIP}"
echo ""
# The runner sums these lines; one per suite (tests/scripts/root.d/README.md).
echo "SUMMARY compartment-root: pass=${PASS} fail=${FAIL} skip=${SKIP}"

if [ "${FAIL}" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
