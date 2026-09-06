#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# compartment-root-landlock.sh — Landlock, mount hardening and the netns
# join inside a real container
#
# Covers, root only:
#   A  `landlock on` and the per-binary exec allow-list
#   B  shared libraries need READ_FILE, the ELF interpreter needs EXECUTE
#   C  mount-ro / mount-noexec / mount-nosuid
#   D  rootdir-flags
#   E  rootdir ownership refusals
#   F  --netns joins an existing namespace
#   G  devpts, /dev/ptmx and /dev/shm
#   H  net-bind / net-connect inside the container
#   I  examples/container.conf's network block loads
#
# Everything it creates lives under one mktemp -d and one network namespace,
# both removed on exit including on failure.  Standalone by design: it builds
# its own busybox rootdir.
#
# Usage: sudo ./tests/scripts/root.d/compartment-root-landlock.sh [--verbose]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CR="${REPO_DIR}/compartment-root"
CU="${REPO_DIR}/compartment-user"
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

echo "=== compartment-root Landlock / mount hardening suite ==="
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: this suite must run as root (it creates real containers)."
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
if [ -z "${BUSYBOX}" ]; then
    echo "ERROR: busybox not available (apt-get install busybox-static)."
    exit 1
fi
if ldd "${BUSYBOX}" >/dev/null 2>&1; then
    echo "ERROR: ${BUSYBOX} is dynamically linked; the rootdir must stand alone."
    exit 1
fi

ABI="$("${CU}" --verify 2>/dev/null | sed -n 's/^Landlock: OK (ABI v\([0-9]*\)).*/\1/p')"
[ -n "${ABI}" ] || ABI=0

echo "  compartment-root: ${CR}"
echo "  busybox:          ${BUSYBOX}"
echo "  kernel:           $(uname -r)"
echo "  Landlock ABI:     ${ABI}"
echo ""

# ── Fixtures ───────────────────────────────────────────────────────

WORK="$(mktemp -d /tmp/compartment-root-ll.XXXXXX)"
JAIL="${WORK}/jail"
NETNS="cpll$$"

cleanup() {
    local rc=$?
    pkill -9 -f "compartment-root .*${WORK}" 2>/dev/null || true
    sleep 0.2
    local mp
    while read -r mp; do
        [ -n "${mp}" ] && umount -l "${mp}" 2>/dev/null || true
    done < <(awk -v p="${WORK}" '$5 ~ "^"p {print $5}' /proc/self/mountinfo | sort -r)
    ip netns del "${NETNS}" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        rm -rf "${WORK}" 2>/dev/null && break
        sleep 0.4
    done
    [ -e "${WORK}" ] && rm -rf "${WORK}" 2>/dev/null
    exit "${rc}"
}
trap cleanup EXIT INT TERM

mkdir -p "${JAIL}"/{bin,dev,proc,sys,tmp,etc,srv,lib,lib64}
cp "${BUSYBOX}" "${JAIL}/bin/busybox"
for applet in sh ls cat echo grep head id env printf sleep true cp chmod \
              mount stat dd nc timeout; do
    ln -sf /bin/busybox "${JAIL}/bin/${applet}"
done
# Two distinct static binaries for the exec allow-list.  They cannot be
# busybox copies: an allow-list keys on the inode, so busybox applet symlinks
# are indistinguishable, and a *copy* of busybox refuses to do anything under
# an unknown argv[0].  This is itself a limitation worth having in a test.
HAVE_TOOLS=0
if command -v cc >/dev/null 2>&1; then
    cat > "${WORK}/marker.c" <<'EOF'
#include <stdio.h>
int main(void) { printf("%s\n", MARKER); return 0; }
EOF
    if cc -static -O2 -DMARKER='"ALLOWED_TOOL_RAN"' \
          -o "${JAIL}/bin/allowed-tool" "${WORK}/marker.c" 2>/dev/null &&
       cc -static -O2 -DMARKER='"DENIED_TOOL_RAN"' \
          -o "${JAIL}/bin/denied-tool" "${WORK}/marker.c" 2>/dev/null; then
        HAVE_TOOLS=1
    fi
fi
printf 'root:x:0:0::/:/bin/sh\nctsvc:x:60000:60000::/:/bin/sh\n' > "${JAIL}/etc/passwd"
printf 'root:x:0:\nctsvc:x:60000:\n' > "${JAIL}/etc/group"
chmod 755 "${JAIL}" "${WORK}"
chmod 1777 "${JAIL}/tmp"
chown 0:0 "${JAIL}" "${WORK}"

CRUSER=(-U ctsvc -u 60000 -g 60000)

RUN_OUT=""
RUN_RC=0
run_cr() {
    RUN_OUT=""
    RUN_RC=0
    [ -n "${VERBOSE}" ] && echo "    CMD: ${CR} $*"
    RUN_OUT="$("${CR}" "$@" 2>&1)" || RUN_RC=$?
    [ -n "${VERBOSE}" ] && { echo "    OUT: ${RUN_OUT}"; echo "    RC:  ${RUN_RC}"; }
    return 0
}

want_out() {
    if printf '%s\n' "${RUN_OUT}" | grep -qF -- "$2"; then
        pass "$1"
    else
        fail "$1 (expected '$2'; got: $(printf '%s' "${RUN_OUT}" | tr '\n' '|' | cut -c1-200))"
    fi
}
want_no_out() {
    if [ "${RUN_RC}" -ne 0 ]; then
        fail "$1 (container did not run: rc=${RUN_RC}: $(printf '%s' "${RUN_OUT}" | tr '\n' '|' | cut -c1-160))"
    elif printf '%s\n' "${RUN_OUT}" | grep -qF -- "$2"; then
        fail "$1 (unexpected '$2')"
    else
        pass "$1"
    fi
}
want_rc() {
    if [ "${RUN_RC}" -eq "$2" ]; then
        pass "$1"
    else
        fail "$1 (expected rc=$2, got rc=${RUN_RC}: $(printf '%s' "${RUN_OUT}" | tr '\n' '|' | cut -c1-200))"
    fi
}
want_rc_nonzero() {
    if [ "${RUN_RC}" -ne 0 ]; then
        pass "$1"
    else
        fail "$1 (expected a non-zero exit)"
    fi
}

# Write a root-owned profile, the only kind compartment-root will load.
mkprofile() {
    local name="$1"
    shift
    printf '%s\n' "$@" > "${WORK}/${name}.conf"
    chown 0:0 "${WORK}/${name}.conf"
    chmod 644 "${WORK}/${name}.conf"
    printf '%s\n' "${WORK}/${name}.conf"
}

# ── A. Landlock inside the container ───────────────────────────────

echo "--- Test group: Landlock exec allow-list (P1-b/d) ---"

if [ "${ABI}" -lt 1 ]; then
    skip "Landlock not available on this kernel"
else
    # Rules but no `landlock on`: the tool must say the rules are inert
    # rather than pretend they are policy.
    P="$(mkprofile inert "rootdir ${JAIL}" "username ctsvc" "uid 60000" \
         "gid 60000" "ro /etc")"
    run_cr --profile "${P}" --dry-run -- /bin/sh
    want_out "path rules without 'landlock on' warn" "Landlock is off"

    # `landlock on` with no rules would deny everything: refuse instead.
    P="$(mkprofile empty "rootdir ${JAIL}" "username ctsvc" "uid 60000" \
         "gid 60000" "landlock on")"
    run_cr --profile "${P}" --dry-run -- /bin/sh
    want_rc_nonzero "'landlock on' with no rules is refused"
    want_out "the refusal explains why" "deny all filesystem access"

    # The allow-list: /bin/busybox (the shell) and /bin/allowed-tool run,
    # /bin/denied-tool does not, and no directory carries execute.
    if [ "${HAVE_TOOLS}" -eq 1 ]; then
        run_cr --landlock --exec /bin/busybox --exec /bin/allowed-tool \
            --ro /etc --ro /proc --rw /dev/null --rw /tmp \
            -c "${JAIL}" "${CRUSER[@]}" -- \
            /bin/sh -c '/bin/allowed-tool; /bin/denied-tool 2>&1 | head -1'
        want_out "exec allow-list: the listed binary runs"   "ALLOWED_TOOL_RAN"
        want_no_out "exec allow-list: the unlisted binary does not run" \
                    "DENIED_TOOL_RAN"
        run_cr --landlock --exec /bin/busybox --exec /bin/allowed-tool \
            --ro /etc --ro /proc --rw /dev/null --rw /tmp \
            -c "${JAIL}" "${CRUSER[@]}" -- \
            /bin/sh -c '/bin/denied-tool 2>&1 | head -1'
        want_out "exec allow-list: the refusal is EACCES"   "Permission denied"
    else
        skip "no C compiler: exec allow-list positive case"
        skip "no C compiler: exec allow-list negative case"
        skip "no C compiler: exec allow-list errno"
    fi

    # `/bin/sh -c ls` works when /bin/sh is listed — the case from the brief.
    run_cr --landlock --exec /bin/busybox --ro /etc --ro /proc \
        --rw /dev/null -c "${JAIL}" "${CRUSER[@]}" -- \
        /bin/sh -c 'ls /etc >/dev/null && echo SH_C_LS_OK'
    want_out "'/bin/sh -c ls' works when the shell is listed" "SH_C_LS_OK"

    # Landlock survives the privilege drop and is visible to the target.
    run_cr --landlock --exec /bin/busybox --ro /etc --ro /proc \
        --rw /dev/null -c "${JAIL}" "${CRUSER[@]}" -- \
        /bin/sh -c 'cat /proc/self/status | grep -i "^Seccomp\|^NoNewPrivs"'
    want_out "the container still gets no_new_privs" "NoNewPrivs:	1"

    # rw is W^X inside the container too.
    run_cr --landlock --exec /bin/busybox --ro /etc --ro /proc \
        --rw /dev/null --rw /tmp -c "${JAIL}" "${CRUSER[@]}" -- \
        /bin/sh -c 'cp /bin/busybox /tmp/bb && /tmp/bb true 2>&1 | head -1'
    want_out "W^X: a binary copied into a rw path cannot be executed" \
             "Permission denied"
fi

echo ""

# ── B. Shared libraries vs the ELF interpreter ─────────────────────

echo "--- Test group: what a dynamically linked binary needs ---"

DYNBIN=""
if command -v cc >/dev/null 2>&1; then
    cat > "${WORK}/dyn.c" <<'EOF'
#include <stdio.h>
int main(void) { printf("DYN_RAN\n"); return 0; }
EOF
    if cc -O2 -o "${JAIL}/bin/dyntest" "${WORK}/dyn.c" 2>/dev/null; then
        DYNBIN="/bin/dyntest"
    fi
fi

if [ -z "${DYNBIN}" ] || [ "${ABI}" -lt 1 ]; then
    skip "no C compiler or no Landlock: shared-library rights inside a container"
    skip "no C compiler or no Landlock: ELF interpreter execute grant"
else
    # Copy the loader and the libraries the binary needs into the jail.
    mkdir -p "${JAIL}/lib" "${JAIL}/lib64"
    LOADER_HOST="$(ldd "${JAIL}/bin/dyntest" | sed -n 's#.*\(/lib[^ ]*ld-linux[^ ]*\).*#\1#p' | head -1)"
    for lib in $(ldd "${JAIL}/bin/dyntest" | sed -n 's#.*=> \(/[^ ]*\) (.*#\1#p'); do
        install -D -m 755 "${lib}" "${JAIL}/lib/$(basename "${lib}")"
    done
    if [ -n "${LOADER_HOST}" ]; then
        install -D -m 755 "${LOADER_HOST}" "${JAIL}${LOADER_HOST}"
        # Some toolchains look for the loader under /lib64 and some /lib.
        LOADER_IN="${LOADER_HOST}"
    else
        LOADER_IN=""
    fi

    if [ -z "${LOADER_IN}" ]; then
        skip "could not resolve the ELF interpreter"
        skip "could not resolve the ELF interpreter (negative case)"
    else
        # `rw` on the library directory: read, no execute.  That is the whole
        # question — ld.so opens a .so read-only and Landlock has no mmap
        # hook, so READ_FILE is all a shared library needs.
        run_cr --landlock --exec "${DYNBIN}" --exec "${LOADER_IN}" \
            --rw /lib --rw /lib64 --ro /etc --ro /proc --rw /dev/null \
            -c "${JAIL}" "${CRUSER[@]}" -- "${DYNBIN}"
        want_out "shared libraries load with read-but-not-execute on /lib" "DYN_RAN"

        # Drop only the interpreter's execute grant: execve() opens it with
        # FMODE_EXEC, so the whole exec is refused.
        run_cr --landlock --exec "${DYNBIN}" \
            --rw /lib --rw /lib64 --ro /etc --ro /proc --rw /dev/null \
            -c "${JAIL}" "${CRUSER[@]}" -- "${DYNBIN}"
        if [ "${RUN_RC}" -ne 0 ] && ! printf '%s' "${RUN_OUT}" | grep -q DYN_RAN; then
            pass "the ELF interpreter needs its own execute grant"
        else
            fail "exec succeeded without an execute grant on the interpreter"
        fi
    fi
fi

echo ""

# ── C. mount-ro / mount-noexec / mount-nosuid ──────────────────────

echo "--- Test group: mount-* flags (P1-c) ---"

P="$(mkprofile mro "rootdir ${JAIL}" "username ctsvc" "uid 60000" "gid 60000" \
     "mount-ro /etc")"
run_cr --profile "${P}" -- /bin/sh -c 'echo x > /etc/probe 2>&1 | head -1; cat /etc/passwd >/dev/null && echo READ_STILL_OK'
want_out "mount-ro: a write fails EROFS"      "Read-only file system"
want_out "mount-ro: reads still work"         "READ_STILL_OK"

P="$(mkprofile mnoexec "rootdir ${JAIL}" "username ctsvc" "uid 60000" \
     "gid 60000" "mount-noexec /tmp")"
run_cr --profile "${P}" -- /bin/sh -c 'cp /bin/busybox /tmp/bb && echo COPIED; chmod 755 /tmp/bb; /tmp/bb true 2>&1 | head -1'
want_out "mount-noexec: the copy still works"    "COPIED"
want_out "mount-noexec: exec fails EACCES"       "Permission denied"

# nosuid: a setuid-root binary inside the mount must not elevate.
HAVE_SUID=0
if command -v cc >/dev/null 2>&1; then
    cat > "${WORK}/suid.c" <<'EOF'
#include <stdio.h>
#include <unistd.h>
int main(void) { printf("uid=%u euid=%u\n", getuid(), geteuid()); return 0; }
EOF
    mkdir -p "${JAIL}/srv/suid"
    if cc -static -O2 -o "${JAIL}/srv/suid/probe" "${WORK}/suid.c" 2>/dev/null; then
        chown 0:0 "${JAIL}/srv/suid/probe"
        chmod 4755 "${JAIL}/srv/suid/probe"
        HAVE_SUID=1
    fi
fi
if [ "${HAVE_SUID}" -eq 1 ]; then
    # The rootdir is nosuid unconditionally, so this proves the directive is
    # accepted and the binary still runs without elevating.
    P="$(mkprofile mnosuid "rootdir ${JAIL}" "username ctsvc" "uid 60000" \
         "gid 60000" "mount-nosuid /srv" "mount-nodev /srv")"
    run_cr --profile "${P}" -- /srv/suid/probe
    want_out "mount-nosuid: setuid-root does not elevate" "euid=60000"
else
    skip "no C compiler: mount-nosuid setuid check"
fi

P="$(mkprofile mbad "rootdir ${JAIL}" "username ctsvc" "uid 60000" \
     "gid 60000" "mount-ro relative/path")"
run_cr --profile "${P}" -- /bin/true
want_rc_nonzero "a relative mount-ro path is refused"

P="$(mkprofile mmissing "rootdir ${JAIL}" "username ctsvc" "uid 60000" \
     "gid 60000" "mount-ro /no/such/place")"
run_cr --profile "${P}" -- /bin/true
want_rc_nonzero "a mount-ro path that does not exist is refused"

echo ""

# ── D. rootdir-flags ───────────────────────────────────────────────

echo "--- Test group: rootdir-flags (P1-c) ---"

P="$(mkprofile rdro "rootdir ${JAIL}" "username ctsvc" "uid 60000" "gid 60000" \
     "rootdir-flags ro")"
run_cr --profile "${P}" -- /bin/sh -c 'echo x > /srv/probe 2>&1 | head -1; echo y > /dev/null && echo DEV_STILL_WRITABLE'
want_out "rootdir-flags ro: the container root is read-only" "Read-only file system"
want_out "rootdir-flags ro: /dev is not swept in"            "DEV_STILL_WRITABLE"

run_cr --profile "${P}" -- /bin/sh -c 'head -1 /proc/self/mountinfo'
want_out "rootdir-flags ro: the mount really carries ro" "ro,"

P="$(mkprofile rdbad "rootdir ${JAIL}" "username ctsvc" "uid 60000" \
     "gid 60000" "rootdir-flags nosuid,bogus")"
run_cr --profile "${P}" --dry-run -- /bin/true
want_rc_nonzero "an unknown rootdir-flag is refused"
want_out "the refusal lists the valid flags" "ro, nosuid, nodev, noexec"

run_cr -c "${JAIL}" "${CRUSER[@]}" --dry-run -- /bin/sh
want_out "nosuid,nodev are reported as unconditional" "rootdir-flags: nosuid,nodev"

echo ""

# ── E. rootdir ownership ───────────────────────────────────────────

echo "--- Test group: rootdir ownership (item 5) ---"

OWNJAIL="${WORK}/ownjail"
cp -a "${JAIL}" "${OWNJAIL}"

chown 60000:60000 "${OWNJAIL}"
run_cr -c "${OWNJAIL}" "${CRUSER[@]}" -- /bin/true
want_rc_nonzero "identity map: a non-root-owned rootdir is refused"
want_out "the refusal names the owner" "is owned by uid 60000"

chown 0:0 "${OWNJAIL}"
chmod 777 "${OWNJAIL}"
run_cr -c "${OWNJAIL}" "${CRUSER[@]}" -- /bin/true
want_rc_nonzero "a world-writable rootdir is refused"
want_out "the refusal names the mode" "group- or world-writable"

chmod 775 "${OWNJAIL}"
run_cr -c "${OWNJAIL}" "${CRUSER[@]}" -- /bin/true
want_rc_nonzero "a group-writable rootdir is refused"

chmod 755 "${OWNJAIL}"
run_cr -c "${OWNJAIL}" "${CRUSER[@]}" -- /bin/sh -c 'echo OWNER_OK'
want_out "a root-owned 0755 rootdir is accepted" "OWNER_OK"

# Shifted map: the rootdir may be owned by the mapped host uid instead.
chown 100000:100000 "${OWNJAIL}"
P="$(mkprofile shifted "rootdir ${OWNJAIL}" "username ctsvc" "uid 60000" \
     "gid 60000" "uid-map 0 100000 65536" "gid-map 0 100000 65536")"
run_cr --profile "${P}" -- /bin/sh -c 'echo SHIFTED_OK'
want_out "shifted map: the mapped host uid may own the rootdir" "SHIFTED_OK"

# A root-owned rootdir also passes the ownership check under a shifted map,
# but the container's root is then an unprivileged host uid that cannot write
# into it, so the run itself fails at the pivot point.  The check is what is
# under test here.
chown 0:0 "${OWNJAIL}"
run_cr --profile "${P}" --dry-run -- /bin/true
want_rc "shifted map: a root-owned rootdir passes the ownership check" 0
want_no_out "and produces no ownership complaint" "is owned by uid"

chown 12345:12345 "${OWNJAIL}"
run_cr --profile "${P}" -- /bin/true
want_rc_nonzero "shifted map: a third uid is still refused"
want_out "the refusal names the mapped uid" "uid 100000"
chown 0:0 "${OWNJAIL}"

echo ""

# ── F. --netns ─────────────────────────────────────────────────────

echo "--- Test group: --netns joins an existing namespace (item 6) ---"

if ! command -v ip >/dev/null 2>&1; then
    skip "iproute2 not installed: --netns join"
    skip "iproute2 not installed: --netns interface visible"
    skip "iproute2 not installed: fresh netns does not see it"
else
    ip netns del "${NETNS}" 2>/dev/null || true
    if ip netns add "${NETNS}" 2>/dev/null &&
       ip netns exec "${NETNS}" ip link add cpdummy0 type dummy 2>/dev/null; then
        ip netns exec "${NETNS}" ip link set cpdummy0 up

        run_cr -c "${JAIL}" "${CRUSER[@]}" -n "${NETNS}" -- \
            /bin/sh -c 'cat /proc/net/dev'
        want_rc "--netns: the container starts" 0
        want_out "--netns: the joined namespace's interface is visible" "cpdummy0"

        run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c 'cat /proc/net/dev'
        want_no_out "without --netns the container gets a fresh namespace" "cpdummy0"
    else
        skip "cannot create a test netns or dummy interface: --netns join"
        skip "cannot create a test netns: interface visible"
        skip "cannot create a test netns: fresh netns comparison"
    fi
fi

echo ""

# ── G. devpts, /dev/ptmx, /dev/shm ─────────────────────────────────

echo "--- Test group: devpts and /dev/shm (item 11) ---"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    '[ -c /dev/ptmx ] && echo PTMX_IS_CHARDEV; [ -d /dev/pts ] && echo PTS_DIR; [ -d /dev/shm ] && echo SHM_DIR'
want_out "/dev/ptmx is a character device" "PTMX_IS_CHARDEV"
want_out "/dev/pts exists"                 "PTS_DIR"
want_out "/dev/shm exists"                 "SHM_DIR"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'grep " /dev/pts " /proc/self/mountinfo | head -1'
want_out "/dev/pts is a devpts mount" "devpts"

run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh -c \
    'echo shmtest > /dev/shm/probe && cat /dev/shm/probe'
want_out "/dev/shm is writable" "shmtest"

# A real pty allocation, with a tiny C helper so nothing has to be installed
# inside the jail.
if command -v cc >/dev/null 2>&1; then
    cat > "${WORK}/pty.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
int main(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0) { printf("PTY_FAIL openpt %s\n", strerror(errno)); return 1; }
    if (grantpt(m) != 0) { printf("PTY_FAIL grantpt %s\n", strerror(errno)); return 1; }
    if (unlockpt(m) != 0) { printf("PTY_FAIL unlockpt %s\n", strerror(errno)); return 1; }
    char *s = ptsname(m);
    if (!s) { printf("PTY_FAIL ptsname %s\n", strerror(errno)); return 1; }
    int sfd = open(s, O_RDWR | O_NOCTTY);
    if (sfd < 0) { printf("PTY_FAIL open %s: %s\n", s, strerror(errno)); return 1; }
    printf("PTY_OK %s\n", s);
    return 0;
}
EOF
    if cc -static -O2 -o "${JAIL}/bin/ptytest" "${WORK}/pty.c" 2>/dev/null; then
        run_cr -c "${JAIL}" "${CRUSER[@]}" -- /bin/ptytest
        want_out "posix_openpt + grantpt + unlockpt + open works inside" "PTY_OK"
    else
        skip "could not build the pty helper"
    fi
else
    skip "no C compiler: pty allocation check"
fi

echo ""

# ── H. Landlock net rules inside the container ─────────────────────

echo "--- Test group: net-bind / net-connect inside the container (P1-b) ---"

if [ "${ABI}" -lt 4 ]; then
    skip "Landlock ABI v${ABI} < 4: no network rules before Linux 6.7 (bind)"
    skip "Landlock ABI v${ABI} < 4: no network rules before Linux 6.7 (connect)"
    skip "Landlock ABI v${ABI} < 4: no network rules before Linux 6.7 (listener)"
else
    # The container has its own loopback-only network namespace, so a
    # listener started inside it is the only thing reachable.  busybox nc
    # provides both halves.
    P="$(mkprofile netok "rootdir ${JAIL}" "username ctsvc" "uid 60000" \
         "gid 60000" "loopback on" "landlock on" "ro /" "rw /dev/null" \
         "rw /tmp" "net-bind 34811" "net-connect 34811" "net-default deny")"
    # Every listener is wrapped in `timeout`.  A build that does not deny the
    # bind leaves nc listening for ever, the container's PID 1 waits for it,
    # and the suite hangs instead of failing — which is exactly what happened
    # when these cases were first run against a pre-Landlock binary.
    run_cr --profile "${P}" -- /bin/sh -c \
        'timeout 8 nc -l -p 34811 >/dev/null 2>&1 & sleep 1; echo hi | nc -w 2 127.0.0.1 34811 && echo NET_ALLOWED_OK; wait'
    want_out "the allowed port can be bound and connected to" "NET_ALLOWED_OK"

    P="$(mkprofile netdeny "rootdir ${JAIL}" "username ctsvc" "uid 60000" \
         "gid 60000" "loopback on" "landlock on" "ro /" "rw /dev/null" \
         "rw /tmp" "net-connect 34811" "net-default deny")"
    run_cr --profile "${P}" -- /bin/sh -c \
        'timeout 8 nc -l -p 34811 2>&1 | head -1'
    want_out "a port with no net-bind rule cannot be bound" "Permission denied"

    run_cr --profile "${P}" -- /bin/sh -c \
        'nc -w 2 127.0.0.1 34812 </dev/null 2>&1 | head -1'
    want_out "a port with no net-connect rule cannot be connected to" \
             "Permission denied"
fi

echo ""

# ── I. container.conf ──────────────────────────────────────────────

echo "--- Test group: examples/container.conf network block (item 2) ---"

CCONF="${WORK}/container.conf"
install -o root -g root -m 0644 "${REPO_DIR}/examples/container.conf" "${CCONF}"
run_cr --profile "${CCONF}" --dry-run -c "${JAIL}" "${CRUSER[@]}" -- /bin/sh
want_rc "container.conf loads" 0
want_out "container.conf is an allow-list" "ALLOW-LIST"
want_out "container.conf allows 133 syscalls" "133 allowed"
want_no_out "container.conf names no unknown syscall" "unknown syscall"

# The reaper is inside the filter now, because container.conf lists what it
# needs.  Two "seccomp ... enforced" lines under --verbose is the witness.
run_cr --profile "${CCONF}" -c "${JAIL}" "${CRUSER[@]}" --verbose -- \
    /bin/sh -c 'grep ^Seccomp: /proc/self/status'
want_out "container.conf: the target is filtered" "Seccomp:	2"
FILTERS="$(printf '%s\n' "${RUN_OUT}" | grep -c 'seccomp ALLOW-LIST enforced')"
if [ "${FILTERS}" -eq 2 ]; then
    pass "container.conf: PID 1 installs the filter too (${FILTERS} filters)"
else
    fail "container.conf: expected 2 seccomp installs, saw ${FILTERS}"
fi

# A policy that does not cover the reaper leaves PID 1 unfiltered and says so.
P="$(mkprofile noreaper "rootdir ${JAIL}" "username ctsvc" "uid 60000" \
     "gid 60000" "block wait4")"
run_cr --profile "${P}" --verbose -- /bin/sh -c 'echo REAPER_SKIP_OK'
want_out "a policy without wait4 leaves PID 1 unfiltered" \
         "container init left outside the seccomp filter"
want_out "and the container still runs" "REAPER_SKIP_OK"

echo ""

# ── Summary ────────────────────────────────────────────────────────

# The suite declares its own assertion count. A block that stops
# running — a `skip` standing in for twenty assertions, a group
# guarded by a tool that is not installed — changes the total, and a
# changed total is a failure rather than a smaller number nobody
# compares against anything.
harness_expect_total 56

echo "=== Results ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  SKIP: ${SKIP}"
echo ""
echo "SUMMARY compartment-root-landlock: pass=${PASS} fail=${FAIL} skip=${SKIP}"
if [ "${FAIL}" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
fi
echo "ALL TESTS PASSED"
exit 0
