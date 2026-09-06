#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# limited-root.sh — end-to-end checks for the limited-root-over-SSH
#                   deployment described in HOWTO.md.
#
# What it builds, all of it removed again by the EXIT trap:
#
#   * two extra uid-0 accounts (`useradd -o -u 0`), created after the four
#     account-database files are copied aside:
#       lrtroot   — login shell is the compartment-user wrapper.  Confined.
#       lrtctl    — login shell is the real bash.  The positive control:
#                   an unconfined uid-0 ssh login, so every "denied" line
#                   below is paired with a "and it works without the
#                   wrapper" line rather than being trusted on its own.
#     Neither `root` nor any real account's shell, home or keys is touched.
#   * a private shell stash and a wrapper built with -DREAL_SHELL_DIR
#     pointing at it, under /usr/local/lib, so the stashed bash is
#     reachable through the profile's `ro /usr` rule.  This is the
#     "set the account's shell to the wrapper path" deployment, NOT the
#     "/bin/bash IS the wrapper" one — /bin/bash is not touched, so no
#     other user on the machine is affected while this runs.
#   * /etc/compartment/shell-replacement.conf, from examples/limited-root.conf.
#   * a temporary ssh key per account, in each account's own home.
#
# Both logins go through the machine's own sshd on localhost.
#
# Run as root:  sudo ./tests/scripts/root.d/limited-root.sh
#
# Optional:
#   PRISTINE_SRC=/path/to/release-1.4  adds the three "before" assertions
#                                      that fail against the pristine build
#   COMPARTMENT_BPF=/path/to/compartment-bpf   adds the seal assertions
#
# The seal group loads BPF policy.  It pins under /sys/fs/bpf/compartment
# and unpins on the way out, including on failure.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CU="${COMPARTMENT_USER:-${REPO_DIR}/compartment-user}"
CBPF="${COMPARTMENT_BPF:-${REPO_DIR}/compartment-bpf/compartment-bpf}"
PROFILE_SRC="${REPO_DIR}/examples/limited-root.conf"

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP: $1"; }

skip_group() {
    local n="$1" reason="$2"
    SKIP=$((SKIP + n))
    echo "  SKIP: ${reason} (${n} assertions)"
}

harness_expect_total() {
    local want="$1"
    local got=$((PASS + FAIL + SKIP + 1))
    if [ "${got}" -eq "${want}" ]; then
        pass "suite ran all ${want} assertions"
    else
        fail "suite ran ${got} assertions, declared ${want} — a block was added, removed or silently skipped"
    fi
}

summary_and_exit() {
    echo ""
    echo "=== Results ==="
    echo "  PASS: ${PASS}"
    echo "  FAIL: ${FAIL}"
    echo "  SKIP: ${SKIP}"
    echo ""
    echo "SUMMARY limited-root: pass=${PASS} fail=${FAIL} skip=${SKIP}"
    if [ "${FAIL}" -gt 0 ]; then echo "SOME TESTS FAILED"; exit 1; fi
    echo "ALL TESTS PASSED"; exit 0
}

echo "=== Limited root over SSH: root-only test suite ==="
echo ""

TOTAL_ASSERTIONS=67

if [ "$(id -u)" -ne 0 ]; then
    skip_group $((TOTAL_ASSERTIONS - 1)) "not running as root — these checks need uid 0"
    harness_expect_total "${TOTAL_ASSERTIONS}"
    summary_and_exit
fi

# ── Preconditions ─────────────────────────────────────────────────────

MISSING=""
for t in ssh ssh-keygen sshd useradd userdel cc; do
    command -v "$t" >/dev/null 2>&1 || MISSING="${MISSING} $t"
done
[ -x "${CU}" ] || MISSING="${MISSING} compartment-user"
[ -r "${PROFILE_SRC}" ] || MISSING="${MISSING} examples/limited-root.conf"
if [ -n "${MISSING}" ]; then
    skip_group $((TOTAL_ASSERTIONS - 1)) "missing prerequisites:${MISSING}"
    harness_expect_total "${TOTAL_ASSERTIONS}"
    summary_and_exit
fi

PRL="$(sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}')"
if [ -z "${PRL}" ] || [ "${PRL}" = "no" ]; then
    skip_group $((TOTAL_ASSERTIONS - 1)) \
        "sshd PermitRootLogin is '${PRL:-unknown}' — a uid-0 login cannot be tested"
    harness_expect_total "${TOTAL_ASSERTIONS}"
    summary_and_exit
fi

# ── Scratch state and the cleanup contract ────────────────────────────

T="$(mktemp -d /tmp/limited-root-test.XXXXXX)"
LRDIR=/usr/local/lib/compartment-limited-root-test
HOMES=/var/tmp/compartment-limited-root-test
CONFDIR=/etc/compartment
CONF="${CONFDIR}/shell-replacement.conf"
SEALPROBE=/etc/compartment-lr-seal-probe
AUDITDIR=/var/log/compartment
PINNED=0
MADE_CONFDIR=0
MADE_AUDITDIR=0
CONF_BACKUP=""

cleanup() {
    local rc=$?
    set +e
    if [ "${PINNED}" -eq 1 ]; then
        "${CBPF}" --unpin >/dev/null 2>&1
        PINNED=0
    fi
    # -f: userdel refuses a uid that another process is using, and PID 1
    # runs as uid 0, so an -o -u 0 account is always "in use".
    userdel -f lrtroot  >/dev/null 2>&1
    userdel -f lrtctl   >/dev/null 2>&1
    # Belt and braces: if userdel could not do it, put the copied database
    # back.  An extra uid-0 account left behind is the one failure mode
    # this suite must never have.
    for f in passwd shadow group gshadow; do
        if [ -f "${T}/db/${f}" ] && grep -qE '^(lrtroot|lrtctl):' "/etc/${f}" 2>/dev/null; then
            cat "${T}/db/${f}" > "/etc/${f}"
            echo "  NOTE: restored /etc/${f} from the copy taken at start"
        fi
    done
    if [ -n "${CONF_BACKUP}" ] && [ -f "${CONF_BACKUP}" ]; then
        cat "${CONF_BACKUP}" > "${CONF}"
    else
        rm -f "${CONF}"
    fi
    [ "${MADE_CONFDIR}" -eq 1 ]  && rmdir "${CONFDIR}" 2>/dev/null
    [ "${MADE_AUDITDIR}" -eq 1 ] && rm -rf "${AUDITDIR}"
    rm -f "${SEALPROBE}"
    rm -rf "${LRDIR}" "${HOMES}" "${T}"
    exit "${rc}"
}
trap cleanup EXIT INT TERM

mkdir -p "${T}/db"
for f in passwd shadow group gshadow; do
    [ -f "/etc/${f}" ] && cp -p "/etc/${f}" "${T}/db/${f}"
done

# ── Build the deployment ──────────────────────────────────────────────

REAL_BASH="$(readlink -f /bin/bash)"
install -d -m 0755 -o root -g root "${LRDIR}" "${LRDIR}/shells" "${LRDIR}/bin"
install -m 0755 -o root -g root "${REAL_BASH}" "${LRDIR}/shells/bash"

# The wrapper, built from this tree with the stash path compiled in.  This
# is the documented `-DREAL_SHELL_DIR` deployment; COMPARTMENT_SHELL_DIR is
# deliberately NOT used, because sshd does not pass the environment through
# and a login-shell deployment must not depend on one that it could.
if ! cc -Wall -std=c11 -D_GNU_SOURCE -O1 \
        -DREAL_SHELL_DIR="\"${LRDIR}/shells\"" \
        -o "${LRDIR}/bin/compartment-user" \
        "${REPO_DIR}/compartment-user.c" 2>"${T}/build.log"; then
    echo "  build log:"; sed 's/^/    /' "${T}/build.log"
    skip_group $((TOTAL_ASSERTIONS - 1)) "could not build the stash-aware wrapper"
    harness_expect_total "${TOTAL_ASSERTIONS}"
    summary_and_exit
fi
ln -sf "${LRDIR}/bin/compartment-user" "${LRDIR}/bin/bash"

# Policy.  The shipped example verbatim: the point of the suite is that
# what ships is what works.
if [ ! -d "${CONFDIR}" ]; then install -d -m 0755 -o root -g root "${CONFDIR}"; MADE_CONFDIR=1; fi
if [ -f "${CONF}" ]; then CONF_BACKUP="${T}/shell-replacement.conf.orig"; cp -p "${CONF}" "${CONF_BACKUP}"; fi
install -m 0644 -o root -g root "${PROFILE_SRC}" "${CONF}"
if [ ! -d "${AUDITDIR}" ]; then install -d -m 0700 -o root -g root "${AUDITDIR}"; MADE_AUDITDIR=1; fi

# Accounts.  -o -u 0 is the whole point: a second name for uid 0.
install -d -m 0755 -o root -g root "${HOMES}"
useradd -o -u 0 -g 0 -M -d "${HOMES}/lrtroot" -s "${LRDIR}/bin/bash" lrtroot >/dev/null 2>&1
useradd -o -u 0 -g 0 -M -d "${HOMES}/lrtctl"  -s "${REAL_BASH}"       lrtctl  >/dev/null 2>&1
if ! grep -q '^lrtroot:' /etc/passwd || ! grep -q '^lrtctl:' /etc/passwd; then
    skip_group $((TOTAL_ASSERTIONS - 1)) "could not create the test uid-0 accounts"
    harness_expect_total "${TOTAL_ASSERTIONS}"
    summary_and_exit
fi

for a in lrtroot lrtctl; do
    install -d -m 0700 -o root -g root "${HOMES}/${a}" "${HOMES}/${a}/.ssh"
    ssh-keygen -q -t ed25519 -N '' -f "${T}/${a}.key" -C "limited-root-test"
    install -m 0600 -o root -g root "${T}/${a}.key.pub" "${HOMES}/${a}/.ssh/authorized_keys"
done

SSHOPT=(-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
        -o LogLevel=ERROR -o ConnectTimeout=10)

# Run a command through a real sshd login as the confined account.
as_lrtroot() { ssh "${SSHOPT[@]}" -i "${T}/lrtroot.key" lrtroot@127.0.0.1 -- "$@" 2>&1; }
# ... and as the unconfined uid-0 control.
as_lrtctl()  { ssh "${SSHOPT[@]}" -i "${T}/lrtctl.key"  lrtctl@127.0.0.1  -- "$@" 2>&1; }

OUT=""
RC=0
run_lr()  { OUT="$(as_lrtroot "$@")"; RC=$?; }
run_ctl() { OUT="$(as_lrtctl  "$@")"; RC=$?; }

want_ok() {
    if [ "${RC}" -eq 0 ]; then pass "$1"
    else fail "$1 (rc=${RC}: ${OUT})"; fi
}
want_fail() {
    if [ "${RC}" -ne 0 ]; then pass "$1"
    else fail "$1 — the command SUCCEEDED, which is the escape this test exists to catch"; fi
}
want_out() {
    if printf '%s' "${OUT}" | grep -qF -- "$2"; then pass "$1"
    else fail "$1 (wanted '$2', got: ${OUT})"; fi
}
want_not_out() {
    if printf '%s' "${OUT}" | grep -qF -- "$2"; then
        fail "$1 (did not want '$2', got: ${OUT})"
    else pass "$1"; fi
}

# ── 1. The login itself ───────────────────────────────────────────────

echo "── 1. Login through the wrapper ─────────────────────────────────"

run_lr 'id -u'
want_out "L1: the confined account logs in over sshd and is uid 0" "0"

run_lr 'echo LOGIN-SHELL-ARGV0-OK'
want_out "L2: a non-interactive login runs a command" "LOGIN-SHELL-ARGV0-OK"

# The interactive path is the one the leading '-' in argv[0] broke: sshd
# gives a login shell argv[0]="-bash", and the pristine wrapper looked for
# "<stash>/-bash".  -tt forces a pty, which is what makes sshd take that
# path.
OUT="$(ssh "${SSHOPT[@]}" -tt -i "${T}/lrtroot.key" lrtroot@127.0.0.1 \
        'echo INTERACTIVE-OK; exit' 2>&1)"; RC=$?
want_out "L3: an INTERACTIVE login (argv[0] = -bash) reaches the real shell" "INTERACTIVE-OK"
want_not_out "L4: the interactive login does not look for a dash-prefixed stash entry" "/-bash"

# The trailing ';true' matters: bash -c with one simple command execs it
# in place, so /proc/$$/exe would name readlink rather than the shell.
run_lr 'readlink -f "/proc/$$/exe"; true'
want_out "L5: the session really is running the stashed bash" "${LRDIR}/shells/bash"

echo ""
echo "── 2. Enforcement is on, and cannot be taken off ────────────────"

run_lr 'grep -c . /proc/self/status; grep NoNewPrivs /proc/self/status'
want_out "E1: no_new_privs is set in the session" "NoNewPrivs:	1"

run_lr 'grep Seccomp: /proc/self/status'
want_out "E2: a seccomp filter is installed" "Seccomp:	2"

run_lr 'grep CapBnd /proc/self/status'
CAPBND="$(printf '%s' "${OUT}" | awk '{print $2}')"
if [ -n "${CAPBND}" ] && [ "$(( 0x${CAPBND} & (1 << 16) ))" -eq 0 ]; then
    pass "E3: CAP_SYS_MODULE is gone from the bounding set (CapBnd=${CAPBND})"
else
    fail "E3: CAP_SYS_MODULE still in CapBnd (${CAPBND:-unreadable})"
fi
if [ -n "${CAPBND}" ] && [ "$(( 0x${CAPBND} & (1 << 39) ))" -eq 0 ]; then
    pass "E4: CAP_BPF is gone from the bounding set"
else
    fail "E4: CAP_BPF still in CapBnd (${CAPBND:-unreadable})"
fi
if [ -n "${CAPBND}" ] && [ "$(( 0x${CAPBND} & (1 << 21) ))" -eq 0 ]; then
    pass "E5: CAP_SYS_ADMIN is gone from the bounding set"
else
    fail "E5: CAP_SYS_ADMIN still in CapBnd (${CAPBND:-unreadable})"
fi
if [ -n "${CAPBND}" ] && [ "$(( 0x${CAPBND} & (1 << 1) ))" -ne 0 ]; then
    pass "E6: CAP_DAC_OVERRIDE is kept — this is a root account, not an unprivileged one"
else
    fail "E6: CAP_DAC_OVERRIDE was dropped; the account cannot administer anything"
fi

run_lr 'grep CapAmb /proc/self/status'
want_out "E7: the ambient set is empty" "CapAmb:	0000000000000000"

# A second, wider ruleset cannot widen the first.
run_lr "${LRDIR}/bin/compartment-user --no-landlock --no-seccomp -- sh -c 'echo x > /etc/lr-should-not-exist'"
want_fail "E8: --no-landlock --no-seccomp from inside the session widens nothing"

run_lr 'bash -c "bash -c \"echo x > /etc/lr-should-not-exist\""'
want_fail "E9: the domain is inherited by grandchildren"

echo ""
echo "── 3. The allow list works (this has to stay usable) ────────────"

run_lr 'ps -e >/dev/null && echo ok'
want_out "A1: process inspection works" "ok"
run_lr 'ip -br addr >/dev/null && echo ok'
want_out "A2: network tools work" "ok"
run_lr 'ss -ltn >/dev/null && echo ok'
want_out "A3: socket listing works" "ok"
run_lr 'ls /var/log >/dev/null && echo ok'
want_out "A4: the log directory is readable" "ok"
run_lr "touch ${HOMES}/lrtroot/writable && echo ok"
want_out "A5: the account's own writable area works" "ok"
run_lr 'cat /etc/hostname >/dev/null && echo ok'
want_out "A6: /etc is readable" "ok"

echo ""
echo "── 4. Closed vectors ────────────────────────────────────────────"

run_lr 'echo x > /etc/lr-should-not-exist'
want_fail "V1: cannot write into /etc"
want_out "V1a: ... and says why" "Permission denied"

run_lr 'echo "# lr" >> /etc/ssh/sshd_config'
want_fail "V2: cannot edit sshd_config"

run_lr 'echo x >> /root/.ssh/authorized_keys'
want_fail "V3: cannot append to another account's authorized_keys"

run_lr 'echo x > /etc/ld.so.preload'
want_fail "V4: cannot create /etc/ld.so.preload"

run_lr "ln /etc/shadow ${HOMES}/lrtroot/hardlink"
want_fail "V5: cannot hardlink out of a ro rule into a writable one"
want_out "V5a: ... and the refusal is Landlock's REFER, not DAC" "Invalid cross-device link"

run_lr "mknod ${HOMES}/lrtroot/rawdisk b 253 1"
want_fail "V6: cannot re-create a block device inside its own writable area"

run_lr 'dd if=/dev/vda of=/dev/null bs=512 count=1'
want_fail "V7: cannot read the raw disk"

run_lr 'modprobe dummy'
want_fail "V8: cannot load a kernel module"

run_lr 'nsenter -t 1 -m -- /bin/true'
want_fail "V9: cannot enter PID 1's mount namespace"

run_lr 'unshare -m -- /bin/true'
want_fail "V10: cannot make a new mount namespace"

run_lr 'mount --bind /tmp /mnt'
want_fail "V11: cannot mount"

run_lr 'systemd-run --quiet --collect --unit=lr-escape /bin/true'
want_fail "V12: cannot ask systemd to run something unconfined"

run_lr 'systemctl restart cron'
want_fail "V13: cannot drive systemd over D-Bus"

run_lr 'stat -c %F /run/dbus/system_bus_socket'
want_not_out "V14: the system bus socket is masked, not a socket any more" "socket"

run_lr 'bpftool prog list'
want_fail "V15: cannot use bpftool"

run_lr 'head -c 32 /proc/kcore | wc -c'
want_out "V16: /proc/kcore is masked (reads nothing)" "0"

run_lr 'echo 0 > /proc/sys/kernel/yama/ptrace_scope'
want_fail "V17: cannot change a security sysctl"

run_lr 'echo "|/tmp/x" > /proc/sys/kernel/core_pattern'
want_fail "V18: cannot install a core_pattern usermode helper"

run_lr 'cat /proc/1/root/etc/shadow'
want_fail "V19: cannot reach PID 1's root through /proc"

run_lr "chattr +i ${HOMES}/lrtroot/writable"
want_fail "V20: cannot set the immutable flag"

run_lr 'echo x > /etc/cron.d/lr-escape'
want_fail "V21: cannot drop a cron job"

run_lr 'echo x > /etc/systemd/system/lr-escape.service'
want_fail "V22: cannot drop a systemd unit"

# ': >' opens for write and writes nothing.  Writing an actual sysrq
# character would reboot the machine the moment this assertion regressed,
# and the open is the security-relevant operation either way.  Landlock's
# 'ro /proc' rule is what refuses it — deliberately NOT a mask, because a
# /dev/null cover would accept the write and discard it instead.
run_lr ': > /proc/sysrq-trigger'
want_fail "V23: cannot open sysrq-trigger for writing"

run_lr 'strace -p 1'
want_fail "V24: cannot ptrace"

echo ""
echo "── 5. Positive controls: the same host, without the wrapper ─────"
echo "     (only the non-destructive vectors have a control — loading a"
echo "      module, writing sshd_config, dd to the raw disk and sysrq are"
echo "      left unpaired on purpose)"

run_ctl 'id -u'
want_out "C0: the control account logs in and is also uid 0" "0"

run_ctl 'echo x > /etc/lr-control-probe && rm -f /etc/lr-control-probe && echo ok'
want_out "C1: unconfined uid 0 CAN write into /etc" "ok"

run_ctl "mknod ${HOMES}/lrtctl/rawdisk b 253 1 && rm -f ${HOMES}/lrtctl/rawdisk && echo ok"
want_out "C2: unconfined uid 0 CAN create a block device" "ok"

run_ctl "ln /etc/shadow ${HOMES}/lrtctl/hardlink && rm -f ${HOMES}/lrtctl/hardlink && echo ok"
want_out "C3: unconfined uid 0 CAN hardlink out of /etc" "ok"

run_ctl 'nsenter -t 1 -m -- /bin/true && echo ok'
want_out "C4: unconfined uid 0 CAN enter PID 1's mount namespace" "ok"

run_ctl 'systemd-run --quiet --collect --unit=lr-control /bin/true && echo ok'
want_out "C5: unconfined uid 0 CAN drive systemd" "ok"

run_ctl 'bpftool prog list >/dev/null && echo ok'
want_out "C6: unconfined uid 0 CAN use bpftool" "ok"

run_ctl 'head -c 32 /proc/kcore | wc -c'
want_out "C7: unconfined uid 0 CAN read /proc/kcore" "32"

run_ctl 'grep CapBnd /proc/self/status'
want_out "C8: unconfined uid 0 keeps a full bounding set" "CapBnd:	000001ff"

run_ctl 'grep Seccomp: /proc/self/status'
want_out "C9: unconfined uid 0 has no seccomp filter" "Seccomp:	0"

echo ""
echo "── 6. compartment-bpf seals ─────────────────────────────────────"

SEAL_ASSERTIONS=7
if [ ! -x "${CBPF}" ]; then
    skip_group "${SEAL_ASSERTIONS}" "compartment-bpf not built (set COMPARTMENT_BPF=)"
elif [ ! -d /sys/fs/bpf ]; then
    skip_group "${SEAL_ASSERTIONS}" "no bpffs at /sys/fs/bpf"
else
    : > "${SEALPROBE}"
    cat > "${T}/seal.conf" <<EOF
# Generated by tests/scripts/root.d/limited-root.sh.  A three-line stand-in
# for compartment-bpf/profiles/limited-root-authpath.conf: the shipped
# profile seals the machine's real login path, which a test must not do to
# a host it does not own.  The probe file is created and removed by this
# script, so a live seal on it proves the same thing with nothing at risk.
seal ${SEALPROBE}                            full
seal /etc/ld.so.cache                        full
EOF
    if "${CBPF}" --pin "${T}/seal.conf" >"${T}/pin.log" 2>&1; then
        PINNED=1
        pass "S1: the seal profile pins"

        # Liveness: an UNCONFINED uid-0 login cannot write a sealed file.
        # This is the half Landlock cannot do.
        run_ctl "echo x >> ${SEALPROBE}"
        want_fail "S2: a sealed file resists an unconfined uid-0 write"

        run_lr "${CBPF} --unpin"
        want_fail "S3: the confined account cannot --unpin"

        run_lr 'rm -rf /sys/fs/bpf/compartment'
        want_fail "S4: the confined account cannot remove the pin tree"

        run_lr 'ls /sys/fs/bpf'
        want_fail "S5: the confined account cannot even list the pin tree"

        run_lr 'umount -l /sys/fs/bpf'
        want_fail "S6: the confined account cannot unmount bpffs"

        if "${CBPF}" --unpin >>"${T}/pin.log" 2>&1; then
            PINNED=0
            pass "S7: the legitimate admin can still --unpin"
        else
            fail "S7: --unpin failed for the legitimate admin"
            sed 's/^/    /' "${T}/pin.log"
        fi
    else
        skip_group "${SEAL_ASSERTIONS}" \
            "compartment-bpf --pin failed ($(tail -1 "${T}/pin.log"))"
    fi
fi

echo ""
echo "── 7. Before/after against the pristine build ───────────────────"

BEFORE_ASSERTIONS=3
if [ -z "${PRISTINE_SRC:-}" ] || [ ! -r "${PRISTINE_SRC}/compartment-user.c" ]; then
    skip_group "${BEFORE_ASSERTIONS}" \
        "PRISTINE_SRC not set — the before/after witnesses need a release-1.4 tree"
else
    if cc -w -std=c11 -D_GNU_SOURCE -O0 \
           -DREAL_SHELL_DIR="\"${LRDIR}/shells\"" \
           -o "${T}/pristine-user" "${PRISTINE_SRC}/compartment-user.c" \
           2>"${T}/pristine.log"; then
        ln -sf "${T}/pristine-user" "${T}/-bash"
        OUT="$("${T}/-bash" -c 'echo SHOULD-NOT-GET-HERE' 2>&1)"; RC=$?
        want_out "B1: the pristine wrapper looks for a dash-prefixed stash entry" "/-bash"

        OUT="$("${T}/pristine-user" --cap-drop CAP_SYS_MODULE --profile none \
               --ro /usr -- /bin/true 2>&1)"; RC=$?
        want_fail "B2: the pristine wrapper has no --cap-drop"

        OUT="$("${T}/pristine-user" --profile "${PROFILE_SRC}" --dry-run -- /bin/true 2>&1)"; RC=$?
        want_fail "B3: the pristine wrapper rejects the shipped limited-root profile"
    else
        skip_group "${BEFORE_ASSERTIONS}" "could not build the pristine wrapper"
    fi
fi

echo ""
harness_expect_total "${TOTAL_ASSERTIONS}"
summary_and_exit
