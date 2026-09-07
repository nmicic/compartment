#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# examples.sh — rootless tests for the shipped example profiles and scripts
#
# The host-key group starts a throwaway sshd as the invoking user, on a
# loopback port, with its own host keys and config; it authenticates nobody
# and is killed at the end. Nothing on the host is modified.
#
# Usage: ./tests/scripts/rootless.d/examples.sh [--verbose]

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CU="${REPO_DIR}/compartment-user"
CR="${REPO_DIR}/compartment-root"
EXAMPLES="${REPO_DIR}/examples"
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
vsay() { [ -n "${VERBOSE}" ] && echo "    $*" || true; }

WORK="$(mktemp -d -t compartment-examples-XXXXXXXX)"
PROFILE_EXAMPLES="${WORK}/profiles"
mkdir -p "${PROFILE_EXAMPLES}"
cp "${EXAMPLES}"/*.conf "${PROFILE_EXAMPLES}/"
chmod go-w "${PROFILE_EXAMPLES}" "${PROFILE_EXAMPLES}"/*.conf
SSHD_PID=""
# The host-key group has to write inside ${HOME}/.ssh/paranoid — that is
# the one path ssh.conf grants, and it is the policy under test — so the
# fixture cannot live under ${WORK}. It can, however, be removed on every
# exit path, which it was not: an abort left a directory in the user's
# real ~/.ssh.
EXAMPLES_KH=""
EXAMPLES_KH_DIR=""
cleanup() {
    [ -n "${SSHD_PID}" ] && kill "${SSHD_PID}" 2>/dev/null || true
    [ -n "${EXAMPLES_KH}" ] && rm -f "${EXAMPLES_KH}"
    [ -n "${EXAMPLES_KH_DIR}" ] && rmdir "${EXAMPLES_KH_DIR}" 2>/dev/null
    rm -rf "${WORK}"
    return 0
}
trap cleanup EXIT INT TERM

echo "=== Example profile and script tests ==="
echo ""

if [ ! -x "${CU}" ]; then
    echo "ERROR: ${CU} not found. Run 'make' first."
    exit 1
fi

# ── Test group: every shipped profile parses ───────────────────────

echo "--- Test group: example profiles parse ---"

# A compartment-root profile parsed by compartment-user now warns, once
# per root-only directive, that the directive belongs to the other tool —
# which is the point of the 1.4 change and not a defect in the example.
# Parse each profile with the tool it is written for.
for conf in "${PROFILE_EXAMPLES}"/*.conf; do
    name="$(basename "${conf}")"
    ERR="${WORK}/${name}.err"
    if grep -qE '^[[:space:]]*rootdir[[:space:]]' "${conf}"; then
        # compartment-root refuses a profile it does not own, so parse a
        # root-owned copy is not possible here; --dry-run through
        # compartment-user with the root directives ignored is still the
        # syntax check this group is for, so filter the expected warnings.
        "${CU}" --dry-run --profile "${conf}" -- /bin/true >/dev/null 2>"${ERR}.raw"
        rc=$?
        grep -vE "warning: '[a-z-]+' is a compartment-root directive" "${ERR}.raw" > "${ERR}"
        if [ "${rc}" -eq 0 ]; then
            pass "${name} parses"
        else
            fail "${name} does not parse: $(head -1 "${ERR}")"
        fi
    elif "${CU}" --dry-run --profile "${conf}" -- /bin/true >/dev/null 2>"${ERR}"; then
        pass "${name} parses"
    else
        fail "${name} does not parse: $(head -1 "${ERR}")"
    fi
    if grep -qiE 'warning|unknown syscall|invalid value' "${ERR}"; then
        fail "${name} parses with complaints: $(grep -iE 'warning|unknown syscall|invalid value' "${ERR}" | head -1)"
    else
        pass "${name} parses with no complaints"
    fi
done

# container.conf is a compartment-root profile: it declares no path rules, so
# compartment-user must refuse rather than run something unrestricted.
if "${CU}" --profile "${PROFILE_EXAMPLES}/container.conf" -- /bin/true >/dev/null 2>&1; then
    fail "container.conf runs under compartment-user despite having no path rules"
else
    pass "container.conf is refused by compartment-user (fail-closed)"
fi
if grep -qE 'NOT usable with compartment-user|NOT USABLE WITH compartment-user' "${PROFILE_EXAMPLES}/container.conf"; then
    pass "container.conf says which tool it is for"
else
    fail "container.conf does not warn that it is compartment-root only"
fi
if grep -q 'covers most server workloads' "${PROFILE_EXAMPLES}/container.conf"; then
    fail "container.conf still claims to cover most server workloads"
else
    pass "container.conf no longer claims to cover server workloads"
fi
# The network block is live now that syscall_table[] carries these names.
for sc in socket bind listen connect epoll_ctl eventfd2 timerfd_create \
          signalfd4 openat2; do
    if grep -qE "^allow ${sc}$" "${PROFILE_EXAMPLES}/container.conf"; then
        pass "container.conf allows '${sc}' (network block enabled)"
    else
        fail "container.conf does not allow '${sc}'"
    fi
done

# Every syscall container.conf names must resolve, or the allow-list is
# quietly one entry short of what it claims.
CC_WARN="${WORK}/container-warn.err"
"${CU}" --dry-run --profile "${PROFILE_EXAMPLES}/container.conf" -- /bin/true \
    >/dev/null 2>"${CC_WARN}" || true
if grep -q 'unknown syscall' "${CC_WARN}"; then
    fail "container.conf names a syscall the table does not know: $(grep -m1 'unknown syscall' "${CC_WARN}")"
else
    pass "container.conf names no unknown syscall"
fi

# restricted-root.conf is the compartment-root demonstration profile: an
# exec allow-list, mount hardening and a TCP port policy in one file.
RR="${PROFILE_EXAMPLES}/restricted-root.conf"
for want in 'landlock on' 'net-default deny' 'rootdir-flags' 'mount-noexec /tmp'; do
    if grep -qE "^${want}" "${RR}"; then
        pass "restricted-root.conf sets '${want}'"
    else
        fail "restricted-root.conf does not set '${want}'"
    fi
done
if grep -qE '^exec /usr/bin/' "${RR}"; then
    pass "restricted-root.conf carries a per-binary exec allow-list"
else
    fail "restricted-root.conf has no per-file exec rule"
fi
if grep -q 'does NOT guarantee' "${RR}"; then
    pass "restricted-root.conf states its limits"
else
    fail "restricted-root.conf does not state what it cannot guarantee"
fi

echo ""

# ── Test group: documented flags must exist ────────────────────────

echo "--- Test group: documented flags exist ---"

"${CU}" --help >"${WORK}/cu-help.txt" 2>&1 || true
if [ -x "${CR}" ]; then
    "${CR}" --help >"${WORK}/cr-help.txt" 2>&1 || true
else
    : > "${WORK}/cr-help.txt"
fi

BAD_FLAGS=""
FLAGS_SEEN=0
while read -r tool flag; do
    [ -n "${flag}" ] || continue
    FLAGS_SEEN=$((FLAGS_SEEN + 1))
    case "${tool}" in
        compartment-user) help="${WORK}/cu-help.txt" ;;
        compartment-root) help="${WORK}/cr-help.txt" ;;
        *) continue ;;
    esac
    grep -q -- "${flag}" "${help}" || BAD_FLAGS="${BAD_FLAGS} ${tool}${flag}"
done < <(grep -horE 'compartment-(user|root) --[a-z][a-z0-9-]*' \
             "${EXAMPLES}" 2>/dev/null \
         | sed -E 's/^(compartment-[a-z]+) (--.*)$/\1 \2/' | sort -u)
# Zero matches meant zero loop iterations, an empty BAD_FLAGS and a pass
# that had read nothing. Require the extractor to have found something.
if [ "${FLAGS_SEEN}" -lt 1 ]; then
    fail "the flag extractor found no compartment-* flag in examples/ — it has stopped matching"
elif [ -z "${BAD_FLAGS}" ]; then
    pass "every compartment-* flag named in examples/ exists in --help (${FLAGS_SEEN} checked)"
else
    fail "examples/ recommend flags that do not exist:${BAD_FLAGS}"
fi

echo ""

# ── Test group: paranoid-ssh.sh host-key handling ──────────────────

echo "--- Test group: paranoid-ssh.sh host-key handling ---"

PSSH="${EXAMPLES}/paranoid-ssh.sh"
if bash -n "${PSSH}" 2>"${WORK}/pssh.err"; then
    pass "paranoid-ssh.sh parses"
else
    fail "paranoid-ssh.sh syntax error: $(head -1 "${WORK}/pssh.err")"
fi

export PARANOID_SSH_KNOWN_HOSTS="${WORK}/known_hosts_test/known_hosts"
if bash "${PSSH}" --dry-run user@host-a >"${WORK}/dry-a.txt" 2>&1; then
    pass "paranoid-ssh.sh --dry-run works"
else
    fail "paranoid-ssh.sh --dry-run failed: $(head -1 "${WORK}/dry-a.txt")"
fi
vsay "$(cat "${WORK}/dry-a.txt")"
bash "${PSSH}" --dry-run user@host-b >"${WORK}/dry-b.txt" 2>&1 || true
bash "${PSSH}" --dry-run user@host-a -p 2222 >"${WORK}/dry-p.txt" 2>&1 || true

if grep -q 'HostKeyAlias=host-a' "${WORK}/dry-a.txt"; then
    pass "ssh identity is pinned to the real host, not to 127.0.0.1"
else
    fail "no HostKeyAlias for the real host — every host shares one known_hosts identity"
fi
ALIAS_A=$(grep -o 'HostKeyAlias=[^ ]*' "${WORK}/dry-a.txt" | head -1 || true)
ALIAS_B=$(grep -o 'HostKeyAlias=[^ ]*' "${WORK}/dry-b.txt" | head -1 || true)
if [ -n "${ALIAS_A}" ] && [ "${ALIAS_A}" != "${ALIAS_B}" ]; then
    pass "two different hosts get two different known_hosts identities"
else
    fail "host-a and host-b collapse onto the same identity (${ALIAS_A} / ${ALIAS_B})"
fi
if grep -q 'HostKeyAlias=\[host-a\]:2222' "${WORK}/dry-p.txt"; then
    pass "a non-default port is part of the identity, as plain ssh writes it"
else
    fail "a non-default port is not reflected in the known_hosts identity"
fi
if grep -q 'UserKnownHostsFile=' "${WORK}/dry-a.txt"; then
    pass "an explicit known_hosts file is used"
else
    fail "no explicit UserKnownHostsFile — first-use keys cannot persist"
fi
if grep -qE 'StrictHostKeyChecking=(no|off)' "${WORK}/dry-a.txt"; then
    fail "host key checking is disabled"
else
    pass "host key checking is not disabled"
fi
if bash "${PSSH}" --dry-run 'evil;host' >/dev/null 2>&1; then
    fail "a host name with shell metacharacters is accepted"
else
    pass "a host name with shell metacharacters is rejected"
fi

# The profile has to make the known_hosts location writable, or first-use
# keys are re-accepted on every single run.
KH_DIR_RULE=$(grep -E '^rwx? \$HOME/\.ssh/' "${PROFILE_EXAMPLES}/ssh.conf" || true)
if [ -n "${KH_DIR_RULE}" ]; then
    pass "ssh.conf grants write access for the known_hosts location (${KH_DIR_RULE})"
else
    fail "ssh.conf keeps ~/.ssh read-only, so accept-new can never record a key"
fi

echo ""

# ── Test group: paranoid-ssh.sh against a throwaway sshd ───────────

echo "--- Test group: host-key verification against a local sshd ---"

if ! command -v ssh >/dev/null 2>&1 || \
   ! command -v ssh-keygen >/dev/null 2>&1 || \
   [ ! -x /usr/sbin/sshd ]; then
    skip_group 3 "host-key verification (needs ssh, ssh-keygen and /usr/sbin/sshd)"
else
    free_port() {
        if command -v python3 >/dev/null 2>&1; then
            python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
        else
            echo $(( 20000 + RANDOM % 20000 ))
        fi
    }
    ssh-keygen -q -t ed25519 -N '' -f "${WORK}/hostkey_1" </dev/null
    ssh-keygen -q -t ed25519 -N '' -f "${WORK}/hostkey_2" </dev/null
    chmod 600 "${WORK}/hostkey_1" "${WORK}/hostkey_2"
    PORT="$(free_port)"
    write_sshd_conf() {
        cat > "${WORK}/sshd.conf" <<EOF
Port ${PORT}
ListenAddress 127.0.0.1
HostKey $1
PidFile ${WORK}/sshd.pid
UsePAM no
StrictModes no
AuthorizedKeysFile ${WORK}/authorized_keys
EOF
    }
    start_sshd() {
        write_sshd_conf "$1"
        /usr/sbin/sshd -f "${WORK}/sshd.conf" -D -e >"${WORK}/sshd.log" 2>&1 &
        SSHD_PID=$!
        for _ in $(seq 1 50); do
            (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null && { exec 3>&- ; return 0; }
            sleep 0.1
        done
        return 1
    }
    stop_sshd() {
        [ -n "${SSHD_PID}" ] && kill "${SSHD_PID}" 2>/dev/null || true
        wait "${SSHD_PID}" 2>/dev/null || true
        SSHD_PID=""
    }
    # Authentication always fails (no authorized key); the host-key exchange
    # happens first, which is the only part under test.
    try_ssh() {
        local alias="$1" out="$2"
        "${CU}" --profile "${PROFILE_EXAMPLES}/ssh.conf" -- \
            ssh -o "HostKeyAlias=${alias}" \
                -o "UserKnownHostsFile=${KH}" \
                -o StrictHostKeyChecking=accept-new \
                -o BatchMode=yes -o ControlMaster=no -o ConnectTimeout=5 \
                -p "${PORT}" nobody@127.0.0.1 true >"${out}" 2>&1
    }

    # ssh.conf grants exactly one writable path in $HOME —
    # `rw $HOME/.ssh/paranoid?` — so the fixture has to live there; that
    # is the policy under test. What it must not do is survive an abort:
    # the directory and the known_hosts file are registered with the EXIT
    # trap here, and the directory is only removed when this suite
    # created it.
    KH_DIR="${HOME}/.ssh/paranoid"
    KH_DIR_PREEXISTING=0
    [ -d "${KH_DIR}" ] && KH_DIR_PREEXISTING=1
    mkdir -p "${KH_DIR}"
    chmod 700 "${KH_DIR}"
    KH="${KH_DIR}/known_hosts.selftest.$$"
    ( umask 077; : > "${KH}" )
    EXAMPLES_KH="${KH}"
    [ "${KH_DIR_PREEXISTING}" -eq 0 ] && EXAMPLES_KH_DIR="${KH_DIR}"

    if start_sshd "${WORK}/hostkey_1"; then
        try_ssh host-a "${WORK}/ssh1.log" || true
        vsay "$(cat "${WORK}/ssh1.log")"
        if [ -s "${KH}" ] && ssh-keygen -F host-a -f "${KH}" >/dev/null 2>&1; then
            pass "first use records the key under the real host name, from inside the sandbox"
        else
            fail "first-use key was not recorded: $(head -2 "${WORK}/ssh1.log" | tr '\n' ' ')"
        fi

        try_ssh host-b "${WORK}/ssh2.log" || true
        if ssh-keygen -F host-b -f "${KH}" >/dev/null 2>&1 && \
           [ "$(grep -c . "${KH}")" -ge 2 ]; then
            pass "a second host gets its own known_hosts entry"
        else
            fail "a second host did not get its own known_hosts entry"
        fi

        stop_sshd
        if start_sshd "${WORK}/hostkey_2"; then
            if try_ssh host-a "${WORK}/ssh3.log"; then
                fail "a changed host key was accepted"
            else
                if grep -qiE 'IDENTIFICATION HAS CHANGED|Host key verification failed' "${WORK}/ssh3.log"; then
                    pass "a changed host key is refused"
                else
                    fail "connection failed but not because of the host key: $(head -2 "${WORK}/ssh3.log" | tr '\n' ' ')"
                fi
            fi
        else
            skip "a changed host key is refused (second sshd did not start)"
        fi
        stop_sshd
    else
        skip_group 3 "throwaway sshd did not start: $(head -1 "${WORK}/sshd.log" 2>/dev/null)"
    fi

    rm -f "${KH}"
    [ "${KH_DIR_PREEXISTING}" -eq 0 ] && rmdir "${KH_DIR}" 2>/dev/null
    EXAMPLES_KH=""
    EXAMPLES_KH_DIR=""
fi

echo ""

# ── Summary ────────────────────────────────────────────────────────

# The suite declares its own assertion count. A block that stops
# running — a `skip` standing in for twenty assertions, a group
# guarded by a tool that is not installed — changes the total, and a
# changed total is a failure rather than a smaller number nobody
# compares against anything.
harness_expect_total 63

echo "=== Results ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  SKIP: ${SKIP}"
echo ""
# The runner sums these lines; one per suite (tests/scripts/rootless.d/README.md).
echo "SUMMARY examples: pass=${PASS} fail=${FAIL} skip=${SKIP}"

if [ "${FAIL}" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
