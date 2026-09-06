#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# profile-trust-root.sh — root-only checks for profile trust.
#
# Everything here is --dry-run: no namespace is created, no container is
# started, nothing is mounted. The only host state touched is
# /etc/compartment (and /var/log/compartment), both removed again if this
# script created them.
#
# Run as root:  sudo ./tests/scripts/root.d/profile-trust-root.sh
#
# Point it at another build to confirm the assertions fail there:
#   COMPARTMENT_ROOT=/path/to/old/compartment-root sudo -E ...

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CU="${COMPARTMENT_USER:-${REPO_DIR}/compartment-user}"
CR="${COMPARTMENT_ROOT:-${REPO_DIR}/compartment-root}"
VERBOSE="${1:-}"

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP: $1"; }

echo "=== Profile trust: root-only test suite ==="
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "  SKIP: not running as root — these checks need uid 0"
    echo ""
    echo "=== Results ==="
    echo "  PASS: 0"
    echo "  FAIL: 0"
    echo "  SKIP: 1"
    echo ""
    echo "ALL TESTS PASSED"
    exit 0
fi

if [ ! -x "${CR}" ] || [ ! -x "${CU}" ]; then
    echo "ERROR: build the tools first (make)."
    exit 1
fi

# An unprivileged identity to own the "attacker" files.
VICTIM_UID="${SUDO_UID:-}"
if [ -z "${VICTIM_UID}" ] || [ "${VICTIM_UID}" = "0" ]; then
    VICTIM_UID="$(id -u nobody 2>/dev/null || echo 65534)"
fi
VICTIM_GID="$(id -g "${VICTIM_UID}" 2>/dev/null || echo 65534)"

WORK="$(mktemp -d)"
CREATED_ETC=0
CREATED_LOG=0
CREATED_VARLIB=0
[ -d /etc/compartment ] || CREATED_ETC=1
[ -d /var/log/compartment ] || CREATED_LOG=1
[ -d /var/lib/compartment ] || CREATED_VARLIB=1

cleanup() {
    rm -f /etc/compartment/cptest-*.conf
    [ "${CREATED_ETC}" -eq 1 ] && rmdir /etc/compartment 2>/dev/null
    [ "${CREATED_LOG}" -eq 1 ] && rm -rf /var/log/compartment
    [ "${CREATED_VARLIB}" -eq 1 ] && rm -rf /var/lib/compartment
    rm -rf "${WORK}"
    return 0
}
trap cleanup EXIT

mkdir -p /etc/compartment
chown root:root /etc/compartment
chmod 0755 /etc/compartment

run() {
    OUT="$("$@" 2>&1)"
    RC=$?
    if [ -n "${VERBOSE}" ]; then
        echo "    CMD: $*"
        echo "    RC:  ${RC}"
        echo "    OUT: ${OUT}"
    fi
    return 0
}
want_rc_nonzero() {
    if [ "${RC}" -ne 0 ]; then pass "$1"
    else fail "$1 (expected non-zero exit, got 0)"; fi
}
want_rc() {
    if [ "${RC}" -eq "$2" ]; then pass "$1"
    else fail "$1 (expected rc=$2, got rc=${RC})"; fi
}
want_out() {
    if printf '%s' "${OUT}" | grep -qF -- "$2"; then pass "$1"
    else fail "$1 (expected '$2' in output)"; fi
}
want_no_out() {
    if printf '%s' "${OUT}" | grep -qF -- "$2"; then
        fail "$1 (unexpected '$2' in output)"
    else pass "$1"; fi
}

# ── C2: compartment-root must never take policy from $HOME ────────────

echo "--- Test group: compartment-root ignores \$HOME (C2) ---"

RHOME="${WORK}/attacker-home"
mkdir -p "${RHOME}/.config/compartment"
cat > "${RHOME}/.config/compartment/cptest-container.conf" <<'EOF'
rootdir /tmp/attacker-jail
username root
cap-allow sys_admin
cap-allow dac_override
EOF
chown -R "${VICTIM_UID}:${VICTIM_GID}" "${RHOME}"
chmod -R go-w "${RHOME}"

run env HOME="${RHOME}" "${CR}" --dry-run --profile cptest-container -- /bin/sh
want_rc_nonzero "C2: profile named only in \$HOME is not found"
want_no_out "C2: attacker rootdir is not adopted" "/tmp/attacker-jail"
want_no_out "C2: \$HOME is not in the search path" ".config/compartment"
want_no_out "C2: attacker capabilities are not kept" "sys_admin"

# Same file handed over as an explicit path: refused on ownership.
run env HOME="${RHOME}" "${CR}" --dry-run \
    --profile "${RHOME}/.config/compartment/cptest-container.conf" \
    -c /srv/x -U root -- /bin/sh
want_rc_nonzero "C2: explicit non-root-owned profile refused"
want_out "C2: message requires root ownership" "must be owned by root"

echo ""

# ── A root-owned system profile is accepted, in every --profile form ──

echo "--- Test group: /etc/compartment profiles (C2, H8) ---"

install -o root -g root -m 0644 "${REPO_DIR}/examples/container.conf" \
    /etc/compartment/cptest-ok.conf

for form in "--profile cptest-ok" "--profile=cptest-ok" "-pcptest-ok" \
            "-p cptest-ok" "--profile=/etc/compartment/cptest-ok.conf"; do
    # shellcheck disable=SC2086
    run "${CR}" --dry-run ${form} -c /srv/x -U root -- /bin/sh
    want_rc "H8: '${form}' loads the profile" 0
    want_out "H8: '${form}' applies the allow-list" "ALLOW-LIST"
done

# A symlink from /etc to a file the user owns must not be trusted.
ln -sfn "${RHOME}/.config/compartment/cptest-container.conf" \
        /etc/compartment/cptest-link.conf
run "${CR}" --dry-run --profile cptest-link -c /srv/x -U root -- /bin/sh
want_rc_nonzero "C2: /etc symlink to a user-owned profile refused"
want_out "C2: refusal names the ownership problem" "must be owned by root"

# A root-owned but group-writable system profile must not be trusted.
install -o root -g root -m 0664 "${REPO_DIR}/examples/container.conf" \
    /etc/compartment/cptest-loose.conf
run "${CR}" --dry-run --profile cptest-loose -c /srv/x -U root -- /bin/sh
want_rc_nonzero "C2: group-writable system profile refused"
want_out "C2: refusal names the mode" "group- or world-writable"

echo ""

# ── One-way switches under root ───────────────────────────────────────

echo "--- Test group: one-way switches (compartment-root) ---"

for sw in seccomp no-new-privs env-sanitize; do
    printf 'rootdir /srv/x\nusername root\n%s off\n' "${sw}" \
        > /etc/compartment/cptest-off.conf
    chown root:root /etc/compartment/cptest-off.conf
    chmod 0644 /etc/compartment/cptest-off.conf
    run "${CR}" --dry-run --profile cptest-off -- /bin/sh
    want_rc_nonzero "one-way: '${sw} off' refused by compartment-root"
done

echo ""

# ── Audit default directory for root ──────────────────────────────────

echo "--- Test group: root audit directory (M7) ---"

rm -rf /var/log/compartment
run "${CU}" --verbose --no-landlock --no-seccomp --audit -- /bin/true
want_out "M7: root audit log defaults to /var/log/compartment" \
         "/var/log/compartment"
want_no_out "M7: root audit log is not under /var/tmp" "/var/tmp/compartment-audit"
if [ -d /var/log/compartment ]; then
    MODE="$(stat -c %a /var/log/compartment)"
    if [ "${MODE}" = "700" ]; then
        pass "M7: /var/log/compartment created 0700"
    else
        fail "M7: /var/log/compartment is mode ${MODE}, expected 700"
    fi
else
    fail "M7: /var/log/compartment was not created"
fi

echo ""

# ── Admin-provisioned per-user audit directory ────────────────────────

echo "--- Test group: /var/lib/compartment/audit (M7) ---"

if [ "${CREATED_VARLIB}" -eq 0 ]; then
    skip "/var/lib/compartment already exists — not touching it"
elif [ -z "${SUDO_USER:-}" ] || ! command -v runuser >/dev/null 2>&1; then
    skip "no SUDO_USER or runuser — cannot exercise the unprivileged path"
else
    U="${SUDO_USER}"
    UID_N="$(id -u "${U}")"
    VARLIB="/var/lib/compartment/audit/${UID_N}"
    VARTMP="/var/tmp/compartment-audit-${UID_N}"
    rm -rf "${VARTMP}"

    install -d -m 0755 -o root -g root /var/lib/compartment /var/lib/compartment/audit
    install -d -m 0700 -o "${U}" "${VARLIB}"

    run runuser -u "${U}" -- "${CU}" --verbose --no-landlock --no-seccomp \
        --audit -- /bin/true
    want_out "M7: an admin-provisioned directory is preferred" "${VARLIB}/"

    # A parent anyone but root can write is not a trust anchor.
    chmod 0775 /var/lib/compartment/audit
    run runuser -u "${U}" -- "${CU}" --verbose --no-landlock --no-seccomp \
        --audit -- /bin/true
    want_out "M7: a group-writable parent is reported" "must be root-owned"
    want_out "M7: a group-writable parent falls back to /var/tmp" "${VARTMP}/"
    chmod 0755 /var/lib/compartment/audit

    # Wrong mode on the per-uid directory: fall back rather than use it.
    chmod 0755 "${VARLIB}"
    run runuser -u "${U}" -- "${CU}" --verbose --no-landlock --no-seccomp \
        --audit -- /bin/true
    want_out "M7: a per-uid directory that is not 0700 falls back" "${VARTMP}/"
    chmod 0700 "${VARLIB}"

    # Someone else squatting the /var/tmp fallback must be fatal.
    rm -rf /var/lib/compartment/audit "${VARTMP}"
    install -d -m 0777 -o daemon -g daemon "${VARTMP}"
    run runuser -u "${U}" -- "${CU}" --no-landlock --no-seccomp --audit -- /bin/true
    want_rc_nonzero "M7: a squatted /var/tmp audit directory is fatal"
    want_out "M7: the squat refusal names the owner" "expected uid ${UID_N}"
    rm -rf "${VARTMP}"
fi

echo ""

# ── Summary ───────────────────────────────────────────────────────────

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
