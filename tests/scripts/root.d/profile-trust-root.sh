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

# The header documents `COMPARTMENT_ROOT=... sudo -E ...`, and under
# sudo -E HOME stays the invoking user's — at uid 0 compartment-user then
# refuses the run ("refusing to use HOME=/home/... as a sandbox root: not
# owned by you") before it ever picks an audit directory, and the M7
# group failed with a confusing missing-string. The suite has an
# undeclared dependency on root's own HOME; declare it.
HOME="$(getent passwd 0 | cut -d: -f6)"
[ -n "${HOME}" ] && [ -d "${HOME}" ] || HOME=/root
export HOME

WORK="$(mktemp -d)"
CREATED_ETC=0
CREATED_LOG=0
CREATED_VARLIB=0
ETC_MODE=""
[ -d /etc/compartment ] || CREATED_ETC=1
[ -d /var/log/compartment ] || CREATED_LOG=1
[ -d /var/lib/compartment ] || CREATED_VARLIB=1
[ "${CREATED_ETC}" -eq 0 ] && ETC_MODE="$(stat -c %a /etc/compartment 2>/dev/null || true)"

# Every path this suite can create is registered here, before anything is
# created. The previous version removed /var/log/compartment
# unconditionally — running the root suite on a host with a real audit
# trail destroyed it — and left /var/tmp/compartment-audit-<uid> behind on
# an abort, which is exactly what made the *rootless* suite skip its whole
# M7 group on every subsequent run.
cleanup() {
    rm -f /etc/compartment/cptest-*.conf
    if [ "${CREATED_ETC}" -eq 1 ]; then
        rmdir /etc/compartment 2>/dev/null
    elif [ -n "${ETC_MODE}" ]; then
        chmod "${ETC_MODE}" /etc/compartment 2>/dev/null
    fi
    [ "${CREATED_LOG}" -eq 1 ] && rm -rf /var/log/compartment
    [ "${CREATED_VARLIB}" -eq 1 ] && rm -rf /var/lib/compartment
    if [ -n "${SUDO_UID:-}" ]; then
        rm -rf "/var/tmp/compartment-audit-${SUDO_UID}"
    fi
    rm -rf "${WORK}"
    return 0
}
trap cleanup EXIT INT TERM

mkdir -p /etc/compartment
chown root:root /etc/compartment
# Only relax the mode when this suite created the directory. An admin who
# keeps /etc/compartment at 0700 got it permanently widened to 0755 by
# running the test suite once.
if [ "${CREATED_ETC}" -eq 1 ]; then
    chmod 0755 /etc/compartment
fi

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

# ── Profile search precedence: /etc outranks $HOME (C1) ───────────────

echo "--- Test group: profile search precedence (C1) ---"

# The headline 1.4 fix. $HOME used to be searched first, so a sandboxed
# agent could drop a file in ~/.config/compartment and un-sandbox every
# future run of the same command line. Only compartment-user can search
# $HOME at all, and only with --user-profiles, so the precedence case
# needs both files present at once — which needs a root-owned
# /etc/compartment. Nothing rootless can set that up, which is why the
# release shipped with the ordering untested.
if [ -z "${SUDO_USER:-}" ] || ! command -v runuser >/dev/null 2>&1; then
    skip "precedence: /etc wins over \$HOME (needs SUDO_USER + runuser)"
    skip "precedence: the \$HOME copy is not loaded (needs SUDO_USER + runuser)"
    skip "precedence: the rule set comes from /etc (needs SUDO_USER + runuser)"
    skip "precedence: the \$HOME rule set is not applied (needs SUDO_USER + runuser)"
    skip "precedence: inherit from /etc does not reach \$HOME (needs SUDO_USER + runuser)"
    skip "precedence: the refusal names the inherited profile (needs SUDO_USER + runuser)"
else
    PU="${SUDO_USER}"
    PHOME="${WORK}/prec-home"
    mkdir -p "${PHOME}/.config/compartment"

    mkdir -p "${PHOME}/etc-marker" "${PHOME}/home-marker"
    printf 'ro %s/etc-marker\n' "${PHOME}" > /etc/compartment/cptest-prec.conf
    chown root:root /etc/compartment/cptest-prec.conf
    chmod 0644 /etc/compartment/cptest-prec.conf

    printf 'ro %s/home-marker\n' "${PHOME}" \
        > "${PHOME}/.config/compartment/cptest-prec.conf"

    # A profile that only exists under $HOME. A profile loaded from /etc
    # drops PROFILE_SEARCH_USER, so `inherit` must not reach it.
    printf 'ro %s/home-marker\n' "${PHOME}" \
        > "${PHOME}/.config/compartment/cptest-prec-child.conf"
    printf 'inherit cptest-prec-child\n' > /etc/compartment/cptest-prec-i.conf
    chown root:root /etc/compartment/cptest-prec-i.conf
    chmod 0644 /etc/compartment/cptest-prec-i.conf

    chown -R "${PU}" "${PHOME}"
    chmod -R go-w "${PHOME}"
    chmod 0755 "${WORK}"

    run runuser -u "${PU}" -- env HOME="${PHOME}" "${CU}" --verbose \
        --user-profiles --dry-run --profile cptest-prec -- /bin/true
    want_out "precedence: /etc wins over \$HOME" \
             "/etc/compartment/cptest-prec.conf"
    want_no_out "precedence: the \$HOME copy is not loaded" \
             "${PHOME}/.config/compartment/cptest-prec.conf"
    want_out "precedence: the rule set comes from /etc" "ro ${PHOME}/etc-marker"
    want_no_out "precedence: the \$HOME rule set is not applied" \
             "ro ${PHOME}/home-marker"

    run runuser -u "${PU}" -- env HOME="${PHOME}" "${CU}" --verbose \
        --user-profiles --dry-run --profile cptest-prec-i -- /bin/true
    want_rc_nonzero "precedence: inherit from /etc does not reach \$HOME"
    want_out "precedence: the refusal names the inherited profile" \
             "inherited profile 'cptest-prec-child' not found"

    rm -f /etc/compartment/cptest-prec.conf /etc/compartment/cptest-prec-i.conf
fi

echo ""

# ── Profile file trust: the group-writable half (C1) ──────────────────

echo "--- Test group: profile file trust, group-writable (C1) ---"

# rootless.d/profile-trust.sh can only reach the world-writable half:
# the caller belongs to exactly one group, its own, and the private-group
# exemption covers that. Dropping S_IWGRP from the trust mask therefore
# left all 420 rootless assertions green while a 0664 profile in a shared
# group became trusted. Root can hand a user-owned file to a group the
# user is not in, which is the shape the exemption must not cover.
if [ -z "${SUDO_USER:-}" ] || ! command -v runuser >/dev/null 2>&1; then
    skip "trust: 0664 in a foreign group refused (needs SUDO_USER + runuser)"
    skip "trust: the refusal names the mode (needs SUDO_USER + runuser)"
    skip "trust: 0775 directory in a foreign group refused (needs SUDO_USER + runuser)"
    skip "trust: the directory refusal names the directory (needs SUDO_USER + runuser)"
    skip "trust: a root-owned user profile is refused (needs SUDO_USER + runuser)"
    skip "trust: control — 0644 owned by the caller is accepted (needs SUDO_USER + runuser)"
else
    TU="${SUDO_USER}"
    TUID="$(id -u "${TU}")"
    FOREIGN_GID="$(id -g daemon 2>/dev/null || echo 1)"
    TDIR="${WORK}/trustmodes"
    mkdir -p "${TDIR}"
    chown "${TUID}" "${TDIR}"
    chmod 0755 "${TDIR}" "${WORK}"

    install -o "${TUID}" -g "${FOREIGN_GID}" -m 0664 \
        "${REPO_DIR}/tests/profiles/test-fs-rw.conf" "${TDIR}/gw-shared.conf"
    run runuser -u "${TU}" -- "${CU}" --dry-run \
        --profile "${TDIR}/gw-shared.conf" -- /bin/true
    want_rc_nonzero "trust: 0664 in a foreign group refused"
    want_out "trust: the refusal names the mode" \
             "is mode 0664 — group- or world-writable policy is not trusted"

    mkdir -p "${TDIR}/gwdir"
    chown "${TUID}:${FOREIGN_GID}" "${TDIR}/gwdir"
    chmod 0775 "${TDIR}/gwdir"
    install -o "${TUID}" -m 0644 \
        "${REPO_DIR}/tests/profiles/test-fs-rw.conf" "${TDIR}/gwdir/p.conf"
    run runuser -u "${TU}" -- "${CU}" --dry-run \
        --profile "${TDIR}/gwdir/p.conf" -- /bin/true
    want_rc_nonzero "trust: 0775 directory in a foreign group refused"
    want_out "trust: the directory refusal names the directory" "profile directory"

    # HOWTO: "a root-owned file never qualifies" for the exemption — and
    # for compartment-user a root-owned profile is not owned by the caller
    # at all, so it is refused on ownership.
    install -o root -g root -m 0664 \
        "${REPO_DIR}/tests/profiles/test-fs-rw.conf" "${TDIR}/root-owned.conf"
    run runuser -u "${TU}" -- "${CU}" --dry-run \
        --profile "${TDIR}/root-owned.conf" -- /bin/true
    want_rc_nonzero "trust: a root-owned user profile is refused"

    # Control: the same file, caller-owned and 0644, is accepted — so the
    # three refusals above are attributable to the mode and the owner and
    # not to anything about runuser or the fixture.
    install -o "${TUID}" -m 0644 \
        "${REPO_DIR}/tests/profiles/test-fs-rw.conf" "${TDIR}/ok.conf"
    run runuser -u "${TU}" -- "${CU}" --dry-run \
        --profile "${TDIR}/ok.conf" -- /bin/true
    want_rc "trust: control — 0644 owned by the caller is accepted" 0
fi

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

# Only clear a log directory this suite is responsible for. Removing a
# real /var/log/compartment destroys the host's audit trail.
if [ "${CREATED_LOG}" -eq 1 ]; then
    rm -rf /var/log/compartment
fi
run "${CU}" --verbose --no-landlock --no-seccomp --audit -- /bin/true
want_rc "M7: the root audit run succeeds" 0
want_out "M7: root audit log defaults to /var/log/compartment" \
         "/var/log/compartment"
want_no_out "M7: root audit log is not under /var/tmp" "/var/tmp/compartment-audit"
if [ ! -d /var/log/compartment ]; then
    fail "M7: /var/log/compartment was not created"
elif [ "${CREATED_LOG}" -eq 0 ]; then
    skip "M7: /var/log/compartment pre-existed — not asserting a mode this suite did not set"
else
    MODE="$(stat -c %a /var/log/compartment)"
    if [ "${MODE}" = "700" ]; then
        pass "M7: /var/log/compartment created 0700"
    else
        fail "M7: /var/log/compartment is mode ${MODE}, expected 700"
    fi
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

# The suite declares its own assertion count. A block that stops
# running — a `skip` standing in for twenty assertions, a group
# guarded by a tool that is not installed — changes the total, and a
# changed total is a failure rather than a smaller number nobody
# compares against anything.
harness_expect_total 46

echo "=== Results ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  SKIP: ${SKIP}"
echo ""
# The runner sums these lines; one per suite (tests/scripts/*.d/README.md).
echo "SUMMARY profile-trust-root: pass=${PASS} fail=${FAIL} skip=${SKIP}"

if [ "${FAIL}" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
