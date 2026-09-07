#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# sandbox.sh — rootless tests for ../../../sandbox.sh
#
# HARD mode needs an unprivileged user namespace with a uid map, which many
# hosts (Ubuntu 23.10+ by default) refuse. Rather than skipping everything
# there, the namespace-facing commands are stubbed: SANDBOX_UNSHARE points at
# a fake unshare that drops the namespace flags and runs the command, and
# fake `ip`/`mount`/`umount` on PATH stand in for the privileged operations.
# The fake mount emulates a bind by copying, but only inside the test's own
# work directory — it never touches /bin, /usr or any real mount.
#
# That is enough to run the whole HARD path for real, including the shell
# intercept and the compartment-user shell-replacement exec that it depends
# on. What it cannot cover is the namespace itself: no machine available to
# this suite allows an unprivileged user namespace, so the real HARD path
# has to be checked by hand on a host that does. SECURITY.md records that
# gap.
#
# Usage: ./tests/scripts/rootless.d/sandbox.sh [--verbose]

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SANDBOX="${REPO_DIR}/sandbox.sh"
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
vsay() { [ -n "${VERBOSE}" ] && echo "    $*" || true; }

WORK="$(mktemp -d -t compartment-sandbox-test-XXXXXXXX)"

# sandbox.sh execs "compartment-user --verbose --audit" with no --audit-log,
# so a run creates the default audit directory.  Leaving it behind makes the
# profile-trust suite skip its default-audit-directory group on the next run
# ("already exists"), so remove it again — but only if this run is what
# created it, never a trail that was already on the machine.
AUDIT_DEFAULT_DIR="/var/tmp/compartment-audit-$(id -u)"
AUDIT_DIR_PREEXISTING=0
[ -e "${AUDIT_DEFAULT_DIR}" ] && AUDIT_DIR_PREEXISTING=1

cleanup() {
    chmod -R u+w "${WORK}" 2>/dev/null || true
    rm -rf "${WORK}"
    if [ "${AUDIT_DIR_PREEXISTING}" -eq 0 ]; then
        rm -rf "${AUDIT_DEFAULT_DIR}"
    fi
}
trap cleanup EXIT

echo "=== sandbox.sh tests ==="
echo ""

[ -f "${SANDBOX}" ] || { echo "ERROR: ${SANDBOX} not found."; exit 1; }
[ -x "${CU}" ] || { echo "ERROR: ${CU} not found. Run 'make' first."; exit 1; }

# ── Test group: static checks ──────────────────────────────────────

echo "--- Test group: static checks ---"

if bash -n "${SANDBOX}" 2>"${WORK}/syntax.err"; then
    pass "sandbox.sh parses"
else
    fail "sandbox.sh syntax error: $(head -1 "${WORK}/syntax.err")"
fi

# The stash must not live under /bin: inside the namespace we are a mapped
# root with no authority over host-root-owned directories, so mkdir there
# fails and the stash is silently never populated.
if grep -qE '(SHELL_STASH|stash)=.*"?/bin/' "${SANDBOX}"; then
    fail "the shell stash is still placed under /bin"
else
    pass "the shell stash is not placed under /bin"
fi

if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -S warning "${SANDBOX}" >"${WORK}/shellcheck.out" 2>&1; then
        pass "sandbox.sh is shellcheck clean at -S warning"
    else
        fail "shellcheck: $(grep -m1 '^In ' "${WORK}/shellcheck.out" || true)"
    fi
else
    skip "shellcheck not installed"
fi

echo ""

# ── Test group: user-namespace availability reporting ──────────────

echo "--- Test group: --verify reports why HARD mode is unavailable ---"

VERIFY_OUT="${WORK}/verify.txt"
SANDBOX_LOGDIR="${WORK}/audit" "${SANDBOX}" --verify >"${VERIFY_OUT}" 2>&1 || true
vsay "$(cat "${VERIFY_OUT}")"

AA_KNOB=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
if [ -r "${AA_KNOB}" ] && [ "$(cat "${AA_KNOB}")" = "1" ]; then
    if grep -qi 'apparmor' "${VERIFY_OUT}"; then
        pass "--verify names AppArmor as the reason HARD mode is unavailable"
    else
        fail "--verify does not mention AppArmor although it blocks userns here"
    fi
    if grep -q 'userns create' "${VERIFY_OUT}"; then
        pass "--verify documents a fallback that does not weaken the whole host"
    else
        fail "--verify offers no fallback for the AppArmor restriction"
    fi
elif unshare --user --map-root-user -- /bin/true 2>/dev/null; then
    if grep -qE 'HARD.*OK|isolation=HARD' "${VERIFY_OUT}"; then
        pass "--verify reports HARD mode as available on this host"
    else
        fail "--verify does not report HARD mode although userns works here"
    fi
    skip "--verify names AppArmor as the reason (the knob is not in play here)"
else
    skip_group 2 "userns is blocked by something other than AppArmor"
fi

if grep -q 'user namespace with a uid map' "${VERIFY_OUT}"; then
    pass "--verify distinguishes plain userns from a mapped-root userns"
else
    fail "--verify does not report whether a uid map can be written"
fi

echo ""

# ── Test group: HARD path with stubbed namespace commands ──────────

echo "--- Test group: HARD path (stubbed namespace) ---"

STUB="${WORK}/stub"
FAKEBIN="${WORK}/fakebin"
FAKEHOME="${WORK}/home"
mkdir -p "${STUB}" "${FAKEBIN}" "${FAKEHOME}"

REAL_SH="$(command -v dash || command -v sh)"
cp "${REAL_SH}" "${FAKEBIN}/sh"
chmod 755 "${FAKEBIN}/sh"

cat > "${STUB}/unshare" <<'STUBEOF'
#!/bin/bash
# Drop unshare's own flags, run what follows.
while [ $# -gt 0 ]; do
    case "$1" in
        --) shift; break ;;
        -*) shift ;;
        *)  break ;;
    esac
done
exec "$@"
STUBEOF

cat > "${STUB}/ip" <<'STUBEOF'
#!/bin/bash
exit 0
STUBEOF

# Emulates just enough of mount(8): logs every call, and turns a --bind into
# a copy when (and only when) the target is inside the test work directory.
cat > "${STUB}/mount" <<'STUBEOF'
#!/bin/bash
echo "mount $*" >> "${MOUNT_LOG}"
if [ "${1:-}" = "--bind" ]; then
    src="$2"; dst="$3"
    if [ -e "$dst" ]; then
        echo "target-exists $dst" >> "${MOUNT_LOG}"
    else
        echo "target-missing $dst" >> "${MOUNT_LOG}"
        exit 32   # what mount(8) returns for "mount point does not exist"
    fi
    # A real bind makes the target resolve to the source inode, mode
    # included; the copy has to carry the mode across too.
    emulate_bind() { cp -f "$1" "$2" && chmod --reference="$1" "$2"; }
    case "$dst" in
        "${STUB_STASH_ROOT}"/*)
            [ "${STUB_SKIP_STASH_COPY:-0}" = "1" ] || emulate_bind "$src" "$dst" ;;
        "${STUB_FAKEBIN}"/*)
            emulate_bind "$src" "$dst" ;;
        *) : ;;   # never touch anything outside the work directory
    esac
fi
exit 0
STUBEOF

cat > "${STUB}/umount" <<'STUBEOF'
#!/bin/bash
echo "umount $*" >> "${MOUNT_LOG}"
exit 0
STUBEOF
chmod 755 "${STUB}"/*

run_sandbox() {
    local log="$1"; shift
    # The stub overwrites the intercepted shell in place (a real bind mount
    # would live in a private mount namespace and vanish with it), so put a
    # fresh shell back before every run.
    cp -f "${REAL_SH}" "${FAKEBIN}/sh"
    chmod 755 "${FAKEBIN}/sh"
    rm -rf "${FAKEHOME}/.compartment-shells"
    MOUNT_LOG="${log}" \
    STUB_STASH_ROOT="${FAKEHOME}/.compartment-shells" \
    STUB_FAKEBIN="${FAKEBIN}" \
    STUB_SKIP_STASH_COPY="${SKIP_STASH_COPY:-0}" \
    HOME="${FAKEHOME}" \
    SANDBOX_LOGDIR="${WORK}/audit" \
    SANDBOX_UNSHARE="${STUB}/unshare" \
    SANDBOX_SHELLS="${FAKEBIN}/sh" \
    PATH="${STUB}:${PATH}" \
        "${SANDBOX}" "$@"
}

# ── The command runs, and its exit status comes back ───────────────
OUT="${WORK}/run1.out"
RC=0
run_sandbox "${WORK}/mount1.log" /bin/sh -c 'echo SHELL_ALIVE' >"${OUT}" 2>"${WORK}/run1.err" || RC=$?
vsay "$(cat "${WORK}/run1.err")"
if [ "${RC}" -eq 0 ] && grep -q SHELL_ALIVE "${OUT}"; then
    pass "sandbox.sh runs the command through the shell intercept"
else
    fail "sandbox.sh did not run the command (rc=${RC}): $(tail -3 "${WORK}/run1.err" | tr '\n' ' ')"
fi

# ── The stash lives somewhere writable AND executable ──────────────
if grep -qE "^mount -t tmpfs .* ${FAKEHOME}/\.compartment-shells/" "${WORK}/mount1.log" 2>/dev/null; then
    pass "the stash is a private tmpfs under \$HOME"
else
    fail "no tmpfs was mounted for the stash: $(grep -m1 '^mount -t' "${WORK}/mount1.log" 2>/dev/null || echo none)"
fi
if grep -qE '^mount .*(/bin/\.shells|--bind [^ ]+ /bin/\.)' "${WORK}/mount1.log" 2>/dev/null; then
    fail "the stash is still under /bin"
else
    pass "no stash directory was created under /bin"
fi

# ── Bind targets are created before they are bound ─────────────────
if grep -q '^target-missing ' "${WORK}/mount1.log" 2>/dev/null; then
    fail "a bind target did not exist: $(grep -m1 '^target-missing ' "${WORK}/mount1.log" 2>/dev/null)"
else
    pass "every bind target existed before it was bound"
fi
if grep -q "^mount --bind ${CU} ${FAKEBIN}/sh$" "${WORK}/mount1.log" 2>/dev/null; then
    pass "compartment-user is bound over the shell"
else
    fail "the shell was never intercepted"
fi

# ── The exit status of the sandboxed command is propagated ─────────
RC=0
run_sandbox "${WORK}/mount2.log" /bin/sh -c 'exit 7' >/dev/null 2>"${WORK}/run2.err" || RC=$?
if [ "${RC}" -eq 7 ]; then
    pass "the sandboxed command's exit status is returned"
else
    fail "expected exit 7, got ${RC}"
fi
AUDIT_LAST="$(grep 'session ended' "${WORK}/audit"/*.log 2>/dev/null | tail -1 || true)"
if echo "${AUDIT_LAST}" | grep -q 'exit=7'; then
    pass "the audit log records the real exit status"
else
    fail "the audit log lost the exit status: ${AUDIT_LAST:-<none>}"
fi

# ── An intercept that cannot run a shell must abort, not proceed ───
# The stash is left empty, exactly as it was on every HARD-mode run before
# this was fixed: the intercept mounts succeed, the stash does not, and every
# shell in the sandbox exits 127.
RC=0
SKIP_STASH_COPY=1 \
    run_sandbox "${WORK}/mount3.log" /bin/sh -c 'echo SHOULD_NOT_RUN' \
    >"${WORK}/run3.out" 2>"${WORK}/run3.err" || RC=$?
vsay "$(cat "${WORK}/run3.err")"
if [ "${RC}" -ne 0 ]; then
    pass "an unusable shell stash aborts the sandbox"
else
    fail "the sandbox ran with a broken shell intercept (every shell would exit 127)"
fi
if grep -q SHOULD_NOT_RUN "${WORK}/run3.out"; then
    fail "the command ran despite the broken shell intercept"
else
    pass "the command did not run with a broken shell intercept"
fi
if grep -qi 'verification failed' "${WORK}/run3.err"; then
    pass "the failure names the shell-intercept verification"
else
    fail "the failure does not say the shell intercept could not be verified"
fi
if grep -q "^umount ${FAKEBIN}/sh$" "${WORK}/mount3.log" 2>/dev/null; then
    pass "the half-installed intercept is rolled back"
else
    fail "a failed intercept was left in place"
fi

# ── The escape hatch skips the intercept without breaking the run ──
RC=0
MOUNT_LOG="${WORK}/mount4.log" \
HOME="${FAKEHOME}" SANDBOX_LOGDIR="${WORK}/audit" \
SANDBOX_NO_SHELL_INTERCEPT=1 SANDBOX_UNSHARE="${STUB}/unshare" \
PATH="${STUB}:${PATH}" \
    "${SANDBOX}" /bin/sh -c 'echo NO_INTERCEPT_OK' >"${WORK}/run4.out" 2>&1 || RC=$?
if [ "${RC}" -eq 0 ] && grep -q NO_INTERCEPT_OK "${WORK}/run4.out"; then
    pass "SANDBOX_NO_SHELL_INTERCEPT=1 runs without the intercept"
else
    fail "SANDBOX_NO_SHELL_INTERCEPT=1 did not run the command (rc=${RC})"
fi

echo ""

# ── Summary ────────────────────────────────────────────────────────

# The suite declares its own assertion count. A block that stops
# running — a `skip` standing in for twenty assertions, a group
# guarded by a tool that is not installed — changes the total, and a
# changed total is a failure rather than a smaller number nobody
# compares against anything.
harness_expect_total 19

echo "=== Results ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  SKIP: ${SKIP}"
echo ""
# The runner sums these lines; one per suite (tests/scripts/rootless.d/README.md).
echo "SUMMARY sandbox: pass=${PASS} fail=${FAIL} skip=${SKIP}"

if [ "${FAIL}" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
