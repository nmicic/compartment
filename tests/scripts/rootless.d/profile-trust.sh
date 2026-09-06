#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# profile-trust.sh — regression tests for profile trust, the parser,
# $HOME validation, audit-log hardening and environment sanitization.
#
# Every assertion here fails against a build that predates the fix it
# guards. To confirm that, point the suite at another binary:
#
#   COMPARTMENT_USER=/path/to/old/compartment-user \
#   COMPARTMENT_ROOT=/path/to/old/compartment-root \
#     bash tests/scripts/rootless.d/profile-trust.sh
#
# Usage: ./tests/scripts/rootless.d/profile-trust.sh [--verbose]

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

echo "=== Profile trust / parser / audit test suite ==="
echo ""

if [ ! -x "${CU}" ]; then
    echo "ERROR: ${CU} not found. Run 'make' first."
    exit 1
fi
if [ ! -x "${CR}" ]; then
    echo "ERROR: ${CR} not found. Run 'make' first."
    exit 1
fi

WORK="$(mktemp -d)"
cleanup() { chmod -R u+w "${WORK}" 2>/dev/null; rm -rf "${WORK}"; }
trap cleanup EXIT
chmod 0700 "${WORK}"

# Run a command, capture stdout+stderr into OUT and status into RC.
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

# A private home with a private profile directory.
mk_home() {
    local h="$1"
    rm -rf "${h}"
    mkdir -p "${h}/.config/compartment"
    chmod go-w "${h}" "${h}/.config" "${h}/.config/compartment"
}

want_rc_nonzero() {
    local label="$1"
    if [ "${RC}" -ne 0 ]; then pass "${label}"
    else fail "${label} (expected non-zero exit, got 0)"; fi
}
want_rc() {
    local label="$1" want="$2"
    if [ "${RC}" -eq "${want}" ]; then pass "${label}"
    else fail "${label} (expected rc=${want}, got rc=${RC})"; fi
}
want_out() {
    local label="$1" pat="$2"
    if printf '%s' "${OUT}" | grep -qF -- "${pat}"; then pass "${label}"
    else fail "${label} (expected '${pat}' in output)"; fi
}
want_no_out() {
    local label="$1" pat="$2"
    if printf '%s' "${OUT}" | grep -qF -- "${pat}"; then
        fail "${label} (unexpected '${pat}' in output)"
    else pass "${label}"; fi
}
# Same, but the pattern is an extended regex, for anchored matches.
want_no_re() {
    local label="$1" re="$2"
    if printf '%s' "${OUT}" | grep -qE -- "${re}"; then
        fail "${label} (unexpected /${re}/ in output)"
    else pass "${label}"; fi
}

# ── C1: a user profile must not outrank /etc, nor disable enforcement ──

echo "--- Test group: profile search order (C1) ---"

H="${WORK}/agenthome"
mk_home "${H}"
printf 'landlock off\nseccomp off\nno-new-privs off\nenv-sanitize off\n' \
    > "${H}/.config/compartment/ai-agent.conf"
chmod go-w "${H}/.config/compartment/ai-agent.conf"

run env HOME="${H}" "${CU}" -- /bin/sh -c 'grep -E "^(NoNewPrivs|Seccomp):" /proc/self/status'
want_out "C1: \$HOME profile does not disable no_new_privs" "NoNewPrivs:	1"
want_out "C1: \$HOME profile does not disable seccomp"      "Seccomp:	2"

# The same file is still refused outright when the user opts in, because a
# profile may only tighten.
run env HOME="${H}" "${CU}" --user-profiles --dry-run -- /bin/true
want_rc_nonzero "C1: --user-profiles + 'landlock off' refused"
want_out "C1: refusal names the one-way rule" "is not allowed in a profile"

# A benign user profile: ignored by default, honoured with --user-profiles.
printf 'ro /usr\nro /bin\nro /lib\nro /lib64\nro /etc\nrw /tmp\nblock ptrace\n' \
    > "${H}/.config/compartment/ai-agent.conf"
chmod go-w "${H}/.config/compartment/ai-agent.conf"

run env HOME="${H}" "${CU}" --verbose --dry-run -- /bin/true
want_out "C1: user profile ignored without --user-profiles" "profile ai-agent (built-in)"

run env HOME="${H}" "${CU}" --verbose --user-profiles --dry-run -- /bin/true
want_out "C1: user profile honoured with --user-profiles" \
         "${H}/.config/compartment/ai-agent.conf"

# Shell-replacement mode never consults $HOME. The stash lives inside the
# fake home so the ai-agent rwx $HOME rule lets the shell exec either way.
printf 'landlock off\nseccomp off\nno-new-privs off\n' \
    > "${H}/.config/compartment/ai-agent.conf"
chmod go-w "${H}/.config/compartment/ai-agent.conf"
SHDIR="${H}/shells"
mkdir -p "${SHDIR}"; chmod go-w "${SHDIR}"
cp /bin/sh "${SHDIR}/fakesh"
ln -sf "$(readlink -f "${CU}")" "${H}/fakesh"
run env HOME="${H}" COMPARTMENT_SHELL_DIR="${SHDIR}" "${H}/fakesh" \
    -c 'grep -E "^(NoNewPrivs|Seccomp):" /proc/self/status'
want_out "C1: shell-replacement ignores \$HOME profile (seccomp)" "Seccomp:	2"
want_out "C1: shell-replacement ignores \$HOME profile (nnp)" "NoNewPrivs:	1"

echo ""

# ── Profile file trust ────────────────────────────────────────────────

# ── C3: invalid values, unknown directives, other-tool directives ────

echo "--- Test group: directive and value validation (C3) ---"

mkconf() {
    local name="$1"; shift
    printf '%s\n' "$@" > "${WORK}/${name}.conf"
    chmod go-w "${WORK}/${name}.conf"
    printf '%s\n' "${WORK}/${name}.conf"
}

# `seccomp-mode` and `env-mode` used to take any value: anything that was
# not allow/allowlist selected deny-list mode with no diagnostic, so a
# misspelled mode line silently swapped a default-deny allow-list for a
# default-allow deny-list. Every other value-taking directive already
# refused an unknown value.
for d in seccomp-mode env-mode; do
    run "${CU}" --dry-run --profile "$(mkconf "bad-${d}" "ro /usr" "${d} allowlst")" -- /bin/true
    want_rc_nonzero "C3: '${d} allowlst' is fatal"
    want_out "C3: the ${d} refusal names the valid values" \
             "invalid value for ${d}: 'allowlst' (use allow/allowlist or deny/denylist)"
done

# The explicit deny spellings are accepted, so the check is a whitelist
# and not "anything but a typo I thought of".
run "${CU}" --dry-run --profile "$(mkconf "sec-deny" "ro /usr" "seccomp-mode denylist" "block ptrace")" -- /bin/true
want_rc "C3: 'seccomp-mode denylist' is accepted" 0
want_out "C3: 'denylist' really selects deny-list mode" "DENY-LIST"
run "${CU}" --dry-run --profile "$(mkconf "env-deny-mode" "ro /usr" "env-mode deny" "env-deny FOO")" -- /bin/true
want_rc "C3: 'env-mode deny' is accepted" 0
want_out "C3: 'deny' really selects deny-list mode" "env: DENY-LIST"

# An unknown directive was a warning on stderr and the run continued, so
# a misspelled security-relevant line left the process running with
# weaker policy than its author wrote.
run "${CU}" --dry-run --profile "$(mkconf "typo" "ro /usr" "blokc ptrace")" -- /bin/true
want_rc_nonzero "C3: an unknown directive is fatal"
want_out "C3: the refusal names the directive" "unknown directive 'blokc'"
want_out "C3: the refusal says why it is fatal" "a profile is policy"

# A directive belonging to the OTHER tool is a different situation and
# gets a different message: the shared parser recognises it, so ignoring
# it is right — but silently ignoring it is how a cap-allow line reads as
# policy when it is not.
run "${CU}" --dry-run --profile "$(mkconf "otherTool" "ro /usr" "cap-allow sys_admin" "rootdir /srv/x")" -- /bin/true
want_rc "C3: a compartment-root directive does not stop compartment-user" 0
want_out "C3: the warning names the owning tool (cap-allow)" \
         "'cap-allow' is a compartment-root directive; compartment-user ignores it"
want_out "C3: the warning names the owning tool (rootdir)" \
         "'rootdir' is a compartment-root directive; compartment-user ignores it"

echo ""

# ── T27-T30: the empty allow-list shapes ─────────────────────────────

echo "--- Test group: empty allow-lists (T27-T30) ---"

# T27/T28: `env-mode allow` with no `env-allow` is a silent clearenv().
# It is fail-closed, but nothing anywhere recorded that it is what
# happens, so a change to fail-open would have been invisible.
ENVOUT_EMPTY="$(env FOO=bar BAZ=qux "${CU}" --no-seccomp \
    --profile "$(mkconf "envallow-empty" "ro /usr" "ro /bin" "ro /lib" "ro /lib64" \
                        "ro /etc" "env-mode allow" "landlock on")" \
    -- /usr/bin/env 2>/dev/null)"
if [ -z "${ENVOUT_EMPTY}" ]; then
    pass "T27: 'env-mode allow' with an empty env-allow clears the environment"
else
    fail "T27: 'env-mode allow' with an empty env-allow leaked: $(printf '%s' "${ENVOUT_EMPTY}" | tr '\n' ' ' | cut -c1-120)"
fi

ENVOUT_ONE="$(env FOO=bar BAZ=qux "${CU}" --no-seccomp \
    --profile "$(mkconf "envallow-one" "ro /usr" "ro /bin" "ro /lib" "ro /lib64" \
                        "ro /etc" "env-mode allow" "env-allow FOO" "landlock on")" \
    -- /usr/bin/env 2>/dev/null)"
if printf '%s\n' "${ENVOUT_ONE}" | grep -q '^FOO=bar$' &&
   ! printf '%s\n' "${ENVOUT_ONE}" | grep -q '^BAZ='; then
    pass "T28: a non-empty env-allow keeps exactly what it names"
else
    fail "T28: env-allow FOO produced: $(printf '%s' "${ENVOUT_ONE}" | tr '\n' ' ' | cut -c1-120)"
fi

# T29: `seccomp-mode allow` with no `allow` lines is a filter that denies
# everything. It must refuse to start rather than install it.
run "${CU}" --profile "$(mkconf "scallow-empty" "ro /usr" "ro /bin" "ro /lib" \
                                "ro /lib64" "ro /etc" "seccomp-mode allow" "landlock on")" \
    -- /bin/true
want_rc_nonzero "T29: 'seccomp-mode allow' with an empty allow-list refuses to run"
want_out "T29: the refusal names the empty list" "seccomp allow-mode with empty list"

# T30: the same profile with a real allow-list is reported as allow-list
# mode (tools/syscall.py's generated profiles are the end-to-end half of
# this, in aux-tools.sh).
run "${CU}" --dry-run --profile "$(mkconf "scallow-some" "ro /usr" "seccomp-mode allow" \
                                          "allow read" "allow write" "allow exit_group")" -- /bin/true
want_rc "T30: 'seccomp-mode allow' with a list parses" 0
want_out "T30: it is reported as allow-list mode" "ALLOW-LIST"

echo ""

# ── T36: --insecure, the degraded-enforcement escape hatch ───────────

echo "--- Test group: --insecure (T36) ---"

# The one flag that lets a run continue with enforcement degraded had no
# test at all.
run "${CU}" --help
want_out "T36: --insecure is documented in --help" "--insecure"

# On a host where preflight is clean it must change nothing: the flag
# permits a degraded run, it does not create one.
A_PLAIN="$("${CU}" --dry-run -- /bin/true 2>&1)"
A_INSEC="$("${CU}" --insecure --dry-run -- /bin/true 2>&1)"
if [ -n "${A_PLAIN}" ] && [ "${A_PLAIN}" = "${A_INSEC}" ]; then
    pass "T36: --insecure does not change the policy when preflight is clean"
else
    fail "T36: --insecure changed the dry-run output on a clean host"
fi

run "${CU}" --insecure -- /bin/sh -c 'grep -E "^(NoNewPrivs|Seccomp):" /proc/self/status'
want_out "T36: --insecure still applies no_new_privs" "NoNewPrivs:	1"
want_out "T36: --insecure still installs the seccomp filter" "Seccomp:	2"

# The degraded half needs a filesystem Landlock cannot enforce (9p, NFS,
# CIFS or FUSE). Neither the host nor the guests have one, so it is a
# stated skip rather than an untested claim.
DEGRADED_MNT=""
while read -r _dev _mnt _fstype _rest; do
    case "${_fstype}" in
        9p|nfs|nfs4|cifs|fuse|fuse.*) DEGRADED_MNT="${_mnt}"; break ;;
    esac
done < /proc/mounts
if [ -z "${DEGRADED_MNT}" ]; then
    skip_group 3 "T36: the degraded path needs a 9p/NFS/CIFS/FUSE mount; this host has none"
else
    run "${CU}" --ro "${DEGRADED_MNT}" -- /bin/true
    want_rc_nonzero "T36: a path Landlock cannot enforce is refused without --insecure"
    want_out "T36: the refusal names the preflight failure" "REFUSING to execute"
    run "${CU}" --insecure --ro "${DEGRADED_MNT}" -- /bin/true
    want_out "T36: --insecure runs it and says so" "INSECURE mode"
fi

echo ""

echo "--- Test group: profile file trust (C1/C2) ---"

cp "${REPO_DIR}/tests/profiles/test-fs-rw.conf" "${WORK}/ww.conf"
chmod 0666 "${WORK}/ww.conf"
run "${CU}" --dry-run --profile "${WORK}/ww.conf" -- /bin/true
want_rc_nonzero "trust: world-writable profile refused"
want_out "trust: message names the mode" "group- or world-writable policy is not trusted"

mkdir -p "${WORK}/wwdir"
chmod 0777 "${WORK}/wwdir"
cp "${REPO_DIR}/tests/profiles/test-fs-rw.conf" "${WORK}/wwdir/p.conf"
chmod 0644 "${WORK}/wwdir/p.conf"
run "${CU}" --dry-run --profile "${WORK}/wwdir/p.conf" -- /bin/true
want_rc_nonzero "trust: profile in a world-writable directory refused"
want_out "trust: message names the directory" "profile directory"

# The documented private-group exemption (HOWTO): umask 002 plus a
# user-private group leaves everything a user creates at 0664, and
# group-write is then no wider than owner-write because the group has
# exactly one member. Assert the exemption in both directions here; the
# refusal half needs a group the caller is not in and therefore lives in
# root.d/profile-trust-root.sh.
cp "${REPO_DIR}/tests/profiles/test-fs-rw.conf" "${WORK}/gw-private.conf"
chmod 0664 "${WORK}/gw-private.conf"
GW_GROUP_MEMBERS="$(getent group "$(id -g)" | cut -d: -f4)"
if [ "$(id -gn)" = "$(id -un)" ] && [ -z "${GW_GROUP_MEMBERS}" ]; then
    run "${CU}" --dry-run --profile "${WORK}/gw-private.conf" -- /bin/true
    want_rc "trust: 0664 in your own private group is accepted" 0
    mkdir -p "${WORK}/gwprivdir"
    chmod 0775 "${WORK}/gwprivdir"
    cp "${REPO_DIR}/tests/profiles/test-fs-rw.conf" "${WORK}/gwprivdir/p.conf"
    chmod 0644 "${WORK}/gwprivdir/p.conf"
    run "${CU}" --dry-run --profile "${WORK}/gwprivdir/p.conf" -- /bin/true
    want_rc "trust: 0775 directory in your own private group is accepted" 0
else
    skip "trust: 0664 in your own private group (gid $(id -g) is not private)"
    skip "trust: 0775 directory in your own private group (gid $(id -g) is not private)"
fi

# A sticky world-writable directory (/tmp) is fine: the sticky bit is what
# stops a third party replacing the file.
STICKY="/tmp/compartment-trust-$$.conf"
cp "${REPO_DIR}/tests/profiles/test-fs-rw.conf" "${STICKY}"
chmod 0644 "${STICKY}"
run "${CU}" --dry-run --profile "${STICKY}" -- /bin/true
want_rc "trust: profile directly in sticky /tmp accepted" 0
rm -f "${STICKY}"

echo ""

# ── H1: a rejected profile must contribute nothing ────────────────────

echo "--- Test group: transactional parse (H1) ---"

# The original failure mode: a profile rejected mid-file had already
# applied its earlier lines, the caller then layered the built-in on top,
# and the result was reported as "(built-in)".
mk_home "${WORK}/badhome"
printf 'rwx /\nlandlock oops\n' \
    > "${WORK}/badhome/.config/compartment/ai-agent.conf"
chmod go-w "${WORK}/badhome/.config/compartment/ai-agent.conf"
run env HOME="${WORK}/badhome" "${CU}" --dry-run -- /bin/true
want_no_re "H1: a rejected profile injects no rule into the built-in" "rwx /$"
want_out "H1: the reported policy source is honest" "(built-in)"

printf 'rwx /\nseccomp-mode allow\nallow read\nlandlock oops\n' > "${WORK}/bad.conf"
chmod go-w "${WORK}/bad.conf"
run "${CU}" --dry-run --profile "${WORK}/bad.conf" -- /bin/true
want_rc_nonzero "H1: profile with a bad directive is fatal"
want_no_re "H1: no rule from the rejected profile leaks" "rwx /$"
want_no_out "H1: does not claim to be running the built-in" "(built-in)"

printf 'ro /usr\nlandlock oops\n' > "${WORK}/base.conf"
printf 'inherit base\nro /bin\n' > "${WORK}/child.conf"
chmod go-w "${WORK}/base.conf" "${WORK}/child.conf"
run "${CU}" --dry-run --profile "${WORK}/child.conf" -- /bin/true
want_rc_nonzero "H1: a rejected inherited profile is fatal"
want_out "H1: names the inherited profile" "inherited profile 'base' was rejected"

# Not found is still distinguishable from invalid.
run "${CU}" --dry-run --profile "${WORK}/does-not-exist.conf" -- /bin/true
want_out "H1: missing profile reports the path it looked for" "looked for the file:"

echo ""

# ── H2: inline comments ───────────────────────────────────────────────

echo "--- Test group: inline comments (H2) ---"

cat > "${WORK}/comment.conf" <<'EOF'
ro /usr           # system libraries
ro /bin
ro /lib
ro /lib64
ro /etc
rw /tmp           # scratch
env-deny LD_PRELOAD   # linker injection
block ptrace          # no debugging
EOF
chmod go-w "${WORK}/comment.conf"

run "${CU}" --verbose --profile "${WORK}/comment.conf" -- /bin/true
want_rc "H2: commented 'ro /usr' still installs a usable rule" 0
want_no_out "H2: no unknown-syscall warning from a commented 'block'" "unknown syscall"

# Same profile with an uncommented 'ro /usr', so the child definitely
# execs and an empty result cannot be mistaken for "variable stripped".
cat > "${WORK}/comment2.conf" <<'EOF'
ro /usr
ro /bin
ro /lib
ro /lib64
ro /etc
rw /tmp
env-deny LD_PRELOAD   # linker injection
EOF
chmod go-w "${WORK}/comment2.conf"
OUT="$(LD_PRELOAD=/nonexistent.so "${CU}" --no-seccomp \
        --profile "${WORK}/comment2.conf" -- /usr/bin/env 2>/dev/null)"
RC=$?
want_out "H2: the probe actually ran" "PATH="
want_no_out "H2: commented 'env-deny LD_PRELOAD' still strips it" "LD_PRELOAD="

printf 'ro /usr\nro /bin\nro /lib\nro /lib64\nro /etc\nrw /tmp/cmp#hash\n' \
    > "${WORK}/hash.conf"
chmod go-w "${WORK}/hash.conf"
run "${CU}" --dry-run --profile "${WORK}/hash.conf" -- /bin/true
want_out "H2: a '#' inside a token stays literal" "rw /tmp/cmp#hash"

echo ""

# ── H3: policy arrays fail closed ─────────────────────────────────────

echo "--- Test group: policy array overflow (H3) ---"

EXTRA=""
for sc in read write close openat lseek dup dup3 fcntl ioctl fstat getcwd \
          chdir mkdirat unlinkat fchmod fchown umask mmap mprotect munmap \
          brk mremap madvise getpid getppid; do
    EXTRA="${EXTRA} --block ${sc}"
done
# shellcheck disable=SC2086
run "${CU}" --dry-run ${EXTRA} -- /bin/true
want_out "H3: 25 extra blocks do not evict pidfd_getfd" "block pidfd_getfd"
want_out "H3: 25 extra blocks do not evict mount_setattr" "block mount_setattr"

OVER=""
for _ in $(seq 1 260); do OVER="${OVER} --block vhangup"; done
# shellcheck disable=SC2086
run "${CU}" --dry-run ${OVER} -- /bin/true
want_rc_nonzero "H3: overflowing the blocked-syscall array is fatal"
want_out "H3: overflow message refuses rather than truncates" \
         "refusing to run with a truncated policy"

echo ""

# ── One-way security switches ─────────────────────────────────────────

echo "--- Test group: one-way security switches ---"

for sw in landlock seccomp no-new-privs env-sanitize; do
    printf 'ro /usr\n%s off\n' "${sw}" > "${WORK}/off.conf"
    chmod go-w "${WORK}/off.conf"
    run "${CU}" --dry-run --profile "${WORK}/off.conf" -- /bin/true
    want_rc_nonzero "one-way: '${sw} off' in a profile is fatal"
done

# The CLI flags still work.
run "${CU}" --dry-run --no-seccomp -- /bin/true
want_out "one-way: --no-seccomp still disables seccomp" "seccomp: no"

echo ""

# ── M2: $HOME validation ──────────────────────────────────────────────

echo "--- Test group: \$HOME validation (M2) ---"

run env HOME=/ "${CU}" --dry-run -- /bin/true
want_rc_nonzero "M2: HOME=/ refused"
want_no_re "M2: no 'rwx /' rule from HOME=/" "rwx /$"

run env HOME=/etc "${CU}" --dry-run -- /bin/true
want_rc_nonzero "M2: HOME not owned by the caller refused"

run env HOME=relative "${CU}" --dry-run -- /bin/true
want_rc_nonzero "M2: relative HOME refused"

run env HOME="${WORK}/no-such-dir" "${CU}" --dry-run -- /bin/true
want_rc_nonzero "M2: nonexistent HOME refused"

echo ""

# ── M3 / L8: shell-replacement mode ───────────────────────────────────

echo "--- Test group: shell replacement (M3, L8) ---"

EVIL="${WORK}/evilshells"
mkdir -p "${EVIL}"
cp /bin/echo "${EVIL}/fakesh"
chmod 0777 "${EVIL}"
run env HOME="${H}" COMPARTMENT_SHELL_DIR="${EVIL}" "${H}/fakesh" -c true
want_out "M3: world-writable COMPARTMENT_SHELL_DIR rejected" \
         "group- or world-writable policy is not trusted"
want_out "M3: falls back to the compile-time stash directory" "falling back to"

# fd cleanup reaches the replaced shell too.
HL="${WORK}/l8home"
mk_home "${HL}"
SHL="${HL}/shells"
mkdir -p "${SHL}"; chmod go-w "${SHL}"
cp /bin/sh "${SHL}/l8sh"
ln -sf "$(readlink -f "${CU}")" "${HL}/l8sh"
OUT="$(HOME="${HL}" COMPARTMENT_SHELL_DIR="${SHL}" "${HL}/l8sh" \
        -c 'ls /proc/self/fd | tr "\n" " "' 9< /etc/hostname 2>/dev/null)"
RC=$?
if [ -z "${OUT}" ]; then
    skip "L8: shell-replacement fd cleanup (shell did not run)"
elif printf '%s' "${OUT}" | grep -qw 9; then
    fail "L8: fd 9 leaked into the replaced shell (${OUT})"
else
    pass "L8: inherited fds are closed before the replaced shell"
fi

echo ""

# ── H8: compartment-root --profile= form ──────────────────────────────

echo "--- Test group: compartment-root option parsing (H8) ---"

# Pre-fix, every one of these silently discarded the profile and exited 0.
run "${CR}" --dry-run --profile=/nonexistent/x.conf -c /srv/x -U root -- /bin/sh
want_rc_nonzero "H8: --profile=FILE is parsed (missing file is fatal)"

run "${CR}" --dry-run -p/nonexistent/x.conf -c /srv/x -U root -- /bin/sh
want_rc_nonzero "H8: -pFILE is parsed"

run "${CR}" --dry-run -dvp/nonexistent/x.conf -c /srv/x -U root -- /bin/sh
want_rc_nonzero "H8: clustered -dvpFILE is parsed"

# A user-owned profile is refused by compartment-root whichever form is used.
cp "${REPO_DIR}/examples/container.conf" "${WORK}/c.conf"
chmod go-w "${WORK}/c.conf"
run "${CR}" --dry-run "--profile=${WORK}/c.conf" -c /srv/x -U root -- /bin/sh
want_rc_nonzero "C2: compartment-root refuses a non-root-owned profile"
want_out "C2: message says root ownership is required" "must be owned by root"

run "${CR}" --dry-run --profile container -c /srv/x -U root -- /bin/sh
want_no_out "C2: compartment-root never searches \$HOME" ".config/compartment"

echo ""

# ── M7: audit log directory ───────────────────────────────────────────

echo "--- Test group: audit log hardening (M7) ---"

mkdir -p "${WORK}/audit-real"
ln -sfn "${WORK}/audit-real" "${WORK}/audit-link"
run "${CU}" --no-landlock --no-seccomp --audit-log "${WORK}/audit-link" -- /bin/true
want_rc_nonzero "M7: symlinked audit directory refused"

mkdir -p "${WORK}/audit-loose"
chmod 0777 "${WORK}/audit-loose"
run "${CU}" --no-landlock --no-seccomp --audit-log "${WORK}/audit-loose" -- /bin/true
want_rc_nonzero "M7: world-writable audit directory refused"
want_out "M7: message names the problem" "not a private, self-owned directory"

# The default must be somewhere the sandboxed process cannot reach. It
# used to be /var/tmp/compartment-audit-$UID (world-writable parent, no
# ownership check); an intermediate revision of this branch moved it under
# $HOME, which the built-in ai-agent profile grants rwx.
AUD="/var/tmp/compartment-audit-$(id -u)"
# /var/tmp is world-writable and sticky, so any local user can pre-create
# this directory — and so does any earlier --audit run. Skipping on it
# turned ten assertions into one `skip` and took mutation M19 (audit log
# moved into $HOME) from caught-by-nine-assertions to escaped, with one
# mkdir. A leftover that is ours is removed; one that is not is an
# environment failure, not a reason to stop testing.
AUD_BLOCKED=""
if [ -e "${AUD}" ] || [ -L "${AUD}" ]; then
    if [ -L "${AUD}" ] || [ ! -d "${AUD}" ]; then
        AUD_BLOCKED="${AUD} exists and is not a plain directory"
    elif [ "$(stat -c %u "${AUD}" 2>/dev/null)" != "$(id -u)" ]; then
        AUD_BLOCKED="${AUD} is owned by uid $(stat -c %u "${AUD}" 2>/dev/null), not by you"
    else
        rm -rf "${AUD}"
        [ -e "${AUD}" ] && AUD_BLOCKED="${AUD} could not be removed"
    fi
fi
if [ -n "${AUD_BLOCKED}" ]; then
    fail "M7: the default audit directory is not testable here (${AUD_BLOCKED})"
    skip_group 9 "M7: the remaining default-audit-directory assertions"
else
    OUT="$("${CU}" --verbose --no-landlock --no-seccomp --audit -- /bin/true 2>&1 \
           | grep 'audit log:')"
    RC=0
    want_out "M7: default audit directory is ${AUD}" "${AUD}/"
    want_no_out "M7: default audit directory is not under \$HOME" "${HOME}/"

    if [ -d "${AUD}" ] && [ "$(stat -c %a "${AUD}")" = "700" ]; then
        pass "M7: default audit directory is created 0700"
    else
        fail "M7: default audit directory is mode $(stat -c %a "${AUD}" 2>/dev/null)"
    fi

    # A newline in the command must not forge a record.
    NLCMD="${WORK}/ok
FORGED user=root uid=0 event=NOTHING"
    : > "${NLCMD}"
    "${CU}" --no-landlock --no-seccomp --audit -- "${NLCMD}" >/dev/null 2>&1
    LOGF="$(ls "${AUD}/"*.log 2>/dev/null | head -1)"
    # `grep -c event= == wc -l` is 0 -eq 0 on an empty file, so this
    # passed when auditing had stopped entirely. Require at least one
    # real record before comparing.
    LOG_LINES=0
    [ -n "${LOGF}" ] && LOG_LINES="$(wc -l < "${LOGF}")"
    if [ -z "${LOGF}" ]; then
        fail "M7: audit log file was not created"
    elif [ "${LOG_LINES}" -lt 1 ]; then
        fail "M7: the audit log is empty — nothing was recorded to forge"
    elif [ "$(grep -c 'event=' "${LOGF}")" -eq "${LOG_LINES}" ] &&
         ! grep -q '^FORGED' "${LOGF}"; then
        pass "M7: newline in the command cannot forge a log record"
    else
        fail "M7: forged record in the audit log ($(cat "${LOGF}"))"
    fi

    # The whole point of the location: the confined process must not be
    # able to rewrite its own trail. /var/tmp is in no built-in path rule,
    # so neither write nor read succeeds.
    DAYLOG="$(basename "${LOGF:-$(date +%F).log}")"
    run "${CU}" --audit -- /bin/sh -c ": > '${AUD}/${DAYLOG}'"
    want_rc_nonzero "M7: sandboxed child cannot write the audit log"
    want_out "M7: the write is denied by Landlock" "Permission denied"

    run "${CU}" --audit -- /bin/sh -c "head -c 1 '${AUD}/${DAYLOG}'"
    want_out "M7: sandboxed child cannot read the audit log" "Permission denied"

    # A directory left behind by someone else under sticky /var/tmp must
    # be fatal, not something we quietly append to.
    rm -rf "${AUD}"
    install -d -m 0755 "${AUD}"
    run "${CU}" --no-landlock --no-seccomp --audit -- /bin/true
    want_rc_nonzero "M7: a default audit directory with the wrong mode is fatal"
    want_out "M7: the refusal names the path" "${AUD}"
    want_out "M7: the refusal names the expected mode" "mode 0700"

    rm -rf "${AUD}"
fi

echo ""

# ── M10 / M12: environment sanitization ───────────────────────────────

echo "--- Test group: environment deny-list (M10, M12) ---"

ENVOUT="$(env GLIBC_TUNABLES=x LD_DEBUG=all LD_PROFILE=p PYTHONPATH=/e \
              PYTHONHOME=/e PERL5DB=x IFS=: PROMPT_COMMAND=id ZDOTDIR=/e \
              GIT_SSH_COMMAND=id GIT_CONFIG_GLOBAL=/e GIT_EDITOR=id PAGER=id \
              MANPAGER=id EDITOR=id VISUAL=id RUBYOPT=x NODE_OPTIONS=x \
              BASH_ENV=/e ENV=/e LD_PRELOAD=/e \
              MODEL_API_KEY=sk-a PROVIDER_API_KEY=sk-b \
              "${CU}" --no-landlock --no-seccomp -- /usr/bin/env 2>/dev/null)"
for v in GLIBC_TUNABLES LD_DEBUG LD_PROFILE LD_PRELOAD PYTHONPATH PYTHONHOME \
         PERL5DB IFS PROMPT_COMMAND ZDOTDIR GIT_SSH_COMMAND GIT_CONFIG_GLOBAL \
         GIT_EDITOR PAGER MANPAGER EDITOR VISUAL RUBYOPT NODE_OPTIONS \
         BASH_ENV ENV; do
    if printf '%s\n' "${ENVOUT}" | grep -q "^${v}="; then
        fail "M10: ${v} reached the sandboxed process"
    else
        pass "M10: ${v} stripped"
    fi
done
for v in MODEL_API_KEY PROVIDER_API_KEY; do
    if printf '%s\n' "${ENVOUT}" | grep -q "^${v}="; then
        pass "M10: ${v} preserved (agents need their provider key)"
    else
        fail "M10: ${v} was stripped — the flagship use case is broken"
    fi
done

# A crafted environment entry with no '=' cannot be removed by unsetenv(),
# which reports success and leaves it in place. sanitize_env() must not
# spin on it. Only execve() with a hand-built envp can produce one.
NOEQ_SRC="${WORK}/noeq.c"
cat > "${NOEQ_SRC}" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    char *env[] = { "LD_NOEQUALS", "PATH=/usr/bin:/bin", NULL };
    char *args[] = { argv[1], "--no-landlock", "--no-seccomp", "--profile",
                     "none", "--", "/usr/bin/env", NULL };
    (void)argc;
    execve(argv[1], args, env);
    perror("execve");
    return 1;
}
EOF
if cc -o "${WORK}/noeq" "${NOEQ_SRC}" 2>/dev/null; then
    timeout 10 "${WORK}/noeq" "${CU}" >/dev/null 2>&1
    NRC=$?
    if [ "${NRC}" -eq 124 ]; then
        fail "env: sanitize_env spins on an environ entry with no '='"
    else
        pass "env: an environ entry with no '=' does not hang sanitize_env"
    fi
else
    skip "env: no C compiler for the malformed-environ probe"
fi

echo ""

# ── M11 / L11: --dump-profile ─────────────────────────────────────────

echo "--- Test group: --dump-profile (M11, L11) ---"

run "${CU}" --dump-profile ai-agent
want_rc "M11: --dump-profile needs no command" 0
want_out "M11: dump contains the \$HOME rule" "rwx ${HOME}"
want_out "M11: dump contains the container-escape blocks" "block pidfd_getfd"
want_out "M11: dump uses prefix env entries" "env-deny LD_*"

"${CU}" --dump-profile ai-agent > "${WORK}/dumped.conf" 2>/dev/null
chmod go-w "${WORK}/dumped.conf"
A="$("${CU}" --dry-run --profile ai-agent -- /bin/true 2>&1 | grep -v 'profile')"
B="$("${CU}" --dry-run --profile "${WORK}/dumped.conf" -- /bin/true 2>&1 | grep -v 'profile')"
# Both sides are greps of tool output, so "" = "" satisfied this whenever
# the tool printed nothing at all. Require a policy to have been printed.
if ! printf '%s\n' "${A}" | grep -q 'landlock:'; then
    fail "M11: the built-in dry-run printed no policy to compare against"
elif [ "${A}" = "${B}" ]; then
    pass "M11: --dump-profile output reloads to the same policy"
else
    fail "M11: dumped profile does not round-trip"
fi

C="$("${CU}" --dry-run --profile "${REPO_DIR}/examples/ai-agent.conf" -- /bin/true 2>&1 \
     | grep -v 'profile')"
if [ "${A}" = "${C}" ]; then
    pass "L11: examples/ai-agent.conf matches the built-in"
else
    fail "L11: examples/ai-agent.conf differs from the built-in"
fi

echo ""

# ── Profile source reporting ──────────────────────────────────────────

echo "--- Test group: profile source reporting ---"

run "${CU}" --verbose --dry-run -- /bin/true
want_out "source: --verbose names the resolved profile" "profile ai-agent (built-in)"

run "${CU}" --no-landlock --no-seccomp --audit \
    --audit-log "${WORK}/audit-src" -- /bin/true
want_out "source: the audit line records where the policy came from" "source=built-in"

echo ""

# ── Summary ───────────────────────────────────────────────────────────

# The suite declares its own assertion count. A block that stops
# running — a `skip` standing in for twenty assertions, a group
# guarded by a tool that is not installed — changes the total, and a
# changed total is a failure rather than a smaller number nobody
# compares against anything.
harness_expect_total 124

echo "=== Results ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  SKIP: ${SKIP}"
echo ""
# The runner sums these lines; one per suite (tests/scripts/*.d/README.md).
echo "SUMMARY profile-trust: pass=${PASS} fail=${FAIL} skip=${SKIP}"

if [ "${FAIL}" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
