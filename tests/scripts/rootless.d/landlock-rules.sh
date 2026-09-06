#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# landlock-rules.sh — per-file Landlock rules, TCP port rules, and the
# policy shapes the tool now refuses
#
# Covers, for compartment-user only (nothing here needs root):
#   A  per-file rules: a rule naming a FILE installs and takes effect
#   B  missing paths are fatal; a trailing '?' makes a rule optional
#   C  --verbose reports rules INSTALLED, not rules asked for
#   D  M9: a `ro` rule nested in a `rw`/`rwx` rule is refused
#   E  `exec` semantics, and the difference from `ro`
#   F  Landlock TCP port rules against a real loopback listener
#   G  seccomp-default parsing
#   H  make install-profiles is not part of make install
#   I  the audit-log-inside-a-writable-rule warning
#
# Every filesystem assertion runs a real command inside the sandbox and
# requires a positive marker in its output, so nothing here can pass because
# a probe never executed.
#
# See README.md for the contract this script honours.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/scripts/lib/harness.sh
. "${SCRIPT_DIR}/../lib/harness.sh"

REPO_DIR="$(harness_repo_dir)"
CU="${REPO_DIR}/compartment-user"

echo "=== Landlock rule semantics ==="
echo ""

if [ ! -x "${CU}" ]; then
    echo "ERROR: ${CU} not found. Run 'make' first." >&2
    exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/compartment-landlock.XXXXXX")"
harness_cleanup_add "${WORK}"

ABI="$("${CU}" --verify 2>/dev/null | sed -n 's/^Landlock: OK (ABI v\([0-9]*\)).*/\1/p')"
[ -n "${ABI}" ] || ABI=0
echo "  Landlock ABI: ${ABI}"
echo ""

# A minimal set of system rules, enough to exec a dynamically linked binary.
# /lib and /lib64 are symlinks on a usr-merged distro; they have to install.
BASE=(--profile none --ro /usr --ro /lib --ro /lib64 --ro /bin --ro /etc
      --ro /proc --rw /dev/null)

RUN_OUT=""
RUN_RC=0
run() {
    RUN_OUT=""
    RUN_RC=0
    RUN_OUT="$("$@" 2>&1)" || RUN_RC=$?
}

want_out() {
    if printf '%s\n' "${RUN_OUT}" | grep -qF -- "$2"; then
        pass "$1"
    else
        fail "$1 (expected '$2' in: $(printf '%s' "${RUN_OUT}" | tr '\n' '|' | cut -c1-180))"
    fi
}
want_no_out() {
    if printf '%s\n' "${RUN_OUT}" | grep -qF -- "$2"; then
        fail "$1 (unexpected '$2')"
    else
        pass "$1"
    fi
}
want_rc() {
    if [ "${RUN_RC}" -eq "$2" ]; then
        pass "$1"
    else
        fail "$1 (expected rc=$2, got rc=${RUN_RC}: $(printf '%s' "${RUN_OUT}" | tr '\n' '|' | cut -c1-180))"
    fi
}
want_rc_nonzero() {
    if [ "${RUN_RC}" -ne 0 ]; then
        pass "$1"
    else
        fail "$1 (expected a non-zero exit)"
    fi
}

# Declared assertion count for the whole suite (see harness_expect_total).
LANDLOCK_RULES_TOTAL=89

if [ "${ABI}" -lt 1 ]; then
    skip_to_total "${LANDLOCK_RULES_TOTAL}" \
        "Landlock not available on this kernel — no rule semantics to test"
    harness_expect_total "${LANDLOCK_RULES_TOTAL}"
    harness_summary "landlock-rules" || exit 1
    exit 0
fi

# ── A. Per-file rules ──────────────────────────────────────────────

echo "--- Test group: rules that name a file (M1, item 3) ---"

echo "original" > "${WORK}/target.txt"
echo "other"    > "${WORK}/other.txt"

# A `rw` rule on a single FILE used to install nothing at all: the kernel
# rejects READ_DIR on a non-directory with EINVAL and the error was
# swallowed.  The file must now be writable and its neighbour must not.
run "${CU}" "${BASE[@]}" --rw "${WORK}/target.txt" -- \
    /bin/sh -c "echo rewritten > '${WORK}/target.txt' && echo WROTE_TARGET"
want_rc "rw FILE: the run succeeds" 0
want_out "rw FILE: the write happened" "WROTE_TARGET"
if [ "$(cat "${WORK}/target.txt")" = "rewritten" ]; then
    pass "rw FILE: the file really changed on disk"
else
    fail "rw FILE: the file was not modified"
fi

run "${CU}" "${BASE[@]}" --rw "${WORK}/target.txt" -- \
    /bin/sh -c "echo x > '${WORK}/other.txt' && echo WROTE_OTHER || echo REFUSED"
want_out "rw FILE: the rule does not leak to a sibling" "REFUSED"

# ro on a file is read-only: the read works, the write does not.
run "${CU}" "${BASE[@]}" --ro "${WORK}/other.txt" -- \
    /bin/sh -c "cat '${WORK}/other.txt' && (echo x > '${WORK}/other.txt' && echo WROTE || echo RO_ENFORCED)"
want_out "ro FILE: the read works" "other"
want_out "ro FILE: the write is refused" "RO_ENFORCED"

# The whole point of M8: the built-in profile can write /dev/null through a
# per-node rule while /dev itself stays read-only.
run "${CU}" -- /bin/sh -c 'echo x > /dev/null && echo DEVNULL_OK'
want_out "ai-agent: /dev/null is writable (per-node rule)" "DEVNULL_OK"
run "${CU}" -- /bin/sh -c 'echo x > /dev/compartment-probe 2>/dev/null && echo DEV_WRITABLE || echo DEV_STILL_RO'
want_out "ai-agent: /dev itself is still read-only" "DEV_STILL_RO"

echo ""

# ── B. Missing paths ───────────────────────────────────────────────

echo "--- Test group: missing paths, fatal vs optional (M1, item 4) ---"

run "${CU}" "${BASE[@]}" --ro "${WORK}/nope" -- /bin/true
want_rc_nonzero "missing path: refuses to run"
want_out "missing path: says which path"      "${WORK}/nope"
want_out "missing path: offers the '?' form"  "make it optional"

run "${CU}" "${BASE[@]}" --ro "${WORK}/nope?" -- /bin/sh -c 'echo OPTIONAL_RAN'
want_rc "optional path: the run proceeds" 0
want_out "optional path: the command ran" "OPTIONAL_RAN"

run "${CU}" --verbose "${BASE[@]}" --ro "${WORK}/nope?" -- /bin/true
want_out "optional path: --verbose says the rule was skipped" "optional rule skipped"

run "${CU}" --dry-run "${BASE[@]}" --ro "${WORK}/nope" -- /bin/true
want_out "--dry-run flags a path that is not there" "ABSENT"

echo ""

# ── C. Installed-rule count ────────────────────────────────────────

echo "--- Test group: the count reported is the count installed ---"

# BASE names 7 paths (--profile none is not one of them).
BASE_PATHS=7
run "${CU}" --verbose "${BASE[@]}" -- /bin/true
want_out "--verbose reports installed of asked-for" \
         "${BASE_PATHS} of ${BASE_PATHS} path rules installed"
want_out "--verbose reports the ABI"                "ABI v${ABI}"

# /lib and /lib64 are symlinks on any usr-merged distro.  Before the fix the
# kernel rejected them with EINVAL and the tool still counted them.
run "${CU}" --verbose "${BASE[@]}" -- /bin/true
INSTALLED="$(printf '%s\n' "${RUN_OUT}" | sed -n 's/.*(ABI v[0-9]*, \([0-9]*\) of \([0-9]*\) path rules.*/\1 \2/p')"
if [ "${INSTALLED% *}" = "${INSTALLED#* }" ]; then
    pass "symlinked /lib and /lib64 install (${INSTALLED% *} of ${INSTALLED#* }) "
else
    fail "some rules did not install: ${INSTALLED}"
fi

# One optional rule skipped means one fewer installed than asked for.
run "${CU}" --verbose "${BASE[@]}" --ro "${WORK}/nope?" -- /bin/true
want_out "an absent optional rule is not counted as installed" \
         "${BASE_PATHS} of $((BASE_PATHS + 1)) path rules installed"

echo ""

# ── D. Landlock is additive (M9) ───────────────────────────────────

echo "--- Test group: a ro rule inside a rw rule is refused (M9) ---"

mkdir -p "${WORK}/proj/secrets"
echo "key" > "${WORK}/proj/secrets/key"

run "${CU}" "${BASE[@]}" --rw "${WORK}/proj" --ro "${WORK}/proj/secrets" -- /bin/true
want_rc_nonzero "nested ro inside rw: refused"
want_out "nested ro: names both paths"        "${WORK}/proj/secrets"
want_out "nested ro: explains why"            "Landlock is additive"

# Order must not matter: the same policy written the other way round.
run "${CU}" "${BASE[@]}" --ro "${WORK}/proj/secrets" --rw "${WORK}/proj" -- /bin/true
want_rc_nonzero "nested ro before the rw rule: also refused"

# rwx is the same case.
run "${CU}" "${BASE[@]}" --rwx "${WORK}/proj" --ro "${WORK}/proj/secrets" -- /bin/true
want_rc_nonzero "nested ro inside rwx: refused"

# A sibling that merely shares a prefix is not nested.
mkdir -p "${WORK}/projX"
run "${CU}" "${BASE[@]}" --rw "${WORK}/proj" --ro "${WORK}/projX" -- /bin/sh -c 'echo SIBLING_OK'
want_rc "a prefix-sharing sibling is not treated as nested" 0
want_out "sibling case really ran" "SIBLING_OK"

# `exec` inside `rw` stays legal — it genuinely adds execute to a W^X area.
cp /bin/true "${WORK}/proj/prog" 2>/dev/null || cp /usr/bin/true "${WORK}/proj/prog"
run "${CU}" "${BASE[@]}" --rw "${WORK}/proj" --exec "${WORK}/proj/prog" -- \
    /bin/sh -c "'${WORK}/proj/prog' && echo EXEC_IN_RW_OK"
want_rc "exec inside rw is allowed" 0
want_out "exec inside rw really executed" "EXEC_IN_RW_OK"

# The shipped examples must all survive the check.
for conf in "${REPO_DIR}"/examples/*.conf; do
    run "${CU}" --dry-run --profile "${conf}" -- /bin/true
    if [ "${RUN_RC}" -eq 0 ]; then
        pass "example parses under the additive check: $(basename "${conf}")"
    else
        fail "example rejected: $(basename "${conf}"): $(printf '%s' "${RUN_OUT}" | head -1)"
    fi
done

echo ""

# ── E. exec semantics ──────────────────────────────────────────────

echo "--- Test group: exec semantics in compartment-user ---"

mkdir -p "${WORK}/bins"
cp /bin/true "${WORK}/bins/allowed"  2>/dev/null || cp /usr/bin/true "${WORK}/bins/allowed"
cp /bin/true "${WORK}/bins/denied"   2>/dev/null || cp /usr/bin/true "${WORK}/bins/denied"

# A per-FILE exec rule is a per-binary grant: the named file runs, its
# neighbour in the same directory does not.
run "${CU}" "${BASE[@]}" --exec "${WORK}/bins/allowed" -- \
    /bin/sh -c "'${WORK}/bins/allowed' && echo ALLOWED_RAN; '${WORK}/bins/denied' 2>/dev/null && echo DENIED_RAN || echo DENIED_BLOCKED"
want_out "exec FILE: the named binary runs"          "ALLOWED_RAN"
want_out "exec FILE: its neighbour does not"         "DENIED_BLOCKED"
want_no_out "exec FILE: the neighbour really did not run" "DENIED_RAN"

# exec grants read as well as execute.
run "${CU}" "${BASE[@]}" --exec "${WORK}/bins" -- \
    /bin/sh -c "head -c4 '${WORK}/bins/allowed' >/dev/null && echo EXEC_GRANTS_READ"
want_out "exec DIR: read is granted too" "EXEC_GRANTS_READ"

# exec does not grant write — that is the difference from rwx.
run "${CU}" "${BASE[@]}" --exec "${WORK}/bins" -- \
    /bin/sh -c "echo x > '${WORK}/bins/new' 2>/dev/null && echo EXEC_GRANTS_WRITE || echo EXEC_NO_WRITE"
want_out "exec DIR: write is not granted" "EXEC_NO_WRITE"

# rw is W^X: no execute, even on a file that is executable in the DAC sense.
run "${CU}" "${BASE[@]}" --rw "${WORK}/bins" -- \
    /bin/sh -c "'${WORK}/bins/allowed' 2>/dev/null && echo RW_EXECUTED || echo RW_NO_EXEC"
want_out "rw: W^X still holds" "RW_NO_EXEC"

# Shared libraries need READ_FILE, not EXECUTE.  The dynamic loader does
# need EXECUTE, because execve() opens the ELF interpreter with FMODE_EXEC.
#
# `rw` is used for the library directory here, not `ro`: `ro` grants EXECUTE
# on everything beneath it, which is exactly the right being tested for.
# `rw` is the one mode that grants read WITHOUT execute (W^X), so it isolates
# the question.  The libraries are root-owned, so nothing can actually write
# them.
LOADER="$(ldd /bin/sh 2>/dev/null | sed -n 's#.*\(/lib[^ ]*ld-linux[^ ]*\).*#\1#p' | head -1)"
LIBC="$(ldd /bin/sh 2>/dev/null | sed -n 's#.*=> \(/[^ ]*libc\.so[^ ]*\).*#\1#p' | head -1)"
if [ -n "${LOADER}" ] && [ -e "${LOADER}" ] && [ -n "${LIBC}" ]; then
    LIBDIR="$(dirname "${LIBC}")"
    LOADERDIR="$(dirname "${LOADER}")"
    run "${CU}" --profile none --ro /etc --ro /proc --rw /dev/null \
        --exec /bin/sh --exec "${LOADER}" \
        --rw "${LIBDIR}" --rw "${LOADERDIR}" -- \
        /bin/sh -c 'echo LIBS_LOADED_WITH_READ_ONLY'
    want_out "shared libraries load with read-but-not-execute on the lib dir" \
             "LIBS_LOADED_WITH_READ_ONLY"

    # The same policy without the execute grant on the interpreter: execve()
    # opens it with FMODE_EXEC, so the exec is refused.
    run "${CU}" --profile none --ro /etc --ro /proc --rw /dev/null \
        --exec /bin/sh --rw "${LIBDIR}" --rw "${LOADERDIR}" -- \
        /bin/sh -c 'echo SHOULD_NOT_RUN'
    if [ "${RUN_RC}" -ne 0 ] && ! printf '%s' "${RUN_OUT}" | grep -q SHOULD_NOT_RUN; then
        pass "the ELF interpreter needs its own EXECUTE grant"
    else
        fail "exec succeeded without an execute grant on the loader"
    fi
else
    skip "no dynamic loader found: shared-library rights"
    skip "no dynamic loader found: shared-library rights (negative case)"
fi

echo ""

# ── F. Landlock TCP port rules ─────────────────────────────────────

echo "--- Test group: Landlock TCP port rules (P1-a) ---"

if [ "${ABI}" -lt 4 ]; then
    for label in "connect to the allowed port succeeds" \
                 "connect to any other port gets EACCES" \
                 "net-deny with no rule blocks every connect" \
                 "bind to the allowed port succeeds" \
                 "bind to any other port gets EACCES" \
                 "no net-* directive leaves the network untouched" \
                 "--dry-run reports the port rules" \
                 "below ABI 4 the tool warns that the policy is inactive"; do
        skip "${label} (Landlock ABI v${ABI} < 4: no network support before Linux 6.7)"
    done
else
    # A listener this suite owns, on a port nothing else is using.
    PORT=0
    LISTENER=""
    for cand in $(seq 34700 34760); do
        if ! (exec 3<>"/dev/tcp/127.0.0.1/${cand}") 2>/dev/null; then
            PORT="${cand}"
            break
        fi
        exec 3>&- 2>/dev/null || true
    done
    OTHER=$((PORT + 1))

    cat > "${WORK}/listener.sh" <<LEOF
#!/bin/bash
exec 3<>/dev/tcp/127.0.0.1/1 2>/dev/null || true
LEOF

    # Prefer python3 for the listener: it is the only thing guaranteed to
    # hold a socket open without pulling in a network tool.
    if command -v python3 >/dev/null 2>&1; then
        python3 - "${PORT}" >"${WORK}/listener.log" 2>&1 <<'PYEOF' &
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', int(sys.argv[1])))
s.listen(8)
print("LISTENING", flush=True)
time.sleep(60)
PYEOF
        LISTENER=$!
        for _ in $(seq 1 40); do
            grep -q LISTENING "${WORK}/listener.log" 2>/dev/null && break
            sleep 0.1
        done
    fi

    if [ -z "${LISTENER}" ] || ! kill -0 "${LISTENER}" 2>/dev/null; then
        for label in "connect to the allowed port succeeds" \
                     "connect to any other port gets EACCES" \
                     "net-deny with no rule blocks every connect" \
                     "bind to the allowed port succeeds" \
                     "bind to any other port gets EACCES" \
                     "no net-* directive leaves the network untouched"; do
            skip "${label} (no python3 to run a loopback listener)"
        done
    else
        # bash's /dev/tcp does the connect() inside the sandboxed shell, so
        # the EACCES it reports is the kernel's, not a tool's.
        CONN="exec 3<>/dev/tcp/127.0.0.1"

        run "${CU}" "${BASE[@]}" --net-connect "${PORT}" -- \
            /bin/bash -c "${CONN}/${PORT} && echo CONNECT_ALLOWED"
        want_out "connect to the allowed port succeeds" "CONNECT_ALLOWED"

        run "${CU}" "${BASE[@]}" --net-connect "${PORT}" -- \
            /bin/bash -c "${CONN}/${OTHER} 2>&1 || echo CONNECT_REFUSED"
        want_out "connect to any other port gets EACCES" "Permission denied"

        run "${CU}" "${BASE[@]}" --net-deny -- \
            /bin/bash -c "${CONN}/${PORT} 2>&1 || echo BLOCKED"
        want_out "net-deny with no rule blocks every connect" "Permission denied"

        # bind: python3 inside the sandbox reports the errno by name.
        cat > "${WORK}/bindtest.py" <<'PYEOF'
import socket, sys, errno
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('127.0.0.1', int(sys.argv[1])))
    print("BIND_OK")
except PermissionError:
    print("BIND_EACCES")
except OSError as e:
    print("BIND_OTHER", errno.errorcode.get(e.errno, e.errno))
PYEOF
        BPORT=$((PORT + 10))
        BOTHER=$((PORT + 11))
        run "${CU}" "${BASE[@]}" --ro "${WORK}/bindtest.py" --net-bind "${BPORT}" -- \
            python3 "${WORK}/bindtest.py" "${BPORT}"
        want_out "bind to the allowed port succeeds" "BIND_OK"

        run "${CU}" "${BASE[@]}" --ro "${WORK}/bindtest.py" --net-bind "${BPORT}" -- \
            python3 "${WORK}/bindtest.py" "${BOTHER}"
        want_out "bind to any other port gets EACCES" "BIND_EACCES"

        # Without any net-* directive the network must be untouched — the
        # default has to stay "ignore", or every existing profile changes
        # behaviour under this release.
        run "${CU}" "${BASE[@]}" -- \
            /bin/bash -c "${CONN}/${PORT} && echo NO_RULES_CONNECT_OK"
        want_out "no net-* directive leaves the network untouched" \
                 "NO_RULES_CONNECT_OK"
    fi

    [ -n "${LISTENER}" ] && kill "${LISTENER}" 2>/dev/null
    wait "${LISTENER}" 2>/dev/null || true

    run "${CU}" --dry-run "${BASE[@]}" --net-connect 5432 --net-bind 8080 --net-deny -- /bin/true
    want_out "--dry-run reports the port rules"   "2 TCP port rules"
    want_out "--dry-run lists net-connect"        "net-connect 5432"
    want_out "--dry-run lists net-default deny"   "net-default deny"
    skip "below ABI 4 the tool warns that the policy is inactive (this kernel is ABI v${ABI})"
fi

# Port validation is not kernel-dependent.
run "${CU}" --dry-run "${BASE[@]}" --net-connect 70000 -- /bin/true
want_rc_nonzero "an out-of-range port is refused"
want_out "the refusal names the range" "0-65535"

run "${CU}" --dry-run "${BASE[@]}" --net-connect http -- /bin/true
want_rc_nonzero "a non-numeric port is refused"

printf 'ro /usr\nnet-connect 5432\nnet-default deny\n' > "${WORK}/net.conf"
chmod go-w "${WORK}/net.conf"
run "${CU}" --dry-run --profile "${WORK}/net.conf" -- /bin/true
want_rc "a profile can carry net-* directives" 0
want_out "profile net-connect is applied" "net-connect 5432"

printf 'ro /usr\nnet-default deny\nnet-default ignore\n' > "${WORK}/netundo.conf"
chmod go-w "${WORK}/netundo.conf"
run "${CU}" --dry-run --profile "${WORK}/netundo.conf" -- /bin/true
want_rc_nonzero "'net-default ignore' cannot undo an earlier deny"
want_out "the refusal explains the one-way rule" "may only tighten"

echo ""

# ── G. seccomp-default ─────────────────────────────────────────────

echo "--- Test group: seccomp-default (L1, item 13) ---"

run "${CU}" --dry-run -- /bin/true
want_out "the default action is still errno" "seccomp-default: errno"

for act in errno kill log; do
    printf 'ro /usr\nblock ptrace\nseccomp-default %s\n' "${act}" > "${WORK}/sd.conf"
    chmod go-w "${WORK}/sd.conf"
    run "${CU}" --dry-run --profile "${WORK}/sd.conf" -- /bin/true
    want_out "seccomp-default ${act} parses" "seccomp-default: ${act}"
done

printf 'ro /usr\nseccomp-default explode\n' > "${WORK}/sdbad.conf"
chmod go-w "${WORK}/sdbad.conf"
run "${CU}" --dry-run --profile "${WORK}/sdbad.conf" -- /bin/true
want_rc_nonzero "an unknown seccomp-default value is refused"
want_out "the refusal lists the valid values" "errno/kill/log"

# kill really kills: a blocked syscall must terminate the process with
# SIGSYS (128+31) rather than returning EPERM.
PROBE="${REPO_DIR}/tests/probes/deny_probe"
if [ -x "${PROBE}" ]; then
    ulimit -c 0 2>/dev/null || true
    printf 'ro /usr\nro /lib\nro /lib64\nro /bin\nro /etc\nro /proc\nrw /dev/null\nblock unshare\n' \
        > "${WORK}/sderrno.conf"
    printf 'ro /usr\nro /lib\nro /lib64\nro /bin\nro /etc\nro /proc\nrw /dev/null\nblock unshare\nseccomp-default kill\n' \
        > "${WORK}/sdkill.conf"
    chmod go-w "${WORK}/sderrno.conf" "${WORK}/sdkill.conf"

    # errno: the probe survives and reports the exact errno.
    run "${CU}" --profile "${WORK}/sderrno.conf" --ro "${PROBE}" -- \
        "${PROBE}" sc_unshare_user
    want_out "errno: the probe ran"            "PROBE_START"
    want_out "errno: unshare returns EPERM"    "EPERM"

    # kill: the same probe is terminated by SIGSYS (128+31 = 159).
    run "${CU}" --profile "${WORK}/sdkill.conf" --ro "${PROBE}" -- \
        "${PROBE}" sc_unshare_user
    if [ "${RUN_RC}" -eq 159 ]; then
        pass "seccomp-default kill terminates with SIGSYS (rc=159)"
    else
        fail "seccomp-default kill: expected rc=159, got rc=${RUN_RC}"
    fi
    want_out "kill: the probe did start" "PROBE_START op=sc_unshare_user"
    want_no_out "kill: no RESULT line — the process died at the syscall" "RESULT op=sc_unshare_user"
else
    skip "deny_probe not built: seccomp-default errno"
    skip "deny_probe not built: seccomp-default errno errno value"
    skip "deny_probe not built: seccomp-default kill"
    skip "deny_probe not built: seccomp-default kill (probe start)"
    skip "deny_probe not built: seccomp-default kill (no RESULT line)"
fi

echo ""

# ── H. make install / install-profiles ─────────────────────────────

echo "--- Test group: make install no longer deploys examples (item 16) ---"

run make -C "${REPO_DIR}" -n install
want_rc "make -n install works" 0
want_no_out "make install does not touch /etc/compartment" "/etc/compartment"
want_out "make install still installs the binaries" "compartment-user"

run make -C "${REPO_DIR}" -n install-profiles
want_rc "make -n install-profiles works" 0
want_out "install-profiles targets the system profile dir" "/etc/compartment"
want_out "install-profiles warns about shadowing" "SHADOW"

echo ""

# ── I. Audit log inside a writable rule ────────────────────────────

echo "--- Test group: audit log inside a rw rule (item 10) ---"

mkdir -p "${WORK}/ws"
run "${CU}" --profile none --ro /usr --ro /lib --ro /lib64 --ro /bin --ro /etc \
    --ro /proc --rw /dev/null --rw "${WORK}/ws" --no-seccomp \
    --audit-log "${WORK}/ws/audit" -- /bin/true
want_rc "the run still succeeds (warning, not refusal)" 0
want_out "warns that the trail is reachable from inside" \
         "rewrite its own audit trail"

run "${CU}" --profile none --ro /usr --ro /lib --ro /lib64 --ro /bin --ro /etc \
    --ro /proc --rw /dev/null --rw "${WORK}/ws" --no-seccomp \
    --audit-log "${WORK}/outside" -- /bin/true
want_rc "an audit dir outside every rw rule still works" 0
want_no_out "and produces no warning" "rewrite its own audit trail"

echo ""

# The suite declares its own assertion count. A block that stops
# running — a `skip` standing in for twenty assertions, a group
# guarded by a tool that is not installed — changes the total, and a
# changed total is a failure rather than a smaller number nobody
# compares against anything.
harness_expect_total "${LANDLOCK_RULES_TOTAL}"
harness_summary "landlock-rules" || exit 1
