#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# aux-tools.sh — rootless tests for tools/syscall.py and the extra/ helpers
#
# Everything here runs as an unprivileged user and starts no daemons.
# The proxy helpers are exercised through stubs (a fake `crontab`, a fake
# PID file) so nothing on the host is touched.
#
# Usage: ./tests/scripts/rootless.d/aux-tools.sh [--verbose]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CU="${REPO_DIR}/compartment-user"
SYSCALL_PY="${REPO_DIR}/tools/syscall.py"
VERBOSE="${1:-}"

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP: $1"; }

WORK="$(mktemp -d -t compartment-aux-XXXXXXXX)"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

vsay() { [ -n "${VERBOSE}" ] && echo "    $*" || true; }

echo "=== Auxiliary tooling tests (syscall.py, extra/) ==="
echo ""

if [ ! -x "${CU}" ]; then
    echo "ERROR: ${CU} not found. Run 'make' first."
    exit 1
fi

# ── Test group: syscall.py ─────────────────────────────────────────

echo "--- Test group: syscall.py ---"

HAVE_PY=0
command -v python3 >/dev/null 2>&1 && HAVE_PY=1
HAVE_STRACE=0
command -v strace >/dev/null 2>&1 && HAVE_STRACE=1

if [ "${HAVE_PY}" -eq 0 ]; then
    skip "syscall.py: python3 not available"
else
    if python3 -m py_compile "${SYSCALL_PY}" 2>"${WORK}/pycompile.err"; then
        pass "syscall.py compiles"
    else
        fail "syscall.py does not compile: $(head -1 "${WORK}/pycompile.err")"
    fi
    rm -rf "${REPO_DIR}/tools/__pycache__"
fi

if [ "${HAVE_PY}" -eq 0 ] || [ "${HAVE_STRACE}" -eq 0 ]; then
    skip "syscall.py profile generation (needs python3 + strace)"
else
    # ── A generated profile must actually load and run ────────────
    # Before the fix, deny mode emitted "inherit ai-agent" (a file that
    # `make install` never deploys, so the load failed outright) and allow
    # mode emitted zero path rules, so compartment-user refused with
    # "landlock enabled but no paths configured".
    for mode in deny allow; do
        GEN="${WORK}/gen-${mode}.conf"
        if ! python3 "${SYSCALL_PY}" profile --seccomp-mode "${mode}" \
             -o "${GEN}" -- /bin/true >"${WORK}/gen.out" 2>"${WORK}/gen.err"; then
            fail "syscall.py profile --seccomp-mode ${mode} failed: $(head -1 "${WORK}/gen.err")"
            continue
        fi
        pass "syscall.py generates a ${mode}-mode profile"

        DRY_ERR="${WORK}/dry-${mode}.err"
        if "${CU}" --dry-run --profile "${GEN}" -- /bin/true \
              >"${WORK}/dry.out" 2>"${DRY_ERR}"; then
            pass "generated ${mode}-mode profile parses (--dry-run)"
        else
            fail "generated ${mode}-mode profile does not parse: $(head -1 "${DRY_ERR}")"
        fi
        vsay "$(cat "${DRY_ERR}")"

        if grep -qiE 'not found|unknown (profile|syscall)|warning' "${DRY_ERR}"; then
            fail "generated ${mode}-mode profile parses with complaints: $(grep -iE 'not found|unknown|warning' "${DRY_ERR}" | head -1)"
        else
            pass "generated ${mode}-mode profile parses with no complaints"
        fi

        # A path-rule count of 0 means Landlock is refused at run time.
        if grep -qE 'landlock: yes \([1-9][0-9]* path rules\)' "${DRY_ERR}"; then
            pass "generated ${mode}-mode profile carries Landlock path rules"
        else
            fail "generated ${mode}-mode profile has no Landlock path rules"
        fi

        if "${CU}" --profile "${GEN}" -- /bin/true >/dev/null 2>"${WORK}/run.err"; then
            pass "generated ${mode}-mode profile enforces and runs /bin/true"
        else
            fail "generated ${mode}-mode profile fails at run time: $(head -1 "${WORK}/run.err")"
        fi
    done

    if grep -q '^inherit ' "${WORK}/gen-deny.conf" 2>/dev/null; then
        fail "deny-mode profile still uses 'inherit' (resolves only to a deployed file)"
    else
        pass "deny-mode profile is self-contained (no 'inherit')"
    fi

    # Syscalls compartment.h can name must be emitted as names, not as
    # architecture-specific numbers.
    if grep -q '^allow openat$' "${WORK}/gen-allow.conf" 2>/dev/null; then
        pass "allow-mode profile emits syscall names, not bare numbers"
    else
        fail "allow-mode profile does not emit 'allow openat' by name"
    fi

    # ── --with-env must not re-admit credentials ──────────────────
    ENVGEN="${WORK}/gen-env.conf"
    OPENAI_API_KEY="test-not-a-real-key" \
    MY_SERVICE_API_KEY="test-not-a-real-key" \
    MY_SERVICE_TOKEN="test-not-a-real-token" \
        python3 "${SYSCALL_PY}" profile --with-env -o "${ENVGEN}" -- /bin/true \
        >/dev/null 2>"${WORK}/env.err" || true
    if [ -f "${ENVGEN}" ] && grep -qiE '^env-allow .*(API_KEY|TOKEN|SECRET|PASSWORD)' "${ENVGEN}"; then
        fail "--with-env emits a credential: $(grep -iE '^env-allow .*(API_KEY|TOKEN|SECRET|PASSWORD)' "${ENVGEN}" | head -1)"
    else
        pass "--with-env emits no credential-looking env-allow line"
    fi
    if [ -f "${ENVGEN}" ] && grep -q '^env-allow PATH$' "${ENVGEN}"; then
        pass "--with-env still emits the benign variables"
    else
        fail "--with-env dropped the benign variables too"
    fi

    # ── A dangerous syscall that only ever failed must still be blocked ─
    cat > "${WORK}/fail-mount.py" <<'PYEOF'
import ctypes
ctypes.CDLL(None, use_errno=True).syscall(165, 0, 0, 0, 0, 0)  # mount() -> EPERM
PYEOF
    M14GEN="${WORK}/gen-m14.conf"
    python3 "${SYSCALL_PY}" profile -o "${M14GEN}" -- \
        python3 "${WORK}/fail-mount.py" >/dev/null 2>&1 || true
    if [ -f "${M14GEN}" ] && grep -q '^block mount$' "${M14GEN}"; then
        pass "attempted-but-denied syscall is still blocked"
    else
        fail "a dangerous syscall that only failed was treated as needed and left unblocked"
    fi
    if [ -f "${M14GEN}" ] && grep -q 'Attempted but never succeeded' "${M14GEN}"; then
        pass "profile records why the attempted syscall is still blocked"
    else
        fail "profile does not record the attempted-but-failed syscall"
    fi

    # ── Failed traces must not report success ─────────────────────
    if python3 "${SYSCALL_PY}" check --profile ai-agent -- /no/such/program \
         >"${WORK}/check.out" 2>&1; then
        fail "check on a nonexistent program reports success"
    else
        pass "check on a nonexistent program exits non-zero"
    fi
    if grep -q 'safe for this program' "${WORK}/check.out"; then
        fail "check on a nonexistent program printed 'safe for this program'"
    else
        pass "check on a nonexistent program does not claim the profile is safe"
    fi
    if python3 "${SYSCALL_PY}" profile -- /no/such/program \
         >/dev/null 2>&1; then
        fail "profile of a nonexistent program reports success"
    else
        pass "profile of a nonexistent program exits non-zero"
    fi

    # ── argv[0] must not inject directives into the .conf ─────────
    INJ_DIR="${WORK}/inject"
    mkdir -p "${INJ_DIR}"
    INJ_BIN="${INJ_DIR}/$(printf 'x\nallow 101')"
    cp /bin/true "${INJ_BIN}"
    INJGEN="${WORK}/gen-inject.conf"
    python3 "${SYSCALL_PY}" profile -o "${INJGEN}" -- "${INJ_BIN}" \
        >/dev/null 2>&1 || true
    if [ -f "${INJGEN}" ] && grep -qE '^[[:space:]]*allow ' "${INJGEN}"; then
        fail "a newline in the program name injected a directive: $(grep -nE '^[[:space:]]*allow ' "${INJGEN}" | head -1)"
    else
        pass "a newline in the program name injects no directive"
    fi
fi

echo ""

# ── Test group: extra/ helper scripts ──────────────────────────────

echo "--- Test group: extra/ helper scripts ---"

# Every helper the docs tell people to run has to be executable.
NON_EXEC=""
while read -r mode _ _ path; do
    case "${path}" in
        *.sh) ;;
        *) continue ;;
    esac
    head -c2 "${REPO_DIR}/${path}" 2>/dev/null | grep -q '#!' || continue
    [ "${mode}" = "100755" ] || NON_EXEC="${NON_EXEC} ${path}"
done < <(git -C "${REPO_DIR}" ls-files -s extra 2>/dev/null || true)
if [ -z "${NON_EXEC}" ]; then
    pass "every extra/ script with a shebang is committed executable"
else
    fail "not executable in the index:${NON_EXEC}"
fi

SH_BAD=""
for f in "${REPO_DIR}"/extra/tinyproxy/*.sh "${REPO_DIR}"/extra/squid-proxy/srv/squid/*.sh; do
    [ -f "${f}" ] || continue
    bash -n "${f}" 2>/dev/null || SH_BAD="${SH_BAD} $(basename "${f}")"
done
if [ -z "${SH_BAD}" ]; then
    pass "extra/ scripts parse (bash -n)"
else
    fail "syntax errors in:${SH_BAD}"
fi

# ── squid.conf must not ship as an open proxy ──────────────────────
SQUID_CONF="${REPO_DIR}/extra/squid-proxy/srv/squid/squid.conf"
squid_line() { grep -E "$1" "${SQUID_CONF}" | grep -v '^[[:space:]]*#' | head -1; }

if [ -n "$(squid_line '^http_port[[:space:]]+(127\.0\.0\.1|\[::1\]):')" ]; then
    pass "squid.conf binds the loopback address"
else
    fail "squid.conf http_port is not bound to loopback: $(squid_line '^http_port')"
fi
if [ -n "$(squid_line '^http_access[[:space:]]+allow[[:space:]]+all[[:space:]]*$')" ]; then
    fail "squid.conf still has 'http_access allow all'"
else
    pass "squid.conf has no blanket 'http_access allow all'"
fi
if [ -n "$(squid_line '^http_access[[:space:]]+deny[[:space:]]+all[[:space:]]*$')" ]; then
    pass "squid.conf ends with a default deny"
else
    fail "squid.conf has no 'http_access deny all'"
fi
for rule in '^acl[[:space:]]+Safe_ports[[:space:]]+port' \
            '^acl[[:space:]]+SSL_ports[[:space:]]+port' \
            '^http_access[[:space:]]+deny[[:space:]]+!Safe_ports' \
            '^http_access[[:space:]]+deny[[:space:]]+CONNECT[[:space:]]+!SSL_ports'; do
    if [ -n "$(squid_line "${rule}")" ]; then
        pass "squid.conf restores baseline ACL: ${rule}"
    else
        fail "squid.conf is missing baseline ACL: ${rule}"
    fi
done
if [ -n "$(grep -E '^[[:space:]]*--network[[:space:]]+host' "${REPO_DIR}/extra/squid-proxy/srv/squid/start.sh")" ]; then
    pass "squid start.sh uses host networking so the loopback bind is the host's"
else
    fail "squid start.sh does not use --network host; a loopback bind inside a bridge container is unreachable"
fi

# ── crontab surgery must touch only our own lines ──────────────────
# A stub `crontab` keeps the real user crontab out of this entirely.
TP="${WORK}/tinyproxy"
cp -a "${REPO_DIR}/extra/tinyproxy" "${TP}"
STUB="${WORK}/stubbin"
mkdir -p "${STUB}"
cat > "${STUB}/crontab" <<'STUBEOF'
#!/bin/bash
case "${1:-}" in
    -l) [ -s "${CRONTAB_STORE}" ] || exit 1; cat "${CRONTAB_STORE}" ;;
    -)  cat > "${CRONTAB_STORE}" ;;
    *)  exit 2 ;;
esac
STUBEOF
chmod 755 "${STUB}/crontab"
export CRONTAB_STORE="${WORK}/crontab.txt"
UNRELATED="30 3 * * * /home/someone/backups/start.sh --nightly"
{
    echo "0 * * * * /usr/bin/true"
    echo "# tinyproxy-autostart"
    echo "@reboot ${TP}/start.sh >> ${TP}/logs/cron-start.log 2>&1"
    echo "${UNRELATED}"
} > "${CRONTAB_STORE}"

# Invoked with `bash`, not directly: the file mode is checked separately
# above, and these assertions are about what the script *does*.
if PATH="${STUB}:${PATH}" bash "${TP}/disable.sh" >"${WORK}/disable.out" 2>&1; then
    vsay "$(cat "${WORK}/disable.out")"
    pass "disable.sh runs to completion"
else
    fail "disable.sh failed: $(head -2 "${WORK}/disable.out" | tr '\n' ' ')"
fi
if grep -qF "# tinyproxy-autostart" "${CRONTAB_STORE}"; then
    fail "disable.sh left its own marker line in the crontab"
else
    pass "disable.sh removed its marker line"
fi
if grep -qF "${TP}/start.sh" "${CRONTAB_STORE}"; then
    fail "disable.sh left its own @reboot entry in the crontab"
else
    pass "disable.sh removed its @reboot entry"
fi
if grep -qF "${UNRELATED}" "${CRONTAB_STORE}"; then
    pass "disable.sh left unrelated crontab lines mentioning start.sh alone"
else
    fail "disable.sh deleted an unrelated crontab line that mentioned start.sh"
fi
if grep -qF "0 * * * * /usr/bin/true" "${CRONTAB_STORE}"; then
    pass "disable.sh left the rest of the crontab alone"
else
    fail "disable.sh deleted an unrelated crontab line"
fi
unset CRONTAB_STORE

# ── PID files must be validated before anything is signalled ───────
mkdir -p "${TP}/run"
PIDF="${TP}/run/tinyproxy.pid"

sleep 300 &
VICTIM=$!
echo "${VICTIM}" > "${PIDF}"

bash "${TP}/reload.sh" >"${WORK}/reload.out" 2>&1 || true
if kill -0 "${VICTIM}" 2>/dev/null; then
    pass "reload.sh refuses to SIGHUP a PID that is not tinyproxy"
else
    fail "reload.sh signalled an unrelated process"
fi

bash "${TP}/stop.sh" >"${WORK}/stop.out" 2>&1 || true
if kill -0 "${VICTIM}" 2>/dev/null; then
    pass "stop.sh refuses to kill a PID that is not tinyproxy"
else
    fail "stop.sh killed an unrelated process"
fi
kill "${VICTIM}" 2>/dev/null || true
wait "${VICTIM}" 2>/dev/null || true

printf 'not-a-pid\n' > "${PIDF}"
if bash "${TP}/stop.sh" >"${WORK}/stop2.out" 2>&1; then
    if grep -qiE 'usable PID|refusing to signal' "${WORK}/stop2.out"; then
        pass "stop.sh rejects a PID file that does not hold a number"
    else
        fail "stop.sh accepted a garbage PID file silently"
    fi
else
    pass "stop.sh rejects a PID file that does not hold a number"
fi
rm -f "${PIDF}"

# ── disable.sh must not report success when stop.sh failed ─────────
chmod -x "${TP}/stop.sh"
export CRONTAB_STORE="${WORK}/crontab2.txt"
: > "${CRONTAB_STORE}"
if PATH="${STUB}:${PATH}" bash "${TP}/disable.sh" >"${WORK}/disable2.out" 2>&1; then
    fail "disable.sh reported success although stop.sh could not run"
else
    pass "disable.sh fails loudly when stop.sh cannot run"
fi
unset CRONTAB_STORE

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
