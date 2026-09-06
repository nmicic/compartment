#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# core-matrix-extra.sh — rootless coverage the main matrix does not reach
#
# Covers, for compartment-user only (nothing here needs root):
#   A  seccomp: x32-ABI bypass, exact errno, deny-list is not a kill-all
#   B  Landlock ro/rw/exec corners, including W^X in both directions
#   C  profile parser limits: line length, path/env caps, inherit depth, cycles
#   D  --dry-run: shape, self-consistency, and that it does not execute
#   E  --verify: output and exit-code semantics
#   F  environment sanitization as observed by the exec'd process
#   G  no_new_privs / seccomp state visible in the sandboxed child
#
# Every assertion that runs deny_probe requires its PROBE_START marker, so a
# case can never pass because the probe failed to execute.
#
# See README.md for the contract this script honours.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/scripts/lib/harness.sh
. "${SCRIPT_DIR}/../lib/harness.sh"

REPO_DIR="$(harness_repo_dir)"
CU="${REPO_DIR}/compartment-user"
PROBE="${REPO_DIR}/tests/probes/deny_probe"

# A blocked x32 syscall is killed with SIGSYS; do not litter the tree with
# core files while proving it.
ulimit -c 0 2>/dev/null || true

echo "=== compartment-user extra matrix ==="
echo ""

if [ ! -x "${CU}" ] || [ ! -x "${PROBE}" ]; then
    echo "ERROR: run 'make && make tests/probes/deny_probe' first" >&2
    exit 1
fi

NO_LANDLOCK=0
"${CU}" --verify > /dev/null 2>&1 || NO_LANDLOCK=1

harness_fixtures
SCRATCH="$(mktemp -d "${FIXTURES}/extra.XXXXXX")"
harness_cleanup_add "${SCRATCH}"
mkdir -p "${SCRATCH}/dir" "${SCRATCH}/conf"
cp "${PROBE}" "${SCRATCH}/deny_probe"
cp /bin/true "${SCRATCH}/dir/true"
echo "content" > "${SCRATCH}/dir/file.txt"
P="${SCRATCH}/deny_probe"

# Minimum path set for exec'ing a dynamically linked binary under
# "--profile none" (no built-in rules at all).
SYSPATHS=(--ro /usr --ro /lib --ro /lib64 --ro /etc --ro /bin)

OK_RESULT="rc=0 errno=0 name=OK"
EACCES_RESULT="rc=-1 errno=13 name=EACCES"
EPERM_RESULT="rc=-1 errno=1 name=EPERM"

OUT=""
RC=0

# cu ARGS... — run compartment-user, capture merged output and exit code
cu() {
    OUT=""
    RC=0
    OUT=$("${CU}" "$@" 2>&1) || RC=$?
}

# expect_probe LABEL OP PATTERN — the probe must have run, and its RESULT
# line for OP must match PATTERN.  The PROBE_START check is what stops an
# assertion passing because compartment-user never exec'd the probe.
expect_probe() {
    local label="$1" op="$2" pat="$3" line
    if ! echo "${OUT}" | grep -q "PROBE_START op=${op} "; then
        fail "${label} (probe never ran, rc=${RC}: $(echo "${OUT}" | head -1))"
        return 0
    fi
    line=$(echo "${OUT}" | grep "RESULT op=${op}" | head -1)
    if echo "${line}" | grep -q -- "${pat}"; then
        pass "${label}"
    else
        fail "${label} (want '${pat}', got '${line}')"
    fi
}

# expect_rc LABEL WANT
expect_rc() {
    if [ "${RC}" -eq "$2" ]; then pass "$1"; else fail "$1 (want rc=$2, got rc=${RC}: $(echo "${OUT}" | head -1))"; fi
}

# expect_out LABEL PATTERN / expect_no_out LABEL PATTERN
expect_out() {
    if echo "${OUT}" | grep -q -- "$2"; then pass "$1"; else fail "$1 (missing '$2' in: $(echo "${OUT}" | head -3 | tr '\n' '|'))"; fi
}
expect_no_out() {
    if echo "${OUT}" | grep -q -- "$2"; then fail "$1 (unexpected '$2')"; else pass "$1"; fi
}

# ── A. seccomp ─────────────────────────────────────────────────────

echo "--- A: seccomp ---"

# A1. x32 ABI bypass: ptrace|0x40000000 must be killed outright, not merely
# refused, so a filter that only matched the low bits of the syscall number
# would show up here as ENOSYS/rc=1 instead of SIGSYS.
if [ "$(uname -m)" = "x86_64" ]; then
    cu --profile none --no-landlock --block ptrace -- "${P}" sc_ptrace_x32
    if ! echo "${OUT}" | grep -q "PROBE_START op=sc_ptrace_x32 "; then
        fail "x32 ptrace: probe never ran (rc=${RC})"
    elif [ "${RC}" -eq 159 ]; then
        pass "x32 ptrace bypass killed with SIGSYS (rc=159)"
    else
        fail "x32 ptrace bypass NOT killed (rc=${RC}, want 159)"
    fi

    # Same syscall unsandboxed is only ENOSYS, so rc=159 above is attributable
    # to the filter and not to the kernel lacking x32 support.
    X32_BASE_RC=0
    "${PROBE}" sc_ptrace_x32 > /dev/null 2>&1 || X32_BASE_RC=$?
    if [ "${X32_BASE_RC}" -ne 159 ]; then
        pass "x32 ptrace: unsandboxed baseline is not SIGSYS (rc=${X32_BASE_RC})"
    else
        fail "x32 ptrace: unsandboxed baseline already SIGSYS — test proves nothing"
    fi
else
    skip "x32 ptrace bypass (not x86_64)"
    skip "x32 ptrace baseline (not x86_64)"
fi

# A2. Native ptrace under the same policy: exact errno, with a baseline that
# succeeds unsandboxed so the denial can only come from seccomp.
PTRACE_BASE=$("${PROBE}" sc_ptrace_traceme 2>/dev/null || true)
if echo "${PTRACE_BASE}" | grep -q "RESULT op=sc_ptrace_traceme .*rc=0"; then
    cu --profile none --no-landlock --block ptrace -- "${P}" sc_ptrace_traceme
    expect_probe "ptrace blocked with exact EPERM" sc_ptrace_traceme "${EPERM_RESULT}"
else
    skip "ptrace blocked with exact EPERM (host already denies ptrace)"
fi

# A3. Same for process_vm_readv.
PVR_BASE=$("${PROBE}" sc_process_vm_readv 2>/dev/null || true)
if echo "${PVR_BASE}" | grep -q "RESULT op=sc_process_vm_readv .*rc=0"; then
    cu --profile none --no-landlock --block process_vm_readv -- "${P}" sc_process_vm_readv
    expect_probe "process_vm_readv blocked with exact EPERM" sc_process_vm_readv "${EPERM_RESULT}"
else
    skip "process_vm_readv blocked with exact EPERM (host already denies it)"
fi

# A4. A deny-list must leave everything else alone.
cu --profile none --no-landlock --block ptrace -- "${P}" fs_read /etc/hostname
expect_probe "deny-list leaves unblocked syscalls alone" fs_read "${OK_RESULT}"

echo ""

# ── B. Landlock ro / rw / exec corners ─────────────────────────────

echo "--- B: Landlock ro/rw/exec ---"

if [ "${NO_LANDLOCK}" -eq 1 ]; then
    skip "Landlock not available (whole group)"
else
    # W^X, direction 1: --rw grants read+write but never execute.
    cu --profile none --no-seccomp "${SYSPATHS[@]}" --rw "${SCRATCH}" \
        -- "${P}" fs_exec "${SCRATCH}/dir/true"
    if [ "${RC}" -eq 127 ] && echo "${OUT}" | grep -qi "permission denied"; then
        pass "W^X: --rw denies exec (compartment-user cannot exec the probe, rc=127)"
    else
        fail "W^X: --rw should deny exec (rc=${RC}: $(echo "${OUT}" | head -1))"
    fi

    # W^X, direction 2: adding --exec on the same path restores execute.
    cu --profile none --no-seccomp "${SYSPATHS[@]}" --rw "${SCRATCH}" --exec "${SCRATCH}" \
        -- "${P}" fs_exec "${SCRATCH}/dir/true"
    expect_probe "W^X: --rw + --exec allows exec" fs_exec "exit=0 ${OK_RESULT}"

    # --ro: read yes, exec yes, write no, create no.
    cu --profile none --no-seccomp "${SYSPATHS[@]}" --ro "${SCRATCH}" \
        -- "${P}" fs_read "${SCRATCH}/dir/file.txt"
    expect_probe "--ro allows read" fs_read "${OK_RESULT}"

    cu --profile none --no-seccomp "${SYSPATHS[@]}" --ro "${SCRATCH}" \
        -- "${P}" fs_exec "${SCRATCH}/dir/true"
    expect_probe "--ro allows exec" fs_exec "exit=0 ${OK_RESULT}"

    cu --profile none --no-seccomp "${SYSPATHS[@]}" --ro "${SCRATCH}" \
        -- "${P}" fs_write "${SCRATCH}/dir/file.txt"
    expect_probe "--ro denies write with exact EACCES" fs_write "${EACCES_RESULT}"

    cu --profile none --no-seccomp "${SYSPATHS[@]}" --ro "${SCRATCH}" \
        -- "${P}" fs_create "${SCRATCH}/dir/new.txt"
    expect_probe "--ro denies create with exact EACCES" fs_create "${EACCES_RESULT}"

    # --rw: the write-side operations all succeed.
    cu --profile none --no-seccomp "${SYSPATHS[@]}" --rw "${SCRATCH}" --exec "${SCRATCH}" \
        -- "${P}" fs_create "${SCRATCH}/dir/created.txt"
    expect_probe "--rw allows create" fs_create "${OK_RESULT}"

    cu --profile none --no-seccomp "${SYSPATHS[@]}" --rw "${SCRATCH}" --exec "${SCRATCH}" \
        -- "${P}" fs_unlink "${SCRATCH}/dir/created.txt"
    expect_probe "--rw allows unlink" fs_unlink "${OK_RESULT}"

    cu --profile none --no-seccomp "${SYSPATHS[@]}" --rw "${SCRATCH}" --exec "${SCRATCH}" \
        -- "${P}" fs_mkdir "${SCRATCH}/dir/sub"
    expect_probe "--rw allows mkdir" fs_mkdir "${OK_RESULT}"

    cu --profile none --no-seccomp "${SYSPATHS[@]}" --rw "${SCRATCH}" --exec "${SCRATCH}" \
        -- "${P}" fs_rmdir "${SCRATCH}/dir/sub"
    expect_probe "--rw allows rmdir" fs_rmdir "${OK_RESULT}"

    # A path covered by no rule at all is denied even for reading.
    cu --profile none --no-seccomp "${SYSPATHS[@]}" --ro "${SCRATCH}" \
        -- "${P}" fs_read /var/log/wtmp
    expect_probe "path outside every rule is denied" fs_read "${EACCES_RESULT}"
fi

echo ""

# ── C. Profile parser limits ───────────────────────────────────────

echo "--- C: profile parser limits ---"

LONG_CONF="${SCRATCH}/conf/long.conf"
{ printf 'ro '; head -c 1200 /dev/zero | tr '\0' 'a'; printf '\n'; } > "${LONG_CONF}"
cu --profile "${LONG_CONF}" --dry-run -- /bin/true
expect_rc  "over-long profile line refused" 1
expect_out "over-long profile line names the limit" "line too long"

PATHS_CONF="${SCRATCH}/conf/paths.conf"
for _ in $(seq 70); do echo "ro /usr"; done > "${PATHS_CONF}"
cu --profile "${PATHS_CONF}" --dry-run -- /bin/true
expect_rc  "path-limit overflow refused" 1
expect_out "path-limit overflow refuses to weaken policy" "path limit (64) reached"

ENV_CONF="${SCRATCH}/conf/env.conf"
for i in $(seq 70); do echo "env-deny FOO${i}"; done > "${ENV_CONF}"
cu --profile "${ENV_CONF}" --dry-run -- /bin/true
expect_rc  "env-deny-limit overflow refused" 1
expect_out "env-deny-limit overflow refuses to weaken policy" "env-deny limit (64) reached"

# inherit: two levels are allowed (MAX_INHERIT_DEPTH 2), three are not.
printf 'block ptrace\nlandlock off\n'              > "${SCRATCH}/conf/c3.conf"
printf 'inherit c3\nblock unshare\nlandlock off\n' > "${SCRATCH}/conf/c2.conf"
printf 'inherit c2\nblock setns\nlandlock off\n'   > "${SCRATCH}/conf/c1.conf"
printf 'inherit c1\nblock chroot\nlandlock off\n'  > "${SCRATCH}/conf/c0.conf"

cu --profile "${SCRATCH}/conf/c1.conf" --dry-run -- /bin/true
expect_rc  "inherit depth 2 accepted" 0
expect_out "inherit depth 2 merges all three profiles" "DENY-LIST (3 blocked)"

cu --profile "${SCRATCH}/conf/c0.conf" --dry-run -- /bin/true
expect_rc  "inherit depth 3 refused" 1
expect_out "inherit depth 3 names the depth limit" "inherit depth limit reached"

# An inherit cycle must terminate rather than recurse forever.
printf 'inherit cyc_b\nlandlock off\n' > "${SCRATCH}/conf/cyc_a.conf"
printf 'inherit cyc_a\nlandlock off\n' > "${SCRATCH}/conf/cyc_b.conf"
CYCLE_RC=0
timeout 20 "${CU}" --profile "${SCRATCH}/conf/cyc_a.conf" --dry-run -- /bin/true \
    > /dev/null 2>&1 || CYCLE_RC=$?
if [ "${CYCLE_RC}" -eq 124 ]; then
    fail "inherit cycle terminates (timed out — infinite recursion)"
elif [ "${CYCLE_RC}" -ne 0 ]; then
    pass "inherit cycle terminates and is refused (rc=${CYCLE_RC})"
else
    fail "inherit cycle accepted (rc=0)"
fi

echo ""

# ── D. --dry-run ───────────────────────────────────────────────────

echo "--- D: --dry-run ---"

cu --profile ai-agent --dry-run -- /bin/true
expect_rc  "--dry-run exits 0" 0
expect_out "--dry-run names the profile"      "profile: ai-agent"
expect_out "--dry-run reports no_new_privs"   "no_new_privs:"
expect_out "--dry-run reports landlock rules" "landlock: yes ([0-9]* path rules)"
expect_out "--dry-run reports seccomp blocks" "seccomp: yes DENY-LIST ([0-9]* blocked)"
expect_out "--dry-run reports env stripping"  "env: DENY-LIST ([0-9]* stripped)"
expect_out "--dry-run echoes the command"     "command: /bin/true"

# The advertised rule count must match the rules actually listed.
DRY_CLAIMED=$(echo "${OUT}" | sed -n 's/.*landlock: yes (\([0-9]*\) path rules).*/\1/p')
DRY_LISTED=$(echo "${OUT}" | grep -c '^    \(ro\|rw\|rwx\) ' || true)
if [ -n "${DRY_CLAIMED}" ] && [ "${DRY_CLAIMED}" -eq "${DRY_LISTED}" ]; then
    pass "--dry-run path-rule count matches the rules listed (${DRY_CLAIMED})"
else
    fail "--dry-run claims ${DRY_CLAIMED:-?} path rules but lists ${DRY_LISTED}"
fi

DRY_BLOCKED=$(echo "${OUT}" | sed -n 's/.*DENY-LIST (\([0-9]*\) blocked).*/\1/p')
DRY_BLOCK_LINES=$(echo "${OUT}" | grep -c '^    block ' || true)
if [ -n "${DRY_BLOCKED}" ] && [ "${DRY_BLOCKED}" -eq "${DRY_BLOCK_LINES}" ]; then
    pass "--dry-run block count matches the blocks listed (${DRY_BLOCKED})"
else
    fail "--dry-run claims ${DRY_BLOCKED:-?} blocks but lists ${DRY_BLOCK_LINES}"
fi

# --dry-run must not run the command.
DRY_MARKER="${SCRATCH}/dry-run-must-not-exist"
rm -f "${DRY_MARKER}"
cu --dry-run -- /bin/touch "${DRY_MARKER}"
if [ -e "${DRY_MARKER}" ]; then
    fail "--dry-run executed the command"
else
    pass "--dry-run does not execute the command"
fi

echo ""

# ── E. --verify ────────────────────────────────────────────────────

echo "--- E: --verify ---"

cu --verify
if [ "${RC}" -eq 0 ] && echo "${OUT}" | grep -q "All checks passed"; then
    pass "--verify: exit 0 agrees with 'All checks passed'"
elif [ "${RC}" -ne 0 ] && echo "${OUT}" | grep -q "VERIFICATION FAILED"; then
    pass "--verify: non-zero exit agrees with 'VERIFICATION FAILED'"
else
    fail "--verify: exit code (${RC}) disagrees with its own output"
fi

expect_out "--verify reports the kernel"       "Kernel:"
expect_out "--verify reports no_new_privs"     "PR_SET_NO_NEW_PRIVS:"
expect_out "--verify reports Landlock"         "Landlock:"
expect_out "--verify reports seccomp"          "seccomp BPF:"
expect_out "--verify reports the architecture" "Architecture:"
expect_out "--verify is honest about network"  "Network: NOT RESTRICTED"

VERIFY_SYSCALLS=$(echo "${OUT}" | sed -n 's/.*Syscall table: \([0-9]*\) entries.*/\1/p')
if [ -n "${VERIFY_SYSCALLS}" ] && [ "${VERIFY_SYSCALLS}" -gt 0 ]; then
    pass "--verify reports a non-empty syscall table (${VERIFY_SYSCALLS} entries)"
else
    fail "--verify reports no syscall table size"
fi

echo ""

# ── F. Environment sanitization at exec ────────────────────────────

echo "--- F: environment sanitization ---"

# Read the environment the exec'd process actually sees, not what the parent
# intended: env_dump prints one "ENV name=value" line per entry.
DANGEROUS=(LD_PRELOAD=libevil.so LD_LIBRARY_PATH=/evil LD_AUDIT=a.so
           BASH_ENV=/evil/rc NODE_OPTIONS=--require=/evil.js
           PERL5OPT=-Mevil PYTHONSTARTUP=/evil.py GCONV_PATH=/evil
           AWS_SECRET_ACCESS_KEY=s3cret GITHUB_TOKEN=ghp_x
           SSH_AUTH_SOCK=/tmp/agent.sock PGPASSWORD=hunter2)

OUT=""
RC=0
OUT=$(env "${DANGEROUS[@]}" COMPARTMENT_KEEPME=survives \
    "${CU}" --no-landlock -- "${PROBE}" env_dump 2>&1) || RC=$?

if ! echo "${OUT}" | grep -q "PROBE_START op=env_dump "; then
    fail "env sanitization: probe never ran (rc=${RC})"
else
    LEAKED=""
    for kv in "${DANGEROUS[@]}"; do
        name="${kv%%=*}"
        if echo "${OUT}" | grep -q "^ENV ${name}="; then
            LEAKED="${LEAKED} ${name}"
        fi
    done
    if [ -z "${LEAKED}" ]; then
        pass "env sanitization: all ${#DANGEROUS[@]} dangerous vars absent from the exec'd process"
    else
        fail "env sanitization: leaked to the exec'd process:${LEAKED}"
    fi

    if echo "${OUT}" | grep -q "^ENV COMPARTMENT_KEEPME=survives"; then
        pass "env sanitization: an unlisted variable survives"
    else
        fail "env sanitization: unlisted variable was stripped too"
    fi
fi

# --no-env-sanitize proves the assertion above measures sanitization and not
# some unrelated reason the variable was missing.
OUT=""
RC=0
OUT=$(env AWS_SECRET_ACCESS_KEY=s3cret \
    "${CU}" --no-landlock --no-env-sanitize -- "${PROBE}" env_get AWS_SECRET_ACCESS_KEY 2>&1) || RC=$?
expect_probe "--no-env-sanitize keeps the variable (control case)" env_get "value=s3cret"

# A CLI --env-deny entry is honoured on its own.
OUT=""
RC=0
OUT=$(env COMPARTMENT_SECRET=leaky \
    "${CU}" --no-landlock --env-deny COMPARTMENT_SECRET -- "${PROBE}" env_get COMPARTMENT_SECRET 2>&1) || RC=$?
expect_probe "--env-deny strips the named variable" env_get "value=(null)"

echo ""

# ── G. Child process state ─────────────────────────────────────────

echo "--- G: sandboxed child state ---"

cu --profile ai-agent -- /bin/sh -c 'grep -E "^(NoNewPrivs|Seccomp):" /proc/self/status'
if echo "${OUT}" | grep -qE '^NoNewPrivs:[[:space:]]*1$'; then
    pass "sandboxed child has NoNewPrivs=1"
else
    fail "sandboxed child has NoNewPrivs=1 (got: $(echo "${OUT}" | tr '\n' '|'))"
fi
if echo "${OUT}" | grep -qE '^Seccomp:[[:space:]]*2$'; then
    pass "sandboxed child runs in seccomp filter mode (Seccomp=2)"
else
    fail "sandboxed child runs in seccomp filter mode (got: $(echo "${OUT}" | tr '\n' '|'))"
fi

cu --profile ai-agent --no-seccomp -- /bin/sh -c 'grep -E "^Seccomp:" /proc/self/status'
if echo "${OUT}" | grep -qE '^Seccomp:[[:space:]]*0$'; then
    pass "--no-seccomp really installs no filter (control case)"
else
    fail "--no-seccomp still installed a filter (got: $(echo "${OUT}" | tr '\n' '|'))"
fi

echo ""
harness_summary "core-matrix-extra" || exit 1
exit 0
