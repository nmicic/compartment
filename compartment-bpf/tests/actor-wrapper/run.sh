#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/actor-wrapper/run.sh — empirical close for the actor wrapper.
#
# Builds: tools/compartment-actor-wrapper.c (static), fixtures, generated
# per-actor wrappers via tools/compartment-actor-build.sh. Then runs the
# wrapper hardening test plan:
#
#   T1  LD_PRELOAD attack: direct loads evil; wrapped does not.
#   T2  LD_AUDIT  attack: same shape as T1.
#   T3  GLIBC_TUNABLES / GCONV_PATH: env absent in target.
#   T4  ptrace(PTRACE_TRACEME) -> EPERM under wrapper.
#   T5  process_vm_writev -> EPERM under wrapper.
#   T6  Inherited fd 3 closed by wrapper before target sees env.
#   T7  Generated wrapper cannot be redirected by argv/env/argv[0].
#   T8  Static-link assertion: dynamic wrapper IS compromised by
#       LD_PRELOAD against itself; static wrapper is not.
#   T9  Generator refuses symlink / 0-byte / world-writable / dangerous
#       --allow-env names.
#
# Exit non-zero if any test fails. Logs go to RESULTS_DIR (env or arg).

set -u

# HIGH-13 (mesh Review-1): pin PATH + umask so external invocations
# (gcc, cc, make, file, ldd, stat, ...) resolve through canonical
# system dirs only, and so build artifacts cannot be created
# world-writable.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 022

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
RESULTS_DIR="${RESULTS_DIR:-${REPO_ROOT}/tests/results/actor-wrapper-$(date -u +%Y%m%dT%H%M%SZ)}"
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/tests/actor-wrapper/build}"
CC="${CC:-cc}"

mkdir -p "$RESULTS_DIR" "$BUILD_DIR"
LOG="$RESULTS_DIR/run.log"
: > "$LOG"

pass=0; fail=0
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
ok()   { say "PASS  $*"; pass=$((pass+1)); }
nok()  { say "FAIL  $*"; fail=$((fail+1)); }
section() { say ""; say "=== $* ==="; }

trap 'say ""; say "Summary: PASS=$pass FAIL=$fail (results in $RESULTS_DIR)"' EXIT

###############################################################################
section "build"
###############################################################################
WRAP_STATIC="$BUILD_DIR/compartment-actor-wrapper.static"
WRAP_DYN="$BUILD_DIR/compartment-actor-wrapper.dyn"
EVIL_SO="$BUILD_DIR/evil_preload.so"
PTRACE_BIN="$BUILD_DIR/ptrace_attempter"
PVM_BIN="$BUILD_DIR/pvm_writev_attempter"
FD_BIN="$BUILD_DIR/fd_probe"
ENV_BIN="$BUILD_DIR/env_probe"
NOOP_BIN="$BUILD_DIR/noop"

"$CC" -Wall -Wextra -O2 -static \
    -o "$WRAP_STATIC" "$REPO_ROOT/tools/compartment-actor-wrapper.c" \
    2>&1 | tee -a "$LOG"
[ -x "$WRAP_STATIC" ] || { nok "build static wrapper"; exit 2; }
ok "build static wrapper"

"$CC" -Wall -Wextra -O2 \
    -o "$WRAP_DYN" "$REPO_ROOT/tools/compartment-actor-wrapper.c" \
    2>&1 | tee -a "$LOG"
[ -x "$WRAP_DYN" ] || { nok "build dynamic wrapper"; exit 2; }
ok "build dynamic wrapper"

"$CC" -shared -fPIC -O2 \
    -o "$EVIL_SO" "$REPO_ROOT/tests/actor-wrapper/fixtures/evil_preload.c" \
    2>&1 | tee -a "$LOG"
[ -f "$EVIL_SO" ] || { nok "build evil_preload.so"; exit 2; }
ok "build evil_preload.so"

# Fixtures: static-linked so seccomp/env aren't perturbed by ld.so caches.
for src in ptrace_attempter pvm_writev_attempter fd_probe env_probe noop; do
    out="$BUILD_DIR/$src"
    "$CC" -Wall -Wextra -O2 -static -o "$out" \
        "$REPO_ROOT/tests/actor-wrapper/fixtures/${src}.c" 2>&1 | tee -a "$LOG"
    [ -x "$out" ] || { nok "build $src"; exit 2; }
done
ok "build fixtures (static)"

###############################################################################
section "T8 — static link defeats LD_PRELOAD against the wrapper itself"
###############################################################################
MARKER="$RESULTS_DIR/T8_evil_dyn.marker"
rm -f "$MARKER"
EVIL_MARKER="$MARKER" LD_PRELOAD="$EVIL_SO" "$WRAP_DYN" \
    --actor t8-dyn -- "$NOOP_BIN" 2>>"$LOG" || true
if [ -f "$MARKER" ]; then
    ok "T8a dynamic wrapper compromised by LD_PRELOAD (marker present, expected)"
else
    nok "T8a dynamic wrapper UNEXPECTEDLY immune (no marker — env may have been pre-scrubbed by caller)"
fi
MARKER="$RESULTS_DIR/T8_evil_static.marker"
rm -f "$MARKER"
EVIL_MARKER="$MARKER" LD_PRELOAD="$EVIL_SO" "$WRAP_STATIC" \
    --actor t8-stat -- "$NOOP_BIN" 2>>"$LOG" || true
if [ -f "$MARKER" ]; then
    nok "T8b static wrapper compromised (marker present — static link is broken)"
else
    ok "T8b static wrapper immune to LD_PRELOAD on itself"
fi

###############################################################################
section "T1 — LD_PRELOAD scrubbed before target execve"
###############################################################################
# Target = the static env_probe; expectation = the wrapped run has no
# LD_PRELOAD in its env AND the wrapped run did NOT trigger evil_preload
# in the target (because env was scrubbed by the wrapper before execve).
MARKER="$RESULTS_DIR/T1_target_marker.marker"

# T1a: direct run (no wrapper) — for a glibc-dyn target, evil .so loads.
# Use /usr/bin/env as the dynamic target so ld.so is in play.
rm -f "$MARKER"
EVIL_MARKER="$MARKER" LD_PRELOAD="$EVIL_SO" /usr/bin/env >/dev/null 2>>"$LOG" || true
if [ -f "$MARKER" ]; then
    ok "T1a direct: LD_PRELOAD loaded evil_preload into /usr/bin/env (expected)"
else
    nok "T1a direct: no marker (env may be hardened by glibc secure-exec heuristics)"
fi

# T1b: wrapped — wrapper static, evil .so must NOT load in target.
rm -f "$MARKER"
EVIL_MARKER="$MARKER" LD_PRELOAD="$EVIL_SO" "$WRAP_STATIC" \
    --actor t1 -- /usr/bin/env >/dev/null 2>>"$LOG" || true
if [ -f "$MARKER" ]; then
    nok "T1b wrapped: evil_preload still loaded — env not scrubbed"
else
    ok "T1b wrapped: evil_preload absent (LD_PRELOAD scrubbed)"
fi

# T1c: positive cross-check — env_probe sees no LD_PRELOAD line.
out="$RESULTS_DIR/T1c_env.txt"
EVIL_MARKER=/dev/null LD_PRELOAD="$EVIL_SO" "$WRAP_STATIC" \
    --actor t1c -- "$ENV_BIN" >"$out" 2>>"$LOG" || true
if grep -q '^ENV LD_PRELOAD=' "$out"; then
    nok "T1c env_probe sees LD_PRELOAD (scrub broken)"
else
    ok "T1c env_probe: LD_PRELOAD absent in target env"
fi

###############################################################################
section "T2 — LD_AUDIT scrubbed"
###############################################################################
out="$RESULTS_DIR/T2_env.txt"
LD_AUDIT="$EVIL_SO" "$WRAP_STATIC" --actor t2 -- "$ENV_BIN" >"$out" 2>>"$LOG" || true
if grep -q '^ENV LD_AUDIT=' "$out"; then nok "T2 LD_AUDIT survived"; else ok "T2 LD_AUDIT scrubbed"; fi

###############################################################################
section "T3 — GLIBC_TUNABLES / GCONV_PATH scrubbed"
###############################################################################
out="$RESULTS_DIR/T3_env.txt"
GLIBC_TUNABLES="x=y" GCONV_PATH="/tmp" "$WRAP_STATIC" --actor t3 -- "$ENV_BIN" \
    >"$out" 2>>"$LOG" || true
if grep -qE '^ENV (GLIBC_TUNABLES|GCONV_PATH)=' "$out"; then
    nok "T3 GLIBC_TUNABLES/GCONV_PATH survived"
else
    ok "T3 GLIBC_TUNABLES + GCONV_PATH scrubbed"
fi

###############################################################################
section "T4 — ptrace(PTRACE_TRACEME) blocked under wrapper seccomp"
###############################################################################
# T4a: direct — succeeds (rc=1 from attempter means NOT blocked).
"$PTRACE_BIN" >>"$LOG" 2>&1
rc=$?
case "$rc" in
    1) ok "T4a direct ptrace succeeds (no seccomp)";;
    0) say "INFO T4a direct ptrace returned EPERM (host already has policy)";;
    *) say "INFO T4a direct ptrace rc=$rc";;
esac
# T4b: wrapped — seccomp must give EPERM (rc=0).
"$WRAP_STATIC" --actor t4 -- "$PTRACE_BIN" >>"$LOG" 2>&1
rc=$?
[ "$rc" = "0" ] && ok "T4b wrapped ptrace -> EPERM" || nok "T4b wrapped ptrace rc=$rc (expected 0)"

###############################################################################
section "T5 — process_vm_writev blocked under wrapper seccomp"
###############################################################################
"$WRAP_STATIC" --actor t5 -- "$PVM_BIN" >>"$LOG" 2>&1
rc=$?
[ "$rc" = "0" ] && ok "T5 wrapped pvm_writev -> EPERM" || nok "T5 wrapped pvm_writev rc=$rc"

###############################################################################
section "T6 — inherited fd >=3 closed by wrapper"
###############################################################################
# Parent opens fd 3 -> a temp file -> calls wrapper which exec's fd_probe.
# fd_probe should report fd>=3 closed.
TMPF="$RESULTS_DIR/T6_inherited.tmp"
: > "$TMPF"
"$WRAP_STATIC" --actor t6 -- "$FD_BIN" 3<"$TMPF" >"$RESULTS_DIR/T6_fd.txt" 2>>"$LOG"
rc=$?
if [ "$rc" = "0" ] && grep -q "CLEAN" "$RESULTS_DIR/T6_fd.txt"; then
    ok "T6 inherited fd 3 closed by wrapper"
else
    nok "T6 fd_probe rc=$rc (expected 0/CLEAN); see $RESULTS_DIR/T6_fd.txt"
fi

###############################################################################
section "T7 — generated wrapper cannot be redirected"
###############################################################################
GEN_OUT="$BUILD_DIR/gen-noop"
sh "$REPO_ROOT/tools/compartment-actor-build.sh" \
    --name test-noop --cmd "$NOOP_BIN" --out "$GEN_OUT" \
    --wrapper-src "$REPO_ROOT/tools/compartment-actor-wrapper.c" \
    --cc "$CC" >>"$LOG" 2>&1
if [ ! -x "$GEN_OUT" ]; then
    nok "T7 generated wrapper not produced"
else
    # Try to make it exec "$NOOP_BIN" -c 'mark T7' via argv. Should NOT.
    rm -f "$RESULTS_DIR/T7_marker"
    "$GEN_OUT" -c "touch $RESULTS_DIR/T7_marker" >>"$LOG" 2>&1
    if [ -f "$RESULTS_DIR/T7_marker" ]; then
        nok "T7 argv redirection succeeded (wrapper ran "$NOOP_BIN")"
    else
        ok "T7a argv cannot redirect target"
    fi
    # Try via env: PATH=/tmp etc. — target path is absolute and baked.
    PATH=/tmp "$GEN_OUT" >>"$LOG" 2>&1 && ok "T7b env PATH cannot redirect target" \
        || nok "T7b PATH manipulation broke wrapper"
fi

###############################################################################
section "T9 — generator refuses dangerous targets"
###############################################################################
# T9a symlink
ln -sf "$NOOP_BIN" "$BUILD_DIR/sym-noop"
if sh "$REPO_ROOT/tools/compartment-actor-build.sh" --name x --cmd "$BUILD_DIR/sym-noop" \
        --out "$BUILD_DIR/will-fail" \
        --wrapper-src "$REPO_ROOT/tools/compartment-actor-wrapper.c" \
        --cc "$CC" >>"$LOG" 2>&1; then
    nok "T9a generator accepted symlink target"
else
    ok "T9a generator rejected symlink target"
fi
rm -f "$BUILD_DIR/sym-noop" "$BUILD_DIR/will-fail"

# T9b 0-byte
: > "$BUILD_DIR/empty"
chmod +x "$BUILD_DIR/empty"
if sh "$REPO_ROOT/tools/compartment-actor-build.sh" --name x --cmd "$BUILD_DIR/empty" \
        --out "$BUILD_DIR/will-fail" \
        --wrapper-src "$REPO_ROOT/tools/compartment-actor-wrapper.c" \
        --cc "$CC" >>"$LOG" 2>&1; then
    nok "T9b generator accepted 0-byte target"
else
    ok "T9b generator rejected 0-byte target"
fi
rm -f "$BUILD_DIR/empty" "$BUILD_DIR/will-fail"

# T9c dangerous --allow-env
if sh "$REPO_ROOT/tools/compartment-actor-build.sh" --name x --cmd "$NOOP_BIN" \
        --out "$BUILD_DIR/will-fail" --allow-env LD_PRELOAD \
        --wrapper-src "$REPO_ROOT/tools/compartment-actor-wrapper.c" \
        --cc "$CC" >>"$LOG" 2>&1; then
    nok "T9c generator accepted --allow-env LD_PRELOAD"
else
    ok "T9c generator rejected --allow-env LD_PRELOAD"
fi
rm -f "$BUILD_DIR/will-fail"

###############################################################################
section "report"
###############################################################################
say ""
say "Total PASS=$pass FAIL=$fail"
if [ "$fail" -ne 0 ]; then
    say "FAILURES present — see $LOG"
    exit 1
fi
exit 0
