#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/actor-wrapper/aide-vm.sh — empirical AIDE attack run.
#
# Designed to run ON THE VM (Resolute) as root, after `tests/actor-wrapper/
# run.sh` has built /usr/local/sbin/compartment-actor-wrapper and the AIDE
# package is installed.
#
# Demonstrates:
#   A) Direct aide --update with LD_PRELOAD=evil.so -> evil constructor runs
#      INSIDE aide (the env was preserved end-to-end). This is the attack.
#   B) Wrapped aide --update via the static wrapper -> evil constructor
#      does NOT run (env was scrubbed before execve). Same target inode,
#      identical actor identity at the file-op hook. The DELTA is launch
#      hygiene, not actor identity.
#   C) Direct ptrace from inside aide-shape (use the static attempter)
#      vs wrapped: wrapped returns EPERM.
#
# Exit non-zero on any deviation.

set -u

# HIGH-13 (mesh Review-1): pin PATH + umask.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 022

RESULTS="${RESULTS:-/tmp/aide-vm-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$RESULTS"
LOG="$RESULTS/aide-vm.log"
: > "$LOG"
WRAP="${WRAP:-/usr/local/sbin/compartment-actor-wrapper}"
EVIL="${EVIL:-/usr/local/lib/evil_preload.so}"

pass=0; fail=0
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
ok()  { say "PASS  $*"; pass=$((pass+1)); }
nok() { say "FAIL  $*"; fail=$((fail+1)); }
section() { say ""; say "=== $* ==="; }

trap 'say ""; say "AIDE-VM summary: PASS=$pass FAIL=$fail (logs $RESULTS)"' EXIT

###############################################################################
section "preflight"
###############################################################################
command -v aide >/dev/null 2>&1 || { nok "aide not installed"; exit 2; }
[ -x "$WRAP" ] || { nok "wrapper not installed at $WRAP"; exit 2; }
[ -f "$EVIL" ] || { nok "evil_preload.so not installed at $EVIL"; exit 2; }
ok "preflight"

# Minimal aide config so --update is fast (just /etc/hostname).
AIDE_CONF="$RESULTS/aide.conf"
AIDE_DB="$RESULTS/aide.db"
AIDE_DB_NEW="$RESULTS/aide.db.new"
cat >"$AIDE_CONF" <<EOF
database_in=file:$AIDE_DB
database_out=file:$AIDE_DB_NEW
gzip_dbout=no
report_url=stdout
/etc/hostname p+i+u+g
EOF
ok "wrote $AIDE_CONF"

# Seed an initial DB so --update has something to compare against.
aide --config="$AIDE_CONF" --init >>"$LOG" 2>&1 && mv "$AIDE_DB_NEW" "$AIDE_DB"
[ -s "$AIDE_DB" ] && ok "aide --init seeded DB ($(stat -c%s "$AIDE_DB") bytes)" \
    || { nok "aide --init failed"; exit 2; }

###############################################################################
section "A — direct aide --update with LD_PRELOAD (attack succeeds)"
###############################################################################
MARKER="$RESULTS/A_direct.marker"; rm -f "$MARKER"
EVIL_MARKER="$MARKER" LD_PRELOAD="$EVIL" \
    aide --config="$AIDE_CONF" --update >>"$LOG" 2>&1 || true
if [ -f "$MARKER" ]; then
    ok "A direct: LD_PRELOAD loaded evil_preload INTO aide (marker present)"
else
    nok "A direct: marker absent — host glibc may already scrub LD_PRELOAD for setuid aide"
fi

###############################################################################
section "B — wrapped aide --update with LD_PRELOAD (attack defeated)"
###############################################################################
MARKER="$RESULTS/B_wrapped.marker"; rm -f "$MARKER"
# Wrapper is static-linked so its own ld.so can't load evil.so; on execve
# it clearenv's so aide doesn't see LD_PRELOAD either.
EVIL_MARKER="$MARKER" LD_PRELOAD="$EVIL" \
    "$WRAP" --actor aide -- /usr/bin/aide --config="$AIDE_CONF" --update \
    >>"$LOG" 2>&1 || true
if [ -f "$MARKER" ]; then
    nok "B wrapped: evil_preload STILL ran (wrapper env scrub broken)"
else
    ok "B wrapped: evil_preload did NOT run (env scrubbed before aide)"
fi

###############################################################################
section "C — env_probe through wrapper sees no dangerous env"
###############################################################################
ENV_BIN="${ENV_BIN:-/usr/local/sbin/env_probe}"
if [ -x "$ENV_BIN" ]; then
    out="$RESULTS/C_env.txt"
    LD_PRELOAD="$EVIL" LD_AUDIT="$EVIL" GLIBC_TUNABLES="x=y" PYTHONPATH="/x" \
        BASH_ENV="/x" GCONV_PATH="/x" \
        "$WRAP" --actor cprobe -- "$ENV_BIN" >"$out" 2>>"$LOG" || true
    if grep -qE '^ENV (LD_PRELOAD|LD_AUDIT|GLIBC_TUNABLES|PYTHONPATH|BASH_ENV|GCONV_PATH)=' "$out"; then
        nok "C env_probe sees one of the dangerous env names"
        grep -E '^ENV (LD_PRELOAD|LD_AUDIT|GLIBC_TUNABLES|PYTHONPATH|BASH_ENV|GCONV_PATH)=' "$out" | tee -a "$LOG"
    else
        ok "C env_probe: all dangerous env names scrubbed"
    fi
else
    say "INFO env_probe not installed; skipping C"
fi

###############################################################################
section "D — ptrace seccomp under wrapper"
###############################################################################
PTR_BIN="${PTR_BIN:-/usr/local/sbin/ptrace_attempter}"
if [ -x "$PTR_BIN" ]; then
    "$WRAP" --actor dptrace -- "$PTR_BIN" >>"$LOG" 2>&1
    rc=$?
    [ "$rc" = "0" ] && ok "D wrapped ptrace -> EPERM" \
        || nok "D wrapped ptrace rc=$rc (expected 0)"
else
    say "INFO ptrace_attempter not installed; skipping D"
fi

###############################################################################
section "E — actor identity is target post-execve (MAJOR-1 confirmation)"
###############################################################################
# Brief MAJOR-1: after wrapper execve's target, current->mm->exe_file is the
# target's inode, not the wrapper's. env_probe now prints /proc/self/exe as
# its first line. Wrap it; assert EXE = env_probe path, NOT wrapper path.
if [ -x "$ENV_BIN" ]; then
    out="$RESULTS/E_exe.txt"
    "$WRAP" --actor eactor -- "$ENV_BIN" >"$out" 2>>"$LOG"
    exe_line=$(grep '^EXE ' "$out" | head -1)
    case "$exe_line" in
        "EXE $ENV_BIN")
            ok "E /proc/self/exe = $ENV_BIN (wrapper NOT in exe_file post-execve)"
            ;;
        *"compartment-actor-wrapper"*)
            nok "E wrapper still in /proc/self/exe ($exe_line) — execve did not swap"
            ;;
        *)
            nok "E unexpected exe line: '$exe_line'"
            ;;
    esac
fi

###############################################################################
say ""
say "AIDE-VM Total PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] || exit 1
exit 0
