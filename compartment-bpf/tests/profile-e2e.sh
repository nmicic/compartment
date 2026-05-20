#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# profile-e2e.sh — V-3b per-profile end-to-end orchestrator.
#
# For each of 5 daemons:
#   1. cleanup_pin -> launch compartment-bpf --pin profiles/<daemon>.conf
#   2. wait up to LIVE_DEADLINE_S for "[run] compartment-bpf live"
#   3. systemctl restart <unit>; sleep SETTLE_S
#   4. run tests/profile-e2e/<daemon>.sh and capture verdict + hash
#   5. count [audit] DENY_* lines; SIGINT compartment-bpf; cleanup_pin
#   6. restore daemon pre-state
#   7. emit CSV row
#
# PASS bar: liveness_pass=1 AND e2e_pass=1 AND unexpected_denies=0.
# CSV schema (stable columns identical across runs, duration_s allowed to vary):
#   daemon,workflow,liveness_pass,e2e_pass,unexpected_denies,workflow_output_hash,duration_s,result
#
# Designed to be safe under both:
#   sudo tests/profile-e2e.sh
#   sudo env REPO=... RESULTS=... tests/profile-e2e.sh
#
set -euo pipefail

# --- env / defaults -----------------------------------------------------------

REPO="${REPO:-$(realpath "$(dirname "$0")/..")}"
RESULTS="${RESULTS:-${REPO}/tests/results/e2e/v3b-$(date -u +%Y%m%dT%H%M%SZ)}"
PROFILES_DIR="${PROFILES_DIR:-${REPO}/profiles}"
BIN="${BIN:-${REPO}/compartment-bpf}"
LIVE_DEADLINE_S="${LIVE_DEADLINE_S:-10}"
SETTLE_S="${SETTLE_S:-3}"
NONCE="${NONCE:-$(printf '%s' "$(date -u +%s%N)" | sha256sum | cut -c1-12)}"
export NONCE

PIN_ROOT="/sys/fs/bpf/compartment"
E2E_DNS_CANARY="${E2E_DNS_CANARY:-one.one.one.one}"
export E2E_DNS_CANARY

mkdir -p "$RESULTS" "${RESULTS}/audit" "${RESULTS}/e2e"

CSV="${RESULTS}/profile-e2e-results.csv"

# --- daemon -> unit map -------------------------------------------------------

declare -A UNIT WORKFLOW

UNIT[sshd]=ssh.service
UNIT[dbus-daemon]=dbus.service
UNIT[polkitd]=polkit.service
UNIT[systemd-resolved]=systemd-resolved.service
UNIT[chronyd]=chrony.service

WORKFLOW[sshd]=ssh_round_trip
WORKFLOW[dbus-daemon]=dbus_listnames
WORKFLOW[polkitd]=pkcheck_self
WORKFLOW[systemd-resolved]=resolve_dns
WORKFLOW[chronyd]=chrony_tracking

# §D-19: auto-discover the profile set. Profiles without a per-
# daemon test script under tests/profile-e2e/<daemon>.sh are
# skipped NOISILY in the main loop — see the per-iteration check
# below. New profiles drop in automatically; new tests just need
# a tests/profile-e2e/<daemon>.sh to be picked up.
mapfile -t ORDER < <(
    find "$PROFILES_DIR" -maxdepth 1 -name '*.conf' \
        ! -name 'all-daemons.conf' \
        -printf '%f\n' | sed 's/\.conf$//' | sort
)

# --- helpers (inlined; do NOT factor into a shared file) ---------------------

die() { echo "ERROR: $*" >&2; exit 1; }

cleanup_pin() {
    # Counter-map pins under ${PIN_ROOT}/maps survive plain link cleanup
    # and EEXIST the next --pin; --unpin clears both synchronously.
    if [ -x "$BIN" ]; then
        "$BIN" --unpin >/dev/null 2>&1 || true
    fi
    if [ -d "${PIN_ROOT}/links" ]; then
        rm -f "${PIN_ROOT}"/links/* 2>/dev/null || true
    fi
    if [ -d "${PIN_ROOT}/maps" ]; then
        rm -f "${PIN_ROOT}"/maps/* 2>/dev/null || true
    fi
}

# --- pre-flight ---------------------------------------------------------------

[ "$EUID" -eq 0 ] || die "must run as root"
[ -x "$BIN" ] || die "compartment-bpf binary not executable: $BIN"
[ -d "$PROFILES_DIR" ] || die "profiles dir missing: $PROFILES_DIR"

# Stale pin guard.
if [ -d "${PIN_ROOT}/links" ]; then
    stale_count=$(find "${PIN_ROOT}/links" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l || true)
    stale_count=${stale_count:-0}
    if [ "$stale_count" -gt 0 ]; then
        die "stale pin: ${PIN_ROOT}/links has ${stale_count} entries"
    fi
fi

# DNS canary reachability.
if ! getent ahostsv4 "$E2E_DNS_CANARY" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ +STREAM'; then
    die "DNS canary unreachable ($E2E_DNS_CANARY), halt not skip (D-V3b.E)"
fi

# NTP reachability.
ntp_refid="$(chronyc -c tracking 2>/dev/null | awk -F, 'NR==1{print $1}' || true)"
if [ -z "$ntp_refid" ] || [ "$ntp_refid" = "00000000" ]; then
    die "NTP unreachable (RefID=${ntp_refid:-EMPTY}), halt not skip"
fi

# Per-daemon unit presence + pre-state capture. Only runs over
# profiles that have a UNIT mapping AND a per-daemon test script
# at tests/profile-e2e/<daemon>.sh; the rest are skipped noisily
# in the main loop below.
: > "${RESULTS}/pre-state.txt"
for d in "${ORDER[@]}"; do
    [ -n "${UNIT[$d]:-}" ] || continue
    [ -f "${REPO}/tests/profile-e2e/${d}.sh" ] || continue
    u="${UNIT[$d]}"
    if ! systemctl status "$u" >/dev/null 2>&1; then
        # status returns non-zero on inactive but still finds the unit;
        # we accept that. Only fail if list-units says it's not loaded.
        if ! systemctl list-unit-files "$u" 2>/dev/null | grep -q "^${u}"; then
            die "systemd unit not found for daemon=$d unit=$u"
        fi
    fi
    active="$(systemctl is-active "$u" 2>/dev/null || true)"
    enabled="$(systemctl is-enabled "$u" 2>/dev/null || true)"
    printf '%s.active=%s\n' "$d" "$active" >> "${RESULTS}/pre-state.txt"
    printf '%s.enabled=%s\n' "$d" "$enabled" >> "${RESULTS}/pre-state.txt"
done

# --- CSV header ---------------------------------------------------------------

echo 'daemon,workflow,liveness_pass,e2e_pass,unexpected_denies,workflow_output_hash,duration_s,result' > "$CSV"

# --- per-daemon runner --------------------------------------------------------

run_one_daemon() {
    local daemon="$1"
    local unit="${UNIT[$daemon]}"
    local workflow="${WORKFLOW[$daemon]}"
    local audit_log="${RESULTS}/audit/${daemon}.audit"
    local e2e_log="${RESULTS}/e2e/${daemon}.log"
    local profile="${PROFILES_DIR}/${daemon}.conf"

    : > "$audit_log"
    : > "$e2e_log"

    local liveness_pass=0
    local e2e_pass=0
    local unexpected_denies=0
    local hash="-"
    local duration_s=0
    local result="FAIL"
    local e2e_rc=99
    local verdict=""

    local t0 t1
    t0=$(date +%s)

    cleanup_pin

    if [ ! -f "$profile" ]; then
        echo "MISSING profile for $daemon: $profile" >> "$e2e_log"
        t1=$(date +%s); duration_s=$((t1 - t0))
        printf '%s,%s,0,0,0,-,%d,FAIL\n' "$daemon" "$workflow" "$duration_s" >> "$CSV"
        return 0
    fi

    # Launch compartment-bpf in its own session so SIGINT to it doesn't
    # leak into the orchestrator process group.
    setsid "$BIN" --pin "$profile" >"$audit_log" 2>&1 &
    local cbpf_pid=$!

    # Wait up to LIVE_DEADLINE_S for "[run] compartment-bpf live".
    local i
    for i in $(seq 1 "$LIVE_DEADLINE_S"); do
        if grep -q '\[run\] compartment-bpf live' "$audit_log" 2>/dev/null; then
            liveness_pass=1
            break
        fi
        if ! kill -0 "$cbpf_pid" 2>/dev/null; then
            break
        fi
        sleep 1
    done

    if [ "$liveness_pass" -ne 1 ]; then
        # Not live — abort this daemon row, but still clean up.
        kill -INT "$cbpf_pid" 2>/dev/null || true
        wait "$cbpf_pid" 2>/dev/null || true
        cleanup_pin
        t1=$(date +%s); duration_s=$((t1 - t0))
        printf '%s,%s,0,0,0,-,%d,FAIL\n' "$daemon" "$workflow" "$duration_s" >> "$CSV"
        return 0
    fi

    # Restart the daemon under enforcement and let it settle.
    systemctl restart "$unit" || true
    sleep "$SETTLE_S"

    # Run per-daemon E2E. Wrap so non-zero doesn't kill orchestrator.
    if "${REPO}/tests/profile-e2e/${daemon}.sh" >"$e2e_log" 2>&1; then
        e2e_rc=0
    else
        e2e_rc=$?
    fi

    # Parse verdict + hash from e2e_log stdout.
    verdict="$(grep -E '^E2E_VERDICT=' "$e2e_log" | tail -n1 | cut -d= -f2- || true)"
    hash="$(grep -E '^WORKFLOW_OUTPUT_HASH=' "$e2e_log" | tail -n1 | cut -d= -f2- || true)"
    if [ -z "$hash" ]; then hash="-"; fi
    if [ "$e2e_rc" -eq 0 ] && [ "$verdict" = "PASS" ]; then
        e2e_pass=1
    else
        e2e_pass=0
        if [ -z "$verdict" ]; then hash="-"; fi
    fi

    # Count DENY_* audit lines (V-3b has no positive-control allowlist).
    local deny_count
    deny_count=$(grep -c '\[audit\] DENY_' "$audit_log" 2>/dev/null || true)
    deny_count=${deny_count:-0}
    # grep -c with -e and no match returns "0" cleanly on most builds, but
    # under set -e the "|| true" above already neutralized non-zero exits.
    unexpected_denies="$deny_count"

    # Tear down compartment-bpf and clean the pin.
    kill -INT "$cbpf_pid" 2>/dev/null || true
    wait "$cbpf_pid" 2>/dev/null || true
    cleanup_pin

    # Restore daemon pre-state (best-effort; do not fail orchestrator).
    local pre_active
    pre_active="$(grep -E "^${daemon}\.active=" "${RESULTS}/pre-state.txt" | cut -d= -f2- || true)"
    case "$pre_active" in
        active)
            if ! systemctl is-active --quiet "$unit"; then
                systemctl start "$unit" >/dev/null 2>&1 || true
            fi
            ;;
        inactive|failed|"")
            systemctl stop "$unit" >/dev/null 2>&1 || true
            ;;
        *)
            # unknown state; leave alone but try restart to a clean baseline
            systemctl restart "$unit" >/dev/null 2>&1 || true
            ;;
    esac

    t1=$(date +%s); duration_s=$((t1 - t0))

    if [ "$liveness_pass" -eq 1 ] && [ "$e2e_pass" -eq 1 ] && [ "$unexpected_denies" -eq 0 ]; then
        result="PASS"
    else
        result="FAIL"
    fi

    printf '%s,%s,%d,%d,%d,%s,%d,%s\n' \
        "$daemon" "$workflow" "$liveness_pass" "$e2e_pass" \
        "$unexpected_denies" "$hash" "$duration_s" "$result" >> "$CSV"
    return 0
}

# --- main loop ----------------------------------------------------------------

pass=0; fail=0
for d in "${ORDER[@]}"; do
    # §D-19: noisy skip for profiles without a per-daemon test script.
    if [ ! -f "${REPO}/tests/profile-e2e/${d}.sh" ]; then
        echo "# SKIP ${d}: no per-daemon test script at tests/profile-e2e/${d}.sh"
        continue
    fi
    # §D-19: noisy skip for profiles without a UNIT/WORKFLOW mapping
    # (covers profiles like shells-allowlist that don't model a unit).
    if [ -z "${UNIT[$d]:-}" ]; then
        echo "# SKIP ${d}: no UNIT/WORKFLOW mapping in this runner"
        continue
    fi
    run_one_daemon "$d"
done

# Tally from CSV (skip header).
pass=$(awk -F, 'NR>1 && $8=="PASS"' "$CSV" | wc -l)
fail=$(awk -F, 'NR>1 && $8!="PASS"' "$CSV" | wc -l)
total=$((pass + fail))

printf 'PASS=%d FAIL=%d TOTAL=%d\n' "$pass" "$fail" "$total"
printf 'CSV=%s\n' "$CSV"
printf 'RESULTS_DIR=%s\n' "$RESULTS"

if [ "$fail" -gt 0 ]; then
    exit 1
fi
exit 0
