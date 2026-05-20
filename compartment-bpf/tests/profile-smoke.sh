#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# profile-smoke.sh — Phase C runner for the top-10 daemon profiles.
#
# For each profiles/<daemon>.conf:
#   1. restart the daemon to a known baseline,
#   2. launch  ./compartment-bpf --pin profiles/<daemon>.conf  in the bg,
#   3. wait up to 10 s for "[run] compartment-bpf live",
#   4. restart the daemon under enforcement,
#   5. sleep 3 s, run the liveness check,
#   6. positive-control: attempt a write to a sealed *config file* (not the
#      running binary, which the kernel already protects with ETXTBSY before
#      the LSM hook fires — see notes column). Expect EACCES + a DENY_WRITE
#      audit line on that inode.
#   7. scan the audit log for any unexpected DENY events (anything that is
#      NOT the positive-control inode),
#   8. SIGINT compartment-bpf, remove pinned links, restart the daemon
#      back to a clean state.
#
# A secondary, *informational* probe also tries to write to the running
# binary; that always fails with ETXTBSY on a live process and never
# reaches the LSM. We log this as evidence of defence-in-depth, not as
# part of the PASS criterion.
#
# Output: tests/profile-smoke-results-<TS>.csv
#
# PASS bar (per brief): 10/10 daemons stay operational AND 10/10 deny
# the positive-control modification.
#
# Run on the Resolute VM in /root/compartment-bpf-profiles. Requires:
#   - ./compartment-bpf built in $PWD
#   - profiles/*.conf in $PWD/profiles
#   - root privileges (BPF LSM load needs CAP_BPF + CAP_SYS_ADMIN).

set -u

PROFILES_DIR="${PROFILES_DIR:-profiles}"
BIN="${BIN:-./compartment-bpf}"
PIN_ROOT="/sys/fs/bpf/compartment"
LIVE_DEADLINE_S=10
SETTLE_S=3
LOG_DIR="${LOG_DIR:-/tmp/profile-smoke-logs}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
CSV="tests/profile-smoke-results-${TS}.csv"

mkdir -p "$LOG_DIR" tests

# --- per-daemon config --------------------------------------------------------
# Format: daemon_key | systemd_unit | binary_path | positive_control_target | liveness_command
# POS_TARGET is a sealed config file (not the running binary) so the LSM
# seal is what denies the write rather than ETXTBSY.

declare -A UNIT BIN_PATH POS_TARGET LIVENESS

# §D-19: auto-discover the profile set. ORDER is derived from
# profiles/*.conf at run time so a new profiles/<x>.conf is picked
# up automatically. Profiles without a UNIT/BIN_PATH/POS_TARGET/
# LIVENESS entry below are skipped noisily (see the per-iteration
# "no test config" branch).
mapfile -t ORDER < <(
    find "$PROFILES_DIR" -maxdepth 1 -name '*.conf' \
        ! -name 'all-daemons.conf' \
        -printf '%f\n' | sed 's/\.conf$//' | sort
)

UNIT[sshd]=ssh.service
BIN_PATH[sshd]=/usr/sbin/sshd
POS_TARGET[sshd]=/etc/ssh/sshd_config
LIVENESS[sshd]='systemctl is-active --quiet ssh && nc -z -w2 127.0.0.1 22'

UNIT[systemd-journald]=systemd-journald.service
BIN_PATH[systemd-journald]=/usr/lib/systemd/systemd-journald
POS_TARGET[systemd-journald]=/etc/systemd/journald.conf
LIVENESS[systemd-journald]='systemctl is-active --quiet systemd-journald && journalctl -n 1 --no-pager >/dev/null'

UNIT[dbus-daemon]=dbus.service
BIN_PATH[dbus-daemon]=/usr/bin/dbus-daemon
POS_TARGET[dbus-daemon]=/usr/share/dbus-1/system.conf
LIVENESS[dbus-daemon]='systemctl is-active --quiet dbus && dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply / org.freedesktop.DBus.ListNames >/dev/null'

UNIT[polkitd]=polkit.service
BIN_PATH[polkitd]=/usr/lib/polkit-1/polkitd
POS_TARGET[polkitd]=/usr/share/polkit-1/polkitd.conf
LIVENESS[polkitd]='systemctl is-active --quiet polkit && dbus-send --system --dest=org.freedesktop.PolicyKit1 --type=method_call --print-reply /org/freedesktop/PolicyKit1/Authority org.freedesktop.DBus.Peer.Ping >/dev/null'

UNIT[cron]=cron.service
BIN_PATH[cron]=/usr/sbin/cron
POS_TARGET[cron]=/etc/crontab
LIVENESS[cron]='systemctl is-active --quiet cron && pgrep -x cron >/dev/null'

UNIT[rsyslogd]=rsyslog.service
BIN_PATH[rsyslogd]=/usr/sbin/rsyslogd
POS_TARGET[rsyslogd]=/etc/rsyslog.conf
LIVENESS[rsyslogd]='systemctl is-active --quiet rsyslog && pgrep -x rsyslogd >/dev/null'

UNIT[systemd-networkd]=systemd-networkd.service
BIN_PATH[systemd-networkd]=/usr/lib/systemd/systemd-networkd
POS_TARGET[systemd-networkd]=/etc/systemd/networkd.conf
LIVENESS[systemd-networkd]='systemctl is-active --quiet systemd-networkd && networkctl list --no-pager 2>/dev/null | grep -q routable'

UNIT[systemd-resolved]=systemd-resolved.service
BIN_PATH[systemd-resolved]=/usr/lib/systemd/systemd-resolved
POS_TARGET[systemd-resolved]=/etc/systemd/resolved.conf
LIVENESS[systemd-resolved]='systemctl is-active --quiet systemd-resolved && resolvectl status --no-pager >/dev/null && getent hosts localhost >/dev/null'

UNIT[systemd-logind]=systemd-logind.service
BIN_PATH[systemd-logind]=/usr/lib/systemd/systemd-logind
POS_TARGET[systemd-logind]=/etc/systemd/logind.conf
LIVENESS[systemd-logind]='systemctl is-active --quiet systemd-logind && loginctl --no-pager >/dev/null'

UNIT[chronyd]=chrony.service
BIN_PATH[chronyd]=/usr/sbin/chronyd
POS_TARGET[chronyd]=/etc/chrony/chrony.conf
LIVENESS[chronyd]='systemctl is-active --quiet chrony && chronyc tracking >/dev/null'

# --- helpers ------------------------------------------------------------------

cleanup_pin() {
    # ED-7 (counter maps) and onward also pin counter maps under
    # $PIN_ROOT/maps/. Pre-ED-7 only links/ existed, so cleanup_pin
    # only swept links. Now sweep both — leaving maps/* behind made
    # the next --pin fail with EEXIST and broke the per-profile loop
    # for every daemon after the first (Leader-8 ED-13 diagnosis).
    if [ -d "$PIN_ROOT/links" ]; then
        rm -f "$PIN_ROOT"/links/* 2>/dev/null || true
    fi
    if [ -d "$PIN_ROOT/maps" ]; then
        rm -f "$PIN_ROOT"/maps/* 2>/dev/null || true
    fi
}

# Read inode of the binary. Used to scope the positive-control DENY check.
inode_of() { stat -c '%i' "$1"; }

# Return 0 if the audit log $1 contains a DENY_WRITE for inode $2.
audit_has_deny_write_for() {
    local log="$1" ino="$2"
    grep -E "DENY_WRITE.* ino=${ino}( |$)" "$log" >/dev/null 2>&1
}

# Return list of unexpected DENY events: any DENY_* line whose inode is NOT
# the positive-control inode. One match per line; "" means clean.
unexpected_denies() {
    local log="$1" pos_ino="$2"
    grep -E '\[audit\] DENY_' "$log" 2>/dev/null \
        | grep -vE " ino=${pos_ino}( |$)" \
        || true
}

# --- main loop ----------------------------------------------------------------

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: must run as root" >&2
    exit 1
fi
if [ ! -x "$BIN" ]; then
    echo "ERROR: $BIN not found or not executable" >&2
    exit 1
fi

echo "timestamp,daemon,unit,seals,live_pass,positive_pass,binary_etxtbsy,unexpected_denies,result,notes" > "$CSV"

pass=0
fail=0
# R2-M9: count SKIPped profiles (no UNIT/BIN_PATH/POS_TARGET/LIVENESS
# test config). Initialized here so the first SKIP increment inside
# the loop does not trip `set -u` ('unbound variable' on $skipped).
skipped=0

for daemon in "${ORDER[@]}"; do
    profile="${PROFILES_DIR}/${daemon}.conf"
    # §D-19: profiles without a UNIT mapping above are auto-discovered
    # but cannot be tested here (no liveness command, no positive-
    # control target). Skip noisily so future maintainers see what is
    # missing and can wire it up.
    if [ -z "${UNIT[$daemon]:-}" ]; then
        # R2-M9 (Review-2 MEDIUM): annotate the SKIP so the summary
        # row at the bottom of this script makes the un-witnessed
        # profile visible. Pre-this, the SKIP only landed in the
        # CSV and was effectively silent against the PASS=N FAIL=N
        # roll-up — operators could mis-read 'PASS=2 FAIL=0' as
        # 'all 17 profiles witnessed' when in fact 15 had no
        # test config.
        printf '# SKIP %s: no test config (UNIT/BIN_PATH/POS_TARGET/LIVENESS) for this profile [annotated R2-M9]\n' "$daemon"
        echo "$(date -u +%FT%TZ),$daemon,-,-,-,-,-,-,SKIP,no test config" >> "$CSV"
        skipped=$((skipped+1))
        continue
    fi
    unit="${UNIT[$daemon]}"
    binpath="${BIN_PATH[$daemon]}"
    pos_target="${POS_TARGET[$daemon]}"
    lcheck="${LIVENESS[$daemon]}"
    log="${LOG_DIR}/${daemon}.log"
    : > "$log"

    printf '\n========== %s (%s) ==========\n' "$daemon" "$unit"

    if [ ! -f "$profile" ]; then
        printf 'SKIP: %s missing\n' "$profile"
        echo "$(date -u +%FT%TZ),$daemon,$unit,-,-,-,-,SKIP,profile missing" >> "$CSV"
        fail=$((fail+1))
        continue
    fi

    seals=$(grep -c '^seal ' "$profile" || true)
    pos_ino="$(inode_of "$pos_target" 2>/dev/null || echo '')"
    if [ -z "$pos_ino" ]; then
        printf 'SKIP: %s positive-control target missing\n' "$pos_target"
        echo "$(date -u +%FT%TZ),$daemon,$unit,$seals,-,-,-,-,SKIP,pos-target missing" >> "$CSV"
        fail=$((fail+1))
        continue
    fi

    cleanup_pin

    # Baseline restart.
    systemctl restart "$unit"
    sleep 1
    if ! systemctl is-active --quiet "$unit"; then
        printf 'FAIL: %s did not come up at baseline\n' "$unit"
        echo "$(date -u +%FT%TZ),$daemon,$unit,$seals,0,-,-,-,FAIL,baseline restart failed" >> "$CSV"
        fail=$((fail+1))
        continue
    fi

    # Launch compartment-bpf in the background (--pin per brief).
    setsid "$BIN" --pin "$profile" >"$log" 2>&1 &
    cbpf_pid=$!

    # Wait up to LIVE_DEADLINE_S seconds for "[run] compartment-bpf live".
    live=0
    for _ in $(seq 1 "$LIVE_DEADLINE_S"); do
        if grep -q '\[run\] compartment-bpf live' "$log"; then
            live=1; break
        fi
        if ! kill -0 "$cbpf_pid" 2>/dev/null; then break; fi
        sleep 1
    done
    if [ "$live" -ne 1 ]; then
        printf 'FAIL: %s never reached [run] live\n' "$daemon"
        kill -INT "$cbpf_pid" 2>/dev/null || true
        wait "$cbpf_pid" 2>/dev/null || true
        cleanup_pin
        echo "$(date -u +%FT%TZ),$daemon,$unit,$seals,0,-,-,-,FAIL,not live" >> "$CSV"
        fail=$((fail+1))
        continue
    fi

    # Restart the daemon under enforcement and let it settle.
    systemctl restart "$unit"
    sleep "$SETTLE_S"

    # Liveness check.
    live_pass=0
    if eval "$lcheck"; then
        live_pass=1
    fi

    # Positive control: write to a sealed *config* file should be denied
    # by the LSM (we want a DENY_WRITE audit line, not ETXTBSY).
    pc_err=""
    if echo X >> "$pos_target" 2>/dev/null; then
        pc_status=1   # write succeeded — bad
    else
        pc_err="$( { echo X >> "$pos_target"; } 2>&1 1>/dev/null )"
        pc_status=0
    fi
    sleep 1   # let the audit ringbuf flush
    positive_pass=0
    if [ "$pc_status" -eq 0 ] && audit_has_deny_write_for "$log" "$pos_ino"; then
        positive_pass=1
    fi

    # Informational: confirm the running binary itself is unwritable.
    # On a live process this is ETXTBSY (kernel exec lock), independent
    # of the LSM. We record this as evidence of defence-in-depth.
    bin_etxtbsy=0
    bin_err="$( { echo X >> "$binpath"; } 2>&1 1>/dev/null )"
    case "$bin_err" in
        *"Text file busy"*|*ETXTBSY*) bin_etxtbsy=1 ;;
    esac

    # Unexpected DENY scan (any DENY not on the positive-control inode).
    unexp="$(unexpected_denies "$log" "$pos_ino" | wc -l)"
    unexp="${unexp:-0}"
    # `unexpected_denies` may emit an empty line; normalize.
    if [ -z "$(unexpected_denies "$log" "$pos_ino" | tr -d '[:space:]')" ]; then
        unexp=0
    fi

    # Tear down compartment-bpf and clean the pin.
    kill -INT "$cbpf_pid" 2>/dev/null || true
    wait "$cbpf_pid" 2>/dev/null || true
    cleanup_pin

    # Restore daemon to a clean (unsealed) state.
    systemctl restart "$unit" >/dev/null 2>&1 || true

    notes=""
    if [ "$pc_status" -ne 0 ]; then notes="positive-control write SUCCEEDED (bad); "; fi
    if [ "$bin_etxtbsy" -ne 1 ]; then notes="${notes}binary not ETXTBSY-locked; "; fi

    if [ "$live_pass" -eq 1 ] && [ "$positive_pass" -eq 1 ] && [ "$unexp" -eq 0 ]; then
        result=PASS; pass=$((pass+1))
    else
        result=FAIL; fail=$((fail+1))
    fi

    printf '%s: live=%d pos=%d etxtbsy=%d unexp=%d -> %s\n' \
        "$daemon" "$live_pass" "$positive_pass" "$bin_etxtbsy" "$unexp" "$result"
    echo "$(date -u +%FT%TZ),$daemon,$unit,$seals,$live_pass,$positive_pass,$bin_etxtbsy,$unexp,$result,$notes" >> "$CSV"
done

cleanup_pin

printf '\n========== SUMMARY ==========\n'
# R2-M9: surface SKIPped profiles in the summary line so 'no test
# config' rows do not silently disappear behind the PASS/FAIL tally.
skipped=${skipped:-0}
printf 'PASS=%d  FAIL=%d  SKIP=%d  TOTAL=%d (SKIP = profiles without UNIT/BIN_PATH/POS_TARGET/LIVENESS config; R2-M9)\n' \
    "$pass" "$fail" "$skipped" "$((pass+fail+skipped))"
printf 'CSV : %s\n' "$CSV"
printf 'logs: %s\n' "$LOG_DIR"

if [ "$fail" -gt 0 ]; then
    exit 1
fi
exit 0
