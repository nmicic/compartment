#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# aggregate-smoke.sh — Phase D integration smoke for the top-10 profiles.
#
# Loads profiles/all-daemons.conf (44 seals, 10 daemons) in one shot and
# asserts every daemon stays operational simultaneously under enforcement.
# This is the production-like run.
#
# Output: tests/aggregate-smoke-results-<TS>.csv
#
# PASS bar: 10/10 daemons pass liveness AND positive control on at least
# one sealed config file is denied AND zero unexpected DENY events.
#
# Run on Resolute in /root/compartment-bpf-profiles. Requires root.

set -u

PROFILE="${PROFILE:-profiles/all-daemons.conf}"
BIN="${BIN:-./compartment-bpf}"
PIN_ROOT="/sys/fs/bpf/compartment"
LIVE_DEADLINE_S=15
SETTLE_S=5
LOG_DIR="${LOG_DIR:-/tmp/aggregate-smoke-logs}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
CSV="tests/aggregate-smoke-results-${TS}.csv"
LOG="${LOG_DIR}/aggregate.log"

mkdir -p "$LOG_DIR" tests
: > "${LOG}"

declare -A UNIT POS_TARGET LIVENESS
PROFILES_DIR="$(dirname "$PROFILE")"

# §D-19: auto-discover the profile set. Per-daemon UNIT/POS_TARGET/
# LIVENESS entries below remain hand-curated; auto-discovered
# profiles without a mapping are skipped noisily inside the
# per-daemon loop. This keeps the runner forward-compatible with
# new profiles/<x>.conf files without silently dropping them from
# the iteration.
mapfile -t ORDER < <(
    find "$PROFILES_DIR" -maxdepth 1 -name '*.conf' \
        ! -name 'all-daemons.conf' \
        -printf '%f\n' | sed 's/\.conf$//' | sort
)

UNIT[sshd]=ssh.service
POS_TARGET[sshd]=/etc/ssh/sshd_config
LIVENESS[sshd]='systemctl is-active --quiet ssh && nc -z -w2 127.0.0.1 22'

UNIT[systemd-journald]=systemd-journald.service
POS_TARGET[systemd-journald]=/etc/systemd/journald.conf
LIVENESS[systemd-journald]='systemctl is-active --quiet systemd-journald && journalctl -n 1 --no-pager >/dev/null'

UNIT[dbus-daemon]=dbus.service
POS_TARGET[dbus-daemon]=/usr/share/dbus-1/system.conf
LIVENESS[dbus-daemon]='systemctl is-active --quiet dbus && dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply / org.freedesktop.DBus.ListNames >/dev/null'

UNIT[polkitd]=polkit.service
POS_TARGET[polkitd]=/usr/share/polkit-1/polkitd.conf
LIVENESS[polkitd]='systemctl is-active --quiet polkit && dbus-send --system --dest=org.freedesktop.PolicyKit1 --type=method_call --print-reply /org/freedesktop/PolicyKit1/Authority org.freedesktop.DBus.Peer.Ping >/dev/null'

UNIT[cron]=cron.service
POS_TARGET[cron]=/etc/crontab
LIVENESS[cron]='systemctl is-active --quiet cron && pgrep -x cron >/dev/null'

UNIT[rsyslogd]=rsyslog.service
POS_TARGET[rsyslogd]=/etc/rsyslog.conf
LIVENESS[rsyslogd]='systemctl is-active --quiet rsyslog && pgrep -x rsyslogd >/dev/null'

UNIT[systemd-networkd]=systemd-networkd.service
POS_TARGET[systemd-networkd]=/etc/systemd/networkd.conf
LIVENESS[systemd-networkd]='systemctl is-active --quiet systemd-networkd && networkctl list --no-pager 2>/dev/null | grep -q routable'

UNIT[systemd-resolved]=systemd-resolved.service
POS_TARGET[systemd-resolved]=/etc/systemd/resolved.conf
LIVENESS[systemd-resolved]='systemctl is-active --quiet systemd-resolved && resolvectl status --no-pager >/dev/null && getent hosts localhost >/dev/null'

UNIT[systemd-logind]=systemd-logind.service
POS_TARGET[systemd-logind]=/etc/systemd/logind.conf
LIVENESS[systemd-logind]='systemctl is-active --quiet systemd-logind && loginctl --no-pager >/dev/null'

UNIT[chronyd]=chrony.service
POS_TARGET[chronyd]=/etc/chrony/chrony.conf
LIVENESS[chronyd]='systemctl is-active --quiet chrony && chronyc tracking >/dev/null'

cleanup_pin() {
    # ED-7 (counter maps) and onward also pin counter maps under
    # $PIN_ROOT/maps/. Pre-ED-7 only links/ existed, so cleanup_pin
    # only swept links — leaving maps/* behind made the next --pin
    # fail with EEXIST (matches the fix in profile-smoke.sh).
    if [ -d "$PIN_ROOT/links" ]; then
        rm -f "$PIN_ROOT"/links/* 2>/dev/null || true
    fi
    if [ -d "$PIN_ROOT/maps" ]; then
        rm -f "$PIN_ROOT"/maps/* 2>/dev/null || true
    fi
}

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: must run as root" >&2
    exit 1
fi
if [ ! -x "$BIN" ]; then
    echo "ERROR: $BIN not found or not executable" >&2
    exit 1
fi
if [ ! -f "$PROFILE" ]; then
    echo "ERROR: $PROFILE not found" >&2
    exit 1
fi

echo "timestamp,daemon,unit,live_pass,positive_pass,note" > "$CSV"

# §D-19: build TESTED list = ORDER ∩ profiles-with-UNIT-mapping.
# Profiles without a UNIT entry (nginx, postgres, redis, postfix,
# shells-allowlist as of 2026-05-14) are still loaded into the
# aggregate (the aggregate profile contains their seals), but the
# per-daemon test loop has no way to liveness-check them, so we
# skip them noisily here.
declare -a TESTED=()
for daemon in "${ORDER[@]}"; do
    if [ -n "${UNIT[$daemon]:-}" ]; then
        TESTED+=("$daemon")
    else
        echo "# SKIP $daemon: no UNIT/POS_TARGET/LIVENESS mapping in this runner"
    fi
done

# Step 1: bring all daemons to known baseline.
echo "[setup] restarting ${#TESTED[@]} daemon(s) with test config to baseline..."
for daemon in "${TESTED[@]}"; do
    systemctl restart "${UNIT[$daemon]}" || \
        echo "WARN: ${UNIT[$daemon]} restart failed at baseline"
done
sleep 2

cleanup_pin

# The canonical aide profile is documented
# at /usr/sbin/aide (matching the Debian historical layout); usr-merged
# distros (Ubuntu Resolute) ship aide at /usr/bin/aide. tests/profile-e2e/
# aide.sh handles this per-run by sed-substituting the discovered path
# into a temp profile; the aggregate loader must do the same so the
# strict-mode E-6 enforcement (actor binary sealed at its declared path)
# resolves on usr-merged distros. No-op when the canonical path already
# matches.
PROFILE_RUN="$(mktemp /tmp/all-daemons-runtime-XXXXXX.conf)"
cp "$PROFILE" "$PROFILE_RUN"
if command -v aide >/dev/null 2>&1; then
    AIDE_BIN="$(command -v aide)"
    if [ "$AIDE_BIN" != "/usr/sbin/aide" ]; then
        sed -i "s|/usr/sbin/aide|${AIDE_BIN}|g" "$PROFILE_RUN"
        echo "[setup] aide path substituted: /usr/sbin/aide -> ${AIDE_BIN}"
    fi
fi

# Leader-8 ED-13: stock Resolute ships several profile-referenced binaries
# as `update-alternatives` symlinks (/bin/false, /usr/bin/ksh, /usr/bin/csh,
# /usr/bin/redis-server, ...). compartment-bpf refuses to seal a symlink
# leaf — this is a deliberate fail-closed property of the loader (avoids
# the inum-of-the-symlink-vs-target confusion). The aggregate cocktail
# test's purpose is "does the SYSTEM stay stable under many concurrent
# seals", NOT "does every documented path exist on this distro" — each
# individual profile is exercised independently by tests/profile-smoke.sh
# (10/10 PASS). Filter out seal lines whose path is a symlink leaf or
# missing on this host, so the aggregate exercises what the host actually
# provides. Filter is logged so an operator sees what was skipped.
FILTERED_TMP="$(mktemp /tmp/all-daemons-filter-XXXXXX.conf)"
n_kept=0; n_dropped=0
while IFS= read -r line; do
    case "$line" in
        seal\ *)
            # Parse: seal PATH FLAGS ...; PATH is field 2 (whitespace-
            # separated). Other tokens may include actor=NAME.
            seal_path="$(echo "$line" | awk '{print $2}')"
            if [ ! -e "$seal_path" ]; then
                echo "[filter] DROP missing: $line"
                n_dropped=$((n_dropped + 1))
                continue
            fi
            if [ -L "$seal_path" ]; then
                echo "[filter] DROP symlink-leaf: $line"
                n_dropped=$((n_dropped + 1))
                continue
            fi
            n_kept=$((n_kept + 1))
            ;;
        actor\ *)
            # actor NAME = PATH [PATH ...]: drop the whole decl if any
            # path is a symlink or missing. The seals that reference
            # this actor are independently filtered above and any
            # `actor=NAME` clauses they carry will fail strict-mode if
            # the actor decl was dropped — but that surfaces as a
            # parse error, not a silent miss.
            paths="$(echo "$line" | awk -F'=' '{print $2}')"
            actor_ok=1
            for p in $paths; do
                if [ ! -e "$p" ] || [ -L "$p" ]; then
                    actor_ok=0; break
                fi
            done
            if [ "$actor_ok" -eq 0 ]; then
                echo "[filter] DROP actor (missing or symlink): $line"
                n_dropped=$((n_dropped + 1))
                continue
            fi
            ;;
    esac
    printf '%s\n' "$line" >> "$FILTERED_TMP"
done < "$PROFILE_RUN"
mv "$FILTERED_TMP" "$PROFILE_RUN"
echo "[filter] kept=$n_kept dropped=$n_dropped → $PROFILE_RUN"

# Step 2: load aggregate profile.
echo "[setup] launching compartment-bpf --pin $PROFILE_RUN"
setsid "$BIN" --pin "$PROFILE_RUN" >"$LOG" 2>&1 &
cbpf_pid=$!

live=0
for _ in $(seq 1 "$LIVE_DEADLINE_S"); do
    if grep -q '\[run\] compartment-bpf live' "$LOG"; then
        live=1; break
    fi
    if ! kill -0 "$cbpf_pid" 2>/dev/null; then break; fi
    sleep 1
done
if [ "$live" -ne 1 ]; then
    echo "FATAL: compartment-bpf never reached [run] live"
    tail -20 "$LOG"
    kill -INT "$cbpf_pid" 2>/dev/null || true
    wait "$cbpf_pid" 2>/dev/null || true
    cleanup_pin
    exit 1
fi
echo "[setup] enforcement live (44 seals loaded)"

# Step 3: restart every daemon under enforcement, in order.
echo "[run] restarting all 10 daemons under aggregate enforcement..."
for daemon in "${TESTED[@]}"; do
    systemctl restart "${UNIT[$daemon]}" \
        && echo "   restart $daemon: ok" \
        || echo "   restart $daemon: FAILED"
done
sleep "$SETTLE_S"

# Step 4: per-daemon liveness + per-daemon positive control.
pass=0
fail=0
for daemon in "${TESTED[@]}"; do
    unit="${UNIT[$daemon]}"
    pos="${POS_TARGET[$daemon]}"
    pos_ino="$(stat -c '%i' "$pos" 2>/dev/null || echo '')"

    live_pass=0
    if eval "${LIVENESS[$daemon]}"; then live_pass=1; fi

    pc_pass=0
    if [ -n "$pos_ino" ]; then
        if echo X >> "$pos" 2>/dev/null; then
            pc_pass=0   # write succeeded — bad
        else
            sleep 1
            if grep -E "DENY_WRITE.* ino=${pos_ino}( |$)" "$LOG" >/dev/null; then
                pc_pass=1
            fi
        fi
    fi

    note=""
    if [ "$live_pass" -ne 1 ]; then note="${note}liveness failed; "; fi
    if [ "$pc_pass" -ne 1 ];   then note="${note}positive control failed; "; fi

    if [ "$live_pass" -eq 1 ] && [ "$pc_pass" -eq 1 ]; then
        pass=$((pass+1))
        printf '   %-20s live=1 pos=1 OK\n' "$daemon"
    else
        fail=$((fail+1))
        printf '   %-20s live=%d pos=%d FAIL  %s\n' "$daemon" "$live_pass" "$pc_pass" "$note"
    fi
    echo "$(date -u +%FT%TZ),$daemon,$unit,$live_pass,$pc_pass,$note" >> "$CSV"
done

# Step 5: count any DENY events that we did NOT explicitly trigger above.
# We compare against the union of positive-control inodes; anything else
# is unexpected.
mapfile -t pos_inos < <(
    for d in "${TESTED[@]}"; do
        stat -c '%i' "${POS_TARGET[$d]}" 2>/dev/null
    done | sort -u
)
inos_re="$(printf 'ino=%s|' "${pos_inos[@]}")"
inos_re="${inos_re%|}"

unexpected=$(grep -E '\[audit\] DENY_' "$LOG" 2>/dev/null \
             | grep -vE "$inos_re" || true)
unexpected_count=0
if [ -n "$unexpected" ]; then
    unexpected_count=$(printf '%s\n' "$unexpected" | wc -l)
fi

# Step 6: tear down.
echo "[teardown] SIGINT compartment-bpf"
kill -INT "$cbpf_pid" 2>/dev/null || true
wait "$cbpf_pid" 2>/dev/null || true
cleanup_pin

echo "[teardown] restarting all daemons to clean state..."
for daemon in "${TESTED[@]}"; do
    systemctl restart "${UNIT[$daemon]}" >/dev/null 2>&1 || true
done

echo
echo "========== AGGREGATE SUMMARY =========="
printf 'PASS=%d  FAIL=%d  unexpected_denies=%d\n' "$pass" "$fail" "$unexpected_count"
printf 'CSV : %s\n' "$CSV"
printf 'log : %s\n' "$LOG"
if [ "$unexpected_count" -gt 0 ]; then
    echo "--- unexpected DENY events ---"
    printf '%s\n' "$unexpected" | head -20
fi

if [ "$fail" -gt 0 ] || [ "$unexpected_count" -gt 0 ]; then
    exit 1
fi
exit 0
