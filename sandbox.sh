#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# sandbox.sh — Run AI CLI agents in a network-isolated user namespace
#
# All API traffic is forced through a transparent proxy bridge (unix socket).
# No root required — uses unprivileged user namespaces + slirp4netns.
#
# Usage:
#   ./sandbox.sh <command...>
#   ./sandbox.sh my-agent --full-auto
#   UPSTREAM_PROXY=http://corp-proxy:8080 ./sandbox.sh my-agent
#
# Verify isolation:
#   ./sandbox.sh --verify
#
# Requirements: unshare and ip (util-linux, iproute2)
#               socat        only when UPSTREAM_PROXY is set
# Optional:     slirp4netns + nsenter (SOFT mode, when the kernel refuses an
#               unprivileged mapped-root namespace)
#
# Environment:
#   UPSTREAM_PROXY              corporate proxy to bridge to (host:port URL)
#   SANDBOX_PROXY_PORT          port the bridge listens on inside (18080)
#   SANDBOX_LOGDIR              audit log directory (~/.sandbox-audit)
#   SANDBOX_NO_SHELL_INTERCEPT  set to 1 to skip the bind-mount shell
#                               replacement entirely
#   SANDBOX_UNSHARE             path to the unshare(1) binary to use
#   SANDBOX_SHELLS              space-separated shells to intercept
#
# Isolation levels:
#   HARD  — loopback-only namespace, no external interfaces, no routes.
#           The ONLY network path is unix-socket → proxy bridge.
#           (requires unprivileged user namespaces with a uid map)
#   SOFT  — slirp4netns provides lo + tap0, --disable-host-loopback.
#           Proxy enforced via env vars. tap0 exists but host loopback blocked.
#           (fallback for restricted container environments)
#
# If neither is available the script says why and exits; it never silently
# runs the command unsandboxed.

set -euo pipefail

# ── Configuration ───────────────────────────────────────────────────────
UPSTREAM_PROXY="${UPSTREAM_PROXY:-${HTTPS_PROXY:-${HTTP_PROXY:-}}}"
INNER_PORT="${SANDBOX_PROXY_PORT:-18080}"
UNSHARE_BIN="${SANDBOX_UNSHARE:-unshare}"
# Validate port is numeric and in range to prevent injection into socat arguments
[[ "$INNER_PORT" =~ ^[0-9]+$ ]] || { echo "sandbox: ERROR: SANDBOX_PROXY_PORT must be numeric" >&2; exit 1; }
[ "$INNER_PORT" -ge 1 ] && [ "$INNER_PORT" -le 65535 ] || { echo "sandbox: ERROR: SANDBOX_PROXY_PORT out of range (1-65535)" >&2; exit 1; }
# Use a private temp directory (mode 700) to avoid predictable /tmp socket paths
SOCK_DIR="$(mktemp -d -t compartment-sandbox-XXXXXXXX)"
chmod 700 "$SOCK_DIR"
SOCK="$SOCK_DIR/proxy.sock"
LOGDIR="${SANDBOX_LOGDIR:-${HOME}/.sandbox-audit}"
LOGFILE="${LOGDIR}/sandbox-$(date +%Y%m%dT%H%M%S)-$$.log"
STATUS=""

die() { echo "sandbox: ERROR: $*" >&2; exit 1; }

log() {
    local msg
    msg="$(date -Iseconds) $*"
    echo "sandbox: $*" >&2
    echo "$msg" >> "$LOGFILE" 2>/dev/null || true
}

cleanup() {
    log "cleanup: stopping bridge processes"
    [ -n "${SOCAT_PID:-}" ]  && kill "$SOCAT_PID" 2>/dev/null || true
    [ -n "${SLIRP_PID:-}" ] && kill "$SLIRP_PID" 2>/dev/null || true
    [ -n "${NS_PID:-}" ]    && kill "$NS_PID" 2>/dev/null || true
    rm -rf "$SOCK_DIR"
    # rmdir only removes empty directories: after a real run the stash tmpfs
    # lived inside the namespace, so what is left here is an empty directory.
    [ -n "${SHELL_STASH:-}" ] && rmdir "$SHELL_STASH" 2>/dev/null || true
    [ -n "${SHELL_STASH_PARENT:-}" ] && rmdir "$SHELL_STASH_PARENT" 2>/dev/null || true
    log "session ended (exit=${STATUS:-unknown})"
}
trap cleanup EXIT

# ── Audit log setup ────────────────────────────────────────────────────
mkdir -p "$LOGDIR" 2>/dev/null || true
chmod 700 "$LOGDIR" 2>/dev/null || true
log "=== sandbox session started ==="
log "user=$(id -un) uid=$(id -u) pid=$$ ppid=$PPID"
log "host=$(hostname) kernel=$(uname -r)"
log "command: $*"
log "upstream_proxy=${UPSTREAM_PROXY:-(none)}"

# ── User-namespace availability ────────────────────────────────────────
# HARD mode needs a user namespace with a uid map. Distributions block that
# in three different places, and only one of them is the sysctl this script
# used to look at — on Ubuntu 23.10+ the block is an AppArmor policy and the
# failure surfaces as "write failed /proc/self/uid_map: Operation not
# permitted", which says nothing about the cause.
userns_block_reason() {
    local v
    if [ -r /proc/sys/kernel/unprivileged_userns_clone ]; then
        v="$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo 1)"
        [ "$v" = "0" ] && { echo "sysctl kernel.unprivileged_userns_clone=0"; return 0; }
    fi
    if [ -r /proc/sys/user/max_user_namespaces ]; then
        v="$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo 1)"
        [ "$v" = "0" ] && { echo "sysctl user.max_user_namespaces=0"; return 0; }
    fi
    if [ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
        v="$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)"
        [ "$v" = "1" ] && {
            echo "AppArmor (kernel.apparmor_restrict_unprivileged_userns=1)"
            return 0
        }
    fi
    return 1
}

# What to do about it, in the order we would recommend.
hard_mode_help() {
    cat >&2 <<'HELP'
sandbox: HARD mode needs an unprivileged user namespace with a uid map.
sandbox: Options, most contained first:
sandbox:   1. Install slirp4netns and nsenter and re-run — sandbox.sh falls
sandbox:      back to SOFT mode, which does not need a mapped root.
sandbox:   2. Grant just this program the right, instead of the whole system.
sandbox:      On AppArmor systems add a profile with "userns create" for the
sandbox:      unshare(1) binary under /etc/apparmor.d/ and reload AppArmor.
sandbox:   3. Last resort, system-wide and permanent:
sandbox:        sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
sandbox:      (or kernel.unprivileged_userns_clone=1 on Debian-family kernels)
sandbox:      This re-enables unprivileged user namespaces for every process
sandbox:      on the machine. Do not do it on a shared host.
HELP
}

# ── Preflight checks ───────────────────────────────────────────────────
check_deps() {
    local missing=""
    for cmd in "$UNSHARE_BIN" ip; do
        command -v "$cmd" >/dev/null 2>&1 || missing="$missing $cmd"
    done
    # socat is only used to bridge to an upstream proxy. Without one, HARD
    # mode is fully airgapped and socat is never invoked, so requiring it
    # would refuse to run a sandbox that works perfectly well.
    if [ -n "$UPSTREAM_PROXY" ]; then
        command -v socat >/dev/null 2>&1 || missing="$missing socat"
    fi
    [ -z "$missing" ] || die "missing dependencies:$missing (install: util-linux, iproute2, socat)"
}

# ── Verify mode ─────────────────────────────────────────────────────────
run_verify() {
    local reason=""
    echo "=== Sandbox Isolation Verification ==="
    echo ""
    echo "1. Dependencies:"
    for cmd in "$UNSHARE_BIN" ip socat nsenter slirp4netns; do
        printf "   %-15s " "$cmd"
        if command -v "$cmd" >/dev/null 2>&1; then
            echo "OK ($(command -v "$cmd"))"
        elif [ "$cmd" = "socat" ] && [ -z "$UPSTREAM_PROXY" ]; then
            echo "MISSING (only needed with UPSTREAM_PROXY)"
        elif [ "$cmd" = "nsenter" ] || [ "$cmd" = "slirp4netns" ]; then
            echo "MISSING (only needed for SOFT mode)"
        else
            echo "MISSING"
        fi
    done

    echo ""
    echo "2. Kernel support:"
    for knob in /proc/sys/kernel/unprivileged_userns_clone \
                /proc/sys/user/max_user_namespaces \
                /proc/sys/kernel/apparmor_restrict_unprivileged_userns; do
        [ -r "$knob" ] || continue
        printf "   %-46s %s\n" "${knob#/proc/sys/}:" "$(cat "$knob")"
    done
    printf "   %-46s " "user+net namespace creation:"
    if "$UNSHARE_BIN" --user --net -- /bin/true 2>/dev/null; then echo "OK"; else echo "FAILED"; fi
    printf "   %-46s " "user namespace with a uid map:"
    if "$UNSHARE_BIN" --user --map-root-user -- /bin/true 2>/dev/null; then
        echo "OK"
    else
        reason="$(userns_block_reason || true)"
        echo "FAILED${reason:+ — blocked by ${reason}}"
    fi

    echo ""
    echo "3. Isolation level:"
    printf "   %-30s " "HARD (lo-only, --map-root-user):"
    if "$UNSHARE_BIN" --user --net --map-root-user --fork -- bash -c 'ip link set lo up' 2>/dev/null; then
        echo "OK — loopback-only namespace works"
        ISOLATION="HARD"
    else
        echo "UNAVAILABLE${reason:+ — blocked by ${reason}}"
    fi
    printf "   %-30s " "SOFT (slirp4netns fallback):"
    if command -v slirp4netns >/dev/null 2>&1 && command -v nsenter >/dev/null 2>&1; then
        echo "OK — slirp4netns available"
        [ "${ISOLATION:-}" != "HARD" ] && ISOLATION="SOFT"
    else
        echo "UNAVAILABLE"
    fi

    echo ""
    echo "4. Network isolation test:"
    if [ "${ISOLATION:-}" = "HARD" ]; then
        "$UNSHARE_BIN" --user --net --map-root-user --fork -- bash -c '
            ip link set lo up 2>/dev/null
            echo "   Interfaces inside namespace:"
            ip -br addr show 2>&1 | sed "s/^/     /"
            echo "   Routes:"
            ip route show 2>&1 | sed "s/^/     /"
            echo "   Direct internet (should fail):"
            printf "     "
            curl -s --connect-timeout 2 http://example.com >/dev/null 2>&1 && echo "REACHABLE (BAD)" || echo "BLOCKED (good)"
        ' 2>/dev/null
    elif [ "${ISOLATION:-}" = "SOFT" ]; then
        echo "   (slirp4netns test skipped — requires background process)"
    else
        echo "   NO ISOLATION AVAILABLE"
    fi

    echo ""
    echo "5. Proxy bridge test:"
    if [ -n "$UPSTREAM_PROXY" ]; then
        echo "   upstream: $UPSTREAM_PROXY"
        printf "   connectivity: "
        verify_hp="${UPSTREAM_PROXY#http://}"
        verify_hp="${verify_hp#https://}"
        verify_hp="${verify_hp%%/*}"
        if [[ "$verify_hp" =~ ^[a-zA-Z0-9._-]+:[0-9]+$ ]]; then
            timeout 3 socat -u /dev/null "TCP:$verify_hp" 2>/dev/null && echo "OK" || echo "UNREACHABLE"
        else
            echo "   INVALID (not host:port)"
        fi
    else
        echo "   UPSTREAM_PROXY not set — set it to your corporate proxy"
    fi

    echo ""
    echo "=== Result: isolation=${ISOLATION:-NONE} ==="
    if [ "${ISOLATION:-NONE}" = "NONE" ]; then
        echo ""
        hard_mode_help
    fi
    echo "Audit logs: $LOGDIR/"
    STATUS=0
    exit 0
}

# ── Parse args ──────────────────────────────────────────────────────────
[ $# -ge 1 ] || die "usage: sandbox.sh [--verify] <command...>"
[ "$1" = "--verify" ] && run_verify

check_deps

# ── Host-side proxy bridge (upstream proxy ← unix socket) ──────────────
if [ -n "$UPSTREAM_PROXY" ]; then
    PROXY_HOSTPORT="${UPSTREAM_PROXY#http://}"
    PROXY_HOSTPORT="${PROXY_HOSTPORT#https://}"
    PROXY_HOSTPORT="${PROXY_HOSTPORT%%/*}"
    # Validate host:port format to prevent socat argument injection
    [[ "$PROXY_HOSTPORT" =~ ^[a-zA-Z0-9._-]+:[0-9]+$ ]] || die "UPSTREAM_PROXY is not valid host:port: $PROXY_HOSTPORT"

    socat "UNIX-LISTEN:$SOCK,fork,mode=600" "TCP:$PROXY_HOSTPORT" &
    SOCAT_PID=$!
    for _ in $(seq 1 30); do [ -S "$SOCK" ] && break; sleep 0.05; done
    [ -S "$SOCK" ] || die "proxy bridge socket did not appear"
    log "proxy bridge: $UPSTREAM_PROXY <-> $SOCK (pid $SOCAT_PID)"
else
    log "WARNING: no UPSTREAM_PROXY set — HARD mode is fully airgapped, SOFT mode has outbound via slirp"
fi

# ── Find compartment-user binary (Landlock + seccomp hardening) ────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPARTMENT=""
for p in "$SCRIPT_DIR/compartment-user" \
         "$SCRIPT_DIR/../extra/compartment-user" \
         "$(dirname "$SCRIPT_DIR")/extra/compartment-user"; do
    [ -x "$p" ] && { COMPARTMENT="$p"; break; }
done
# Also check PATH
[ -z "$COMPARTMENT" ] && command -v compartment-user >/dev/null 2>&1 && \
    COMPARTMENT="$(command -v compartment-user)"

if [ -n "$COMPARTMENT" ]; then
    log "compartment-user: $COMPARTMENT (Landlock + seccomp + env sanitize)"
else
    log "compartment-user: not found (skipping Landlock/seccomp hardening)"
    log "  build with: make compartment-user"
fi

# ── Shell replacement via bind mount (Option A) ───────────────────────
# compartment-user is bind-mounted over /bin/bash (and friends) so every
# subprocess the agent spawns is sandboxed too. The real shells are moved
# aside into a stash that compartment-user finds via COMPARTMENT_SHELL_DIR.
#
# Where the stash lives is not a detail. Inside the namespace we are uid 0
# mapped to an unprivileged host uid, so host-root-owned directories such as
# /bin are not writable and the old "mkdir -p /bin/.shells_XXXX" failed with
# EACCES; the stash was never populated while the intercept mounts succeeded,
# so every shell in the sandbox exited 127. /tmp is writable but the ai-agent
# profile maps it "rw", and rw is W^X, so a shell stashed there cannot be
# executed either. $HOME is the one location that is both ours to write and
# "rwx" in the profile.
SHELL_STASH_PARENT=""
SHELL_STASH=""
SHELL_INTERCEPT=""
if [ -n "$COMPARTMENT" ] && [ "${SANDBOX_NO_SHELL_INTERCEPT:-0}" != "1" ]; then
    [ -n "${HOME:-}" ] && [ -d "$HOME" ] && [ -w "$HOME" ] || \
        die "HOME is not a writable directory — the shell intercept needs one (set SANDBOX_NO_SHELL_INTERCEPT=1 to run without it)"
    SHELL_STASH_PARENT="${HOME}/.compartment-shells"
    SHELL_STASH="${SHELL_STASH_PARENT}/$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    mkdir -p "$SHELL_STASH" || die "cannot create the shell stash $SHELL_STASH"
    chmod 700 "$SHELL_STASH_PARENT" "$SHELL_STASH"

    SANDBOX_SHELLS="${SANDBOX_SHELLS:-/bin/bash /usr/bin/bash /bin/sh /usr/bin/sh /bin/dash /usr/bin/dash /bin/zsh /usr/bin/zsh}"
    SHELL_INTERCEPT='
    _intercept_shells() {
        stash="'"$SHELL_STASH"'"
        compartment="'"$COMPARTMENT"'"
        intercepted=""
        probe_shell=""
        rc=0

        # A private tmpfs: somewhere we can certainly create files, that
        # disappears with the namespace, and that inherits the rwx $HOME
        # Landlock rule from the directory it is mounted on.
        if ! mount -t tmpfs -o mode=0700,nosuid tmpfs "$stash"; then
            echo "sandbox: ERROR: cannot mount the shell stash on $stash" >&2
            return 1
        fi

        for sh in '"$SANDBOX_SHELLS"'; do
            [ -x "$sh" ] || continue
            name="${sh##*/}"
            if [ ! -e "$stash/$name" ]; then
                # Create the bind target first: binding a file onto a path
                # that does not exist fails with "mount point does not
                # exist", which is what left the old stash empty.
                if ! : > "$stash/$name"; then
                    echo "sandbox: ERROR: cannot create stash entry $stash/$name" >&2
                    rc=1
                    break
                fi
                if ! mount --bind "$sh" "$stash/$name"; then
                    echo "sandbox: ERROR: cannot stash $sh in $stash/$name" >&2
                    rc=1
                    break
                fi
                # Belt and braces against a write-through to the real shell
                # binary. DAC already refuses it (the host root owner is not
                # mapped into this namespace), so this is not fatal.
                if ! mount -o remount,bind,ro "$stash/$name" 2>/dev/null; then
                    echo "sandbox: note: $stash/$name could not be made read-only" >&2
                fi
            fi
            if mount --bind "$compartment" "$sh"; then
                intercepted="$intercepted $sh"
                [ -n "$probe_shell" ] || probe_shell="$sh"
                echo "sandbox: shell intercept: $sh -> compartment-user" >&2
            else
                echo "sandbox: ERROR: cannot intercept $sh" >&2
                rc=1
                break
            fi
        done

        if [ "$rc" -eq 0 ] && [ -z "$probe_shell" ]; then
            echo "sandbox: ERROR: no shell was intercepted" >&2
            rc=1
        fi

        if [ "$rc" -eq 0 ]; then
            # Verify the whole path end to end, through a shell we actually
            # intercepted. This catches an empty stash (every shell in the
            # sandbox would exit 127) and a stash the Landlock profile
            # refuses to execute from — neither of which the mount commands
            # above would have reported.
            export COMPARTMENT_SHELL_DIR="$stash"
            probe_rc=0
            "$probe_shell" -c "exit 42" || probe_rc=$?
            if [ "$probe_rc" -ne 42 ]; then
                echo "sandbox: ERROR: shell intercept verification failed:" >&2
                echo "sandbox:        $probe_shell -c \"exit 42\" returned $probe_rc," >&2
                echo "sandbox:        expected 42 — the stashed shell does not run" >&2
                rc=1
            fi
        fi

        if [ "$rc" -ne 0 ]; then
            unset COMPARTMENT_SHELL_DIR
            for p in $intercepted; do
                umount "$p" || echo "sandbox: WARNING: could not undo intercept on $p" >&2
            done
            return 1
        fi

        # NOTE: the stash path is discoverable via /proc/self/mountinfo.
        # That is a known limitation of the bind-mount approach; the real
        # security boundary is Landlock + seccomp, not path hiding.
        return 0
    }

    probe_target=""
    for sh in '"$SANDBOX_SHELLS"'; do
        [ -x "$sh" ] && { probe_target="$sh"; break; }
    done
    if [ -z "$probe_target" ]; then
        echo "sandbox: WARNING: none of the shells to intercept exist: '"$SANDBOX_SHELLS"'" >&2
    elif probe_err=$(mount --bind "$probe_target" "$probe_target" 2>&1); then
        if ! _intercept_shells; then
            echo "sandbox: refusing to continue with a half-installed shell intercept." >&2
            echo "sandbox: re-run with SANDBOX_NO_SHELL_INTERCEPT=1 to skip it." >&2
            exit 1
        fi
    else
        echo "sandbox: WARNING: bind mounts unavailable ($probe_err)" >&2
        echo "sandbox: WARNING: child processes will use the real shell, unsandboxed" >&2
    fi
    '
fi

# ── Inner namespace setup (shared between both paths) ───────────────────
# This script runs INSIDE the namespace after lo is up.
# It sets up the socat reverse bridge and proxy env vars, then execs the command.
INNER_SETUP='
    if [ -S "'"$SOCK"'" ]; then
        socat "TCP-LISTEN:'"$INNER_PORT"',fork,bind=127.0.0.1,reuseaddr" \
              "UNIX-CLIENT:'"$SOCK"'" 2>/dev/null &
        sleep 0.3
        export HTTP_PROXY="http://127.0.0.1:'"$INNER_PORT"'"
        export HTTPS_PROXY="http://127.0.0.1:'"$INNER_PORT"'"
        export http_proxy="$HTTP_PROXY"
        export https_proxy="$HTTPS_PROXY"
    fi
    # Unset any NO_PROXY that might bypass our bridge
    unset NO_PROXY no_proxy 2>/dev/null
    # Shell replacement: bind-mount compartment-user over /bin/bash
    '"$SHELL_INTERCEPT"'
    # Apply compartment-user hardening to the main command too
    if [ -x "'"$COMPARTMENT"'" ]; then
        exec "'"$COMPARTMENT"'" --verbose --audit -- "$@"
    fi
    exec "$@"
'

# ── Try HARD isolation first (lo-only namespace) ────────────────────────
if "$UNSHARE_BIN" --user --mount --net --map-root-user --fork -- \
   bash -c 'ip link set lo up 2>/dev/null' 2>/dev/null; then
    log "isolation=HARD (loopback-only namespace, no external interfaces)"
    log "network: lo=UP, tap0=NONE, routes=NONE, only unix socket bridge"
    # Do NOT use exec here — the EXIT trap must run to clean up socat/slirp
    STATUS=0
    # `set -e` would kill the script on a non-zero inner exit before STATUS
    # was ever assigned, and cleanup() would then log "exit=unknown".
    "$UNSHARE_BIN" --user --mount --net --map-root-user --fork -- bash -c '
        mount --make-rprivate / 2>/dev/null || true
        ip link set lo up 2>/dev/null
        '"$INNER_SETUP" -- "$@" || STATUS=$?
    exit "$STATUS"
fi

# ── Fallback: SOFT isolation (slirp4netns) ──────────────────────────────
USERNS_REASON="$(userns_block_reason || true)"
if ! command -v slirp4netns >/dev/null 2>&1 || ! command -v nsenter >/dev/null 2>&1; then
    log "HARD mode unavailable${USERNS_REASON:+ — blocked by ${USERNS_REASON}}"
    hard_mode_help
    die "no isolation available: HARD mode needs a mapped-root user namespace, SOFT mode needs slirp4netns and nsenter"
fi

log "isolation=SOFT (slirp4netns, --disable-host-loopback)${USERNS_REASON:+ — HARD blocked by ${USERNS_REASON}}"
if [ -n "$UPSTREAM_PROXY" ]; then
    log "network: lo=UP, tap0=UP (slirp, host-loopback blocked), proxy via env vars"
else
    log "WARNING: SOFT mode without proxy — outbound connections possible via slirp tap0"
fi

# Create persistent namespace
"$UNSHARE_BIN" --user --mount --net -- sleep 86400 &
NS_PID=$!
# Wait for the namespace process to be ready
for _ in $(seq 1 30); do
    [ -d "/proc/$NS_PID/ns" ] && break
    sleep 0.1
done
[ -d "/proc/$NS_PID/ns" ] || die "namespace process $NS_PID did not appear"

slirp4netns --configure --disable-host-loopback "$NS_PID" tap0 &
SLIRP_PID=$!
# Wait for slirp4netns to configure tap0 (poll instead of fixed sleep)
for _ in $(seq 1 50); do
    nsenter -U -n --preserve-credentials -t "$NS_PID" -- \
        ip link show tap0 >/dev/null 2>&1 && break
    sleep 0.1
done
nsenter -U -n --preserve-credentials -t "$NS_PID" -- \
    ip link show tap0 >/dev/null 2>&1 || die "slirp4netns tap0 did not appear"

# Use --pid --fork so all descendant processes die when the main command
# exits (prevents background processes from surviving sandbox teardown).
STATUS=0
nsenter -U -m -n --preserve-credentials -t "$NS_PID" -- \
    "$UNSHARE_BIN" --pid --fork -- bash -c '
    mount --make-rprivate / 2>/dev/null || true
    '"$INNER_SETUP" -- "$@" || STATUS=$?
exit "$STATUS"
