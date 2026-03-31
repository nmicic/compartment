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
#   ./sandbox.sh codex --full-auto
#   ./sandbox.sh claude --model claude-opus-4-6
#   UPSTREAM_PROXY=http://corp-proxy:8080 ./sandbox.sh codex
#
# Verify isolation:
#   ./sandbox.sh --verify
#
# Requirements: unshare, socat, newuidmap (uidmap pkg)
# Optional:     slirp4netns (fallback when kernel blocks lo bringup)
#
# Isolation levels:
#   HARD  — loopback-only namespace, no external interfaces, no routes.
#           The ONLY network path is unix-socket → proxy bridge.
#           (requires: unprivileged user namespaces + newuidmap)
#   SOFT  — slirp4netns provides lo + tap0, --disable-host-loopback.
#           Proxy enforced via env vars. tap0 exists but host loopback blocked.
#           (fallback for restricted container environments)

set -euo pipefail

# ── Configuration ───────────────────────────────────────────────────────
UPSTREAM_PROXY="${UPSTREAM_PROXY:-${HTTPS_PROXY:-${HTTP_PROXY:-}}}"
INNER_PORT="${SANDBOX_PROXY_PORT:-18080}"
# Use a private temp directory (mode 700) to avoid predictable /tmp socket paths
SOCK_DIR="$(mktemp -d -t compartment-sandbox-XXXXXXXX)"
chmod 700 "$SOCK_DIR"
SOCK="$SOCK_DIR/proxy.sock"
LOGDIR="${SANDBOX_LOGDIR:-${HOME}/.sandbox-audit}"
LOGFILE="${LOGDIR}/sandbox-$(date +%Y%m%dT%H%M%S)-$$.log"

die() { echo "sandbox: ERROR: $*" >&2; exit 1; }

log() {
    local msg="$(date -Iseconds) $*"
    echo "sandbox: $*" >&2
    echo "$msg" >> "$LOGFILE" 2>/dev/null || true
}

cleanup() {
    log "cleanup: stopping bridge processes"
    [ -n "${SOCAT_PID:-}" ]  && kill "$SOCAT_PID" 2>/dev/null || true
    [ -n "${SLIRP_PID:-}" ] && kill "$SLIRP_PID" 2>/dev/null || true
    [ -n "${NS_PID:-}" ]    && kill "$NS_PID" 2>/dev/null || true
    rm -rf "$SOCK_DIR"
    log "session ended (exit=${STATUS:-unknown})"
}
trap cleanup EXIT

# ── Audit log setup ────────────────────────────────────────────────────
mkdir -p "$LOGDIR" 2>/dev/null || true
log "=== sandbox session started ==="
log "user=$(id -un) uid=$(id -u) pid=$$ ppid=$PPID"
log "host=$(hostname) kernel=$(uname -r)"
log "command: $*"
log "upstream_proxy=${UPSTREAM_PROXY:-(none)}"

# ── Preflight checks ───────────────────────────────────────────────────
check_deps() {
    local missing=""
    for cmd in unshare socat newuidmap; do
        command -v "$cmd" >/dev/null 2>&1 || missing="$missing $cmd"
    done
    [ -z "$missing" ] || die "missing dependencies:$missing (install: uidmap, socat)"

    # Check unprivileged user namespaces enabled
    local userns=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo "1")
    [ "$userns" = "1" ] || die "unprivileged user namespaces disabled (sysctl kernel.unprivileged_userns_clone=0)"

    # Check subuid/subgid configured
    grep -q "^$(id -un):" /etc/subuid 2>/dev/null || die "no subuid entry for $(id -un) — ask admin to run: usermod --add-subuids 100000-165535 $(id -un)"
}

# ── Verify mode ─────────────────────────────────────────────────────────
run_verify() {
    echo "=== Sandbox Isolation Verification ==="
    echo ""
    echo "1. Dependencies:"
    for cmd in unshare socat newuidmap slirp4netns; do
        printf "   %-15s " "$cmd"
        if command -v "$cmd" >/dev/null 2>&1; then echo "OK ($(which $cmd))"; else echo "MISSING"; fi
    done

    echo ""
    echo "2. Kernel support:"
    local userns=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo "unknown")
    printf "   %-30s %s\n" "unprivileged_userns_clone:" "$userns"
    printf "   %-30s " "user+net namespace creation:"
    if unshare --user --net -- /bin/true 2>/dev/null; then echo "OK"; else echo "FAILED"; fi

    echo ""
    echo "3. Isolation level:"
    printf "   %-30s " "HARD (lo-only, --map-root-user):"
    if unshare --user --net --map-root-user --fork -- bash -c 'ip link set lo up' 2>/dev/null; then
        echo "OK — loopback-only namespace works"
        ISOLATION="HARD"
    else
        echo "UNAVAILABLE"
    fi
    printf "   %-30s " "SOFT (slirp4netns fallback):"
    if command -v slirp4netns >/dev/null 2>&1; then
        echo "OK — slirp4netns available"
        [ "${ISOLATION:-}" != "HARD" ] && ISOLATION="SOFT"
    else
        echo "UNAVAILABLE"
    fi

    echo ""
    echo "4. Network isolation test:"
    if [ "${ISOLATION:-}" = "HARD" ]; then
        unshare --user --net --map-root-user --fork -- bash -c '
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
        timeout 3 bash -c "echo | socat - TCP:${UPSTREAM_PROXY#http*://}" 2>/dev/null && echo "OK" || echo "UNREACHABLE"
    else
        echo "   UPSTREAM_PROXY not set — set it to your corporate proxy"
    fi

    echo ""
    echo "=== Result: isolation=${ISOLATION:-NONE} ==="
    echo "Audit logs: $LOGDIR/"
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
# If compartment-user is available and we have a mount namespace,
# bind-mount it over /bin/bash (and /bin/sh) so every subprocess
# spawned by the AI agent gets sandboxed automatically.
#
# The real shells are saved at /bin/shells/ and compartment-user
# finds them via REAL_SHELL_DIR (default) or COMPARTMENT_SHELL_DIR env.
# Use a randomized directory name inside the namespace so the real shell
# path isn't guessable even if an attacker reads /proc/*/maps.
SHELL_STASH="/bin/.shells_$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SHELL_INTERCEPT=""
if [ -n "$COMPARTMENT" ]; then
    SHELL_INTERCEPT='
        if mount --bind /bin/bash /bin/bash 2>/dev/null; then
            mkdir -p "'"$SHELL_STASH"'" 2>/dev/null
            export COMPARTMENT_SHELL_DIR="'"$SHELL_STASH"'"
            for sh in /bin/bash /bin/sh; do
                [ -x "$sh" ] || continue
                mount --bind "$sh" "'"$SHELL_STASH"'/$(basename "$sh")" 2>/dev/null
                mount --bind "'"$COMPARTMENT"'" "$sh" 2>/dev/null && \
                    echo "sandbox: shell intercept: $sh -> compartment-user -> '"$SHELL_STASH"'/$(basename $sh)" >&2
            done
        else
            echo "sandbox: WARNING: shell intercept bind mount failed — child processes will use real shell" >&2
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
if unshare --user --mount --net --map-root-user --fork -- \
   bash -c 'ip link set lo up 2>/dev/null' 2>/dev/null; then
    log "isolation=HARD (loopback-only namespace, no external interfaces)"
    log "network: lo=UP, tap0=NONE, routes=NONE, only unix socket bridge"
    # Do NOT use exec here — the EXIT trap must run to clean up socat/slirp
    unshare --user --mount --net --map-root-user --fork -- bash -c '
        ip link set lo up 2>/dev/null
        '"$INNER_SETUP" -- "$@"
    STATUS=$?
    exit $STATUS
fi

# ── Fallback: SOFT isolation (slirp4netns) ──────────────────────────────
command -v slirp4netns >/dev/null 2>&1 || \
    die "neither --map-root-user nor slirp4netns available — cannot create sandbox"

log "isolation=SOFT (slirp4netns, --disable-host-loopback)"
if [ -n "$UPSTREAM_PROXY" ]; then
    log "network: lo=UP, tap0=UP (slirp, host-loopback blocked), proxy via env vars"
else
    log "WARNING: SOFT mode without proxy — outbound connections possible via slirp tap0"
fi

# Create persistent namespace
unshare --user --mount --net -- sleep 86400 &
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

nsenter -U -m -n --preserve-credentials -t "$NS_PID" -- bash -c "$INNER_SETUP" -- "$@"
STATUS=$?
exit $STATUS
