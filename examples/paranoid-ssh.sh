#!/bin/bash
# paranoid-ssh.sh — Split SSH client from TCP layer for defense-in-depth
#
# Architecture:
#   ┌──────────────────────────┐     ┌──────────────────────────┐
#   │  SSH (read-only fs)      │────▶│  socat (no user files)   │────▶ remote:PORT
#   │  • can read keys         │     │  • no $HOME access       │
#   │  • cannot write anywhere │     │  • cannot read SSH keys  │
#   │  • Landlock + seccomp    │     │  • Landlock + seccomp    │
#   └──────────────────────────┘     └──────────────────────────┘
#            localhost:LOCAL_PORT
#
# Security model (privilege separation):
#   SSH process: can read ~/.ssh keys but cannot write to disk.
#     → A reverse-exploited SSH client cannot save stolen data locally.
#   socat process: has network access but cannot read any user files.
#     → Even if socat is exploited, attacker cannot access credentials.
#   Neither process alone can both access secrets AND exfiltrate them.
#
# Usage:
#   ./paranoid-ssh.sh user@host [-p port] [ssh-options...]
#   ./paranoid-ssh.sh user@remote-host -p 2222
#   ./paranoid-ssh.sh user@remote-host "uptime"
#
# Requirements: compartment-user, socat

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CU="${REPO_DIR}/compartment-user"

die() { echo "paranoid-ssh: ERROR: $*" >&2; exit 1; }

# ── Parse arguments ──────────────────────────────────────────────────
REMOTE_PORT=22
SSH_USER=""
REMOTE_HOST=""
SSH_ARGS=()

# Extract user@host and -p port from args, pass rest through to SSH
while [ $# -gt 0 ]; do
    case "$1" in
        -p) REMOTE_PORT="$2"; shift 2 ;;
        -*) SSH_ARGS+=("$1"); shift ;;
        *)
            if [ -z "$REMOTE_HOST" ]; then
                if [[ "$1" == *@* ]]; then
                    SSH_USER="${1%%@*}"
                    REMOTE_HOST="${1#*@}"
                else
                    REMOTE_HOST="$1"
                fi
            else
                SSH_ARGS+=("$1")
            fi
            shift
            ;;
    esac
done

[ -n "$REMOTE_HOST" ] || die "usage: paranoid-ssh.sh [user@]host [-p port] [ssh-options...]"

# ── Validate ─────────────────────────────────────────────────────────
[ -x "$CU" ] || die "compartment-user not found at $CU (run 'make' first)"
command -v socat >/dev/null || die "socat not found"

# Pick a random local port for the socat bridge
LOCAL_PORT=$(shuf -i 10000-60000 -n 1)

# ── Start socat bridge (sandboxed: network-only, no user file access) ─
"$CU" --profile "${SCRIPT_DIR}/socat-proxy.conf" -- \
    socat "TCP-LISTEN:${LOCAL_PORT},bind=127.0.0.1,reuseaddr,fork" \
          "TCP:${REMOTE_HOST}:${REMOTE_PORT}" &
SOCAT_PID=$!

cleanup() {
    kill "$SOCAT_PID" 2>/dev/null || true
    wait "$SOCAT_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for socat to be ready
for _ in $(seq 1 30); do
    socat -u /dev/null "TCP:127.0.0.1:${LOCAL_PORT}" 2>/dev/null && break
    sleep 0.1
done
socat -u /dev/null "TCP:127.0.0.1:${LOCAL_PORT}" 2>/dev/null || die "socat bridge did not start"

# ── Run SSH client (sandboxed: read-only filesystem) ─────────────────
USER_ARGS=()
[ -n "$SSH_USER" ] && USER_ARGS+=("-l" "$SSH_USER")

exec "$CU" --profile "${SCRIPT_DIR}/ssh.conf" -- \
    ssh -o StrictHostKeyChecking=accept-new \
        -o BatchMode=yes \
        -p "$LOCAL_PORT" \
        "${USER_ARGS[@]}" \
        127.0.0.1 \
        "${SSH_ARGS[@]}"
