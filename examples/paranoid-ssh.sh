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
# Host-key verification:
#   ssh connects to 127.0.0.1 on a fresh random port each run, so without
#   help it would file the server's key under "[127.0.0.1]:<random port>" —
#   a brand new, empty trust decision on every single invocation, which is
#   strictly weaker than plain ssh.  HostKeyAlias pins the entry to the real
#   destination instead, and the entries live in a dedicated known-hosts file
#   that this profile makes writable (and nothing else).  A host whose key
#   changes is refused, exactly as with plain ssh.
#
#   Pre-seed trust for a host you already know:
#     mkdir -p -m 700 ~/.ssh/paranoid
#     ssh-keygen -F myhost -f ~/.ssh/known_hosts \
#         >> ~/.ssh/paranoid/known_hosts
#
# Usage:
#   ./paranoid-ssh.sh [--dry-run] user@host [-p port] [ssh-options...]
#   ./paranoid-ssh.sh user@remote-host -p 2222
#   ./paranoid-ssh.sh user@remote-host "uptime"
#
# Environment:
#   PARANOID_SSH_KNOWN_HOSTS   known-hosts file (default:
#                              ~/.ssh/paranoid/known_hosts).  Its
#                              directory is the only writable path the
#                              ssh profile grants inside $HOME.
#   PARANOID_SSH_STRICT        StrictHostKeyChecking value (default:
#                              accept-new — trust on first use, refuse on
#                              change).  Set to "yes" to refuse unknown
#                              hosts as well; you must then pre-seed the
#                              known-hosts file yourself.
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
DRY_RUN=0
SSH_ARGS=()

# Extract user@host and -p port from args, pass rest through to SSH
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        -p) [ $# -ge 2 ] || die "-p needs a port number"
            REMOTE_PORT="$2"; shift 2 ;;
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

[ -n "$REMOTE_HOST" ] || \
    die "usage: paranoid-ssh.sh [--dry-run] [user@]host [-p port] [ssh-options...]"

# ── Validate ─────────────────────────────────────────────────────────
# REMOTE_HOST is interpolated into socat's address argument and into
# HostKeyAlias, so keep it to hostname/IPv4 characters.
[[ "$REMOTE_HOST" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]] || \
    die "invalid host name: $REMOTE_HOST"
[[ "$REMOTE_PORT" =~ ^[0-9]+$ ]] && \
    [ "$REMOTE_PORT" -ge 1 ] && [ "$REMOTE_PORT" -le 65535 ] || \
    die "invalid port: $REMOTE_PORT"
[ -x "$CU" ] || die "compartment-user not found at $CU (run 'make' first)"

# ── Host-key identity ────────────────────────────────────────────────
# Key the known-hosts entry on the real destination, not on the loopback
# address ssh actually dials.  The "[host]:port" form for non-default ports
# is the same one plain ssh writes, so entries stay interchangeable.
if [ "$REMOTE_PORT" = "22" ]; then
    HOST_ALIAS="$REMOTE_HOST"
else
    HOST_ALIAS="[${REMOTE_HOST}]:${REMOTE_PORT}"
fi
KNOWN_HOSTS="${PARANOID_SSH_KNOWN_HOSTS:-${HOME}/.ssh/paranoid/known_hosts}"
STRICT="${PARANOID_SSH_STRICT:-accept-new}"

# The file and its directory have to exist before compartment-user starts:
# ssh.conf marks the rule optional so the profile still loads without them,
# and an optional rule that is skipped grants nothing — ssh could then not
# record a first-use key.  The rule names the directory rather than the
# file because accept-new writes a temporary file next to known_hosts and
# renames it into place.
KNOWN_HOSTS_DIR="$(dirname "$KNOWN_HOSTS")"
mkdir -p "$KNOWN_HOSTS_DIR"
chmod 700 "$KNOWN_HOSTS_DIR"
[ -e "$KNOWN_HOSTS" ] || ( umask 077; : > "$KNOWN_HOSTS" )
[ -w "$KNOWN_HOSTS" ] || die "known-hosts file is not writable: $KNOWN_HOSTS"

SSH_CMD=(ssh
    -o "HostKeyAlias=${HOST_ALIAS}"
    -o "UserKnownHostsFile=${KNOWN_HOSTS}"
    -o "StrictHostKeyChecking=${STRICT}"
    -o BatchMode=yes
    -o ControlMaster=no)
[ -n "$SSH_USER" ] && SSH_CMD+=(-l "$SSH_USER")

if [ "$DRY_RUN" -eq 1 ]; then
    echo "socat bridge:  127.0.0.1:<random> -> ${REMOTE_HOST}:${REMOTE_PORT}"
    echo "ssh command:   ${SSH_CMD[*]} -p <random> 127.0.0.1 ${SSH_ARGS[*]:-}"
    echo "known hosts:   ${KNOWN_HOSTS}"
    echo "host key alias: ${HOST_ALIAS}"
    exit 0
fi

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
socat -u /dev/null "TCP:127.0.0.1:${LOCAL_PORT}" 2>/dev/null || \
    die "socat bridge did not start"

# ── Run SSH client (sandboxed: read-only filesystem) ─────────────────
exec "$CU" --profile "${SCRIPT_DIR}/ssh.conf" -- \
    "${SSH_CMD[@]}" \
    -p "$LOCAL_PORT" \
    127.0.0.1 \
    "${SSH_ARGS[@]}"
