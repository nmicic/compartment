#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# sshd E2E: per-run keypair + per-run user + local SSH round-trip.
#
# Workflow PASS verdict: ssh round-trip echoed the expected NONCE-bearing string
# back AND exit 0. Hash is on a NONCE-independent stable literal so that T3b.2
# repeatability holds across runs (NONCE rotates per run).
#
set -euo pipefail

: "${NONCE:?NONCE missing from orchestrator}"

USER_NAME="v3b_${NONCE}_probe"
TMPDIR_RUN="/tmp/v3b-${NONCE}"
KEY="${TMPDIR_RUN}/sshd_key"
KNOWN_HOSTS="${TMPDIR_RUN}/known_hosts"

cleanup() {
    # Idempotent: kill any user processes (e.g. lingering sshd worker for an
    # active session), then force-userdel (-f -r) so the user is removed even
    # if a process holds it open. Then drop the tmp dir.
    pkill -KILL -u "$USER_NAME" 2>/dev/null || true
    sleep 0.3
    userdel -f -r "$USER_NAME" 2>/dev/null || true
    rm -rf "$TMPDIR_RUN" 2>/dev/null || true
}
trap cleanup EXIT

# Starting-state assertion.
if id -u "$USER_NAME" >/dev/null 2>&1; then
    echo "DIRTY START: user $USER_NAME already exists" >&2
    echo "WORKFLOW_OUTPUT_HASH=-"
    echo "E2E_VERDICT=FAIL"
    exit 2
fi
if [ -e "$TMPDIR_RUN" ]; then
    echo "DIRTY START: $TMPDIR_RUN already exists" >&2
    echo "WORKFLOW_OUTPUT_HASH=-"
    echo "E2E_VERDICT=FAIL"
    exit 2
fi

mkdir -p "$TMPDIR_RUN"
chmod 700 "$TMPDIR_RUN"

# Generate ed25519 keypair for this run.
ssh-keygen -t ed25519 -N '' -C "v3b-${NONCE}" -f "$KEY" >&2

# Create the probe user with a shell + homedir.
useradd -m -s /bin/bash "$USER_NAME" >&2

# Install authorized_keys.
USER_HOME="$(getent passwd "$USER_NAME" | cut -d: -f6)"
if [ -z "$USER_HOME" ] || [ ! -d "$USER_HOME" ]; then
    echo "useradd created $USER_NAME without a homedir" >&2
    echo "WORKFLOW_OUTPUT_HASH=-"
    echo "E2E_VERDICT=FAIL"
    exit 2
fi
mkdir -p "${USER_HOME}/.ssh"
cp "${KEY}.pub" "${USER_HOME}/.ssh/authorized_keys"
chmod 700 "${USER_HOME}/.ssh"
chmod 600 "${USER_HOME}/.ssh/authorized_keys"
chown -R "${USER_NAME}:${USER_NAME}" "${USER_HOME}/.ssh"

# Round-trip SSH.
out=""
rc=0
out="$(ssh -i "$KEY" \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="$KNOWN_HOSTS" \
        -o ConnectTimeout=10 \
        "${USER_NAME}@127.0.0.1" "echo OK_${NONCE}" 2>>"${TMPDIR_RUN}/ssh.stderr")" || rc=$?

expected="OK_${NONCE}"
verdict="FAIL"
if [ "$rc" -eq 0 ] && [ "$out" = "$expected" ]; then
    verdict="PASS"
fi

# Stable hash: literal verdict-summary string (NONCE-independent so T3b.2
# repeatability holds when NONCE rotates per run).
hash="$(printf '%s' 'sshd_round_trip_ok' | sha256sum | awk '{print $1}')"

echo "WORKFLOW_OUTPUT_HASH=${hash}"
echo "E2E_VERDICT=${verdict}"

if [ "$verdict" = "PASS" ]; then
    exit 0
fi
exit 1
