#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Usage: sudo bash ubuntu-resolute_sign.sh <script_to_sign>
#
# HMAC-SHA256-signs a script using a root-only secret at /root/.watch_secret.
# Generic — works on any script, used by ubuntu-resolute_watcher.sh to verify
# its own integrity before executing.

TARGET="${1}"
SECRET_FILE="/root/.watch_secret"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <script_to_sign>"
    exit 1
fi

if [[ ! -f "$TARGET" ]]; then
    echo "ERROR: Target script not found: $TARGET"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root."
    exit 1
fi

# Generate secret if it doesn't exist yet
if [[ ! -f "$SECRET_FILE" ]]; then
    echo "[*] Generating new secret key at $SECRET_FILE"
    openssl rand -hex 32 > "$SECRET_FILE"
    chmod 400 "$SECRET_FILE"
    chown root:root "$SECRET_FILE"
    echo "[*] Secret created. Keep this safe — losing it means you must re-sign."
fi

SECRET=$(cat "$SECRET_FILE")

# Strip existing signature line, write to tmpfile
TMPFILE=$(mktemp)
grep -v '^# SIG:' "$TARGET" > "$TMPFILE"

# Verify tmpfile has content
if [[ ! -s "$TMPFILE" ]]; then
    echo "ERROR: Stripped file is empty. Aborting."
    rm -f "$TMPFILE"
    exit 1
fi

# Compute HMAC-SHA256 — use $NF to handle any OpenSSL version output format
SIG=$(cat "$TMPFILE" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')

if [[ -z "$SIG" ]]; then
    echo "ERROR: HMAC computation failed. Check openssl."
    rm -f "$TMPFILE"
    exit 1
fi

# Append signature line
echo "# SIG: $SIG" >> "$TMPFILE"

mv "$TMPFILE" "$TARGET"
chmod 500 "$TARGET"
chown root:root "$TARGET"

echo "[*] Signed   : $TARGET"
echo "[*] Signature: $SIG"
