#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Polling daemon: rebuilds the Resolute smoke-test VM on demand.
#
# Usage:
#   sudo bash ubuntu-resolute_sign.sh ubuntu-resolute_watcher.sh   # sign once
#   sudo bash ubuntu-resolute_watcher.sh                            # run (foreground)
#
# To trigger a rebuild from another shell:
#   touch kvm/ubuntu-resolute_recreate.txt

# ── Self-integrity check ────────────────────────────────────────────────────
SECRET_FILE="/root/.watch_secret"

if [[ ! -f "$SECRET_FILE" ]]; then
    echo "[$(date)] FATAL: Secret file missing: $SECRET_FILE"
    exit 1
fi

SECRET=$(cat "$SECRET_FILE")
SELF="$0"
SCRIPT_DIR=$(cd "$(dirname "$SELF")" && pwd)

# Extract stored signature from last line: "# SIG: <hash>"
STORED_SIG=$(tail -n 1 "$SELF" | grep '^# SIG:' | awk '{print $NF}')

if [[ -z "$STORED_SIG" ]]; then
    echo "[$(date)] FATAL: No signature found in script. Run ubuntu-resolute_sign.sh to sign it."
    exit 1
fi

if [[ "$STORED_SIG" == "UNSIGNED" ]]; then
    echo "[$(date)] FATAL: Script is intentionally shipped unsigned. Run ubuntu-resolute_sign.sh once before enabling the watcher."
    exit 1
fi

# Compute HMAC over everything except the last signature line
COMPUTED_SIG=$(head -n -1 "$SELF" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')

if [[ -z "$COMPUTED_SIG" ]]; then
    echo "[$(date)] FATAL: HMAC computation returned empty. Check openssl installation."
    exit 1
fi

if [[ "$COMPUTED_SIG" != "$STORED_SIG" ]]; then
    echo "[$(date)] SECURITY ALERT: Self-integrity check FAILED. Script may have been tampered with."
    echo "[$(date)]   Expected : $STORED_SIG"
    echo "[$(date)]   Computed : $COMPUTED_SIG"
    exit 1
fi

echo "[$(date)] Self-integrity OK."
# ── End self-check ──────────────────────────────────────────────────────────

TRIGGER_FILE="${SCRIPT_DIR}/ubuntu-resolute_recreate.txt"
SCRIPT="${SCRIPT_DIR}/ubuntu-resolute.sh"

if [[ ! -f "$SCRIPT" ]]; then
    echo "[$(date)] ERROR: Managed script not found: $SCRIPT"
    exit 1
fi

# Store trusted MD5 of the managed script at startup
TRUSTED_MD5=$(md5sum "$SCRIPT" | awk '{print $1}')
echo "[$(date)] Trusted MD5 of managed script: $TRUSTED_MD5"

while true; do
    if [[ -f "$TRIGGER_FILE" ]]; then
        echo "[$(date)] Trigger file found. Verifying managed script integrity..."

        CURRENT_MD5=$(md5sum "$SCRIPT" | awk '{print $1}')

        if [[ "$CURRENT_MD5" != "$TRUSTED_MD5" ]]; then
            echo "[$(date)] SECURITY ALERT: Managed script MD5 mismatch! Refusing to execute."
            echo "[$(date)]   Expected : $TRUSTED_MD5"
            echo "[$(date)]   Current  : $CURRENT_MD5"
            rm -f "$TRIGGER_FILE"
        else
            echo "[$(date)] MD5 OK. Deleting trigger and running script..."
            rm -f "$TRIGGER_FILE"
            bash "$SCRIPT"
        fi
    fi
    sleep 60
done
# SIG: UNSIGNED
