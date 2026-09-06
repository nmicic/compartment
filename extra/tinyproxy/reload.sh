#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
# Reload config without dropping connections (SIGHUP)
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="${BASE_DIR}/run/tinyproxy.pid"

[[ -f "$PID_FILE" ]] || { echo "Not running."; exit 1; }
PID=$(cat "$PID_FILE")
kill -0 "$PID" 2>/dev/null || { echo "Stale PID — run start.sh"; exit 1; }
kill -HUP "$PID"
echo "Config reloaded (pid $PID)."
