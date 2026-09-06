#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
# Reload config without dropping connections (SIGHUP)
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="${BASE_DIR}/run/tinyproxy.pid"
# shellcheck source=pidfile.sh
. "${BASE_DIR}/pidfile.sh"

[[ -f "$PID_FILE" ]] || { echo "Not running."; exit 1; }
PID=$(pidfile_read "$PID_FILE") || { echo "Stale or foreign PID — run start.sh"; exit 1; }
kill -HUP "$PID"
echo "Config reloaded (pid $PID)."
