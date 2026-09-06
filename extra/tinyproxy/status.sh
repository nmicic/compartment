#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
set -uo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="${BASE_DIR}/run/tinyproxy.pid"
LOG_FILE="${BASE_DIR}/logs/tinyproxy.log"
# shellcheck source=pidfile.sh
. "${BASE_DIR}/pidfile.sh"

echo "=== tinyproxy status ==="
if PID=$(pidfile_read "$PID_FILE" 2>/dev/null); then
  echo "  Status : RUNNING (pid $PID)"
  echo "  Port   : $(ss -tlnp 2>/dev/null | grep "pid=${PID}," || echo 'run: ss -tlnp | grep 8080')"
  echo "  Crontab: $(crontab -l 2>/dev/null | grep -cF "${BASE_DIR}/start.sh") @reboot entry"
else
  echo "  Status : STOPPED"
fi
echo ""
echo "=== Last 10 log lines ==="
[[ -f "$LOG_FILE" ]] && tail -10 "$LOG_FILE" || echo "  (no log yet)"
