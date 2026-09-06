#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="${BASE_DIR}/run/tinyproxy.pid"
LOG_FILE="${BASE_DIR}/logs/tinyproxy.log"

echo "=== tinyproxy status ==="
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  PID=$(cat "$PID_FILE")
  echo "  Status : RUNNING (pid $PID)"
  echo "  Port   : $(ss -tlnp 2>/dev/null | grep "$PID" || echo "  run: ss -tlnp | grep 8080")"
  echo "  Crontab: $(crontab -l 2>/dev/null | grep -c start.sh || echo 0) @reboot entry"
else
  echo "  Status : STOPPED"
fi
echo ""
echo "=== Last 10 log lines ==="
[[ -f "$LOG_FILE" ]] && tail -10 "$LOG_FILE" || echo "  (no log yet)"
