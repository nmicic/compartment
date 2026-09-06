#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="${BASE_DIR}/run/tinyproxy.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "No PID file found — tinyproxy not running (or started elsewhere)."
  exit 0
fi

PID=$(cat "$PID_FILE")
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  echo "tinyproxy stopped (pid $PID)."
  rm -f "$PID_FILE"
else
  echo "Process $PID not found — removing stale PID file."
  rm -f "$PID_FILE"
fi
