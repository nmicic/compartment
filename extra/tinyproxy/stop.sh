#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="${BASE_DIR}/run/tinyproxy.pid"
# shellcheck source=pidfile.sh
. "${BASE_DIR}/pidfile.sh"

if [[ ! -f "$PID_FILE" ]]; then
  echo "No PID file found — tinyproxy not running (or started elsewhere)."
  exit 0
fi

if ! PID=$(pidfile_read "$PID_FILE"); then
  echo "No live tinyproxy for $PID_FILE — removing stale PID file."
  rm -f "$PID_FILE"
  exit 0
fi

# Only remove the PID file once the process is confirmed gone; reporting
# "stopped" while it is still running is how a second start.sh ends up with
# two proxies fighting over the port.
if pidfile_stop "$PID_FILE"; then
  rm -f "$PID_FILE"
  echo "tinyproxy stopped (pid $PID)."
else
  echo "tinyproxy (pid $PID) could not be stopped — PID file left in place." >&2
  exit 1
fi
