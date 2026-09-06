#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
# Remove @reboot crontab entry and stop tinyproxy
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
MARKER="# tinyproxy-autostart"

if crontab -l 2>/dev/null | grep -qF "$MARKER"; then
  # Remove the marker line and the line after it
  crontab -l 2>/dev/null | grep -v -A1 "$MARKER" | grep -v "start.sh" | crontab -
  echo "Removed from crontab."
else
  echo "Not found in crontab — nothing to remove."
fi

# Stop if running
"${BASE_DIR}/stop.sh" 2>/dev/null || true
