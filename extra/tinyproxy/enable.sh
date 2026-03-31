#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
# Add @reboot crontab entry — survives reboots without systemd
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
ENTRY="@reboot ${BASE_DIR}/start.sh >> ${BASE_DIR}/logs/cron-start.log 2>&1"
MARKER="# tinyproxy-autostart"

# Check if already present
if crontab -l 2>/dev/null | grep -qF "$MARKER"; then
  echo "Already enabled in crontab."
  exit 0
fi

# Append to existing crontab (or create new)
( crontab -l 2>/dev/null; echo "${MARKER}"; echo "${ENTRY}" ) | crontab -

echo "Enabled. tinyproxy will start automatically on next login/reboot."
echo ""
echo "Crontab entry:"
crontab -l | grep -A1 "$MARKER"
