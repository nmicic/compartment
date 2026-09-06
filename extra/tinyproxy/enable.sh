#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
# Add @reboot crontab entry — survives reboots without systemd
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=crontab.sh
. "${BASE_DIR}/crontab.sh"

ENTRY="@reboot ${BASE_DIR}/start.sh >> ${BASE_DIR}/logs/cron-start.log 2>&1"

crontab_lock
CUR="${BASE_DIR}/run/crontab.current.$$"
NEW="${BASE_DIR}/run/crontab.new.$$"
trap 'rm -f "${CUR}" "${NEW}"' EXIT

crontab_snapshot "$CUR"
if grep -qF "$CRONTAB_MARKER" "$CUR"; then
  echo "Already enabled in crontab."
  exit 0
fi

crontab_backup_from "$CUR"
{ cat "$CUR"; echo "${CRONTAB_MARKER}"; echo "${ENTRY}"; } > "$NEW"
crontab_install "$NEW"
crontab_unlock

echo "Enabled. tinyproxy will start automatically on next login/reboot."
echo ""
echo "Crontab entry:"
crontab -l | grep -A1 -F "$CRONTAB_MARKER"
