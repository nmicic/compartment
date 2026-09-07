#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
# Remove @reboot crontab entry and stop tinyproxy
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=crontab.sh
. "${BASE_DIR}/crontab.sh"

crontab_lock
CUR="${BASE_DIR}/run/crontab.current.$$"
NEW="${BASE_DIR}/run/crontab.new.$$"
trap 'rm -f "${CUR}" "${NEW}"' EXIT

crontab_snapshot "$CUR"
if grep -qF "$CRONTAB_MARKER" "$CUR"; then
  crontab_backup_from "$CUR"
  # Delete exactly two kinds of line: the marker, and an entry naming *this*
  # directory's start.sh.  The previous version used `grep -v -A1`, which
  # prints context around the *non*-matching lines and so left the marker in
  # place, and an unanchored `grep -v start.sh`, which deleted every
  # unrelated cron line that happened to mention a start.sh anywhere.
  grep -vF -e "$CRONTAB_MARKER" -e "${BASE_DIR}/start.sh" "$CUR" > "$NEW" || true
  crontab_install "$NEW"
  echo "Removed from crontab (backup: ${CRONTAB_BACKUP})."
else
  echo "Not found in crontab — nothing to remove."
fi
crontab_unlock

# Stop if running.  Do not hide the result: reporting success while
# tinyproxy keeps running is worse than a visible failure.
if [[ -x "${BASE_DIR}/stop.sh" ]]; then
  "${BASE_DIR}/stop.sh"
else
  echo "warning: ${BASE_DIR}/stop.sh is not executable — tinyproxy not stopped" >&2
  exit 1
fi
