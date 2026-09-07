# shellcheck shell=bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# crontab.sh — shared crontab handling for enable.sh / disable.sh.
#
# Sourced, not executed (no shebang on purpose).  Expects $BASE_DIR.
#
# `crontab -l | filter | crontab -` is a read-modify-write that replaces the
# user's entire crontab, so a mistake costs every entry — and it runs the
# reader and the writer concurrently against the same spool file.  Here the
# current crontab is snapshotted to a file first, filtered into a second
# file, and only then installed, with a backup of the previous contents and
# a lock around the whole sequence.
#
# CRONTAB_CMD exists so tests can point at a stub instead of the real crontab.

CRONTAB_CMD="${CRONTAB_CMD:-crontab}"
# shellcheck disable=SC2034  # read by enable.sh / disable.sh
CRONTAB_MARKER="# tinyproxy-autostart"
CRONTAB_BACKUP=""

crontab() { command "$CRONTAB_CMD" "$@"; }

crontab_workdir() { mkdir -p "${BASE_DIR}/run"; }

crontab_lock() {
  crontab_workdir
  if command -v flock >/dev/null 2>&1; then
    exec 9>"${BASE_DIR}/run/crontab.lock"
    flock 9
  fi
}

crontab_unlock() {
  if command -v flock >/dev/null 2>&1; then
    exec 9>&- || true
  fi
}

# crontab_snapshot FILE — write the current crontab to FILE (empty if none).
crontab_snapshot() {
  crontab_workdir
  ( umask 077; crontab -l 2>/dev/null > "$1" || : > "$1" )
}

# crontab_backup_from FILE — keep a copy of the pre-change crontab.
crontab_backup_from() {
  crontab_workdir
  CRONTAB_BACKUP="${BASE_DIR}/run/crontab.backup.$(date +%Y%m%dT%H%M%S)"
  ( umask 077; cp "$1" "$CRONTAB_BACKUP" )
  echo "Saved current crontab to ${CRONTAB_BACKUP}"
}

# crontab_install FILE — replace the crontab with FILE's contents.
crontab_install() { crontab - < "$1"; }
