# shellcheck shell=bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# pidfile.sh — shared PID-file handling for the tinyproxy helper scripts.
#
# Sourced, not executed (no shebang on purpose).
#
# A PID file is not proof that a process exists, and a PID that exists is not
# proof that it is the process the file was written for: PIDs are reused, so
# `kill "$(cat pidfile)"` on a stale file can signal an unrelated process
# owned by the same user. Every read goes through pidfile_read(), which
# checks that the file contains a plain number and that /proc/<pid>/comm is
# the process we expect.

PIDFILE_COMM="${PIDFILE_COMM:-tinyproxy}"

# pidfile_read FILE
#   Prints the PID on stdout and returns 0 only when FILE holds a decimal PID
#   belonging to a live process whose comm is $PIDFILE_COMM.
#   Returns 1 (no output) otherwise; diagnostics go to stderr.
pidfile_read() {
  local file="$1" pid comm
  [[ -f "$file" ]] || return 1

  pid=$(tr -d '[:space:]' < "$file" 2>/dev/null || true)
  if [[ ! "$pid" =~ ^[0-9]+$ ]] || [[ "$pid" -le 1 ]]; then
    echo "PID file does not contain a usable PID: $file" >&2
    return 1
  fi

  comm=$(cat "/proc/${pid}/comm" 2>/dev/null || true)
  if [[ -z "$comm" ]]; then
    return 1          # no such process — stale file, not an error
  fi
  if [[ "$comm" != "$PIDFILE_COMM" ]]; then
    echo "pid $pid is '$comm', not $PIDFILE_COMM — refusing to signal it" >&2
    return 1
  fi

  printf '%s' "$pid"
}

# pidfile_stop FILE [TIMEOUT_SECONDS]
#   SIGTERM, wait for the process to actually go away, then SIGKILL.
#   Returns 0 when the process is gone, 1 when it survived.
pidfile_stop() {
  local file="$1" timeout="${2:-10}" pid i
  pid=$(pidfile_read "$file") || return 1

  kill -TERM "$pid" 2>/dev/null || true
  for ((i = 0; i < timeout * 10; i++)); do
    [[ -e "/proc/${pid}" ]] || return 0
    [[ "$(cat "/proc/${pid}/comm" 2>/dev/null || true)" == "$PIDFILE_COMM" ]] || return 0
    sleep 0.1
  done

  echo "pid $pid did not exit after ${timeout}s — sending SIGKILL" >&2
  kill -KILL "$pid" 2>/dev/null || true
  for ((i = 0; i < 20; i++)); do
    [[ -e "/proc/${pid}" ]] || return 0
    sleep 0.1
  done
  echo "pid $pid is still alive after SIGKILL" >&2
  return 1
}
