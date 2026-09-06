#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
CONF_TPL="${BASE_DIR}/tinyproxy.conf"
CONF_RUN="${BASE_DIR}/run/tinyproxy.conf"   # rendered at start time
PID_FILE="${BASE_DIR}/run/tinyproxy.pid"
LOG_DIR="${BASE_DIR}/logs"
LOG_FILE="${LOG_DIR}/tinyproxy.log"
BIN="${HOME}/.local/bin/tinyproxy"

# ── Sanity checks ───────────────────────────────────────────
[[ -x "$BIN" ]] || { echo "Binary not found: $BIN — run build.sh first."; exit 1; }
[[ -f "$CONF_TPL" ]] || { echo "Config template missing: $CONF_TPL"; exit 1; }

# ── Already running? ────────────────────────────────────────
if [[ -f "$PID_FILE" ]]; then
  PID=$(cat "$PID_FILE")
  if kill -0 "$PID" 2>/dev/null; then
    echo "tinyproxy already running (pid $PID)."
    exit 0
  else
    echo "Stale PID file removed."
    rm -f "$PID_FILE"
  fi
fi

# ── Prepare dirs ────────────────────────────────────────────
mkdir -p "${BASE_DIR}/run" "$LOG_DIR"

# ── Render config (replace __PIDFILE__ / __LOGFILE__ tokens) ─
sed \
  -e "s|__PIDFILE__|${PID_FILE}|g" \
  -e "s|__LOGFILE__|${LOG_FILE}|g" \
  "$CONF_TPL" > "$CONF_RUN"

# ── Launch ──────────────────────────────────────────────────
"$BIN" -c "$CONF_RUN"
sleep 0.5

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "tinyproxy started (pid $(cat "$PID_FILE"))."
  echo "Upstream: $(grep '^Upstream' "$CONF_RUN" | head -1)"
  echo "Listening: 127.0.0.1:8080"
  echo ""
  echo "Test:  curl -x http://127.0.0.1:8080 https://example.com -I"
else
  echo "tinyproxy failed to start. Check logs:"
  echo "  tail -30 ${LOG_FILE}"
  exit 1
fi
