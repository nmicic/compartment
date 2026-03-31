#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
# Optional: run tinyproxy in Docker instead of userspace
# Same layout as squid: config :ro, logs writable, container read-only
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINER=tinyproxy
IMAGE=vimagick/tinyproxy   # Alpine-based, 10MB
LOG_DIR="${BASE_DIR}/logs"
CONF="${BASE_DIR}/tinyproxy.conf"

mkdir -p "$LOG_DIR"

# Render conf to a temp file with real paths (Docker sees /logs inside)
CONF_RUN="${BASE_DIR}/run/tinyproxy.conf"
mkdir -p "${BASE_DIR}/run"
sed \
  -e 's|__PIDFILE__|/tmp/tinyproxy.pid|g' \
  -e 's|__LOGFILE__|/logs/tinyproxy.log|g' \
  "$CONF" > "$CONF_RUN"

if docker inspect "$CONTAINER" &>/dev/null; then
  STATUS=$(docker inspect -f '{{.State.Status}}' "$CONTAINER")
  if [[ "$STATUS" == "running" ]]; then
    echo "Already running."; exit 0
  fi
  docker rm "$CONTAINER"
fi

docker run -d \
  --name "$CONTAINER" \
  --restart=always \
  --read-only \
  --tmpfs /tmp:mode=1777 \
  -p 127.0.0.1:8080:8080 \
  -v "${CONF_RUN}":/etc/tinyproxy/tinyproxy.conf:ro \
  -v "${LOG_DIR}":/logs \
  "$IMAGE"

echo "tinyproxy (Docker) started."
echo "Test: curl -x http://127.0.0.1:8080 https://example.com -I"
