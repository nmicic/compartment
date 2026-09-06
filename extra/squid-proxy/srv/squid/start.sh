#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

CONTAINER=squid
IMAGE=ubuntu/squid
CONF_DIR=/srv/squid
LOG_DIR=/srv/logs

# Ensure log dir exists and is owned by squid uid (13 in ubuntu/squid)
mkdir -p "$LOG_DIR"
chown 13:13 "$LOG_DIR" 2>/dev/null || true

# Remove a stopped/dead container if present
if docker inspect "$CONTAINER" &>/dev/null; then
  STATUS=$(docker inspect -f '{{.State.Status}}' "$CONTAINER")
  if [[ "$STATUS" != "running" ]]; then
    echo "Removing stale container ($STATUS)..."
    docker rm "$CONTAINER"
  else
    echo "Squid is already running."
    docker inspect -f 'ID={{.Id[:12]}}  Status={{.State.Status}}' "$CONTAINER"
    exit 0
  fi
fi

echo "Starting squid..."
# --network host, not -p: squid.conf binds 127.0.0.1:8080, which has to be
# the host's loopback for the bind to mean anything.  A bridge-networked
# container cannot bind the host loopback, so it would have to listen on all
# of its own interfaces and rely on the published port alone — reachable
# from every other container on the same bridge.
docker run -d \
  --name "$CONTAINER" \
  --restart=always \
  --read-only \
  --network host \
  --tmpfs /var/run/squid:uid=13,gid=13,mode=0755 \
  --tmpfs /tmp:mode=1777 \
  -v "${CONF_DIR}/squid.conf":/etc/squid/squid.conf:ro \
  -v "${LOG_DIR}":/var/log/squid \
  "$IMAGE"

echo "Squid started on 127.0.0.1:8080 (host loopback only). Test with:"
echo "  curl -x http://127.0.0.1:8080 https://example.com -I"
