#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
CONTAINER=squid
if ! docker inspect "$CONTAINER" &>/dev/null; then
  echo "Container not found — run start.sh first."
  exit 1
fi
docker update --restart=always "$CONTAINER"
echo "Squid will now auto-start on boot / Docker daemon restart."
