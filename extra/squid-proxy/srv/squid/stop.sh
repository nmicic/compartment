#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
CONTAINER=squid
if ! docker inspect "$CONTAINER" &>/dev/null; then
  echo "Container '$CONTAINER' does not exist."
  exit 0
fi
echo "Stopping squid..."
docker stop "$CONTAINER"
docker rm   "$CONTAINER"
echo "Done."
