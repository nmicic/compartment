#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
CONTAINER=squid
if ! docker inspect "$CONTAINER" &>/dev/null; then
  echo "Container not found — nothing to disable."
  exit 0
fi
docker update --restart=no "$CONTAINER"
docker stop "$CONTAINER"
echo "Squid stopped and will NOT restart automatically."
echo "Run enable.sh + start.sh to bring it back."
