#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# make_fixtures.sh — create fixture tree for compartment tests
#
# Creates /tmp/compartment-fixtures/ with known file structure.
# Idempotent — safe to run multiple times.

set -euo pipefail

FIXTURES="/tmp/compartment-fixtures"

echo "=== Creating fixture tree at ${FIXTURES} ==="

rm -rf "${FIXTURES}"
mkdir -p "${FIXTURES}"/{readable,writable,protected,subdir}

# Readable files
echo "readable-content" > "${FIXTURES}/readable/file.txt"
echo '#!/bin/sh' > "${FIXTURES}/readable/script.sh"
echo 'echo "executed"' >> "${FIXTURES}/readable/script.sh"
chmod +x "${FIXTURES}/readable/script.sh"

# Writable area (for rw tests)
echo "original" > "${FIXTURES}/writable/existing.txt"
touch "${FIXTURES}/writable/truncate-me.txt"
echo "some data" > "${FIXTURES}/writable/truncate-me.txt"

# Protected area (should be blocked by ro Landlock)
echo "protected-content" > "${FIXTURES}/protected/secret.txt"
chmod 644 "${FIXTURES}/protected/secret.txt"

# Symlink targets
echo "symlink-target" > "${FIXTURES}/subdir/target.txt"

# For rename tests
echo "rename-me" > "${FIXTURES}/writable/rename-src.txt"

# For exec test — a harmless binary
cp /bin/true "${FIXTURES}/readable/true" 2>/dev/null || \
    cp /usr/bin/true "${FIXTURES}/readable/true" 2>/dev/null || \
    { echo '#!/bin/sh' > "${FIXTURES}/readable/true"; \
      echo 'exit 0' >> "${FIXTURES}/readable/true"; \
      chmod +x "${FIXTURES}/readable/true"; }

# Copy deny_probe into fixtures so it's accessible under all profiles
PROBE_SRC="$(cd "$(dirname "$0")/../probes" && pwd)/deny_probe"
if [ -x "${PROBE_SRC}" ]; then
    cp "${PROBE_SRC}" "${FIXTURES}/readable/deny_probe"
    chmod +x "${FIXTURES}/readable/deny_probe"
fi

echo "=== Fixture tree created ==="
find "${FIXTURES}" -type f | sort
