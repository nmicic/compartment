#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# make_fixtures.sh — create the fixture tree for compartment tests
#
# Usage:
#   make_fixtures.sh [DIR]
#
#   DIR                     populate this directory (created if missing)
#   $COMPARTMENT_FIXTURES   used when DIR is omitted
#   neither                 a fresh mktemp -d root is created and printed
#
# The fixture root is deliberately NOT a fixed path such as
# /tmp/compartment-fixtures: that is world-guessable, so any local user can
# pre-create it, or replace files between the moment a test writes them and
# the moment the sandboxed probe reads them. Callers get an unpredictable
# mktemp root and are responsible for removing it (tests/scripts/lib/harness.sh
# does this from an EXIT trap).
#
# Idempotent — safe to run repeatedly against the same root.
#
# The last line of stdout is always:  FIXTURES=<path>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

FIXTURES="${1:-${COMPARTMENT_FIXTURES:-}}"
if [ -z "${FIXTURES}" ]; then
    BASE="${COMPARTMENT_FIXTURE_BASE:-${HOME}/.cache}"
    if ! mkdir -p "${BASE}" 2>/dev/null || [ ! -w "${BASE}" ]; then
        BASE="${TMPDIR:-/tmp}"
    fi
    FIXTURES="$(mktemp -d "${BASE}/compartment-fixtures.XXXXXXXXXX")"
fi

case "${FIXTURES}" in
    /*) ;;
    *)  echo "make_fixtures.sh: fixture root must be an absolute path" >&2; exit 2 ;;
esac

echo "=== Creating fixture tree at ${FIXTURES} ==="

mkdir -p "${FIXTURES}"
rm -rf "${FIXTURES:?}"/{readable,writable,protected,subdir,profiles}
mkdir -p "${FIXTURES}"/{readable,writable,protected,subdir,profiles}
chmod 700 "${FIXTURES}"

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
PROBE_SRC="${REPO_DIR}/tests/probes/deny_probe"
if [ -x "${PROBE_SRC}" ]; then
    cp "${PROBE_SRC}" "${FIXTURES}/readable/deny_probe"
    chmod +x "${FIXTURES}/readable/deny_probe"
fi

# Render the test profiles: tests/profiles/*.conf are templates in which
# @FIXTURES@ stands for the (per-run, unpredictable) fixture root.
for src in "${REPO_DIR}"/tests/profiles/*.conf; do
    dst="${FIXTURES}/profiles/$(basename "${src}")"
    while IFS= read -r line; do
        printf '%s\n' "${line//@FIXTURES@/${FIXTURES}}"
    done < "${src}" > "${dst}"
done
# Profiles are security policy, not ordinary collaborative build output.
# The developer may use umask 002, but every rendered fixture must satisfy
# the same trust rule the installed product enforces.
chmod go-w "${FIXTURES}/profiles" "${FIXTURES}/profiles"/*.conf

echo "=== Fixture tree created ==="
find "${FIXTURES}" -type f | sort
echo "FIXTURES=${FIXTURES}"
