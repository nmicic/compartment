#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# sandbox-hard.sh — run sandbox.sh HARD mode against a real namespace.
#
# HARD mode is the mode README:265 describes as "loopback-only, no
# external interfaces, no routes", and until now it had never executed
# anywhere: Ubuntu 24.04 and both test guests set
# kernel.apparmor_restrict_unprivileged_userns=1, so
# run_sandbox_proxy_matrix.sh reported pass=0 fail=0 skip=1 on every
# machine it has ever run on, and rootless.d/sandbox.sh exercises the same
# code through stubbed unshare/ip/mount — which proves the control flow
# and nothing about the isolation.
#
# This suite clears that sysctl for the duration and puts it back, then
# runs the assertions as the invoking (unprivileged) user, because an
# unprivileged user namespace is the thing under test.  The sysctl is
# restored by the EXIT trap on every path, including a failure and a
# SIGINT.  If the value cannot be changed — no such knob, a read-only
# /proc/sys, no SUDO_USER to drop to — the suite skips with the reason
# rather than pretending.
#
# Usage: sudo ./tests/scripts/root.d/sandbox-hard.sh [--verbose]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/scripts/lib/harness.sh
. "${SCRIPT_DIR}/../lib/harness.sh"
# shellcheck source=tests/scripts/lib/sandbox-hard.sh
. "${SCRIPT_DIR}/../lib/sandbox-hard.sh"

REPO_DIR="$(harness_repo_dir)"
SANDBOX="${REPO_DIR}/sandbox.sh"

AA_KNOB=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
AA_SAVED=""

restore_knob() {
    if [ -n "${AA_SAVED}" ]; then
        printf '%s\n' "${AA_SAVED}" > "${AA_KNOB}" 2>/dev/null || true
        echo "  (restored ${AA_KNOB}=$(cat "${AA_KNOB}" 2>/dev/null))"
        AA_SAVED=""
    fi
}
trap restore_knob EXIT INT TERM

echo "=== sandbox.sh HARD mode (real namespaces) ==="
echo ""

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sandbox-hard.XXXXXX")"
harness_cleanup_add "${WORK}"

DROP_USER="${SUDO_USER:-}"

if [ "$(id -u)" -ne 0 ]; then
    skip_group "${SANDBOX_HARD_COUNT}" "this suite must run as root (it changes a sysctl)"
elif [ ! -x "${SANDBOX}" ]; then
    skip_group "${SANDBOX_HARD_COUNT}" "sandbox.sh not found at ${SANDBOX}"
elif [ -z "${DROP_USER}" ] || ! command -v runuser >/dev/null 2>&1; then
    skip_group "${SANDBOX_HARD_COUNT}" \
        "no SUDO_USER or no runuser — an unprivileged user namespace is the thing under test"
elif ! command -v unshare >/dev/null 2>&1; then
    skip_group "${SANDBOX_HARD_COUNT}" "unshare(1) is not installed"
else
    # Clear the knob only if it is there and set. Everything else — a
    # kernel without the AppArmor restriction, a seccomp filter, a
    # container that blocks CLONE_NEWUSER outright — is reported as the
    # reason instead of being retried.
    if [ -r "${AA_KNOB}" ] && [ "$(cat "${AA_KNOB}")" != "0" ]; then
        AA_SAVED="$(cat "${AA_KNOB}")"
        if printf '0\n' > "${AA_KNOB}" 2>/dev/null; then
            echo "  ${AA_KNOB}: ${AA_SAVED} -> 0 (restored on exit)"
        else
            AA_SAVED=""
            echo "  ${AA_KNOB} is not writable"
        fi
    fi

    if runuser -u "${DROP_USER}" -- unshare --user --map-root-user -- /bin/true 2>/dev/null; then
        echo "  running as ${DROP_USER} with unprivileged user namespaces available"
        echo ""
        sandbox_hard_assertions "${SANDBOX}" "${WORK}" "${DROP_USER}"
    else
        skip_group "${SANDBOX_HARD_COUNT}" \
            "unprivileged user namespaces are still unavailable to ${DROP_USER} after clearing ${AA_KNOB} (kernel or container policy)"
    fi
fi

restore_knob

echo ""
# The suite declares its own assertion count. A block that stops
# running — a `skip` standing in for the whole HARD-mode group — changes
# the total, and a changed total is a failure rather than a smaller
# number nobody compares against anything.
harness_expect_total $(( SANDBOX_HARD_COUNT + 1 ))
harness_summary "sandbox-hard" || exit 1
exit 0
