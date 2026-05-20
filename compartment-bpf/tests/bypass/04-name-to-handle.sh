#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Bypass class: name_to_handle_at + open_by_handle_at. Bypasses pathname
# resolution but the kernel hooks see the same (dev, ino).
# Suggestion ID: 4.2d
set -u
BYPASS_NAME="04-name-to-handle"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env
bypass_setup "no-write"

"$SEALPROBE" open-by-handle-wronly "$TARGET" >/dev/null 2>&1; rc=$?
case $rc in
	1) bypass_pass "open_by_handle_at(O_WRONLY) denied" ;;
	4) bypass_skip "filesystem doesn't support file handles (rc=STAGE_ERROR)" ;;
	0) bypass_fail "BYPASS: open_by_handle_at(O_WRONLY) succeeded" ;;
	*) bypass_fail "unexpected rc=$rc" ;;
esac
