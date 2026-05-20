#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Bypass class: truncate(2) without opening the file first. file_truncate
# LSM hook (kernel 6.5+) must catch it.
# Suggestion ID: 4.2b
set -u
BYPASS_NAME="02-truncate-no-open"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env
bypass_setup "no-write"

"$SEALPROBE" truncate "$TARGET" >/dev/null 2>&1; rc=$?
case $rc in
	1) bypass_pass "truncate(2) without open denied" ;;
	0) bypass_fail "BYPASS: truncate(2) succeeded without open" ;;
	*) bypass_fail "unexpected rc=$rc" ;;
esac
