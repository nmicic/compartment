#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Bypass class: open RO + mmap RO + mprotect R→RW. file_mprotect hook on
# a shared file mapping must catch the upgrade.
# Suggestion ID: 4.2c
set -u
BYPASS_NAME="03-mprotect-rw"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env
bypass_setup "no-write"

"$SEALPROBE" mprotect-rw "$TARGET" >/dev/null 2>&1; rc=$?
case $rc in
	1) bypass_pass "mprotect R->RW on shared mapping denied" ;;
	0) bypass_fail "BYPASS: mprotect R->RW succeeded" ;;
	*) bypass_fail "unexpected rc=$rc" ;;
esac
