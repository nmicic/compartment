#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Bypass class: open the sealed inode from a different mount namespace.
# (dev, ino) keying is invariant across mount namespaces, so the deny
# must fire identically.
# Suggestion ID: 4.2h
set -u
BYPASS_NAME="08-mount-namespace"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env
bypass_setup "no-write"

# Run sealprobe inside a fresh mount namespace via unshare.
unshare -m "$SEALPROBE" open-write "$TARGET" >/dev/null 2>&1; rc=$?
case $rc in
	1) bypass_pass "open-write in fresh mount-ns denied" ;;
	0) bypass_fail "BYPASS: open-write succeeded in fresh mount-ns" ;;
	*) bypass_fail "unexpected rc=$rc" ;;
esac
