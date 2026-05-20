#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Bypass class: create a hardlink to a sealed inode in an unsealed dir,
# then unlink the LINK. The (dev, ino) is unchanged so the deny must
# fire on the link path too.
# Suggestion ID: 4.2a
set -u
BYPASS_NAME="01-hardlink-unlink"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env
bypass_setup "no-unlink"

mkdir "$TMP/decoy"
ln "$TARGET" "$TMP/decoy/link" || bypass_die "could not hardlink (fs-level)"

"$SEALPROBE" unlink "$TMP/decoy/link" >/dev/null 2>&1; rc=$?
case $rc in
	1) bypass_pass "unlink-via-hardlink denied (rc=DENY)" ;;
	0) bypass_fail "BYPASS: unlink succeeded via hardlink" ;;
	*) bypass_fail "unexpected rc=$rc" ;;
esac
