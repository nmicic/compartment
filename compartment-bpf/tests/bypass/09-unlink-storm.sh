#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Bypass class: many concurrent unlink attempts against a sealed inode.
# A TOCTOU race in the LSM hook would let one of them through; the file
# must survive and every attempt must fail.
# Suggestion ID: 4.2i
set -u
BYPASS_NAME="09-unlink-storm"
. "$(dirname "$0")/lib-bypass.sh"
bypass_check_env
bypass_setup "no-unlink"

WORKERS=${WORKERS:-16}
ITERS=${ITERS:-50}

# Track worker pids explicitly. `wait` with no args would also wait for
# the daemon process started by bypass_setup, which never exits on its
# own — leading to an apparent hang.
worker_pids=
i=0
while [ "$i" -lt "$WORKERS" ]; do
	(
		j=0
		while [ "$j" -lt "$ITERS" ]; do
			"$SEALPROBE" unlink "$TARGET" >/dev/null 2>&1
			j=$((j+1))
		done
	) &
	worker_pids="$worker_pids $!"
	i=$((i+1))
done
for pid in $worker_pids; do wait "$pid" 2>/dev/null || true; done

if [ -e "$TARGET" ]; then
	bypass_pass "$WORKERS×$ITERS concurrent unlinks all denied; file survived"
else
	bypass_fail "BYPASS: file disappeared during concurrent unlink storm"
fi
