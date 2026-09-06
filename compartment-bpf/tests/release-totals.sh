#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/release-totals.sh — assert the assertion counts in a `make check`
# transcript against tracked minima.
#
# `make check-release` could tell that every suite exited 0 and that every
# SKIP line was documented. It could not tell that a suite had stopped
# asserting: a bypass witness that prints PASS without running a probe, a
# renamed mesh block that quietly runs 300 fewer trials, a strict-launch
# corpus that shrank from 17 witnesses to 11 — none of that changes an
# exit status or produces a SKIP line, and the allowlist entry for the
# bypass tally is unanchored and unbounded, so it swallows a smaller
# number too.
#
# This is the same ratchet as the coverage manifest, applied to the
# counts: a floor per suite, so a corpus can grow without editing this
# file but cannot shrink without failing the release. Floors, not exact
# values, because several counts legitimately differ between the 6.8 and
# 7.0 guests.
#
# Usage: tests/release-totals.sh <make-check-log>
# Exit:  0 all floors met, 1 otherwise.

set -u

LOG="${1:-}"
[ -n "$LOG" ] && [ -r "$LOG" ] || {
	echo "[totals] FAIL: usage: $0 <make-check-log>" >&2
	exit 1
}

rc=0

# check NAME MIN SED-EXPRESSION
#   SED-EXPRESSION must print the count and nothing else.
check() {
	name=$1; min=$2; expr=$3
	got=$(sed -n "$expr" "$LOG" | head -1)
	if [ -z "$got" ]; then
		echo "[totals] FAIL $name: no count line in the transcript (the suite did not run, or its summary line changed)"
		rc=1
		return
	fi
	if [ "$got" -lt "$min" ]; then
		echo "[totals] FAIL $name: $got, floor is $min — the corpus shrank"
		rc=1
		return
	fi
	echo "[totals] OK $name: $got (floor $min)"
}

check bypass          39   's/^\[bypass-local\] \([0-9]*\) PASS \/ .*/\1/p'
check bypass-scripts  39   's/^\[bypass-local\] [0-9]* PASS \/ [0-9]* FAIL \/ [0-9]* SKIP over \([0-9]*\) scripts$/\1/p'
check mesh            3200 's/^\[mesh\] \([0-9]*\) ENFORCED trials matched.*/\1/p'
check strict-launch   17   's/^PASS=\([0-9]*\) FAIL=[0-9]*$/\1/p'
check observe         21   's/^Summary: PASS=\([0-9]*\) FAIL=[0-9]*.*/\1/p'
check dir-matrix      40   's/^\[check-dir-matrix\] \([0-9]*\)\/[0-9]* PASS$/\1/p'
check parser-actor    46   's/^parser-actor: \([0-9]*\) passed, [0-9]* failed$/\1/p'
check negtest         15   's/^\[negtest\] summary: PASS=\([0-9]*\) .*/\1/p'
check inode-seal      5    's/^\[inode-seal-witness\] \([0-9]*\) passed, [0-9]* failed$/\1/p'
check loader-refusal  5    's/^\[loader-refusal-witness\] \([0-9]*\) PASS \/ [0-9]* FAIL$/\1/p'
check limit-stress    2    's/^\[limit-stress\] \([0-9]*\) PASS \/ [0-9]* FAIL$/\1/p'
check wrapper         21   's/^check-wrapper Total PASS=\([0-9]*\) FAIL=[0-9]*$/\1/p'
check profiles        19   's/^\[check-profiles\] \([0-9]*\)\/[0-9]* profiles parsed cleanly$/\1/p'
check pin-regression  6    's/^pin-regression: \([0-9]*\) passed, [0-9]* failed.*/\1/p'
check counter-smoke   4    's/^counter-smoke: \([0-9]*\)\/[0-9]* passed, [0-9]* failed$/\1/p'

if [ "$rc" -ne 0 ]; then
	echo "[totals] FAIL: at least one suite is below its tracked floor."
	echo "[totals]       If a corpus was legitimately reduced, lower the floor"
	echo "[totals]       in tests/release-totals.sh in the same commit and say why."
else
	echo "[totals] OK: every suite met its tracked floor."
fi
exit "$rc"
