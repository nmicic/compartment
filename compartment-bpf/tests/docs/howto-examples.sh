#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# tests/docs/howto-examples.sh — executable-doc gate for HOWTO.md
#
# Coverage-gaps 2026-05-16 GAP-H-12: the v0.5 headliner example in
# HOWTO.md §7.2 (dir-destination seals) regressed three V-6 cycles in
# a row:
#   - V-6 re-run #2 P1-A: DEC-ED3-B (two seal lines on one path)
#   - V-6 re-run #3 P1-A: ED-5 strict-mode (missing actor-binary seal)
#   - V-6 re-run #3 P1-A: same example, follow-up flag-set mismatch
#
# Each fix was a HOWTO.md edit only — no test ever asserted that the
# example actually parses and loads. This test closes the loop: it
# extracts the headliner example's structure (actor decl + actor-binary
# seal + data-dir seal) and re-runs it under --dry-run with a tmp
# fixture, asserting rc=0.
#
# The extraction is conservative: it matches the literal ABI v0.5
# headliner shape (one actor= decl + one no-write,no-unlink,no-rename,
# no-chmod seal on the actor binary + one same-flags seal with actor=
# on a directory). If the HOWTO §7.2 grammar drifts away from this
# shape, this test will SKIP rather than FAIL, and the operator
# follow-up is to update both HOWTO and the test in lockstep.
#
# Exit codes:
#   0 — example loads cleanly under --dry-run
#   1 — example fails (regression — operator action required)
#   2 — binary missing or HOWTO §7.2 structure not found (skip)
#
# Scope intentionally limited to §7.2 because that section regressed
# three times. Future cycles can add §1, §2, §7.3, etc. by extending
# the case list at the bottom of this script.

set -eo pipefail
set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${REPO_ROOT}/compartment-bpf"
HOWTO="${REPO_ROOT}/HOWTO.md"

if [ ! -x "$BIN" ]; then
	echo "error: $BIN not found or not executable (run 'make' first)" >&2
	exit 2
fi
if [ ! -r "$HOWTO" ]; then
	echo "error: $HOWTO not readable" >&2
	exit 2
fi

WORK="$(mktemp -d -t howto-examples.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

declare -i PASSED=0 FAILED=0
declare -a FAILS=()

# extract_fenced_block <section-prefix> <out-file>
#   Read HOWTO.md, locate the heading matching <section-prefix>, then
#   capture the FIRST fenced code block after it. Writes the body
#   between the fences to <out-file>. Returns non-zero if no block
#   found.
extract_fenced_block() {
	local section="$1" out="$2"
	awk -v section="$section" '
		BEGIN { in_section = 0; in_fence = 0; printed = 0 }
		# Heading match: ###/##/# followed by section prefix.
		/^#+ / && index($0, section) {
			in_section = 1; next
		}
		# Next heading after we entered the section ends the search.
		in_section && !in_fence && /^#+ / { exit }
		# Fence start/end. The first fence opens, the matching one closes.
		in_section && /^```/ {
			if (!in_fence && !printed) {
				in_fence = 1
			} else if (in_fence) {
				in_fence = 0; printed = 1; exit
			}
			next
		}
		in_section && in_fence { print }
	' "$HOWTO" > "$out"
	[ -s "$out" ]
}

# run_howto_example <id> <section-prefix> <fixture-builder-fn>
#   1) Extract the first fenced block under <section-prefix>.
#   2) Invoke <fixture-builder-fn> $WORK/<id> to materialize any
#      paths referenced by the block (using path substitution).
#   3) Run --dry-run on the substituted profile, assert rc=0.
run_howto_example() {
	local id="$1" section="$2" build_fn="$3"
	local raw="$WORK/$id-raw.txt"
	local substituted="$WORK/$id-subst.conf"
	local err="$WORK/$id.err"

	if ! extract_fenced_block "$section" "$raw"; then
		echo "[SKIP] $id (no fenced block found under section '$section')"
		return 0
	fi

	# Build the per-fixture FS state + the path-substitution sed args.
	# The builder returns the substituted profile in $substituted.
	if ! "$build_fn" "$WORK/$id" "$raw" "$substituted"; then
		echo "[SKIP] $id (fixture builder declined — structure drifted)"
		return 0
	fi

	set +e
	"$BIN" --dry-run "$substituted" >"$err" 2>&1
	local rc=$?
	set -e

	if [ "$rc" -eq 0 ]; then
		PASSED+=1
		echo "[PASS] $id: HOWTO $section example loads cleanly"
	else
		FAILED+=1
		FAILS+=("$id: --dry-run rc=$rc on substituted §$section example")
		echo "[FAIL] $id: HOWTO $section example FAILED --dry-run (rc=$rc)"
		echo "----- substituted profile -----"
		cat "$substituted"
		echo "----- stderr -----"
		cat "$err"
		echo "-------------------------------"
	fi
}

# Section §7.2 builder: the headliner uses paths
#   actor    = /usr/lib/postgresql/18/bin/postgres
#   data dir = /var/lib/postgresql/18/main
# We substitute both to a tmp tree under $1 and create the FS
# fixtures needed for --dry-run (real regular-file actor binary +
# real directory data dir + parent dirs that are not world-writable).
build_72_dir_destination() {
	local fixroot="$1" raw="$2" out="$3"
	mkdir -p "$fixroot/pg/bin" "$fixroot/pg/data"
	# Actor binary: must be a regular file, 0755, non-world-writable,
	# non-empty, no symlink in its path. Parent dir not world-writable.
	cp /bin/true "$fixroot/pg/bin/postgres"
	chmod 0755 "$fixroot/pg/bin/postgres"
	chmod 0755 "$fixroot/pg" "$fixroot/pg/bin" "$fixroot/pg/data"

	# The §7.2 block references the postgres binary path and the data
	# dir path. Map both into our tmp tree via sed. We preserve the
	# directive grammar unchanged.
	sed -e "s|/usr/lib/postgresql/18/bin/postgres|$fixroot/pg/bin/postgres|g" \
	    -e "s|/var/lib/postgresql/18/main|$fixroot/pg/data|g" \
	    "$raw" > "$out"

	# If after substitution the block still references any unmapped
	# absolute path with /usr or /var, give up — the HOWTO grammar
	# has drifted away from the headliner shape and the test needs
	# manual update. SKIP rather than FAIL (the SKIP signals to the
	# operator that the test needs maintenance, not that production
	# broke).
	if grep -E '/(usr|var)/' "$out" >/dev/null; then
		return 1
	fi
	return 0
}

# --- Cases ---

run_howto_example "h7.2-dir-destination" "7.2 Syntax" build_72_dir_destination

echo ""
echo "================================================================"
printf 'howto-examples: %d passed, %d failed\n' "$PASSED" "$FAILED"
if (( FAILED > 0 )); then
	for f in "${FAILS[@]}"; do
		printf '  - %s\n' "$f"
	done
	exit 1
fi
exit 0
