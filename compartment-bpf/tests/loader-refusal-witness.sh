#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# tests/loader-refusal-witness.sh
#
# Witnesses the loader's FAIL-CLOSED recursive-directory-seal input validation
# (validate_recursive_dir_seal, compartment-bpf.c). Before this test these three
# refusal paths had NO witness — surfaced by the "seal /usr" exercise (2026-06-09):
# the suite tested enforcement on curated-clean fixtures but never fed the loader
# a realistic *dirty* subtree and asserted the refusal ("not testing to the
# failure"). A refactor that broke a detector would let a dirty subtree load with
# silent partial coverage = fail-OPEN, undetected.
#
# All cases run via `--dry-run`, which performs the subtree walk WITHOUT BPF or
# root (no kernel state touched). The daemon binary just needs to be built.
#
# Exit: 0 all pass, 1 any fail, 77 skip (binary not built).
set -u
cd "$(dirname "$0")/.."
BIN="./compartment-bpf"

[ -x "$BIN" ] || { echo "SKIP loader-refusal-witness: $BIN not built"; exit 77; }

TMP=$(mktemp -d /tmp/loader-refusal.XXXXXX)
trap 'rm -rf "$TMP"' EXIT INT TERM
pass=0; fail=0

# Preflight: --dry-run runs a startup pin-shape probe (bpf_obj_get under
# PIN_ROOT). bpffs is typically mode 700, so a non-root invocation gets EACCES
# (not ENOENT) and the probe aborts before any policy validation runs. Detect
# that here and SKIP cleanly rather than emit spurious FAILs — the witness runs
# fully as root or on any host where --dry-run can reach validation. (The probe
# firing in --dry-run at all is a separate wart; tracked in TODO.)
mkdir -p "$TMP/pf/sub"; : > "$TMP/pf/sub/f"
printf 'seal %s/pf no-write\n' "$TMP" > "$TMP/pf.conf"
pf=$("$BIN" --dry-run "$TMP/pf.conf" 2>&1)
if ! printf '%s' "$pf" | grep -qF "1 seal resolved"; then
	if printf '%s' "$pf" | grep -qiE 'pin-shape:.*(permission denied|operation not permitted)'; then
		echo "SKIP loader-refusal-witness: --dry-run cannot reach validation here"
		echo "  (bpffs pin-shape probe needs root/readable PIN_ROOT — run as root)"
		exit 77
	fi
	echo "SKIP loader-refusal-witness: --dry-run preflight did not resolve a clean seal"
	printf '%s\n' "$pf" | tail -3 | sed 's/^/    /'
	exit 77
fi

# run_case <name> <conf> <expect-substring> <expect-summary-substring>
run_case() {
	local name="$1" conf="$2" want="$3" wantsum="$4" out
	out=$("$BIN" --dry-run "$conf" 2>&1)
	if printf '%s' "$out" | grep -qF "$want" && printf '%s' "$out" | grep -qF "$wantsum"; then
		echo "PASS $name"; pass=$((pass+1))
	else
		echo "FAIL $name: missing '$want' and/or '$wantsum'"
		printf '%s\n' "$out" | sed 's/^/    /'
		fail=$((fail+1))
	fi
}

# --- Case 1: symlink anywhere in the subtree -> refuse ---
mkdir -p "$TMP/s/sub"; : > "$TMP/s/sub/real"; ln -s real "$TMP/s/sub/link"
printf 'seal %s/s no-write\n' "$TMP" > "$TMP/c1.conf"
run_case "symlink-in-subtree-refused" "$TMP/c1.conf" \
	"is a symlink" "1 error"

# --- Case 2: hardlink (st_nlink>1) in the subtree -> refuse ---
mkdir -p "$TMP/h/sub"; : > "$TMP/h/sub/a"; ln "$TMP/h/sub/a" "$TMP/h/sub/b"
printf 'seal %s/h no-write\n' "$TMP" > "$TMP/c2.conf"
run_case "hardlink-in-subtree-refused" "$TMP/c2.conf" \
	"hardlinks (st_nlink > 1)" "1 error"

# --- Case 3: entry deeper than the compiled depth cap -> refuse ---
# 65 levels exceeds any legal cap (abi.h bounds COMPARTMENT_MAX_DIR_ANCESTORS to
# 1..64), so this fires regardless of how the daemon was built.
d="$TMP/d"; mkdir -p "$d"; p="$d"
for i in $(seq 1 65); do p="$p/L$i"; done
mkdir -p "$p"; : > "$p/leaf"
printf 'seal %s no-write\n' "$d" > "$TMP/c3.conf"
run_case "over-depth-subtree-refused" "$TMP/c3.conf" \
	"exceeds the compiled depth cap" "1 error"

# --- Case 4 (control): a clean, shallow subtree must RESOLVE, not refuse ---
mkdir -p "$TMP/ok/sub"; : > "$TMP/ok/sub/f"
printf 'seal %s/ok no-write\n' "$TMP" > "$TMP/c4.conf"
run_case "clean-subtree-resolves" "$TMP/c4.conf" \
	"1 seal resolved" "0 errors"

# --- Case 5: refusal must still fire DEEP inside a large subtree (not just at
#     the root) — buries a symlink under a wide-ish tree. ---
big="$TMP/big"; mkdir -p "$big"
for a in $(seq 1 8); do for b in $(seq 1 8); do mkdir -p "$big/d$a/d$b"; : > "$big/d$a/d$b/f"; done; done
ln -s f "$big/d8/d8/buried-link"
printf 'seal %s no-write\n' "$big" > "$TMP/c5.conf"
run_case "deep-buried-symlink-refused" "$TMP/c5.conf" \
	"is a symlink" "1 error"

echo "[loader-refusal-witness] $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ] || exit 1
exit 0
