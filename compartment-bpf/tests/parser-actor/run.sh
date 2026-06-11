#!/usr/bin/env bash
#
# tests/parser-actor/run.sh — ED-1 + ED-2 parser/loader fixture runner.
#
# Eight grammar fixtures (01..08) drive the parser via --parse-only (no
# FS access). Five resolution fixtures (09..13) drive the loader via
# --dry-run with a tmp working directory of real files / symlinks /
# world-writable / 0-byte / not-regular paths.
#
# Exit codes:
#   0 — all tests passed.
#   1 — at least one test failed; one '[FAIL]' line per failure on
#       stdout, with the captured stderr inline.
#   2 — usage / setup error (compartment-bpf binary missing).
#
# Determinism notes:
#   - 01..08 do not touch the filesystem; they only need the binary.
#   - 09..13 build their fixtures under a private mktemp -d that is
#     wiped on exit (trap EXIT). No hardcoded /tmp paths leak.
#   - No uid/gid/group dependency. World-writable check uses chmod
#     0666, which any user can set on a file they own.
#
# `set -eo pipefail` catches command failures and pipe-
# left-side failures eagerly. The existing per-test set+e/set-e guards
# inside run_parse / run_dryrun remain in place so the harness can
# inspect non-zero exit codes from the binary under test without
# aborting the whole run.
set -eo pipefail
set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${REPO_ROOT}/compartment-bpf"
DIR="${REPO_ROOT}/tests/parser-actor"

if [[ ! -x "$BIN" ]]; then
    echo "error: $BIN not found or not executable (run 'make' first)" >&2
    exit 2
fi

# Test bookkeeping
declare -i PASSED=0 FAILED=0
declare -a FAILS=()

# Args: <id> <conf> <expect_pass|expect_fail> <stderr_regex>
#   <stderr_regex> is checked only when expect_fail (the FAIL diagnostic
#   must mention the named class). For expect_pass it is ignored.
run_parse() {
    local id="$1" conf="$2" expect="$3" pattern="${4:-}"
    local out
    local rc

    set +e
    out="$("$BIN" --parse-only "$conf" 2>&1)"
    rc=$?
    set -e

    if [[ "$expect" == "expect_pass" && $rc -eq 0 ]]; then
        PASSED+=1
        echo "[PASS] $id"
    elif [[ "$expect" == "expect_fail" && $rc -ne 0 ]]; then
        if [[ -n "$pattern" ]] && ! grep -Eq "$pattern" <<<"$out"; then
            FAILED+=1
            FAILS+=("$id: failed with rc=$rc but output did NOT match expected pattern: $pattern")
            echo "[FAIL] $id (pattern '$pattern' not in stderr)"
            echo "----- stderr -----"
            echo "$out"
            echo "------------------"
        else
            PASSED+=1
            echo "[PASS] $id (rejected as expected)"
        fi
    else
        FAILED+=1
        FAILS+=("$id: expected $expect, got rc=$rc")
        echo "[FAIL] $id (expected $expect, got rc=$rc)"
        echo "----- stderr -----"
        echo "$out"
        echo "------------------"
    fi
}

# Args: <id> <conf> <expect_pass|expect_fail> <stderr_regex>
# Like run_parse but uses --dry-run (stats the FS).
run_dryrun() {
    local id="$1" conf="$2" expect="$3" pattern="${4:-}"
    local out
    local rc

    set +e
    out="$("$BIN" --dry-run "$conf" 2>&1)"
    rc=$?
    set -e

    if [[ "$expect" == "expect_pass" && $rc -eq 0 ]]; then
        if [[ -n "$pattern" ]] && ! grep -Eq "$pattern" <<<"$out"; then
            FAILED+=1
            FAILS+=("$id: passed but output did NOT match expected pattern: $pattern")
            echo "[FAIL] $id (pattern '$pattern' not in stderr)"
            echo "----- stderr -----"
            echo "$out"
            echo "------------------"
        else
            PASSED+=1
            echo "[PASS] $id"
        fi
    elif [[ "$expect" == "expect_fail" && $rc -ne 0 ]]; then
        if [[ -n "$pattern" ]] && ! grep -Eq "$pattern" <<<"$out"; then
            FAILED+=1
            FAILS+=("$id: failed with rc=$rc but output did NOT match expected pattern: $pattern")
            echo "[FAIL] $id (pattern '$pattern' not in stderr)"
            echo "----- stderr -----"
            echo "$out"
            echo "------------------"
        else
            PASSED+=1
            echo "[PASS] $id (rejected as expected)"
        fi
    else
        FAILED+=1
        FAILS+=("$id: expected $expect, got rc=$rc")
        echo "[FAIL] $id (expected $expect, got rc=$rc)"
        echo "----- stderr -----"
        echo "$out"
        echo "------------------"
    fi
}

# -------- Parser tests (01..08): --parse-only, no FS dependency --------

run_parse "01-basic"                          "$DIR/01-basic.conf"                          expect_pass
run_parse "02-multiple-paths"                 "$DIR/02-multiple-paths.conf"                 expect_pass
run_parse "03-forward-ref"                    "$DIR/03-forward-ref.conf"                    expect_fail "unknown actor 'aide'"
run_parse "04-unknown-name"                   "$DIR/04-unknown-name.conf"                   expect_fail "unknown actor 'ghost'"
run_parse "05-duplicate-decl"                 "$DIR/05-duplicate-decl.conf"                 expect_fail "duplicate actor declaration"
run_parse "06-empty-rhs"                      "$DIR/06-empty-rhs.conf"                      expect_fail "empty RHS"
run_parse "07-mixed-anon-and-bound"           "$DIR/07-mixed-anon-and-bound.conf"           expect_pass
run_parse "08-no-actor-key-existing-profile"  "$DIR/08-no-actor-key-existing-profile.conf"  expect_pass
run_parse "14-actor-overflow"                 "$DIR/14-actor-overflow.conf"                 expect_fail "too many paths"
# ME-8 §3.8: file-fixture form of P2 inline test for visible coverage.
run_parse "24-multiple-actor-clauses"         "$DIR/24-multiple-actor-clauses.conf"         expect_fail "multiple actor= clauses"

# Additional grammar-tightening cases the SPEC names but the 8 fixtures
# above do not cover individually. These are 1-line .conf inputs piped
# directly to --parse-only via /dev/stdin so the test surface stays
# tight. Each MUST be rejected with the matching error class.
run_parse_inline() {
    local id="$1" pattern="$2"; shift 2
    local tmp
    tmp="$(mktemp)"
    printf '%s\n' "$@" >"$tmp"
    run_parse "$id" "$tmp" expect_fail "$pattern"
    rm -f "$tmp"
}

run_parse_inline "P1-actor-eq-empty" \
    "(malformed actor= clause|empty NAME)" \
    "actor a = /usr/sbin/a" \
    "seal /etc/a no-write actor="

run_parse_inline "P2-double-actor-clause" \
    "multiple actor= clauses" \
    "actor a = /usr/sbin/a" \
    "actor b = /usr/sbin/b" \
    "seal /etc/a no-write actor=a actor=b"

run_parse_inline "P3-actor-eq-with-no-flags" \
    "at least one flag before actor= clause" \
    "actor a = /usr/sbin/a" \
    "seal /etc/a actor=a"

run_parse_inline "P4-bad-actor-name-charset" \
    "(malformed actor name|invalid NAME)" \
    "actor 1bad = /usr/sbin/a" \
    "seal /etc/a no-write actor=1bad"

# Vacuously-strict seal — `strict-launch`
# without any other op-flag enforces nothing. Parser must reject so the
# operator gets an actionable diagnostic instead of a profile that
# passes parse but ships unprotected. SL-loader-rejects-vacuous witness.
run_parse_inline "SL-loader-rejects-vacuous" \
    "strict-launch is a modifier" \
    "actor-strict aide = /usr/sbin/aide launcher=/usr/libexec/compartment-actors/aide" \
    "seal /usr/sbin/aide full" \
    "seal /usr/libexec/compartment-actors/aide full" \
    "seal /var/lib/aide/aide.db strict-launch actor=aide"

# env directives removed from v0.4 grammar.
# Loader rejects profiles containing `env NAME=VALUE` / `env NAME=*` with
# a clear pointer at HOWTO.md §4.1. Negative witness for the deletion.
run_parse_inline "SL-loader-rejects-env-directive" \
    "env. directive removed in v0.4" \
    "actor-strict aide = /usr/sbin/aide launcher=/usr/libexec/compartment-actors/aide" \
    "  env PATH=/usr/sbin:/usr/bin" \
    "seal /usr/sbin/aide full"

# --- Coverage-gaps 2026-05-16 (GAP-H-1, M-1..M-3, H-5) ---
#
# parse_actor_strict_decl (compartment-bpf.c:562-651) had nine
# error-return paths with zero parser-inline witnesses (coverage audit
# 2026-05-16 GAP-H-1). Each fixture below pins one diagnostic so a
# regression that softened any of the v0.4 strict-launch grammar
# rejections would fail loudly. The closing brace lines are kept tight
# (single-line .conf with one error) so the pattern is intentionally
# the first thing matched.

run_parse_inline "SL-parse-missing-name" \
    "actor-strict missing NAME" \
    "actor-strict"

run_parse_inline "SL-parse-missing-equals" \
    "missing '=' after NAME" \
    "actor-strict aide"

run_parse_inline "SL-parse-missing-target" \
    "missing TARGET path" \
    "actor-strict aide ="

run_parse_inline "SL-parse-target-not-abs" \
    "TARGET 'usr/sbin/aide' must be absolute" \
    "actor-strict aide = usr/sbin/aide launcher=/x"

run_parse_inline "SL-parse-missing-launcher" \
    "missing 'launcher=PATH' clause" \
    "actor-strict aide = /usr/sbin/aide"

run_parse_inline "SL-parse-launcher-not-abs" \
    "launcher path must be absolute and non-empty" \
    "actor-strict aide = /usr/sbin/aide launcher=relative"

run_parse_inline "SL-parse-launcher-empty" \
    "launcher path must be absolute and non-empty" \
    "actor-strict aide = /usr/sbin/aide launcher="

run_parse_inline "SL-parse-trailing-tokens" \
    "trailing tokens after launcher=" \
    "actor-strict aide = /usr/sbin/aide launcher=/x trailing-garbage"

# Cross-namespace duplicate: legacy `actor` then `actor-strict` with
# same NAME. They share `profile_find_actor` lookup.
run_parse_inline "SL-parse-cross-namespace-dup" \
    "duplicate actor declaration" \
    "actor aide = /usr/sbin/aide" \
    "actor-strict aide = /usr/sbin/aide launcher=/x"

# GAP-M-1: parse_flagspec "unknown seal flag" had no witness.
run_parse_inline "P5-unknown-flag" \
    "unknown seal flag" \
    "seal /etc/x no-such-flag"

# GAP-M-2: load_conf "unknown directive" had no witness.
run_parse_inline "P6-unknown-directive" \
    "unknown directive" \
    "bogus /etc/x"

# GAP-M-3: load_conf "missing seal target" had no witness.
run_parse_inline "P7-missing-seal-target" \
    "missing seal target" \
    "seal"

# -------- Resolution tests (09..13): --dry-run, real FS fixtures --------
#
# Each fixture creates a small private workspace; the .conf is generated
# inline referencing the workspace paths. After the test the workspace
# is wiped (trap EXIT below).

WORK="$(mktemp -d -t parser-actor.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# A real seal target so the profile is not "no seals" (which would
# otherwise trip the empty-profile fail-closed). Used by 09..13.
echo "fixture-content" > "$WORK/target.txt"

# 09: actor path that does not exist.
mkdir -p "$WORK/09"
cat > "$WORK/09/profile.conf" <<EOF
actor missing = /tmp/parser-actor-this-path-does-not-exist-$$-$RANDOM

seal $WORK/target.txt no-write actor=missing
EOF
run_dryrun "09-actor-binary-missing" "$WORK/09/profile.conf" expect_fail \
    "actor missing: open .* No such file"

# 10: actor path is a symlink → O_NOFOLLOW returns the symlink itself,
# S_ISLNK rejects it.
mkdir -p "$WORK/10"
echo "real-binary" > "$WORK/10/real-binary"
chmod 0755 "$WORK/10/real-binary"
ln -sf "$WORK/10/real-binary" "$WORK/10/symlink-to-binary"
cat > "$WORK/10/profile.conf" <<EOF
actor sym = $WORK/10/symlink-to-binary

seal $WORK/target.txt no-write actor=sym
EOF
run_dryrun "10-actor-binary-symlink" "$WORK/10/profile.conf" expect_fail \
    "symlink leaf"

# 11: actor binary is world-writable → S_IWOTH rejects it.
mkdir -p "$WORK/11"
echo "world-writable-binary" > "$WORK/11/ww-binary"
chmod 0666 "$WORK/11/ww-binary"
cat > "$WORK/11/profile.conf" <<EOF
actor ww = $WORK/11/ww-binary

seal $WORK/target.txt no-write actor=ww
EOF
run_dryrun "11-actor-binary-world-writable" "$WORK/11/profile.conf" expect_fail \
    "world-writable"

# 11b (Coverage-gaps GAP-M-5): actor binary is GROUP-writable only
# (S_IWGRP without S_IWOTH). F17 (compartment-bpf.c:897-910) refuses
# either bit; fixture 11 only exercises S_IWOTH (chmod 0666). A
# regression that narrowed F17 to S_IWOTH alone would let
# group-writable binaries pass silently.
mkdir -p "$WORK/11b"
echo "group-writable-binary" > "$WORK/11b/gw-binary"
chmod 0775 "$WORK/11b/gw-binary"
cat > "$WORK/11b/profile.conf" <<EOF
actor gw = $WORK/11b/gw-binary

seal $WORK/target.txt no-write actor=gw
EOF
run_dryrun "11b-actor-binary-group-writable" "$WORK/11b/profile.conf" expect_fail \
    "group-writable|world-writable"

# 11c (Coverage-gaps GAP-M-6): actor binary is non-executable
# (S_IXUSR|S_IXGRP|S_IXOTH all clear). F22 (compartment-bpf.c:997-1007)
# rejects with "not executable". Distinct from the 0-byte path (Z1
# above), which uses chmod 0755 on an empty file.
mkdir -p "$WORK/11c"
echo "non-exec-binary" > "$WORK/11c/no-x-binary"
chmod 0644 "$WORK/11c/no-x-binary"
cat > "$WORK/11c/profile.conf" <<EOF
actor nx = $WORK/11c/no-x-binary

seal $WORK/target.txt no-write actor=nx
EOF
run_dryrun "11c-actor-binary-not-executable" "$WORK/11c/profile.conf" expect_fail \
    "not executable"

# 12: actor path is a directory → S_ISREG rejects it.
mkdir -p "$WORK/12/not-a-binary-dir"
cat > "$WORK/12/profile.conf" <<EOF
actor d = $WORK/12/not-a-binary-dir

seal $WORK/target.txt no-write actor=d
EOF
run_dryrun "12-actor-binary-not-regular" "$WORK/12/profile.conf" expect_fail \
    "not a regular file"

# 13: same path under two actors. Loader MUST accept; we expect a
# colliding-inode informational log line.
mkdir -p "$WORK/13"
echo "shared-binary" > "$WORK/13/shared-binary"
chmod 0755 "$WORK/13/shared-binary"
cat > "$WORK/13/profile.conf" <<EOF
actor a = $WORK/13/shared-binary
actor b = $WORK/13/shared-binary

# F3: strict-mode (ED-5) requires every actor binary to be sealed at
# its declared path; without this line the dry-run fails for that
# reason rather than for the inode-collision message the test exists
# to assert.
seal $WORK/13/shared-binary full
seal $WORK/target.txt no-write actor=a
EOF
run_dryrun "13-resolved-pair-mismatch" "$WORK/13/profile.conf" expect_pass \
    "share inode"

# Extra: zero-byte actor binary
mkdir -p "$WORK/Z1"
: > "$WORK/Z1/zero-byte"
chmod 0755 "$WORK/Z1/zero-byte"
cat > "$WORK/Z1/profile.conf" <<EOF
actor z = $WORK/Z1/zero-byte

seal $WORK/target.txt no-write actor=z
EOF
run_dryrun "Z1-actor-binary-zero-byte" "$WORK/Z1/profile.conf" expect_fail \
    "0-byte file"

# -------- ED-5 strict-mode tests (15..18): --dry-run, real FS fixtures --------
#
# 15: two seal lines on the same path with different actor clauses — two seal lines on the same path where
#     one carries actor=. Must be refused at the in-memory merge level
#     (so it fires in --dry-run too, not just real-load).
mkdir -p "$WORK/15"
echo "ed5-target" > "$WORK/15/target.txt"
echo "ed5-actor-bin" > "$WORK/15/actor-bin"
chmod 0755 "$WORK/15/actor-bin"
cat > "$WORK/15/profile.conf" <<EOF
actor aide = $WORK/15/actor-bin

seal $WORK/15/target.txt no-write
seal $WORK/15/target.txt no-unlink actor=aide
EOF
run_dryrun "15-seal-merge-with-actor" "$WORK/15/profile.conf" expect_fail \
    "refusing to merge seal lines"

# 15b (Coverage-gaps GAP-H-5): cross-actor seal collision. Same path

# refuses the merge regardless of whether the actor= clauses agree;
# without an explicit two-different-actors witness, a regression that
# only refused same-actor collisions would ship silently.
mkdir -p "$WORK/15b"
echo "ed5-target" > "$WORK/15b/target.txt"
echo "ed5-reader" > "$WORK/15b/reader-bin"; chmod 0755 "$WORK/15b/reader-bin"
echo "ed5-writer" > "$WORK/15b/writer-bin"; chmod 0755 "$WORK/15b/writer-bin"
cat > "$WORK/15b/profile.conf" <<EOF
actor reader = $WORK/15b/reader-bin
actor writer = $WORK/15b/writer-bin

seal $WORK/15b/reader-bin full
seal $WORK/15b/writer-bin full
seal $WORK/15b/target.txt no-write actor=reader
seal $WORK/15b/target.txt no-chmod actor=writer
EOF
run_dryrun "15b-cross-actor-seal-collision" "$WORK/15b/profile.conf" expect_fail \
    "refusing to merge seal lines"

# 16: actor binary referenced but NEVER sealed. Strict-mode rejects at
#     load time because an unsealed actor binary defeats exec-domain.
mkdir -p "$WORK/16"
echo "ed5-target" > "$WORK/16/target.txt"
echo "ed5-aide" > "$WORK/16/aide-bin"
chmod 0755 "$WORK/16/aide-bin"
cat > "$WORK/16/profile.conf" <<EOF
actor aide = $WORK/16/aide-bin

seal $WORK/16/target.txt no-write actor=aide
EOF
run_dryrun "16-strict-actor-not-sealed" "$WORK/16/profile.conf" expect_fail \
    "is not sealed at its declared path"

# 17: actor binary sealed but with PARTIAL flags (missing no-rename + no-chmod).
#     Strict-mode rejects; the error names the missing flags explicitly.
mkdir -p "$WORK/17"
echo "ed5-target" > "$WORK/17/target.txt"
echo "ed5-aide" > "$WORK/17/aide-bin"
chmod 0755 "$WORK/17/aide-bin"
cat > "$WORK/17/profile.conf" <<EOF
actor aide = $WORK/17/aide-bin

seal $WORK/17/aide-bin no-write,no-unlink
seal $WORK/17/target.txt no-write actor=aide
EOF
run_dryrun "17-strict-actor-partial-seal" "$WORK/17/profile.conf" expect_fail \
    "missing flags \[no-rename,no-chmod\]"

# 18: actor binary sealed with the FULL flag set. Strict-mode passes.
mkdir -p "$WORK/18"
echo "ed5-target" > "$WORK/18/target.txt"
echo "ed5-aide" > "$WORK/18/aide-bin"
chmod 0755 "$WORK/18/aide-bin"
cat > "$WORK/18/profile.conf" <<EOF
actor aide = $WORK/18/aide-bin

seal $WORK/18/aide-bin full
seal $WORK/18/target.txt no-write actor=aide
EOF
run_dryrun "18-strict-actor-fully-sealed" "$WORK/18/profile.conf" expect_pass \
    "dry-run.*summary"

# 19: Sec-2/F5 hardlink-bypass guard. Actor binary at $WORK/19/aide-bin;
#     a hardlink at $WORK/19/alias is sealed instead. Pre-fix this passed
#     strict-mode (the (dev, ino) match succeeded). Post-fix this fails
#     because the declared path of the seal ('alias') does not equal the
#     declared path of the actor ('aide-bin') even though the inodes match.
mkdir -p "$WORK/19"
echo "ed5-target" > "$WORK/19/target.txt"
echo "ed5-aide" > "$WORK/19/aide-bin"
chmod 0755 "$WORK/19/aide-bin"
ln "$WORK/19/aide-bin" "$WORK/19/alias"
cat > "$WORK/19/profile.conf" <<EOF
actor aide = $WORK/19/aide-bin

seal $WORK/19/alias full
seal $WORK/19/target.txt no-write actor=aide
EOF
run_dryrun "19-hardlink-bypass" "$WORK/19/profile.conf" expect_fail \
    "is not sealed at its declared path"

# 20: Sec-8/F13 overlong-line fuzz fixture. Synthesises a profile line
#     that exceeds the parser's fgets() buffer; loader MUST hard-reject
#     with the "line too long" diagnostic and NOT silently misparse the
#     remainder of the file.
mkdir -p "$WORK/20"
{
    # 4096 bytes of 'X' = comfortably beyond the 2048-byte fgets buffer.
    printf 'seal /tmp/sealed-target no-write actor='
    printf 'X%.0s' $(seq 1 4096)
    printf '\n'
} > "$WORK/20/profile.conf"
run_parse "20-overlong-actor-line" "$WORK/20/profile.conf" expect_fail \
    "line too long"

# 21: Sec-8/F13 companion — a directive comfortably WITHIN the buffer
#     parses cleanly. Verifies the hard-reject above is not over-broad.
mkdir -p "$WORK/21"
echo "ed5-target" > "$WORK/21/target.txt"
cat > "$WORK/21/profile.conf" <<EOF
# An ordinary in-bound profile; the parse-only path stats nothing.
seal /tmp/x no-write
EOF
run_parse "21-actor-line-at-bound" "$WORK/21/profile.conf" expect_pass

# 22: Sec-10/F18 parent-dir-writable. mkdir a 0777 parent + place an
#     actor binary inside it; loader MUST reject at resolve time even
#     though the binary file itself is mode 0755.
mkdir -p "$WORK/22"
mkdir -m 0777 "$WORK/22/ww-parent"
echo "ed5-actor" > "$WORK/22/ww-parent/aide"
chmod 0755 "$WORK/22/ww-parent/aide"
cat > "$WORK/22/profile.conf" <<EOF
actor aide = $WORK/22/ww-parent/aide

seal $WORK/22/ww-parent/aide full
seal $WORK/target.txt no-write actor=aide
EOF
run_dryrun "22-actor-parent-world-writable" "$WORK/22/profile.conf" expect_fail \
    "parent dir.*world-.*writable"

# 25: ME-8 §3.8 glob-in-actor-path. The loader MUST NOT expand globs;
#     the literal path '/tmp/parser-actor-glob-target-does-not-exist-*'
#     cannot be opened → fails resolve-time as for any missing actor
#     binary (fixture 09 equivalent). Asserts an attacker who can
#     create files in /tmp cannot smuggle themselves in via glob.
run_dryrun "25-glob-in-actor" "$DIR/25-glob-in-actor.conf" expect_fail \
    "actor globby: open .* No such file"

echo ""
echo "================================================================"
printf 'parser-actor: %d passed, %d failed\n' "$PASSED" "$FAILED"
if (( FAILED > 0 )); then
    for f in "${FAILS[@]}"; do
        printf '  - %s\n' "$f"
    done
    exit 1
fi
exit 0
