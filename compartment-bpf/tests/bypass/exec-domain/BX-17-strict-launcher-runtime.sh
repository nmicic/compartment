#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# tests/bypass/exec-domain/BX-17-strict-launcher-runtime.sh
#
# GAP-H-2 (coverage audit 2026-05-16): `strict_validate_launchers`
# runtime-error returns had no in-tree witnesses. Three classes are
# pinned here, plus the per-actor sanity guard A2-P2-2:
#
#   W1 — dynamically-linked launcher:
#        elf_has_interp() trips on PT_INTERP and the loader emits
#        "dynamically linked (PT_INTERP present); refusing".
#   W2 — launcher not sealed `full` in the profile:
#        the seal-scan finds no lmatch and the loader emits
#        "launcher ... is not sealed `full`".
#   W3 — target binary not sealed at its declared path:
#        enforce_actor_binaries_sealed (which runs immediately before
#        strict_validate_launchers and shares its `required` flag set)
#        emits "is not sealed at its declared path"; strict_validate_launchers'
#        target_sealed_full check is defense-in-depth for the same class.
#   W4 — launcher and target share (dev,ino):
#        A2-P2-2 — the strict-launch gate is hollow if the launcher exec
#        and the actor exec are the same file. The loader emits
#        "launcher ... and target ... resolve to the same (dev=..., ino=...)".
#
# All four are exercised under `--dry-run` so the witnesses are
# self-contained (no BPF attach, no daemon supervision). The runtime
# rejection paths fire identically under `--pin` and `--dry-run`.
set -u
BYPASS_NAME="BX-17-strict-launcher-runtime"
. "$(dirname "$0")/../lib-bypass.sh"
. "$(dirname "$0")/lib-exec-domain.sh"

bypass_check_env
command -v gcc >/dev/null 2>&1 || bypass_skip "gcc not in PATH (need it to build static + dyn stubs)"

TMP=$(mktemp -d /tmp/bypass.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

# Stub launcher source. Tiny enough for both -static and dynamic-link.
cat > "$TMP/stub.c" <<'EOF'
int main(int argc, char **argv) { (void)argc; (void)argv; return 0; }
EOF

DYN_LAUNCHER="$TMP/launcher-dyn"
STATIC_LAUNCHER="$TMP/launcher-static"

# Default gcc output is dynamically linked → PT_INTERP set, perfect for W1.
gcc -O0 -o "$DYN_LAUNCHER" "$TMP/stub.c" 2>"$TMP/gcc-dyn.err" \
    || { cat "$TMP/gcc-dyn.err" >&2; bypass_die "could not build dyn launcher"; }
chmod 0755 "$DYN_LAUNCHER"

# Static launcher needed by W2/W3 — without -static, those witnesses
# would trip the dyn-link check first and we wouldn't isolate the
# seal-list defects we're pinning. Static glibc is optional on some
# distros (libc6-dev-* or musl-tools provides it); skip cleanly.
if ! gcc -O0 -static -o "$STATIC_LAUNCHER" "$TMP/stub.c" 2>"$TMP/gcc-static.err"; then
    cat "$TMP/gcc-static.err" >&2
    bypass_skip "static glibc not available; cannot build static launcher (install libc6-dev / musl-tools)"
fi
chmod 0755 "$STATIC_LAUNCHER"

# Actor target binary (copy of sealprobe — has distinct inode + is executable).
ACTOR_TARGET=$(ed_create_actor target)

# ----- W1: dynamically-linked launcher → PT_INTERP refuse -----
cat > "$TMP/w1.conf" <<EOF
actor-strict st = $ACTOR_TARGET launcher=$DYN_LAUNCHER
seal $DYN_LAUNCHER no-write,no-unlink,no-rename,no-chmod
seal $ACTOR_TARGET no-write,no-unlink,no-rename,no-chmod
EOF
OUT1="$TMP/w1.err"
"$DAEMON" --dry-run "$TMP/w1.conf" >"$OUT1" 2>&1
rc1=$?
if [ "$rc1" -eq 0 ]; then
    cat "$OUT1" >&2
    bypass_fail "W1: loader accepted dynamically-linked launcher (H-2 dyn-link gap)"
fi
if ! grep -q "dynamically linked" "$OUT1" || ! grep -q "PT_INTERP" "$OUT1"; then
    cat "$OUT1" >&2
    bypass_fail "W1: rejected but no 'dynamically linked / PT_INTERP' diagnostic"
fi
if ! grep -q "refusing" "$OUT1"; then
    cat "$OUT1" >&2
    bypass_fail "W1: diagnostic missing 'refusing' verb"
fi

# ----- W2: launcher not sealed `full` -----
# Target IS sealed (so enforce_actor_binaries_sealed passes), launcher
# omitted from seal list → strict_validate_launchers' lmatch scan fails.
cat > "$TMP/w2.conf" <<EOF
actor-strict st = $ACTOR_TARGET launcher=$STATIC_LAUNCHER
seal $ACTOR_TARGET no-write,no-unlink,no-rename,no-chmod
EOF
OUT2="$TMP/w2.err"
"$DAEMON" --dry-run "$TMP/w2.conf" >"$OUT2" 2>&1
rc2=$?
if [ "$rc2" -eq 0 ]; then
    cat "$OUT2" >&2
    bypass_fail "W2: loader accepted profile with unsealed launcher (H-2 unsealed-launcher gap)"
fi
if ! grep -q "launcher .* is not sealed" "$OUT2"; then
    cat "$OUT2" >&2
    bypass_fail "W2: rejected but no 'launcher … is not sealed' diagnostic"
fi
# Match the actor name so a regression renaming the diagnostic doesn't
# silently slide past the substring.
if ! grep -q "actor-strict st:" "$OUT2"; then
    cat "$OUT2" >&2
    bypass_fail "W2: diagnostic missing 'actor-strict st:' prefix"
fi

# ----- W3: target not sealed at its declared path -----
# Launcher is sealed `full`; target omitted from seal list. Loader hits
# enforce_actor_binaries_sealed first ("not sealed at its declared path")
# which is the user-facing "target not sealed" message. (The
# strict_validate_launchers target_sealed_full check is the second-line
# guard — it is rendered unreachable here only because enforce runs
# first; both gates close the same hole.)
cat > "$TMP/w3.conf" <<EOF
actor-strict st = $ACTOR_TARGET launcher=$STATIC_LAUNCHER
seal $STATIC_LAUNCHER no-write,no-unlink,no-rename,no-chmod
EOF
OUT3="$TMP/w3.err"
"$DAEMON" --dry-run "$TMP/w3.conf" >"$OUT3" 2>&1
rc3=$?
if [ "$rc3" -eq 0 ]; then
    cat "$OUT3" >&2
    bypass_fail "W3: loader accepted profile with unsealed target (H-2 unsealed-target gap)"
fi
if ! grep -Eq "(target .* is not sealed|is not sealed at its declared path)" "$OUT3"; then
    cat "$OUT3" >&2
    bypass_fail "W3: rejected but no 'target/declared-path not sealed' diagnostic"
fi
if ! grep -q "$ACTOR_TARGET" "$OUT3"; then
    cat "$OUT3" >&2
    bypass_fail "W3: diagnostic does not name the unsealed target path"
fi

# ----- W4: launcher and target share (dev,ino) — A2-P2-2 -----
# Hardlink the STATIC launcher to a second path and declare it as the
# actor target. Both paths resolve to the same inode → strict_validate_
# launchers' A2-P2-2 guard fires. We use the static launcher (not the
# sealprobe-derived ACTOR_TARGET) so the dyn-link check at line 1176
# passes first; otherwise the dyn-link diagnostic would fire before
# the launcher==target check we want to witness.
STATIC_TARGET="$TMP/target-hardlinked-to-launcher"
ln "$STATIC_LAUNCHER" "$STATIC_TARGET" \
    || bypass_die "W4 setup: ln $STATIC_LAUNCHER $STATIC_TARGET failed"
cat > "$TMP/w4.conf" <<EOF
actor-strict st = $STATIC_TARGET launcher=$STATIC_LAUNCHER
seal $STATIC_TARGET no-write,no-unlink,no-rename,no-chmod
seal $STATIC_LAUNCHER no-write,no-unlink,no-rename,no-chmod
EOF
OUT4="$TMP/w4.err"
"$DAEMON" --dry-run "$TMP/w4.conf" >"$OUT4" 2>&1
rc4=$?
if [ "$rc4" -eq 0 ]; then
    cat "$OUT4" >&2
    bypass_fail "W4: loader accepted launcher==target same-inode (A2-P2-2 gap)"
fi
if ! grep -q "resolve to the same" "$OUT4"; then
    cat "$OUT4" >&2
    bypass_fail "W4: rejected but no 'resolve to the same (dev,ino)' diagnostic"
fi
if ! grep -q "distinct binary" "$OUT4"; then
    cat "$OUT4" >&2
    bypass_fail "W4: diagnostic missing 'distinct binary' verbiage"
fi

bypass_pass "strict_validate_launchers rejects: dyn-linked launcher (W1), unsealed launcher (W2), unsealed target (W3), launcher==target same-inode (W4)"
