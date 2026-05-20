#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# compartment-actor-build — Option B generator.
# Emits a statically-linked per-actor wrapper with the target path baked in.
# Argv-substitution / env-injection / argv[0] tricks cannot redirect the
# target because TARGET_PATH is a compile-time constant.
#
# Usage:
#   compartment-actor-build --name aide --cmd /usr/sbin/aide \
#       [--allow-env LANG --allow-env TZ ...] \
#       --out /usr/libexec/compartment-actors/aide
#
# Refuses:
#   - symlink leaf targets, non-regular targets, 0-byte targets,
#     world-writable targets, non-executable targets
#   - dangerous env names in --allow-env (LD_PRELOAD etc.)
#
# Output binary is statically linked (mandatory).

set -eu

# Pin PATH + umask so cc / file / chmod /
# mktemp resolve through canonical system dirs only, and so the
# generated wrapper binary cannot be created world-writable.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 022

PROG="compartment-actor-build"
NAME=""
CMD=""
OUT=""
ALLOW_ENV=""
WRAPPER_SRC="${WRAPPER_SRC:-tools/compartment-actor-wrapper.c}"
CC="${CC:-cc}"

die() { echo "$PROG: FATAL: $*" >&2; exit 2; }
usage() {
    cat >&2 <<EOF
Usage: $PROG --name NAME --cmd /abs/target --out /abs/out [opts]

Options:
  --name NAME              Actor name (logged).
  --cmd  /abs/target       Absolute path to the real actor binary.
  --out  /abs/wrapper      Where the generated wrapper is installed.
  --allow-env NAME         Add NAME to the env allowlist (repeatable).
                           Refuses dangerous names (LD_PRELOAD etc.).
  --wrapper-src PATH       Override wrapper C source path.
  --cc COMPILER            Override C compiler (default: cc).
  -h, --help               Show this help.
EOF
}

# A6-P2-2: derive DANGEROUS from the authoritative C header so the shell
# pre-check and the wrapper's runtime scrub cannot drift. allow_add() in
# the wrapper re-checks against the same header, so this is defense in
# depth, but a divergent list is the exact HIGH-6 class. Default resolves
# next to this script so callers can run from any cwd; override via the
# DANGEROUS_HEADER env var.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DANGEROUS_HEADER="${DANGEROUS_HEADER:-$SCRIPT_DIR/compartment-dangerous-env.h}"
[ -f "$DANGEROUS_HEADER" ] || die "dangerous-env header not found at $DANGEROUS_HEADER (refusing fail-open)"
# grep -oE catches every X("NAME") on a line; sed's `.*X(...)` is greedy
# and only matches the LAST X() on a multi-X line (lost LD_PRELOAD etc.,
# regressed in p2-cleanup A4; caught by tests/actor-wrapper T9c).
DANGEROUS=$(grep -oE 'X\("[A-Za-z0-9_]+"\)' "$DANGEROUS_HEADER" \
            | sed 's/^X("\(.*\)")$/\1/' \
            | tr '\n' ' ')
[ -n "$DANGEROUS" ] || die "$DANGEROUS_HEADER parsed to empty list (refusing fail-open)"
case " $DANGEROUS " in
    *' LD_PRELOAD '*) : ;;
    *) die "$DANGEROUS_HEADER parsed list missing LD_PRELOAD (extractor regression)" ;;
esac

# The heredoc below interpolates $CMD / $NAME /
# $ALLOW_ENV values into a C string literal context AND an `#include`
# directive. An attacker (or a careless caller) who passes
# --cmd '/usr/sbin/aide"; system("rm -rf /"); char dummy[]="' would
# inject arbitrary C at build time. validate_id() refuses any input
# containing characters outside the well-formed set [A-Za-z0-9_./-].
# Apply to --name, --cmd, --out (the C string-literal slots) and to
# every --allow-env name (which gets stringified into the allowlist
# array AND must additionally have no `=` / whitespace so the
# DANGEROUS-name check below sees the bare name, not NAME=value).
validate_id() {
    case "$1" in
        '' )
            die "empty value for $2" ;;
        *[!A-Za-z0-9_./-]*)
            die "invalid $2 '$1': only [A-Za-z0-9_./-] allowed" ;;
    esac
}
validate_env_name() {
    case "$1" in
        '' )
            die "empty --allow-env name" ;;
        *[!A-Za-z0-9_]* | [0-9]*)
            die "invalid --allow-env '$1': env names must match [A-Za-z_][A-Za-z0-9_]*" ;;
    esac
    # Defence in depth — env names cannot contain `=` or whitespace by
    # POSIX environ definition. The first case above already catches
    # both, but spell out the intent so a future regex relaxation does
    # not silently re-open the gap.
    case "$1" in
        *=*|*' '*|*'	'*)
            die "invalid --allow-env '$1': contains '=' or whitespace" ;;
    esac
}

while [ $# -gt 0 ]; do
    case "$1" in
        --name)         NAME="$2"; shift 2 ;;
        --cmd)          CMD="$2";  shift 2 ;;
        --out)          OUT="$2";  shift 2 ;;
        --allow-env)
            validate_env_name "$2"
            for d in $DANGEROUS; do
                [ "$2" = "$d" ] && die "--allow-env $2 refused (dangerous)"
            done
            ALLOW_ENV="$ALLOW_ENV $2"; shift 2 ;;
        --wrapper-src)  WRAPPER_SRC="$2"; shift 2 ;;
        --cc)           CC="$2"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *)              die "unknown option: $1 (use --help)" ;;
    esac
done

[ -n "$NAME" ] || die "--name required"
[ -n "$CMD"  ] || die "--cmd required"
[ -n "$OUT"  ] || die "--out required"
# Refuse any character outside the safe set
# BEFORE the values land in the C heredoc and the absolute-path check.
validate_id "$NAME" --name
validate_id "$CMD"  --cmd
validate_id "$OUT"  --out
case "$CMD" in /*) ;; *) die "--cmd must be absolute, got: $CMD" ;; esac
case "$OUT" in /*) ;; *) die "--out must be absolute, got: $OUT" ;; esac
[ -f "$WRAPPER_SRC" ] || die "wrapper source not found: $WRAPPER_SRC"
# Resolve WRAPPER_SRC to an absolute path so the generated stub's #include
# works regardless of where the temp .c file lives.
case "$WRAPPER_SRC" in
    /*) ;;
    *) WRAPPER_SRC="$(cd "$(dirname "$WRAPPER_SRC")" && pwd)/$(basename "$WRAPPER_SRC")" ;;
esac

# Refuse symlink / non-regular / 0-byte / world-writable / non-exec targets.
if [ -L "$CMD" ]; then die "target $CMD is a symlink — refusing"; fi
[ -f "$CMD" ] || die "target $CMD is not a regular file"
[ -s "$CMD" ] || die "target $CMD is 0 bytes"
[ -x "$CMD" ] || die "target $CMD is not executable"
# World-writable check (POSIX shell, no GNU stat assumed).
perms=$(ls -ld "$CMD" | awk '{print $1}')
case "$perms" in
    *w?-*|*-w?*)
        # naive — fall back to stat if available.
        if command -v stat >/dev/null 2>&1; then
            mode=$(stat -c '%a' "$CMD" 2>/dev/null || stat -f '%Lp' "$CMD")
            # last digit & 2 != 0 means world-writable.
            last=${mode#${mode%?}}
            case "$last" in
                2|3|6|7)
                    die "target $CMD is world-writable (mode=$mode)" ;;
            esac
        fi
        ;;
esac

# Build allow-env macro: { "NAME1", "NAME2", ..., NULL }
ALLOW_MACRO="{"
for n in $ALLOW_ENV; do
    ALLOW_MACRO="$ALLOW_MACRO \"$n\","
done
ALLOW_MACRO="$ALLOW_MACRO NULL }"

# Compile with target baked in. Static link is mandatory.
TMPC="$(mktemp --suffix=.c)"
cat > "$TMPC" <<EOF
/* generated wrapper stub — compiles the canonical wrapper with config. */
#define WRAPPER_GENERATED 1
#define TARGET_PATH "$CMD"
#define ACTOR_NAME  "$NAME"
#define WRAPPER_GENERATED_ALLOW_ENV_LIST $ALLOW_MACRO
#include "$WRAPPER_SRC"
EOF

echo "$PROG: building static wrapper for actor='$NAME' target='$CMD' -> '$OUT'"
"$CC" -Wall -Wextra -O2 -static -o "$OUT" "$TMPC" || {
    rm -f "$TMPC"
    die "compile failed"
}
rm -f "$TMPC"

# A6-P2-3: assert the output is actually statically linked. `cc -static`
# silently degrades to dynamic if the static C runtime is missing on the
# host (e.g. glibc-static not installed). A dynamic wrapper re-opens the
# LD_PRELOAD class the wrapper was created to close, so refuse to install
# a non-static binary fail-closed.
FILE_OUT=$(file "$OUT" 2>/dev/null || true)
echo "$FILE_OUT"
case "$FILE_OUT" in
    *"statically linked"*) ;;
    *) die "wrapper binary $OUT is not statically linked: $FILE_OUT" ;;
esac
chmod 0755 "$OUT" || die "chmod $OUT failed"
echo "$PROG: wrote $OUT"
