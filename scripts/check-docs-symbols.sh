#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# check-docs-symbols.sh — every source symbol named in the
# compartment-bpf docs must exist in the sources.
#
# Four of the seven doc-vs-code count claims audited at the 1.4 gate were
# wrong in the shipped tree, and nothing anywhere compared a documented
# symbol against the code. This is the cheap half of the proposed
# check-docs gate (the other half — round-tripping fenced profile blocks
# — is check-howto-examples in compartment-bpf/Makefile): a hook,
# program, action or counter named in README.md, HOWTO.md or
# LIMITATIONS.md and absent from the sources is a documentation defect
# that a reader cannot tell from a real feature.
#
# Symbol classes gated:
#   comp_*   BPF program / link names
#   ao_*     observe-mode program names
#   DENY_*   audit action tokens
#   *_total  counters
#
# Usage: scripts/check-docs-symbols.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BPF_DIR="${REPO_DIR}/compartment-bpf"
cd "${REPO_DIR}" || exit 1

DOCS=("${BPF_DIR}/README.md" "${BPF_DIR}/HOWTO.md" "${BPF_DIR}/LIMITATIONS.md")
SOURCES=("${BPF_DIR}/compartment.bpf.c" "${BPF_DIR}/compartment-observe.bpf.c"
         "${BPF_DIR}/compartment-bpf.c" "${BPF_DIR}/compartment-observe.c"
         "${BPF_DIR}/compartment-abi.h")

for d in "${DOCS[@]}"; do
    [ -r "${d}" ] || { echo "check-docs-symbols: missing ${d}"; exit 1; }
done
present=()
for f in "${SOURCES[@]}"; do
    [ -r "${f}" ] && present+=("${f}")
done
if [ "${#present[@]}" -eq 0 ]; then
    echo "check-docs-symbols: no compartment-bpf sources found"
    exit 1
fi

# Comments are stripped first. A gate that greps raw C is satisfied by
# the token appearing in a comment — which is exactly how the ABI gate
# beside this one can be kept green while every real call site is
# deleted. compartment-bpf.c carries the literal
# "/* v0.8: was comp_bprm_check_security */", so without this the gate
# would certify a pre-v0.8 name that no longer exists anywhere.
HAYSTACK="$(mktemp)"
trap 'rm -f "${HAYSTACK}"' EXIT
awk '
{
    line = $0; out = ""
    while (length(line) > 0) {
        if (inblock) {
            p = index(line, "*/")
            if (p == 0) { line = ""; break }
            line = substr(line, p + 2); inblock = 0; continue
        }
        b = index(line, "/*"); l = index(line, "//")
        if (l > 0 && (b == 0 || l < b)) { out = out substr(line, 1, l - 1); line = ""; break }
        if (b > 0) { out = out substr(line, 1, b - 1); line = substr(line, b + 2); inblock = 1; continue }
        out = out line; line = ""
    }
    print out
}' "${present[@]}" > "${HAYSTACK}"

# Symbols named in the docs. Backticked or bare; the trailing `()` some
# rows use is stripped. `comp_` names that a row explicitly marks as
# absent from this version are still expected to exist somewhere in the
# sources, because every such row names the hook it is talking about.
mapfile -t symbols < <(
    grep -ohE '\b(comp_[a-z0-9_]+|ao_[a-z0-9_]+|DENY_[A-Z0-9_]+|[a-z][a-z0-9_]*_total)\b' "${DOCS[@]}" \
        | sort -u
)

missing=()
historical=0
for sym in "${symbols[@]}"; do
    if grep -qE "(^|[^a-zA-Z0-9_])${sym}([^a-zA-Z0-9_]|$)" "${HAYSTACK}"; then
        continue
    fi
    # A name the docs mention only to say it is gone is not a defect —
    # but every line that mentions it has to say so, or it reads as a
    # live symbol to anyone but the author.
    total_lines="$(grep -hE "(^|[^a-zA-Z0-9_])${sym}([^a-zA-Z0-9_]|$)" "${DOCS[@]}" | wc -l)"
    hist_lines="$(grep -hE "(^|[^a-zA-Z0-9_])${sym}([^a-zA-Z0-9_]|$)" "${DOCS[@]}" \
                  | grep -cE '(absent|removed|no longer|replaced|renamed|former|pre-v0\.[0-9]|used to)' || true)"
    if [ "${total_lines:-0}" -gt 0 ] && [ "${hist_lines:-0}" -eq "${total_lines}" ]; then
        historical=$((historical + 1))
        continue
    fi
    missing+=("${sym}")
done

if [ "${#missing[@]}" -gt 0 ]; then
    echo "check-docs-symbols: ${#missing[@]} symbol(s) named in the compartment-bpf docs do not exist in the sources:"
    for m in "${missing[@]}"; do
        echo "  ${m}"
        grep -nH -m1 -- "${m}" "${DOCS[@]}" 2>/dev/null | head -1 | sed 's/^/      /'
    done
    echo "check-docs-symbols: fix the doc, or the symbol."
    exit 1
fi

echo "check-docs-symbols: ${#symbols[@]} documented symbols, all present in the sources (${historical} named only as historical)"
exit 0
