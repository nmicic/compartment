#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# check-shell-bpf.sh — shellcheck over compartment-bpf/, against a
# tracked baseline.
#
# check-shell deliberately excludes compartment-bpf/, so the largest
# body of shell in the project — 39 bypass witnesses, a 3000-line mesh
# runner, the stability harness — has never been linted by any gate. It
# has 94 findings at -S warning today, and fixing them all at a release
# gate would mean touching every one of those files.
#
# So: a baseline of (file, code) pairs, without line numbers, so ordinary
# edits do not churn it. A NEW pair fails. The count can only go down —
# clear an entry and delete its line in the same commit.
#
# Usage: scripts/check-shell-bpf.sh [--regenerate]

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_DIR}" || exit 1
BASELINE="scripts/shellcheck-bpf-baseline.txt"

command -v shellcheck >/dev/null 2>&1 || {
    echo "check-shell-bpf: shellcheck not installed (apt install shellcheck)"
    exit 1
}

if git rev-parse --git-dir >/dev/null 2>&1; then
    mapfile -t files < <(git ls-files 'compartment-bpf/*.sh' 'compartment-bpf/**/*.sh' | sort)
else
    mapfile -t files < <(find compartment-bpf -name '*.sh' -type f | sort)
fi
[ "${#files[@]}" -gt 0 ] || { echo "check-shell-bpf: no shell files found"; exit 1; }

current="$(mktemp)"
trap 'rm -f "${current}"' EXIT
shellcheck -S warning -f gcc "${files[@]}" 2>/dev/null \
    | sed -E 's/^([^:]+):[0-9]+:[0-9]+: [a-z]+: .*\[(SC[0-9]+)\]$/\1 \2/' \
    | grep -E '^[^ ]+ SC[0-9]+$' | sort -u > "${current}"

if [ "${1:-}" = "--regenerate" ]; then
    {
        echo "# scripts/shellcheck-bpf-baseline.txt"
        echo "#"
        echo "# One '<file> <SCcode>' pair per known shellcheck -S warning finding"
        echo "# under compartment-bpf/. Line numbers are deliberately absent so an"
        echo "# ordinary edit does not churn this file. A pair that is not listed"
        echo "# here fails check-shell-bpf: the list may shrink, never grow."
        echo "#"
        echo "# Regenerate ONLY to remove entries: scripts/check-shell-bpf.sh --regenerate"
        cat "${current}"
    } > "${BASELINE}"
    echo "check-shell-bpf: baseline regenerated ($(grep -cvE '^#' "${BASELINE}") entries)"
    exit 0
fi

[ -f "${BASELINE}" ] || { echo "check-shell-bpf: ${BASELINE} is missing"; exit 1; }

known="$(mktemp)"
newfind="$(mktemp)"
gone="$(mktemp)"
trap 'rm -f "${current}" "${known}" "${newfind}" "${gone}"' EXIT
grep -vE '^[[:space:]]*(#|$)' "${BASELINE}" | sort -u > "${known}"
comm -13 "${known}" "${current}" > "${newfind}"
comm -23 "${known}" "${current}" > "${gone}"

rc=0
if [ -s "${newfind}" ]; then
    echo "check-shell-bpf: $(wc -l < "${newfind}") new shellcheck finding(s) under compartment-bpf/:"
    sed 's/^/  /' "${newfind}"
    echo "check-shell-bpf: fix them, or (if genuinely unavoidable) add a"
    echo "check-shell-bpf:   'shellcheck disable=' next to the line, with a reason."
    rc=1
fi
if [ -s "${gone}" ]; then
    echo "check-shell-bpf: $(wc -l < "${gone}") baseline entry/entries no longer occur — remove them:"
    sed 's/^/  /' "${gone}"
    echo "check-shell-bpf: the baseline is a ratchet; a stale entry hides a regression."
    rc=1
fi
[ "${rc}" -eq 0 ] && \
    echo "check-shell-bpf: ${#files[@]} files, $(wc -l < "${current}") known findings, no new ones"
exit "${rc}"
