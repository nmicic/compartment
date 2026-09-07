#!/bin/bash
# Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
# SPDX-License-Identifier: Apache-2.0
#
# check-orphans.sh — fail when a test script is reachable from nothing.
#
# run_kernel_matrix.sh carried ~70 assertions and was invoked by no
# runner, no Makefile target and no CI job. It is not the only one this
# has happened to, and an orphaned suite is worse than a missing one: it
# reads as coverage in tests/README.md and in review, and it rots,
# because nothing ever runs it.
#
# A test script counts as reachable when it is
#   - in tests/scripts/rootless.d/ or tests/scripts/root.d/, which the two
#     runners discover by globbing, or
#   - named by the Makefile, by a CI workflow, or by another shell script
#     under tests/ or scripts/.
#
# Scope is this repository's own tests/. compartment-bpf/ has its own
# Makefile and its own conventions and is gated separately.
#
# Usage: scripts/check-orphans.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_DIR}" || exit 1

if git rev-parse --git-dir >/dev/null 2>&1; then
    mapfile -t candidates < <(git ls-files 'tests/**/*.sh' 'tests/*.sh' | sort)
else
    mapfile -t candidates < <(find tests -name '*.sh' -type f | sort)
fi

# Everything that can name a test script.
mapfile -t referrers < <(
    { echo "Makefile"
      ls .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null
      find tests scripts -name '*.sh' -type f 2>/dev/null
    } | sort -u
)

orphans=()
checked=0
for f in "${candidates[@]}"; do
    [ -f "${f}" ] || continue
    head -c2 "${f}" | grep -q '#!' || continue     # sourced libraries: not suites
    checked=$((checked + 1))

    case "${f}" in
        tests/scripts/rootless.d/*|tests/scripts/root.d/*) continue ;;
    esac

    base="$(basename "${f}")"
    found=0
    for r in "${referrers[@]}"; do
        [ "${r}" = "${f}" ] && continue            # a script naming itself
        [ -f "${r}" ] || continue
        if grep -q -F -- "${base}" "${r}"; then found=1; break; fi
    done
    [ "${found}" -eq 1 ] || orphans+=("${f}")
done

if [ "${#orphans[@]}" -gt 0 ]; then
    echo "check-orphans: ${#orphans[@]} test script(s) are reachable from no runner, target or workflow:"
    for o in "${orphans[@]}"; do echo "  ${o}"; done
    echo "check-orphans: wire each one into a Makefile target or a runner, or delete it."
    echo "check-orphans:   a suite nothing runs still reads as coverage in review."
    exit 1
fi

echo "check-orphans: ${checked} test scripts, all reachable"
exit 0
