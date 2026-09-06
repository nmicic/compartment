<!-- Copyright (c) 2026 Nenad Mićić <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# `tests/scripts/rootless.d/` — discovered rootless suites

Every executable `*.sh` in this directory is run by
`tests/scripts/run_all.sh` as its own suite, in glob (lexical) order, with
the same PASS/FAIL accounting and exit-code semantics as the hand-wired
suites. Nothing else needs to be edited to add a test: drop a script in,
`chmod 755`, done.

Use a numeric prefix (`10-`, `20-`, …) to make the order obvious. Ordering
must never be *required*: see rule 1.

## Contract

A script in this directory:

1. **Is independent.** It runs correctly on its own, in any order, and
   leaves nothing another script depends on. `./tests/scripts/rootless.d/NN-x.sh`
   must work as a standalone command.
2. **Runs unprivileged.** It must not need root and must not call `sudo`.
   Root-only checks belong in `tests/scripts/root.d/`.
3. **Is executable and has a shebang** (`#!/bin/bash`, mode 755). CI fails
   the build on a non-executable `*.sh`, and `run_all.sh` reports a
   non-executable script here as a failed suite rather than skipping it
   silently.
4. **Prints one summary line** as its last output:

   ```
   SUMMARY <suite-name>: pass=<n> fail=<n> skip=<n>
   ```

   `harness_summary <suite-name>` (see below) prints it for you.
5. **Exits non-zero on any failure**, 0 only when `fail=0`. A missing
   precondition the script cannot control (no Landlock, no `slirp4netns`,
   no network) is a **skip**, not a failure, and still exits 0.
6. **Cleans up everything it creates**, including on failure — register an
   EXIT trap, or use `harness_cleanup_add`.
7. **Asserts that the thing under test actually ran.** An assertion that
   passes because a probe never executed, or because the host already
   denied the operation, is worse than no assertion at all. Require a
   positive marker (`deny_probe` prints `PROBE_START op=<op> pid=<n>`),
   and compare exact errno values rather than "did not succeed".

## Helpers

`tests/scripts/lib/harness.sh` is optional but does the boring parts:

```bash
#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/scripts/lib/harness.sh
. "${SCRIPT_DIR}/../lib/harness.sh"

REPO_DIR="$(harness_repo_dir)"
harness_fixtures                 # sets FIXTURES, removed on exit
CU="${REPO_DIR}/compartment-user"

echo "=== my suite ==="
if "${CU}" --dry-run -- /bin/true >/dev/null 2>&1; then
    pass "dry-run works"
else
    fail "dry-run works"
fi

harness_summary "my-suite" || exit 1
```

It provides `pass`/`fail`/`skip`, `harness_summary`, `harness_repo_dir`,
`harness_fixtures` (sets `FIXTURES`), `harness_profile NAME.conf` (path of
a rendered test profile) and `harness_cleanup_add PATH`. Suites that source
it must not install their own EXIT trap.

## Environment

| Variable | Set by | Meaning |
|---|---|---|
| `COMPARTMENT_FIXTURES` | `run_all.sh` | Fixture root shared by the whole run. `harness_fixtures` reuses it when set and creates a private one otherwise. |
| `COMPARTMENT_FIXTURE_BASE` | caller | Directory the fixture root is created under. Default `${HOME}/.cache` — *not* `/tmp`, because the built-in `ai-agent` profile maps `/tmp` `rw` (W^X) so a probe there cannot be exec'd. |
