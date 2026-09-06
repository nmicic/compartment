<!-- Copyright (c) 2026 Nenad Mićić <nenad@micic.be> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# `tests/scripts/root.d/` — discovered root-only suites

Every executable `*.sh` in this directory is run by
`tests/scripts/run_root_tests.sh` (`sudo make test-root`) as its own suite,
in glob (lexical) order, with the same PASS/FAIL accounting and exit-code
semantics as the rootless suites.

The runner **refuses to run as a non-root user** (exit 2). These scripts are
never reached by `make test` / `make test-integration`; put anything that
works unprivileged in `tests/scripts/rootless.d/` instead, so it runs on
every push.

```bash
sudo make test-root                     # build, then run every suite here
sudo ./tests/scripts/run_root_tests.sh  # same, without the build
```

## Contract

A script in this directory:

1. **Is independent.** It runs correctly on its own, in any order, and
   leaves nothing another script depends on.
2. **Is executable and has a shebang** (`#!/bin/bash`, mode 755). CI fails
   the build on a non-executable `*.sh`, and the runner reports a
   non-executable script here as a failed suite rather than skipping it.
3. **Prints one summary line** as its last output:

   ```
   SUMMARY <suite-name>: pass=<n> fail=<n> skip=<n>
   ```
4. **Exits non-zero on any failure**, 0 only when `fail=0`. A missing
   precondition (no user namespaces, no `newuidmap`, no cgroup v2 delegation)
   is a **skip**, not a failure.
5. **Cleans up everything it creates, including on failure.** This matters
   far more here than in `rootless.d`: unmount every mount, remove every
   jail directory, delete every cgroup, kill every process it started, and
   do it from an EXIT trap so a failed assertion still cleans up. A leaked
   mount namespace or a stray bind mount on `/` breaks the whole machine,
   not just the test run.
6. **Touches nothing outside its own scratch tree.** Build the jail under
   `mktemp -d`, never under a fixed path, and never modify host state
   (`/etc`, systemd units, sysctls, iptables) without restoring it.
7. **Asserts that the thing under test actually ran** — see rule 7 in
   `../rootless.d/README.md`.

## Helpers

`tests/scripts/lib/harness.sh` works here too; see
`../rootless.d/README.md` for the skeleton. `COMPARTMENT_FIXTURES` is
exported by the runner.
