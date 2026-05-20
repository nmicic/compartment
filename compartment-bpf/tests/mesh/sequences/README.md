# Mesh ME-21 sequence files

Per `EXEC-DOMAIN-MESH-DRAFT.md` §3.21. Each `*.seq` is sourced by the
ME-21 runner in `tests/mesh/run-mesh.sh` with the surrounding shell
scope (vars: `$WORK`, `$ME19_SECRET`, `$ME19_ESCAPE`, `$ME19_LEGIT`,
`$ME17_SEALED_TARGET`, `$ME18_ALIAS`, helpers `caller_path`,
`run_trial`).

Step rows call `me21_step <step_n> <caller> <op> <target> <expected> <intent>`
which executes the trial and emits a CSV row.

Sequences are hand-authored; state created in step N persists into
step N+1 within a sequence. Cross-sequence isolation comes from
each sequence sourcing on a clean (pre-loaded) profile — sequences
must not depend on fixtures created by earlier sequences.

The two-line header at the top of each file documents the sequence
id + one-line intent. The runner echoes these for the harness summary.
