# Counters — catalogue + minimal-overhead telemetry/polling contract

The compartment-bpf security data plane keeps a small set of always-on, lossless
per-CPU counters. They are the **minimal telemetry** surface: an operator
reads them out-of-band via `compartment-bpf --stats` with
effectively zero hot-path cost. This file is the authoritative catalogue; the
`telemetry-smoke.sh` test asserts the implementation, the `--stats` table, and
this catalogue stay in parity (drift fails CI).

## Polling contract (what a poller relies on)

- **Read primitive:** `compartment-bpf --stats` — read-only. Opens the pinned
  counter maps (`/sys/fs/bpf/compartment/maps/<name>`), sums per-CPU slots, prints
  one line: `[stats] name=value name=value ...` (stable `name=value`, space-sep).
- **Minimal overhead:** counters are `BPF_MAP_TYPE_PERCPU_ARRAY[1]` bumped with a
  non-atomic per-CPU `(*v)++` on the hot path (no cross-core atomics, no lock). The
  cost of *reading* is entirely out-of-band (a userspace map read), so polling does
  not perturb enforcement and does not add hot-path cost. Poll on whatever interval
  you like.
- **Lossless aggregate:** the *count* is exact even when the audit ringbuf drops
  detail events under flood — `deny_total` stays exact while `audit_drop_total`
  quantifies the lost detail. This is what lets a consumer detect event-loss gaps.
- **Reset semantics:** counters live in the pinned maps; they persist across daemon
  exit (pins keep them alive) and reset to zero only on `--unpin` + fresh `--pin`.
  There is no in-place reset command (restart is the reset).
- **Generic model:** each counter is one cell of `(object, operation, outcome)`
  (see OBSERVABILITY model). Future counters slot into the same shape; add the map,
  add it to the `--stats` table, and add a row here — `telemetry-smoke.sh` enforces
  all three.

## Catalogue (12 counters)

All are `BPF_MAP_TYPE_PERCPU_ARRAY` (1 × u64), pinned at
`/sys/fs/bpf/compartment/maps/<name>`, surfaced by `--stats`.

| name | (object, operation, outcome) | meaning |
|------|------------------------------|---------|
| `deny_total` | (inode, *, deny) | Every enforcement DENY returned by a compartment LSM hook, regardless of the specific errno (`-EACCES` for file/seal denials, `-EPERM` for the prctl/ptrace hooks). Incremented **before** the ringbuf reserve (decision counter). |
| `audit_drop_total` | (audit, reserve, drop) | `bpf_ringbuf_reserve()` returned NULL after a deny was already counted — the deny is enforced but its audit detail was lost. |
| `actor_mismatch_total` | (inode, write, deny) | A write to an actor-scoped seal by a caller binary that is not the allow-listed actor (dev,ino) → deny. |
| `strict_launch_missing_total` | (strict_launch_marker, exec, deny) | A strict actor was launched without the required launch marker → deny. |
| `strict_launch_allowed_total` | (strict_launch_marker, exec, allow) | A strict actor launch was permitted (valid marker present). |
| `marker_set_total` | (strict_launch_marker, set, commit) | A strict-launch marker was set for a task. |
| `marker_clear_foreign_exec_total` | (strict_launch_marker, exec, clear) | Marker cleared because a foreign (non-actor) binary exec'd over the task. |
| `marker_copy_fork_total` | (strict_launch_marker, fork, copy) | Marker copied to a child across fork. |
| `marker_stale_generation_total` | (strict_launch_marker, verify, deny) | Marker rejected because its policy generation was stale (policy reloaded). |
| `prctl_set_mm_exe_file_denied_total` | (task, prctl, deny) | Any `PR_SET_MM` prctl while a strict policy is loaded → deny. The hook gates the **entire `PR_SET_MM` sub-op family** (EXE_FILE, MAP, AUXV, …), not just `PR_SET_MM_EXE_FILE` — broadened to close the `PR_SET_MM_MAP` exe_file-overwrite bypass. The counter name is retained for operator continuity; it names the protected resource (the exe_file pointer). |
| `ptrace_access_denied_total` | (task, ptrace, deny) | ptrace access to a protected actor → deny. |
| `ptrace_traceme_denied_total` | (task, ptrace_traceme, deny) | `PTRACE_TRACEME` by a protected actor → deny. |

(Exact hook sites: see `emit_audit()` and the per-hook increments in
`compartment.bpf.c`. The `(object, operation, outcome)` column is the
catalogue's mapping into the generic telemetry model, not a wire format.)

## Test coverage matrix (which test asserts each counter's accuracy)

Every counter has an **exact-`==` delta** accuracy assertion. The 3 inode counters
live in `counter-smoke.sh`; the 9 exec-domain counters in `strict-launch/run.sh`
(per-witness `name=val` exact deltas). All three suites are gated by `make check`
(`smoke-counters`, `check-strict-launch`, `smoke-telemetry`).

| counter | accuracy test (exact delta) |
|---------|-----------------------------|
| `deny_total` | counter-smoke T4b.1 (=1000), T4b.2 (=5000); strict-launch SL-10 (=200) |
| `audit_drop_total` | counter-smoke T4b.2 (drop under ringbuf pressure, deny still exact) |
| `actor_mismatch_total` | counter-smoke T4b.4 (=500) |
| `strict_launch_missing_total` | strict-launch SL-2/3/6/7b (miss `+1` per direct/foreign attempt) |
| `strict_launch_allowed_total` | strict-launch SL-1/4 (allow `+2` per sanctioned launch) |
| `marker_set_total` | strict-launch SL-1/3/4/5 (`=1`) |
| `marker_clear_foreign_exec_total` | strict-launch SL-3/5 (`=1`) |
| `marker_copy_fork_total` | strict-launch SL-4 (`=1`) |
| `marker_stale_generation_total` | strict-launch SL-9 (`=0`, **negative-only**: v0.4 is fresh-load-only — the loader never bumps `policy_state.generation` in place, so the positive/stale path is unreachable by design; SL-9 asserts it never spuriously fires) |
| `prctl_set_mm_exe_file_denied_total` | strict-launch SL-7a (PR_SET_MM_EXE_FILE `=1`), SL-7c (PR_SET_MM_MAP `=1`) |
| `ptrace_access_denied_total` | strict-launch SL-8 (`+1`; falls back to KNOWN-GAP only if the kernel surfaces no ptrace event — on 7.0 it fires) |
| `ptrace_traceme_denied_total` | strict-launch SL-8c (LSM-direct `+1`) |
| *(all 12)* | telemetry-smoke TM-1 parity / TM-2 PERCPU type / TM-3 at-rest stability / TM-4 non-perturbing minimal-overhead polling / TM-5 catalogue coverage |

VM-verified 2026-06-06: counter-smoke 4/4, strict-launch 15/15, telemetry-smoke 7/7.

## Run

`make smoke-counters` (3 inode counters), `make check-strict-launch` (9 exec-domain
counters), `make smoke-telemetry` (parity/overhead) — all included in `make check`.
Run on the VM (require root + bpf in the active LSM list).
