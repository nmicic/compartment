# Results — counter longevity soak + enforcement overhead

VM: Resolute, kernel 7.0.0-22. Date: 2026-06-06. Both runs read-only (no data-plane
change). Harnesses: `tests/stability/counter-longevity.sh` (`make check-counter-longevity`)
and `tests/bench/actor-overhead.sh` (`make bench-overhead`).

## 1. Counter longevity soak — 10,000 iterations: 9/9 PASS

Sustained provocation of every counter under one long-lived daemon (Phase A) +
repeated provoker suites (Phase B), watching for always-0/stuck/wrapped counters and
leaks.

| check | result |
|-------|--------|
| CL-A1 no counter decreased across 10,000 iters | **PASS** (no wrap/reset/corruption) |
| CL-A2 deny_total + actor_mismatch_total grew every iter | **PASS** (not stuck) |
| CL-A3 daemon RSS flat under sustained load | **PASS** — first=5716 kB, last=5716 kB, **Δ=0 kB** |
| CL-B1 counter-smoke green across 5 repeats | **PASS** (5/5) |
| CL-B2 strict-launch green across 5 repeats | **PASS** (5/5; exec-domain deltas held) |
| CL-COV all 10 deterministic counters provoked >0 | **PASS** (no always-0 / dead counter) |
| CL-DROP audit_drop_total provoked under ringbuf pressure | **PASS** (>0) |
| T-STAB-1 taint unchanged | **PASS** (0) |
| T-STAB-1 dmesg | **PASS** (no BUG/Oops/WARNING/hung_task/RCU stall) |

Volume / monotonicity over the run:
- `deny_total`: **300 → 3,000,000** — exactly 300/iter, strictly monotonic (no wrap, no
  stuck, no reset).
- `actor_mismatch_total`: 100/iter → 1,000,000.
- **RSS: a single distinct value (5716 kB) across all 10,000 iters → zero leak** under
  ~3M denied writes + ~1M actor-mismatch denials.
- `marker_stale_generation_total`: 0 (negative-only by design — v0.4 fresh-load-only).

Conclusion: counters are exact and leak/wrap/stuck-free under sustained real-life load;
no dead (always-0) counter; the daemon does not leak.

Observation (not a defect): at this volume the daemon's always-on per-deny audit
logging is I/O-heavy (~3M log lines), which slowed iteration rate. This reinforces the
architecture's deny-as-signal + on-demand/bounded telemetry stance — full always-on
deny logging is not the steady state you want at scale; counters (lossless aggregate)
+ on-demand detail is.

## 2. Enforcement overhead — 3 %

Representative actor workload (4000 `open(write)+open(read)` cycles + 400 `/bin/true`
exec — the operations compartment's LSM hooks intercept), timed WITH compartment
enforcing (daemon pinned, hooks on the ALLOW hot path) vs WITHOUT (no daemon), median
of 7 reps. The A-vs-B delta isolates the per-syscall LSM-hook cost (shell overhead
cancels — identical workload both modes).

| | time |
|---|---|
| baseline (no compartment) | 542 ms |
| with compartment (enforcing) | 559 ms |
| delta | 17 ms |
| **overhead** | **3 %** |

PASS (≤ 60 % soft gate). For a file-I/O + exec-heavy workload, kernel enforcement costs
~3 % wall-time. (Complements `bench-runner.sh`'s per-op MODE-A/MODE-B micro-rows with
the single headline number.)

Caveats: single-VM, single workload shape; numbers are illustrative, not a spec. Re-run
`make bench-overhead` per host/kernel; crank `BENCH_OVERHEAD_OPS/EXECS/REPS` for a
heavier sample. An actor-write (actor-check hot path) variant is a tracked follow-up.
