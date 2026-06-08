# Concurrency scaling of enforcement — RESOLVED (2026-06-07)

> Resolves the previously-INCONCLUSIVE "parallel-load concurrency cliff"
> (2026-06-07). Verdict: **no concurrency cliff exists.** The earlier `>100s`
> stall was an environment/measurement artifact (stale stacked LSM programs from
> improper teardown), not a property of compartment's enforcement.

## The original symptom

While stress-testing option A (deny→candidate-rule) under a deny-storm, a shell
micro-benchmark — *20 subshell workers × 100 `open` cycles* (2000 ops) — appeared
to **time out >100s** with a daemon attached, vs ~58ms with no daemon. It seemed
to reproduce on the ALLOW path (no audit emit). On a shared **2-CPU** VM, with
ad-hoc ssh one-liners, I could not distinguish a real cliff from an artifact, so
it was flagged UNRESOLVED rather than over-claimed.

A `>100s` time for a mere 2000 ops is not load-proportional — it is a **stall**,
not a "cliff". That was the tell.

## Clean re-measurement (this run)

All three runs use a **verified-clean single enforcement set**: `--unpin` first
(`lsm_links` back to baseline), then exactly one `--pin` (link-delta = 21 = one
set), workload file **unsealed** → ALLOW hot path.

### 1. `file_open` hot path — threaded C, zero fork/exec (`open-concurrency.c`)

N pthreads, each `open()/close()` the same file in a tight loop. Isolates the
LSM `file_open` hook from all shell/fork noise. `make bench-concurrency`.

| threads | OFF wall | ON wall | overhead |
|--------:|---------:|--------:|---------:|
| 1  | 479 ms  | 472 ms  | −1% |
| 2  | 473 ms  | 499 ms  | +5% |
| 4  | 988 ms  | 984 ms  |  0% |
| 8  | 2254 ms | 2027 ms | −10% |
| 16 | 3921 ms | 3960 ms |  0% |

3.2M opens across 16 threads (8× oversubscribed on 2 CPU): **0% worst-case
overhead, flat scaling.** The `file_open` path does not serialize.

### 2. `exec`/`bprm` path — parallel exec storm

8 workers × 200 `/bin/true` execs (1600 parallel execs): **619 ms OFF vs 619 ms
ON.** The exec/bprm hook does not serialize under concurrency either.

### 3. The original shell pattern, against a clean daemon

20 workers × 100 shell open-cycles (the exact confounded pattern): **1083 ms OFF
vs 1191 ms ON (~10%)** — and critically **no stall**. The `>100s` does not
reproduce.

## Root cause of the original stall

Stale **stacked LSM programs**. Pinned LSM links survive `pkill` — only `--unpin`
sweeps them (one clean daemon legitimately attaches 21 links; baseline→22 on pin,
→baseline on teardown). During the earlier ad-hoc session, repeated
pin / pkill / re-pin without `--unpin` left multiple enforcement sets stacked on
every hook, so each syscall ran through many BPF programs — amplified on a 2-CPU
box also running the daemon poll loop. Once teardown is correct (`--unpin`), the
artifact is gone.

## Verdict

- **No concurrency cliff** on the ALLOW (`file_open`), exec (`bprm`), or shell
  paths with a clean single enforcement set.
- Combined with the serial evidence — `bench-overhead` 3%, 10K soak leak-free
  over 3M denies — compartment's enforcement **scales cleanly under parallel
  load**.
- **A-under-stress is acceptable → option C (core-gated dormant debug ring) is
  PARKED** (the user's gate: "test A under stress, if acceptable then C can be
  parked") — a core-gated dormant debug ring stays a future option for if/when
  the per-deny ring-reserve cost ever justifies it.
- **Operational lesson (already known, now load-bearing):** always `--unpin`
  between daemon restarts in tests/benchmarks; `pkill` alone leaves stacked links
  that silently corrupt concurrency measurements. `open-concurrency.sh` and the
  bench harnesses do this by construction.

## Reproduce

```sh
make bench-concurrency                                   # threaded file_open sweep (CSV + summary)
make bench-concurrency OC_THREADS="1 2 4 8 16 32" OC_ITERS=200000   # override the sweep
```
