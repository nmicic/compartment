# Stability test results

The template this file used to be is below, after the recorded run. Each
invocation of `tests/stability/pin-unpin-churn.sh` also writes its own
RESULTS.md into `$STAB_DIR` (`tests/stability/results/<UTC>/` by
default); this file records the full 1024-cycle soak, which had never been
run anywhere before 1.4.

---

## Recorded run — full soak, 1024 cycles

**Date:** 2026-09-06T14:43:57Z
**Tree:** `fix/test-hardening` @ `599d5a2`
**VM:** Resolute, Ubuntu 26.04, kernel 7.0.0-31-generic, Landlock ABI 8
**Cycles:** 1024 (`sudo make check-stability`, `DUAL_PROFILE=0`)
**Duration:** 1173 s (19 min 33 s)

### Headline

```
Loop A+B complete: duration=1173s mesh_iters=65 pass=213005 fail=0 timeouts=0
=== stability summary: pass=8 fail=0 skip=0 total=8 ===
```

### T-STAB-1 Kernel-level signals

- taint: baseline=0 end=0 — **PASS**
- dmesg new BUG/Oops/WARNING/hung_task/RCU stall: 0 — **PASS**

### T-STAB-2 Memory growth

- compartment-bpf RSS baseline=0kB end=0kB growth=0kB (<50MB) — **PASS**
  (0 because the daemon is not resident between cycles in this mode: each
  cycle pins and unpins, so the sample lands with no daemon running.)

### T-STAB-3 Bpffs clean after unpin

- `/sys/fs/bpf/compartment` pinned objects after the final `--unpin`: 0 —
  **PASS** (the PIN_ROOT directory structure is preserved by design)

### T-STAB-4 Mesh pass-rate during churn, and BPF object drift

- iterations: 65
- total trials counted: 213005
- total FAIL rows during churn: 0
- aggregate: 213005/213005 (pct100=10000, >= 99%) — **PASS**
- BPF prog count 15 -> 16, map count 4 -> 4 (within +/-4) — **PASS**

### T-STAB-6 Stuck-state detection

- D-state processes after run: 0 — **PASS**
- mesh timeouts (>120 s outer cap): 0 — **PASS**

### T-STAB-8 Pin witness

- **1024/1024 cycles observed a live pin** under
  `/sys/fs/bpf/compartment/links` — **PASS**. This is the assertion that
  the churn was not a no-op; a first attempt at this soak failed it
  (`0/1024`) because a leftover pin tree from an aborted run made every
  `--pin` refuse fail-closed, which is the witness doing its job.

### T-STAB-5 Corner-case witnesses

Not exercised by this target: the ten `tests/stability/corner-cases/CC-*.sh`
scripts are invoked by nothing, and nine of the ten call `--pin` in the
foreground, which blocks. Wiring them up is open item 6.3's sibling and is
not attempted here.

### Environment afterwards

links=0, maps=0, 1 LSM program (the distribution's own), 30 mounts (the
baseline), 0 loop devices, no `compartment-bpf` process, taint 0, no
`BUG:`/`Oops`/hung-task in `dmesg`. The guest was not rebooted.

---

## Template — what a run records

---

**Date:** YYYY-MM-DDTHH:MM:SSZ
**SHA:** <git sha>
**VM:** Resolute 7.0, kernel 7.0.0-15-generic
**Cycles:** 1024 (or 64 for quick run; 16 for VM-smoke gating)

## T-STAB-1 Kernel-level signals

- taint: baseline=0 end=0 — PASS
- dmesg new BUG/Oops/WARNING/hung_task/RCU stall: 0 — PASS

## T-STAB-2 Memory growth

- compartment-bpf RSS baseline: Xkb end: Ykb growth: Zkb (<50MB) — PASS/FAIL
- kernel bpf_* slab objs: baseline=N end=M — informational (no FAIL gate)

## T-STAB-3 Bpffs clean after unpin

- /sys/fs/bpf/compartment/ entries after final --unpin: 0 — PASS

## T-STAB-4 Mesh pass-rate during churn

- iterations: N
- total trials counted (PASS rows): P
- total FAIL rows during churn: F
- aggregate pct (P / (P+F)): >=99% — PASS/FAIL

## T-STAB-5 Corner-case witnesses

- CC-01 pin-during-mesh: PASS/FAIL/SKIP
- CC-02 unpin-during-enforcement: PASS/FAIL/SKIP
- CC-03 exec-during-unpin: PASS/FAIL/SKIP
- CC-04 child-actor-unpin: PASS/FAIL/SKIP
- CC-05 rapid-pin-unpin: PASS/FAIL/SKIP
- CC-06 sigkill-repin: PASS/FAIL/SKIP
- CC-07 unpin-during-ringbuf: PASS/FAIL/SKIP
- CC-08 concurrent-pin: PASS/FAIL/SKIP
- CC-09 sigstop-sigcont: PASS/FAIL/SKIP
- CC-10 pin-unpin-pin-unpin: PASS/FAIL/SKIP

## T-STAB-6 Stuck-state detection

- D-state processes after run: 0 — PASS
- mesh timeout count (>120s outer): 0 — PASS

## T-STAB-7 Counter consistency

- BPF prog count drift (±4): PASS
- BPF map count drift (±4): PASS

## Overall

- Aggregate: PASS / FAIL
- Evidence directory: tests/stability/results/<UTC>/
- Logs: loop-a.log, mesh-iter-*.log, dmesg-new.txt, bpffs-residue.txt
