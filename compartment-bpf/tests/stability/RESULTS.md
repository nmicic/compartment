# Stability test results — template

This file is a documentation template, not a real result. Each run of
`tests/stability/pin-unpin-churn.sh` writes its own RESULTS.md into
`tests/stability/results/<UTC>/`; refer to that file for the actual
per-run record.

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
