# V-4b: deny / audit-drop counters

Phase-0 V-4b adds two kernel-side counters so the V-7 soak run (and any
operator inspecting a live profile) can answer two questions without
reading every audit event:

- "Did the policy decide to deny anything since the daemon started?"
- "Did the audit ringbuf drop any events while denying?"

The second question is the load-bearing one: when ringbuf reserve fails,
the audit log goes silent for that event but the policy *still* denies
with `-EACCES`. Without `audit_drop_total`, a soak operator would see no
audit lines and assume nothing happened, even though enforcement was
active and dropping events. Counters separate the policy decision from
the audit-stream observation.

## Counter names and meaning

| name               | type                    | meaning                                                                                  |
| ------------------ | ----------------------- | ---------------------------------------------------------------------------------------- |
| `deny_total`       | `BPF_MAP_TYPE_PERCPU_ARRAY` (1 × u64) | Incremented *before* the ringbuf reserve at every enforcement deny. One increment per `-EACCES` returned by a compartment-bpf LSM hook. |
| `audit_drop_total` | `BPF_MAP_TYPE_PERCPU_ARRAY` (1 × u64) | Incremented when `bpf_ringbuf_reserve()` returns NULL after `deny_total` was already counted — i.e. the deny happened but the audit event was lost. |

The ordering invariant is intentional and load-bearing: `deny_total` is
the *decision* counter, `audit_drop_total` is an *observation* counter,
and the return code never depends on whether the audit succeeded. See
`emit_audit()` in `compartment.bpf.c`.

## Per-CPU semantics

Both maps are per-CPU to avoid cross-core atomics on the hot path. The
BPF-side increment uses a non-atomic `(*v)++` on the current CPU's slot.
Userspace sums across all possible CPUs (`libbpf_num_possible_cpus()`)
to produce a single global number, e.g.:

```
[stats] deny_total=12345 audit_drop_total=42
```

## Reset semantics

Counters reset to zero on **daemon restart**. The BPF maps are part of
the skeleton; each `compartment_bpf__open()` allocates fresh maps with
zeroed per-CPU slots. After the maps are pinned under
`PIN_ROOT/maps/{deny_total,audit_drop_total}`, the values persist across
daemon exit (the pin keeps the map alive) up to the next `--unpin`.

Concretely:

- `compartment-bpf --pin profile.conf` → both counters at 0.
- Daemon emits N denies → `deny_total = N`, `audit_drop_total = some K ≤ N`.
- Daemon killed (SIGTERM); pinned links keep enforcement live and pinned
  maps keep counters readable. `--stats` continues to return the
  last-observed values.
- New daemon launched with `--pin` after `--unpin` → fresh maps, fresh
  zero. There is no separate `--reset-stats` command; restart is the
  reset.

This matches the V-4 pin-lifecycle model: `--pin` creates state,
`--unpin` removes it, no in-place mutation commands.

## Counter limits (what V-4b deliberately does *not* do)

- **No per-path attribution.** `deny_total` does not say *which* sealed
  path triggered the deny. Audit events still carry `(dev, ino)`; the
  counter is intentionally scalar so the BPF increment stays a single
  per-CPU `(*v)++` with no key lookup beyond index 0. A future revision
  may add per-action counters (`deny_unlink_total`, `deny_write_total`,
  ...) if soak telemetry calls for it.
- **No histograms.** No latency buckets, no time-series.
- **No JSON telemetry or Prometheus exporter.** `--stats` prints one
  human-readable line. Operators wire that into whatever scraper they
  already use.
- **No reset command.** Restart the daemon if a fresh window is needed.
- **No path-level counters.** See "no per-path attribution" above.

## Why counters beat audit logs during ringbuf drops

Audit events go through `bpf_ringbuf_reserve` → `submit`. When the
ringbuf is full (no userspace consumer, slow consumer, burst of
denies), `reserve` returns NULL. Without counters, that event is
invisible: the deny still returns `-EACCES`, but no log line is
produced and no metric ever records it. A soak operator watching only
the audit stream sees silence and assumes nothing was denied — exactly
the wrong inference.

`deny_total` is incremented *before* `reserve` is called, so it counts
every policy decision regardless of whether the audit event survives.
`audit_drop_total` is the explicit signal that audits were dropped, so
the operator knows when the audit log is incomplete.

The counter increments themselves cannot fail under any memory or
ringbuf pressure: they are a single `bpf_map_lookup_elem` on a
`PERCPU_ARRAY[1]` map followed by a non-atomic increment. The map is
pre-allocated at load time, the lookup always succeeds for `key=0`, and
the increment touches only this CPU's slot. There is no allocation, no
RCU section, no contended lock.

## --stats CLI

```
compartment-bpf --stats
```

Read-only. Opens `PIN_ROOT/maps/deny_total` and
`PIN_ROOT/maps/audit_drop_total` via `bpf_obj_get`, reads each as
`PERCPU_ARRAY[0]`, sums values across all possible CPUs, prints exactly:

```
[stats] deny_total=<N> audit_drop_total=<M>
```

to **stdout**, exits 0.

Exit codes:

| exit | condition                                                             | stream  |
| ---- | --------------------------------------------------------------------- | ------- |
| 0    | both counters read successfully                                       | stdout  |
| 2    | neither counter is pinned (`[stats] no pinned counters found`)        | stderr  |
| 1    | a pin existed but reading it failed (open succeeded, lookup failed)   | stderr  |

`--stats` is mutually exclusive with `--pin`, `--dry-run`,
`--allow-empty`, `--unpin`, and a profile argument. It does no kernel
state mutation; safe to run repeatedly from a metrics scraper.

## How V-7 should consume this

The V-7 soak brief should snapshot `[stats] deny_total=… audit_drop_total=…`
at fixed intervals (e.g. every 60 s) for the duration of the soak. The
deltas between snapshots give per-window deny rate and per-window drop
rate. The cumulative `audit_drop_total` value at the end of soak is the
single most important number: any value greater than zero means the
audit log under-reports denies for that interval and the soak's
audit-derived deny counts cannot be trusted as exact.

The instruction-count baseline captured in
`tests/results/v4b-counters-*/bpf-instr-count.txt` is the comparison
point for V-7's drift check: if V-7 finds any compartment-bpf program
has grown more than ~10 % over the V-4b numbers, the BPF code has
changed and the V-7 soak is no longer measuring what V-4b measured.
