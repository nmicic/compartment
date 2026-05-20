# compartment-bpf - Actor Filesystem Observe SPEC

> Status: draft v0.1, 2026-05-15
> Audience: implementers, profile authors, reviewers
> Companions:
> - `experimental/DENY-FIRST-PROFILE-GENERATION.md`
> - `experimental/EXEC-DOMAIN-SPEC.md`
> - `experimental/strict-launch-marker/results/FEASIBILITY.md`
> - `tools/profile-draft.py`
> Goal: observe one actor, or all candidate actors, and generate
> compartment-bpf profile candidates from real filesystem behavior.

## 1. Purpose

`tools/profile-draft.py` drafts profiles from package/systemd metadata.
`DENY-FIRST-PROFILE-GENERATION.md` validates by starting narrow, then
adding only rules proven necessary by denial events.

This SPEC adds the missing discovery mode:

```
observe actor/file behavior -> draft candidate profile -> validate with deny-first
```

The tool observes process lineage and filesystem activity from BPF,
then emits candidate `actor` and `seal` rules. It is not a syscall
profiler. It profiles the thing compartment-bpf actually enforces:
actor identity plus filesystem objects.

## 2. Command shape

Default output is stdout. `-o` is optional and `-o -` is the explicit
stdout spelling.

```
compartment-bpf observe [OPTIONS] [-- COMMAND [ARGS...]]
```

Common examples:

```
# Observe a known actor for 5 minutes, emit candidate profile to stdout.
compartment-bpf observe \
  --actor mysqld=/usr/sbin/mysqld \
  --duration 300

# Same, write files.
compartment-bpf observe \
  --actor mysqld=/usr/sbin/mysqld \
  --duration 300 \
  -o profiles/mysql.generated.conf \
  --provenance-out profiles/mysql.generated.provenance.json

# Launch a command under observation.
compartment-bpf observe \
  --actor aide=/usr/sbin/aide \
  -- /usr/sbin/aide --check

# Live compact stream for one actor.
compartment-bpf observe \
  --actor aide=/usr/sbin/aide \
  --format compact \
  --verbose

# Global actor discovery. Shows execs, launchers, children, and touched
# paths so the operator can decide what should become an actor.
compartment-bpf observe --global --format compact --duration 60
```

### 2.1 Options

```
--actor NAME=PATH          Track this actor binary by resolved inode.
                           May be repeated; each adds an actor slot.
--pid PID                  Seed observation from an already-running task.
--global                   Observe all execs and build actor candidates.
                           (AO-6, deferred)
--duration SECONDS         Stop after duration. Default: until SIGINT
                           except --global, which defaults to 60 seconds.
                           Use --duration 0 for run-until-SIGINT.
--format profile           Emit candidate profile. Default.
--format compact           Emit one-line live events.
--format jsonl             Emit machine-readable event stream.
--format audit             Emit audit-log-like lines.
--verbose                  Include parent chain, helper execs, and samples.
--include-stat             Include stat/metadata-only activity.
                           (AO-7, deferred)
--no-resolve-paths         Emit dev/ino only; skip path resolution.
--transform PATH           Optional transform/collapse rules.
-o PATH                    Output file. Default: stdout.
-o -                       Explicit stdout.
--provenance-out PATH      Optional provenance JSON file.
```

`--actor`, `--pid`, and `--global` are selectors. At least one is
required unless `COMMAND` is supplied and `--actor` can be inferred
from `argv[0]`.

`--global --include-stat` is allowed but must print a startup warning:
metadata activity on a busy host can saturate observe maps quickly;
scope with `--actor` unless global stat visibility is intentional.

## 3. Non-goals

- No Python, strace, inotify, fanotify, auditd, or external daemon
  dependency for the core observe path.
- No enforcement decisions are made by observe mode.
- No claim that observation alone proves a profile complete.
- No recursive subtree enforcement is implied by a directory candidate.
- No argv/env capture by default. Command lines and env values can
  contain secrets.
- No product dependency or semantic coupling to any external BPF
  observability project. This is ordinary local BPF collection shaped
  around compartment-bpf profile generation.

## 4. Why not inotify

An inotify/fanotify prototype could observe some path activity, but it
does not give the right authority boundary for this tool:

- It does not know compartment-bpf actor identity.
- It does not give clean parent/child actor lineage.
- It does not naturally bind events to executable inodes.
- It is path-centric, while compartment-bpf enforcement is inode-keyed.
- It is weaker across namespaces, hardlinks, deleted files, and
  renamed paths.
- It cannot share state with future strict-launch task markers.

BPF gives one self-contained binary with kernel-side filtering by actor
inode and task lineage. That is the right dependency shape.

## 5. Identity model

Observation must be actor/inode based. PID is metadata only.

### 5.1 Actor identity

An actor declaration resolves to:

```
actor name -> target file_id(dev, ino)
```

At `bprm_check_security` or `sched_process_exec`, if the exec target
matches an actor target, the task receives two separate observation
markers:

```
struct current_actor_marker {
    __u32 actor_slot;
    __u32 generation;
};

struct lineage_marker {
    __u32 origin_actor_slot;
    __u32 generation;
    __u8 observation_only;
};
```

The maps must also be structurally separate:

```
current_actor_markers  task -> current_actor_marker
lineage_markers        task -> lineage_marker
```

`current_actor_markers` means the task's current executable is still
the actor binary, or a fork-without-exec child of that actor.

`lineage_markers` means the task descends from an actor, even if it
later execs a helper. This is discovery-only metadata. Enforcement code
must never read `lineage_markers`; keeping it in a distinct map makes
that rule structural instead of relying on comments.

### 5.2 Parent and launcher capture

For each actor exec, observe mode records:

- actor name
- actor target dev/ino
- actor pid/tgid
- immediate parent pid/tgid
- parent executable dev/ino if available
- launcher executable path hint if resolvable
- timestamp and cgroup id from `bpf_get_current_cgroup_id()`

This answers: "which parents launch this actor?"

### 5.3 Fork and thread handling

Forked children inherit observation lineage. Default implementation:
reuse the strict-launch `lsm/task_alloc` copy-hook pattern from
`experimental/strict-launch-marker/bpf/slm.bpf.c`. Strict-launch v0.4
validated Outcome (B): task storage does not inherit automatically on
the production kernel floor, and a small `task_alloc` hook copies the
marker verifier-cleanly.

Observe mode should copy both marker maps on fork:

- current actor marker: copied when present;
- lineage marker: copied when present;
- counters: `current_actor_copy_fork_total`,
  `lineage_copy_fork_total`.

Thread creation should not create a new actor identity. Thread events
aggregate under the actor tgid unless the thread execs.

### 5.4 Helper exec handling

If an actor task execs a non-actor helper:

- `current_actor_markers` entry is deleted.
- `lineage_markers` entry remains set by default for observe mode.
- file touches are reported as `under_actor_lineage`, not as direct
  actor touches.
- profile output must not silently add the helper as an actor. It is
  emitted as a review candidate.

This separates "the actor itself needs this file" from "a helper
spawned by the actor touched this file."

## 6. Events to collect

### 6.1 Exec and lineage events

- actor exec
- non-actor exec under actor lineage
- fork/clone under actor lineage
- task exit under actor lineage
- parent/launcher summary

### 6.2 Filesystem events

Collect by LSM hooks where possible, because these hooks align with
the enforcement surface:

- `file_open`: read/write/append/truncate intent
- `inode_create`, `inode_mkdir`, `inode_mknod`, `inode_symlink`
- `inode_unlink`, `inode_rmdir`
- `inode_rename`
- `inode_link`: classify both destination-directory creation and
  source-inode link attempts as separate axes
- `inode_setattr`: chmod/chown/truncate-style metadata changes
- `inode_getattr` or equivalent metadata path when `--include-stat`
  is set
- `mmap_file` with executable mapping, for future exec-trust and
  library visibility

Stat-only events are noisy. Default profile generation should record
them in provenance but not turn them into seal rules unless a transform
explicitly asks for that.

## 7. BPF data model

The hot path must aggregate in maps and emit ringbuf events only for
first sightings or live verbose mode.

### 7.1 Maps

```
actor_targets        file_id -> actor_slot
current_actor_markers task -> current_actor_marker
lineage_markers      task -> lineage_marker
observed_files       observed_key -> observed_value
observed_launchers   launcher_key -> counters
event_counters       percpu counters
events               ringbuf
```

`observed_key`:

```
struct observed_key {
    __u32 actor_slot;
    __u32 op_class;
    __u64 dev;
    __u64 ino;
    __u64 parent_dev;
    __u64 parent_ino;
};
```

`observed_value`:

```
struct observed_value {
    __u64 count;
    __u64 first_ns;
    __u64 last_ns;
    __u32 sample_pid;
    __u32 sample_tgid;
    __u32 flags_seen;
    __u8 under_current_actor;
    __u8 under_actor_lineage;
};
```

### 7.2 Counters

Minimum counters:

- `events_seen_total`
- `events_sampled_total`
- `events_ringbuf_drop_total`
- `observed_files_total`
- `observed_files_overflow_total`
- `current_actor_copy_fork_total`
- `lineage_copy_fork_total`
- `lineage_exec_helper_total`
- `path_resolve_fail_total`

Ringbuf loss must not lose aggregate counts. The map is the primary
truth; ringbuf is a live/sample stream.

### 7.3 Map-full behavior

`observed_files` should be a normal hash map, not LRU, for v0. When a
new key cannot be inserted because the map is full:

- preserve existing entries;
- drop the new key;
- increment `observed_files_overflow_total`;
- emit at most one rate-limited warning event.

For profile generation, preserving first sightings is preferable to
LRU eviction because early startup dependencies are often more
important than later noisy steady-state repeats.

## 8. Output formats

### 8.1 `--format profile` default

The default output is a candidate profile on stdout:

```
# generated by compartment-bpf observe
#@compartment-bpf-profile-status: candidate
# target: mysqld
# observed_at: 2026-05-15T...
# validation: candidate only; run deny-first before enforcing

actor mysqld = /usr/sbin/mysqld
seal /usr/sbin/mysqld full

# observed launchers:
# parent /usr/bin/systemd count=1

# directory destination rule; one-level child protection, not recursive.
seal /var/lib/mysql no-write no-unlink no-rename no-chmod actor=mysqld

# enumerated fallback for runtimes without directory-destination support:
seal /var/lib/mysql/ibdata1 no-write no-unlink no-rename actor=mysqld
seal /var/lib/mysql/ib_logfile0 no-write no-unlink no-rename actor=mysqld

# helper execs under actor lineage, review before adding as actors:
# helper /usr/bin/find touched /var/lib/mysql/... count=3
```

The output must always include a candidate/provenance warning unless
the profile has also passed deny-first validation.
The `#@compartment-bpf-profile-status:` line is machine-parseable so
automation can reject unvalidated profiles.

### 8.2 `--format compact`

Compact mode is for humans watching a live system:

```
12:04:55 actor=mysqld pid=1234 ppid=1 exec=/usr/sbin/mysqld parent=/usr/bin/systemd
12:04:56 actor=mysqld pid=1234 op=open_w path=/var/lib/mysql/ibdata1 count=1
12:04:57 actor=mysqld lineage pid=1260 helper=/usr/bin/find op=getattr path=/var/lib/mysql/db1
```

With `--verbose`, include dev/ino, cgroup id, operation flags, and
parent chain samples.

### 8.3 `--format jsonl`

One JSON object per sampled event:

```json
{"type":"file","actor":"mysqld","pid":1234,"op":"open_write","dev":64768,"ino":123,"path":"/var/lib/mysql/ibdata1","count":1}
```

### 8.4 `--format audit`

Audit-like text for operators who want log-style output:

```
type=COMP_OBSERVE actor=mysqld pid=1234 op=open_write dev=64768 ino=123 path=/var/lib/mysql/ibdata1
```

## 9. Folder and file rule generation

The transform stage turns observations into candidate rules. It must
be honest about current compartment-bpf semantics and about the
directory-destination correction tracked in
`experimental/DIR-DESTINATION-ACTOR-SEALS-SPEC.md`.

### 9.1 Directory destination semantics

At the time this observe SPEC was drafted, current code treats
directory seals as structural guards only. A seal on a directory blocks
create, link, unlink, rename, mkdir, rmdir, mknod, symlink, and related
metadata operations under that directory, but does not block writes to
already-existing child files.

The intended exec-domain model is stronger and is specified in
`DIR-DESTINATION-ACTOR-SEALS-SPEC.md`: a directory seal should also
gate write/metadata operations on immediate child files. In that model,
this rule:

```
seal /var/lib/mysql no-write no-unlink no-rename no-chmod actor=mysqld
```

means non-actors cannot create entries under `/var/lib/mysql` and
cannot write existing immediate child files of `/var/lib/mysql`.

Therefore observe mode has four output classes:

1. `dir-destination`: one-level directory destination rule. Emit once
   `DIR-DESTINATION-ACTOR-SEALS-SPEC.md` is implemented.
2. `dir-struct`: structural-only rule for current pre-correction code.
3. `dir-enumerated`: emit per-file rules for existing observed files
   when running against pre-correction code.
4. `dir-recursive`: future rule class; emit only as a comment unless a
   recursive-subtree feature exists.

### 9.2 Default collapse rules

The default transform can collapse many file observations into a
directory candidate when all are true:

- common parent is not a broad system path like `/`, `/usr`, `/etc`,
  `/var`, `/var/lib`, `/run`, or `/tmp`;
- path is under a known package/state/runtime/log/cache directory, or
  explicitly named in `--transform`;
- operation masks are compatible;
- at least N files in the directory were observed, default N=3;
- no conflicting helper lineage suggests the directory is shared by
  multiple unrelated actors.

For example, many writes under `/var/lib/mysql/` produce:

```
seal /var/lib/mysql no-write no-unlink no-rename no-chmod actor=mysqld
```

If directory-destination semantics are not present, observe mode must
also emit per-file rules for observed existing files or warn that the
generated directory rule is structural-only.

If directory-destination semantics are present, observe mode must still
check the load-time invariants from
`DIR-DESTINATION-ACTOR-SEALS-SPEC.md`: immediate symlink children and
non-directory children with `st_nlink > 1` make strict directory
destination output unsafe unless the operator fixes them or explicitly
keeps the output as a review-only candidate.

### 9.3 New files

If an actor creates new files directly under a directory, the
directory-destination rule covers those immediate child files once the
feature lands. It still does not recursively cover files under a new
subdirectory unless that subdirectory is also sealed or a future
recursive-subtree primitive exists.

Observe mode must surface this plainly:

```
# WARNING: actor created new files under /var/lib/mysql.
# Directory-destination seals cover immediate child files only.
# Full subtree write protection requires sealing observed subdirs
# or a future recursive-subtree primitive.
```

## 10. Relationship to deny-first

Observe-first and deny-first answer different questions:

- observe-first: what did this actor touch during the run?
- deny-first: what is required for this actor to pass the workload?

Recommended workflow:

```
1. observe with representative workload
2. draft candidate profile to stdout or file
3. review folder collapses and helper candidates
4. validate with deny-first
5. sign/pin only after validation passes
```

Observation is allowed to over-approximate. Deny-first is the
sufficiency gate.

## 11. Global actor discovery

`--global` mode is for reconnaissance on a real host:

- show execs grouped by executable inode;
- show parent launchers;
- show long-lived daemons;
- show binaries touching mutable state under `/var/lib`, `/var/log`,
  `/run`, `/etc`, and configured roots;
- show fork-heavy services that may need explicit inheritance testing;
- show helper execs under existing candidate actors.

Global mode should default to compact output and aggressive aggregation.
It must not emit a giant profile unless `--format profile` is requested
explicitly.

Global mode duration defaults to 60 seconds. Use `--duration 0` for
run-until-SIGINT. If `--global --include-stat` is used, print a startup
warning because metadata collection on a busy host can saturate maps.

Candidate actor ranking:

1. long-lived daemon launched by systemd/init;
2. process touches package-owned mutable state;
3. process writes or structurally mutates files under service-specific
   directories;
4. process has stable executable path under `/usr/sbin`, `/usr/bin`,
   `/usr/libexec`, or package libexec dir;
5. process has repeatable parent launcher.

## 12. Performance and robustness

- Actor-specific mode must filter in BPF before emitting events.
- Global mode must aggregate in maps and sample ringbuf events.
- No per-open path string copying in BPF.
- No argv/env capture by default.
- No unbounded loops over path components in BPF.
- Map size limits must be explicit and printed in the provenance.
- If maps fill, increment overflow/drop counters and print a warning.
- For `observed_files`, map-full behavior is refuse-new/preserve-old,
  with `observed_files_overflow_total`.
- `--include-stat` is off by default because metadata reads are noisy.
- Path resolution happens in userspace from dev/ino plus pid/root
  context; failures remain dev/ino records.

## 13. Security notes

- Path hints are not authoritative. Enforcement uses dev/ino.
- Path hints are resolved best-effort in userspace. Between the BPF
  event and userspace resolution, a path may be renamed or
  unlinked-and-recreated. The original dev/ino remains authoritative.
- PIDs recycle. PID is display metadata, not identity.
- Hardlinks may produce several path hints for one inode. Provenance
  should record aliases when discovered.
- Deleted files may have no stable path. Keep dev/ino records.
- Different mount namespaces can resolve the same dev/ino differently.
  Include cgroup/mount namespace metadata where feasible.
- Observed helper activity is not automatically actor activity.
- Observation records current host behavior. If the host is suspected
  of compromise, baseline or rebuild before observation. A profile
  generated from a compromised host can codify an attacker's helper as
  a candidate actor.
- Output may contain sensitive filenames. `--redact` can be a later
  feature, but the MVP should warn before writing world-readable files.

## 14. Implementation phases

### AO-1 CLI and output discipline

Add `compartment-bpf observe` with:

- `-o -` and stdout default;
- `--format profile|compact|jsonl|audit`;
- duration and SIGINT handling, including `--global` default 60s and
  `--duration 0` for run-until-SIGINT;
- repeated `--actor NAME=PATH` actor slots;
- startup warning for `--global --include-stat`;
- no dependency on Python, strace, inotify, fanotify, or auditd.

### AO-2 Actor marker and lineage

BPF-side actor target map, structurally separate current-actor and
lineage marker maps, exec detection, and fork copy using the
strict-launch `lsm/task_alloc` pattern. Witness tests:

- direct actor exec marked;
- parent launcher captured;
- fork child attributed;
- helper exec becomes lineage-only.

### AO-3 Filesystem aggregation

Collect file and inode operation classes into BPF maps. Ringbuf only
first-sighting/sample events. Witness tests:

- open read/write/append/truncate classified;
- create/unlink/rename/mkdir/rmdir classified;
- inode_link source-inode and destination-directory axes classified
  separately;
- chmod/chown/truncate classified;
- stat only appears with `--include-stat`.

### AO-4 Path resolver and provenance

Userspace resolver maps dev/ino to path hints from procfs and mount
tables. Provenance records unresolved entries, aliases, map drops,
and transform decisions.

### AO-5 Profile draft transform

Generate candidate `actor` and `seal` lines, including directory
collapse with directory-destination awareness and current-v0 warnings
when the running binary lacks that feature. Default to stdout.

### AO-6 Global compact mode

Global candidate actor view with compact live output and ranking.

### AO-7 Deny-first bridge

Add a documented handoff:

```
compartment-bpf observe ... -o candidate.conf
compartment-bpf genprofile --seed candidate.conf ...   # command name TBD
```

The exact deny-first command name is still TBD. The contract is that
observe output is reviewable seed input, not final proof.

## 15. Acceptance tests

Minimum test matrix:

- stdout default: no `-o` prints profile to stdout.
- `-o FILE` writes profile and keeps stderr for diagnostics.
- compact mode prints bounded live lines.
- actor selector follows exact inode, not just path string.
- repeated actor selectors create distinct actor slots.
- pid selector follows forked child.
- helper exec is lineage-only.
- global mode sees at least `/bin/true`, a shell, and a test daemon.
- global mode defaults to 60 seconds.
- `--global --include-stat` prints the saturation warning.
- directory collapse refuses broad roots.
- directory-destination warning appears when the runtime lacks that
  feature.
- recursive-subtree warning appears when actor creates nested child
  files.
- map overflow/drop warning is surfaced.
- path resolution failure does not drop dev/ino observation.

## 16. First useful target

Use AIDE first because it is short-running and already important for
actor-strict. The immediate AIDE pipeline is:

```
observe -> actor-strict candidate -> deny-first validation
```

Use MySQL/Postgres second because they exercise:

- systemd parent launch;
- fork/thread behavior;
- large data directories;
- helper processes;
- directory collapse;
- current-v0 recursive-subtree limitations.

Strict-launch v0.4 has proven fork marker copy via `task_alloc`, so
observe mode should reuse that hook. Databases still need their own
validation because prefork/multi-worker behavior, helper execs, and
deep data trees stress more profile-generation surfaces than AIDE.

The expected first-release posture is conservative: AIDE-style tools
can produce useful profile candidates quickly; database profiles are
useful for discovery but must carry explicit one-level-directory and
recursive-subtree warnings until those semantics are fully implemented
and tested.
