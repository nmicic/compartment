# compartment-bpf - Strict Launch Marker Feasibility SPEC

> Status: small feasibility SPEC v0.1, 2026-05-15
> Audience: Linux validation team, BPF implementers, release reviewers
> Source draft: `experimental/drafts/EXEC-DOMAIN-EXTENSIONS-SPIKE.md`
> Evidence base: `experimental/bprm-strict/results/FEASIBILITY.md`,
> `experimental/bprm-strict/results/DEC-BPRM-STRICT-A.md`
> Goal: decide whether strict actor launch can be safe enough and small
> enough for the first exec-domain release.

## 1. Problem

Current exec-domain actor enforcement authorizes protected file
operations by the calling task's executable inode. That closes
`root writes sealed file with /bin/sh`, but it does not close:

```
LD_PRELOAD=/tmp/evil.so /usr/sbin/aide ...
```

If `/usr/sbin/aide` is the authorized actor, a hostile environment can
inject code into the authorized actor process before the actor touches
the sealed file. That is the same class of gap the original LIDS-era
deployment had to care about: binary identity alone is not a clean
launch guarantee.

This SPEC is intentionally narrow. It does not try to build full exec
trust. It asks whether compartment-bpf can add one small primitive:

> For selected actors, protected file operations are allowed only when
> the actor was reached through a sealed static launcher that cleaned
> the environment first.

## 2. Non-goals

- Do not implement kernel-side env scrubbing in this phase.
- Do not scan env strings from BPF at `bprm_check_security`.
- Do not implement per-actor capability ceilings here.
- Do not implement mmap-exec or full shared-library trust here.
- Do not claim general prevention of injected code execution outside
  compartment-bpf protected operations.

The `bprm-strict` spike already showed why BPF env walking is the
wrong primitive at this hook: user-memory helpers return `-EFAULT`
against env pointers because env strings live in `bprm->mm`, not
`current->mm`.

## 3. Desired property

For a seal marked `strict-launch`, an actor match is valid only if all
of these are true:

1. The current executable inode matches the declared actor target.
2. The current task has a valid strict-launch marker.
3. The marker was set by exec of the declared sealed launcher.
4. The marker target matches the current actor target.
5. The marker policy generation matches the policy generation pinned
   at the most recent `--pin` operation. Generation values are not
   bumped in place; the supported reload path is `--unpin` followed by
   `--pin`, which destroys the per-task `actor_marker` storage and
   forces every protected actor to re-launch through its declared
   launcher (Review-1 HIGH-3 amend, 2026-05-15; see §3a below).

If the same actor target is exec'd directly with `LD_PRELOAD`, it has
no marker. It may start running, but it must not receive
actor-authorized access to `strict-launch` seals.

This distinction matters. The feature closes "dirty direct actor can
modify protected files." It does not by itself close every possible
effect of running a dirty actor process. If first release claims
LD_PRELOAD-safe actor protection, that claim must be scoped to
compartment-bpf protected operations.

### 3a. Policy reload semantics (v0.4: fresh-load-only)

v0.4 does **not** support in-place policy hot-reload. The implementation
ships the generation-tracking scaffolding (`policy_state.generation`,
`seal_value.strict_generation`, the dual-side `marker_stale_generation_total`
check) so that the v0.5 hot-reload path can land without an ABI bump,
but the v0.4 loader never bumps generation after the initial `--pin`.

Operator procedure for policy changes:

1. `compartment-bpf --unpin` — releases pinned maps; the kernel's
   per-task `actor_marker` storage entries are destroyed alongside.
2. Edit the profile.
3. `compartment-bpf --pin <new-profile>` — fresh generation, fresh
   marker storage. Every protected actor must re-launch through its
   declared launcher before it can write to a `strict-launch` seal
   again; the first such launch sets a marker against the new
   generation.

Hot-reload (changing policy without taking the protected actor offline)
is deferred to v0.5. See LIMITATIONS.md "Hard caveat — policy reload"
and `DEC-STRICT-LAUNCH-A.md` "Open follow-ups" for the v0.5 entry.

## 4. Proposed profile surface

Minimal syntax for the v0.4 release (Review-1 HIGH-7 amend, path b,
2026-05-15: `env NAME=VALUE` / `env NAME=*` directives are not part of
the v0.4 grammar; env policy is sourced from the wrapper build —
`tools/compartment-actor-build.sh --allow-env NAME` — and the loader
rejects `env` directives with a clear error pointing the operator at
HOWTO.md §6.4):

```
actor-strict aide = /usr/sbin/aide launcher=/usr/libexec/compartment-actors/aide

seal /var/lib/aide/aide.db no-write actor=aide strict-launch
seal /usr/sbin/aide full
seal /usr/libexec/compartment-actors/aide full
```

Semantics:

- `actor-strict NAME = TARGET launcher=PATH` declares that `TARGET`
  is an actor only when reached through `PATH`.
- `strict-launch` on a seal requires a valid marker in addition to
  the existing actor inode match.
- Env policy is the wrapper's responsibility, not the loader's. The
  wrapper `clearenv()`s before `execve()` and admits only names
  explicitly listed at build time via `--allow-env`. The loader does
  not parse `env` directives; profiles containing them are rejected
  at load time.

The launcher must be a static binary. A dynamic launcher has the same
`LD_PRELOAD` problem before its own `main`.

Launcher implementation should reuse the existing static wrapper design
(`tools/compartment-actor-wrapper.c` plus
`tools/compartment-actor-build.sh`). This SPEC adds the kernel marker
requirement; it should not cause a second launcher design to be
invented.

The wrapper hard-rejects the following dangerous dynamic-loader /
interpreter env names at build time (the list is shared with the
loader's `STRICT_DANGEROUS_ENV_NAMES` table via
`tools/compartment-dangerous-env.h`, Review-1 HIGH-6):

```
LD_PRELOAD
LD_AUDIT
LD_LIBRARY_PATH
GLIBC_TUNABLES
GCONV_PATH
LOCPATH
NLSPATH
BASH_ENV
ENV
PYTHONPATH
PYTHONSTARTUP
PERL5LIB
PERL5OPT
RUBYLIB
RUBYOPT
NODE_OPTIONS
```

There is no v0.x override. If a future actor truly needs one of these,
that belongs in a separate sealed-library or full-exec-trust design,
not in the first strict-launch release.

### Rationale for the wrapper-as-single-source-of-env-policy invariant

Pre-amend, the loader parsed `env NAME=VALUE` directives and stored
them on the `actor_group` structure, but **no code path consumed the
stored list** — the wrapper built independently from build-time
inputs. An operator writing `env TZ=*` in a profile saw the parser
accept it but the wrapper was unaware; the directive was silently
dropped at exec time. Review-1 HIGH-7 catalogued this as a contract
integrity bug.

Path (a) — wire `env_directives` into the wrapper build — would
require operator-driven wrapper rebake at load time (operationally
complex; breaks the FEASIBILITY-tested wrapper shape) or a runtime
allowlist mechanism in the wrapper (new code surface against the
clearenv-then-allowlist invariant). Path (b) is the simpler primitive:
delete the parser, document the invariant. Path (b) is the simpler and
safer primitive for v0.x because it keeps loader and wrapper policy in
one place.

## 5. BPF state model

The feasibility implementation should use two small pieces of BPF
state.

### 5.1 Launcher map

Map: `launcher_to_actor`

Key:

```
struct file_id {
    __u64 dev;
    __u64 ino;
};
```

Value:

```
struct launcher_actor {
    struct file_id target;
    __u32 actor_slot;
    __u32 policy_generation;
};
```

The loader populates this map from `actor-strict` declarations.

### 5.2 Task marker

Map: `actor_marker`, `BPF_MAP_TYPE_TASK_STORAGE`

Value:

```
struct actor_marker {
    struct file_id target;
    __u32 actor_slot;
    __u32 policy_generation;
    __u8 state;
};
```

`policy_generation` is required so old marked tasks cannot silently
survive reload into a different policy meaning.

## 6. Hook behavior

### 6.1 `bprm_check_security`

At every exec:

1. Resolve the exec target inode.
2. If target inode is a declared launcher:
   - Create or overwrite current task marker.
   - Marker payload is the mapped actor target and policy generation.
   - Allow exec.
3. Else if current task already has a marker:
   - If exec target equals marker target, keep marker and allow exec.
   - If exec target does not equal marker target, clear marker and
     allow exec. Increment `marker_clear_foreign_exec_total` before
     clearing.
4. Else allow exec.

This hook is not a deny hook in the feasibility phase. The deny point
is the existing file-operation enforcement path.

### 6.2 File-operation actor check

For each protected file operation:

1. Run existing seal lookup.
2. Run existing actor inode check.
3. If the seal does not have `strict-launch`, preserve current
   behavior.
4. If the seal has `strict-launch`:
   - Require a task marker.
   - Require marker target equals current executable inode.
   - Require marker actor slot matches the seal actor.
   - Require marker policy generation equals the loaded generation.
5. On failure, deny with a new explicit action code:
   `ACTION_DENY_STRICT_LAUNCH_MISSING` or equivalent.

The explicit action code matters. A false-green test must not be able
to confuse normal actor deny, missing marker deny, and ringbuf loss.

### 6.3 Cheap hardening hooks

These are separate but should be tested with the strict-launch marker:

- `task_prctl`: deny **all `PR_SET_MM` sub-ops** globally whenever any
  strict actor policy is loaded. Originally scoped to
  `PR_SET_MM_EXE_FILE` only (FEASIBILITY v0.1); broadened to the whole
  option family in Review-1 HIGH-5 (2026-05-15) after `PR_SET_MM_MAP`
  (sub-op 14) was identified as a direct bypass — its `struct
  prctl_mm_map` accepts an `exe_fd` field that overwrites
  `current->mm->exe_file` at the same CAP_SYS_RESOURCE privilege tier
  as `PR_SET_MM_EXE_FILE`. Per-sub-op enumeration is fragile (the
  kernel has historically added sub-ops between releases); legitimate
  userspace does not need `PR_SET_MM` under strict-launch. This is
  deliberately not limited to marked tasks; an unmarked attacker must
  not be able to prepare a forged actor identity before reaching
  protected file operations.
- `ptrace_access_check` and `ptrace_traceme`: deny ptrace access to
  strict actor tasks, and verify `process_vm_writev`, `pidfd_getfd`,
  and `/proc/<pid>/mem` coverage on the target kernel.

The `bprm-strict` spike showed these hooks attach and enforce on the
Resolute VM. They still need end-to-end negative witnesses before
promotion.

### 6.4 Minimum BPF counters (cross-cutting across §6 hooks)

- `strict_launch_missing_total` — incremented by §6.2 on file-op deny.
- `marker_set_total` — incremented by §6.1 step 2 (launcher exec).
- `marker_clear_foreign_exec_total` — incremented by §6.1 step 3b
  (foreign exec from marked task) before clearing.
- `prctl_set_mm_exe_file_denied_total` — incremented by §6.3
  `task_prctl` deny.
- `ptrace_denied_total` — incremented by §6.3 ptrace hook denies.

All deny counters must increment **before** any ringbuf reserve
attempt so that deny is visible even when audit events drop. The
marker-clear counter should increment even when no audit event is
emitted; it is the visibility signal for helper/shell chain breaks.

Per-hook counters MAY be added (e.g., separating `ptrace_denied_total`
into `ptrace_attach_denied_total` / `ptrace_traceme_denied_total`)
during implementation. The five names above are the minimum required
for §9 witness assertions and the G10 gate.

## 7. Loader and launcher requirements

The loader must reject a strict actor unless:

- The launcher exists at load time.
- The launcher is a regular file.
- The launcher is static, or the feasibility report explicitly
  documents why a non-static launcher is safe. Default answer is
  reject non-static.
- The launcher is sealed `full`.
- The target is sealed `full`.
- The launcher map and actor maps agree on actor slot and target inode.

The launcher must:

- Start with a clean env.
- Add only `env NAME=VALUE` entries.
- Pass through only `env NAME=*` entries that exist in the caller env.
- Exec the exact target path embedded or supplied by the generated
  profile metadata.
- Avoid shell interpretation.
- Avoid PATH lookup for the target.

The feasibility build may use one generated launcher per actor. A
generic launcher is allowed only if the spec proves its argument
surface cannot reintroduce shell/PATH/confusion risk.

## 8. Feasibility gates

This work is green only if every gate below has direct evidence.

| Gate | Required result |
| --- | --- |
| G1 env-in-BPF pivot | No env scan or env mutation is attempted in BPF. |
| G2 marker on launcher | Exec of sealed launcher sets the expected marker. |
| G3 marker survives target exec | Launcher -> target keeps marker visible in file-op hooks. |
| G4 direct actor dirty env | Direct `LD_PRELOAD=... target` is denied on strict protected write. |
| G5 chain break | Launcher -> target -> `/bin/sh` -> target loses marker and is denied. |
| G6 fork behavior | Fork-without-exec is explicitly measured. If marker is not inherited, implement a safe copy mechanism or declare strict actors incompatible with forking services. |
| G7 stale marker | Policy reload via the supported `--unpin` + `--pin` cycle cannot let an old marker authorize a new policy (markers are destroyed alongside the per-task storage at unpin time). In-place hot-reload is **not supported** in v0.4 (§3a); the gate witnesses the unpin cycle only. |
| G8 prctl spoof | `PR_SET_MM_EXE_FILE` cannot manufacture actor authorization. |
| G9 ptrace tamper | ptrace/process_vm/pidfd/proc-mem paths cannot modify a strict actor task. |
| G10 counters | Denies increment BPF-side counters before any ringbuf reserve, and marker-clear-on-foreign-exec increments `marker_clear_foreign_exec_total`. |
| G11 perf | Incremental hot file-open overhead stays inside the release threshold. |

G6 is a hard gate. The larger spike draft states that task storage
copies on fork, but the current evidence proves exec survival only.
The Linux team must treat fork propagation as unknown until measured
or implemented.

Acceptable G6 outcomes:

- **(A)** A kernel-supported task-storage inherit-on-fork mode exists
  on the production kernel floor and passes the witness test.
- **(B)** A small `task_alloc`-style LSM copy hook is feasible and
  passes the witness test.
- **(C)** Strict-launch v0.x is explicitly scoped to short-running
  tools and incompatible with fork-without-exec daemons. Acceptable
  for AIDE/mkfs/rsync-style first-release use; **not** acceptable
  for postgres/nginx-prefork examples until (A) or (B) lands.

**Feasibility note on (A).** As of mainline kernel 6.x,
`BPF_MAP_TYPE_TASK_STORAGE` does not expose an inherit-on-fork flag
to the BPF side. The realistic answer on the Resolute 7.0 kernel
floor is therefore **(B)** or **(C)**. The Linux team should not
spend cycles searching for (A) before confirming the kernel version
they target actually exposes it. If (B) verifier-clean cost is small
(the spike measured ~1.7% for a single task-storage lookup; a
`task_alloc` copy adds one short-circuited path), prefer (B) over
(C); otherwise default to (C) for v0.x.

## 9. Witness tests

Required tests for the feasibility branch:

```
SL-1 wrapper -> target -> sealed write
expected: allow

SL-2 direct target with LD_PRELOAD -> sealed write
expected: deny strict-launch-missing

SL-3 wrapper -> target -> exec /bin/sh -> target -> sealed write
expected: deny strict-launch-missing and marker_clear_foreign_exec_total +1

SL-4 wrapper -> target -> fork child without exec -> sealed write
expected: allow if marker inheritance/copy is supported; otherwise documented no-go

SL-5 wrapper -> target -> exec helper -> sealed write
expected: deny and marker_clear_foreign_exec_total +1

SL-6 direct target without LD_PRELOAD -> sealed write
expected: deny strict-launch-missing

SL-7 PR_SET_MM_EXE_FILE spoof to actor inode -> sealed write
expected: deny at task_prctl, and prctl_set_mm_exe_file_denied_total +1.
The subsequent sealed-write attempt (with the spoof refused) is denied
at the file-op hook with strict_launch_missing_total +1.

SL-7b PR_SET_MM_MAP spoof to actor inode -> sealed write (Review-1 HIGH-5
amend, 2026-05-15)
expected: deny at task_prctl on the prctl(PR_SET_MM, PR_SET_MM_MAP, &map,
sizeof(map), 0) call itself; prctl_set_mm_exe_file_denied_total +1. The
PR_SET_MM gate now spans all sub-ops so the prctl_mm_map.exe_fd
overwrite cannot reach current->mm->exe_file.

SL-8 external ptrace/process_vm_writev/pidfd_getfd/proc-mem tamper
expected: runtime deny for ptrace and process_vm_writev, with
ptrace_denied_total +1 per blocked op. For pidfd_getfd and
/proc/<pid>/mem, either run negative witnesses (asserting same
counter increments) or cite the target-kernel source path proving
they route through security_ptrace_access_check().

SL-9 policy reload semantics (v0.4 amend: §3a fresh-load-only)
expected (v0.4): the supported reload path is `--unpin` + `--pin`;
the unpin destroys per-task marker storage so re-pin re-launches every
protected actor through its declared launcher. A negative witness
confirms that in-place generation manipulation is not a supported
operator path — the v0.4 loader never bumps generation outside the
pin lifecycle, and the spike's `slm_runner --generation N` knob is
preserved only as forward-compat scaffolding for the v0.5 hot-reload
feature (deferred). See §3a.

SL-10 ringbuf pressure during strict-launch denies
expected: enforcement and BPF counters remain correct even if audit events drop
```

## 10. Performance gates

Minimum measurements:

- Baseline file-open loop with no compartment-bpf.
- Existing exec-domain file-open loop without strict-launch.
- Strict-launch miss path.
- Strict-launch hit path.
- Deny storm with ringbuf drops.
- Exec throughput with `bprm_check_security` marker logic loaded.

Initial acceptance target:

- Strict-launch incremental file-open overhead should be below 5%
  against existing exec-domain actor enforcement on the same kernel.
- Deny counters must remain exact under ringbuf pressure.
- Profile size should not affect hot-path miss cost except through
  normal hash-map behavior.

The existing spike measured roughly 1.7% incremental cost for an
unmarked task-storage lookup on the Resolute VM. That is encouraging,
but not sufficient as release evidence.

## 11. Release decision

If all feasibility gates pass:

- Ship `actor-strict` in the first exec-domain release.
- Prefer `actor-strict` for examples that claim LD_PRELOAD-safe actor
  protection.
- Keep legacy `actor=` for compatibility, but document it as binary
  identity only, not clean-launch identity.

If any hard gate fails:

- Do not claim LD_PRELOAD-safe actor protection in first release.
- Ship the static launcher as defense in depth only.
- Keep the limitation explicit in `LIMITATIONS.md` and
  `EXEC-DOMAIN-SPEC.md`.

The elephant in the room: releasing actor allowlists while implying
they solve hostile env injection would be worse than not releasing the
strict mode. The safe release shape is either strict-launch passes, or
the docs say plainly that `actor=` alone is not clean-launch trust.

## 12. Requested Linux-team deliverable

Create an isolated branch or experimental directory:

```
experimental/strict-launch-marker/
```

Deliver:

- Minimal BPF implementation for marker set/verify/clear.
- Minimal loader or test harness to populate launcher map.
- One static launcher fixture.
- Parser fixture proving `strict-launch` is accepted as a seal flag in
  the same syntactic position as `no-write`, `no-unlink`, `no-rename`,
  `no-chmod`, and `full`.
- Witness tests from section 9.
- Perf CSV from section 10.
- Final report:

```
experimental/strict-launch-marker/results/FEASIBILITY.md
```

The final report should answer one question directly:

> Is strict-launch marker enforcement feasible and small enough for
> first release, or should first release keep actor allowlists labeled
> as non-clean-launch protection?
