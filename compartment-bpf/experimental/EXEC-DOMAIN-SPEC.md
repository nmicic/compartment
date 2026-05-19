# compartment-bpf — Exec-Domain Spec

> Status: draft v0.3, May 2026 — authoritative consolidation of the
>          exec-domain feature family for compartment-bpf
> Audience: implementers, profile authors, reviewers
> Companion to: the future signed-policy / `bpf_gate` design notes and
>               the broader compartment-bpf design rationale
> Prerequisite: v0 enforcement surface (existing seal model)
> Lineage: LIDS exec-domain (1998–2002) — historical motivation
>          for the actor-allowlist property; the author's 2001
>          production deployment used it to protect Oracle datafiles
>          against root-driven tampering. Note: the LIDS family also
>          included a capability-dropping primitive ("make root
>          non-root") that is NOT in this spec. That property is
>          historical motivation only; v0.x of compartment-bpf does
>          not implement capability bounding, and any future
>          treatment of it belongs in a companion tool, not here.

Implementation status (updated 2026-05-14): ED-1..ED-12 closed on
the `exec-domain` branch (Leader-1..Leader-8). ABI v0.3
(audit_event.version + actor_name, seal_value.actor_name) is live;
the BPF-side actor allowlist enforces in 16 LSM hooks; Review-1 +
Review-1b sidebar items closed; ED-8 bypass witnesses, ED-9 AIDE +
ED-10 postgres actor-bound profiles + e2e, ED-11 unpin-passphrase
Argon2id sentinel (action code 7), and ED-12 docs all empirically
validated on the Resolute KVM (kernel 7.0.0-15, BPF LSM active).
ED-13 (full regression pyramid) is the final gate before Sec-4
release; in-flight at the time of this SPEC update. The §10–§12
exec-trust seal is still a separate experimental design and has
NOT shipped.

---

## 1. Scope

This document is the single authoritative spec for exec-domain
enforcement in compartment-bpf. The two sub-features it covers
sit at very different maturity points and the rest of the document
reflects that:

### 1.1 Near-term design — actor allowlist (§2–§9)

Per-seal `actor=GROUP` clause that conditions file-op enforcement
on the calling process's exe inode. AIDE can update its baseline,
root with a different binary cannot. **This is the near-term
design** — the implementation surface is small, the threat model
is well-understood, and the LIDS 2001 precedent shows the
operational shape is workable. The bulk of this spec describes
this feature and treats it as the next concrete work item after
v0.1 stabilizes.

### 1.2 Separate experimental design — exec-trust seal (§10–§12)

A per-cgroup `execve` allowlist enforced via the
`bprm_check_security` LSM hook. Sits in this document because it
belongs to the same "binary identity matters" feature family, but
**it is not at the same readiness level as the actor allowlist.**
Two open problems make it research-only for now:

1. **Direct dynamic-loader execution requires operator
   discipline.** A normal `execve` of a dynamically-linked ELF
   does NOT go through `bprm_check_security` for the dynamic
   loader — the kernel's `binfmt_elf` loads `PT_INTERP` inline
   within the same exec call, no second LSM hook fires. So the
   loader does NOT need to be in `allow-exec` for normal
   binaries to run, and the drafter MUST NOT generate one. The
   only path that triggers `bprm` on the loader is direct
   invocation (`/lib/.../ld-linux-x86-64.so.2 /tmp/evil`); that
   path is denied by default. The risk is operator error —
   adding ld-linux to the allowlist "to be safe" turns the
   direct-loader invocation into a bypass. §12.1 documents the
   discipline.
2. **Library / code-loading is a separate problem.** Shared
   libraries are loaded via `mmap`, not `execve`. Any complete
   "the kernel only runs sealed code" story needs an mmap-exec
   policy alongside the bprm hook; this spec does not specify
   one (§12.3).

Until problem #2 is resolved (mmap-exec policy) and the operator
discipline in problem #1 is exercised against real profiles in
audit-only deployments, exec-trust enforcement is **audit-only
research**. The spec keeps it here so the design space is
recorded, but no production deployment of exec-trust enforcement
is recommended from this document.

### 1.3 Discovery workflow (§13)

Audit-mode profile authoring loop: log every exec attempt without
denying, observe the resulting invocation pattern, draft the
allowlist from ground truth, then enforce. Required scaffolding
for any non-trivial exec-trust rollout, and useful for actor
allowlists too.

### 1.4 Out of scope (§14)

- **Behavioral-LSM / shell-guard.** PPID-chain attestation,
  open-socket policy at exec time, TTY-controlled-terminal checks,
  IP allowlists, forbidden env-var rejection. These belong in a
  sibling tool (`compartment-user` shell-guard, or a dedicated
  `compartment-exec-trust`), not in this BPF LSM. §14 names the
  technical landmines a future BPF implementation would have to
  resolve, so the demarcation is informed rather than assumed.

---

## 2. Actor allowlist — the property

compartment-bpf v0's seal model is inode-keyed and process-uniform:
every seal applies to every process attempting the protected
operation. This forbids modification by *anyone*, including the
file's legitimate owner. It works for read-mostly surfaces (configs,
binaries, certs, host keys) but cannot protect read-write data
files where the legitimate owner *must* write — databases, audit
logs, integrity-check baselines, backup metadata.

The actor allowlist adds the missing primitive: per-seal list of
binaries permitted past the seal. For a given inode `I`, a seal
flag `F`, and a syscall attempt by process `P`, allow the operation
iff one of:

- The seal has no `actor=` clause (current v0 behavior — anyone
  attempting the flagged op is denied).
- The seal has an `actor=GROUP` clause AND `P->mm->exe_file`'s
  `(dev, ino)` is in `GROUP`.

In English: a sealed file with no actor list is uniformly denied
to all processes. A sealed file with an actor list is denied to
everyone except the listed binaries. The actor identity primitive
is the inode of the calling task's current exe
(`task->mm->exe_file`). Same primitive as a seal — file identity is
`(dev, ino)`.

### 2.1 Canonical use cases

| Daemon | Actor binary | Sealed paths | Property protected |
|---|---|---|---|
| AIDE | `/usr/sbin/aide` | `/var/lib/aide/aide.db`, `.new` | Root can't edit baseline; whitewash via `aide --update` is audit-visible |
| auditd | `/sbin/auditd` | `/var/log/audit/audit.log` | Audit logs only written by auditd |
| fail2ban | `/usr/bin/fail2ban-server` | `/var/lib/fail2ban/` | Ban list integrity |
| certbot | `/usr/bin/certbot` | `/etc/letsencrypt/live/` | Cert key rotation only via certbot |
| Oracle | `$ORACLE_HOME/bin/oracle` (path varies by install) | datafiles under `$ORACLE_HOME/oradata/` | Raw db files unreachable to non-oracle |
| postgres | `/usr/lib/postgresql/<v>/bin/postgres` (one binary; workers reuse it via `fork` and rename themselves in `argv`) | `/var/lib/postgresql/<v>/main/` (dir; structural-mutation guard only) + `PG_VERSION` (per-file write protection) | **v0.x scope:** structural mutation guard on the data dir (rename / unlink / chmod of entries) + PG_VERSION sentinel write-protection. Heap files / WAL segments are NOT individually sealed in v0.x (no recursive-subtree-seal primitive); root could `cat > base/<oid>/<n>`. Per-file seals are the v0.x answer for any specific file that must freeze. **v1.x** plans recursive-subtree seal for full data-tree write protection. (R2-F5) |
| journald | `/lib/systemd/systemd-journald` | `/var/log/journal/` | Journal files only by journald |
| chronyd | `/usr/sbin/chronyd` | `/var/lib/chrony/drift` | Drift file integrity |
| borg / restic | `/usr/bin/borg`, `/usr/bin/restic` | backup cache + repokey | Backup metadata integrity |

This is the LIDS exec-domain pattern from 2001 production deployment.

#### Directory-seal semantics (load-bearing for the postgres / oracle / journald rows above)

A seal on a **directory** path (e.g. `seal /var/lib/postgresql/15/main
no-write actor=postgres`) blocks **structural changes** to entries
inside that directory: create, link, unlink, rename, mkdir, rmdir,
mknod, symlink. The kernel hook surface is the parent-directory
inode_* hooks; the dir-seal is consulted on every directory-mutation
LSM check (see §6).

The dir-seal does **NOT** block **in-place writes to existing files**
inside the directory. `cat > /var/lib/postgresql/15/main/PG_VERSION`
opens an existing file and writes to it — the LSM gate for that path
is `file_open` / `file_permission` / `file_truncate` against
PG_VERSION's own inode, not against the parent directory's inode.
For per-file write protection, place a per-file seal:

```
seal /var/lib/postgresql/15/main           no-write actor=postgres
seal /var/lib/postgresql/15/main/PG_VERSION no-write actor=postgres
```

Or a per-extension wildcard if/when SPEC adds one (none today).
This caveat is also documented in the
`profiles/{nginx,postgres,postfix}.conf` headers; cross-reference
those for the operator-facing wording.

---

## 3. Actor allowlist — profile syntax

Actor groups are declared once and referenced by seal:

```
actor aide = /usr/sbin/aide
actor postgres = /usr/lib/postgresql/15/bin/postgres

seal /var/lib/aide/aide.db     no-write no-unlink no-rename actor=aide
seal /var/lib/aide/aide.db.new no-write no-unlink no-rename actor=aide
seal /etc/aide/aide.conf       no-write no-unlink no-rename
seal /usr/sbin/aide            full

seal /var/lib/postgresql/15/main no-write no-unlink no-rename actor=postgres
seal /usr/lib/postgresql/15/bin/postgres full
```

Note: postgres's worker processes (autovacuum, walwriter, bgwriter,
checkpointer, etc.) all execute the same on-disk binary; they
differentiate themselves via `argv[0]` rename after fork. The actor
group only needs the binary's inode listed once — every forked
worker has the same `mm->exe_file` inode.

### 3.1 Syntax rules

- `actor NAME = PATH [PATH ...]` — declares a named actor group.
  `NAME` is a profile-local identifier (`[a-zA-Z_][a-zA-Z0-9_-]*`).
  Each `PATH` is an absolute path resolved to `(dev, ino)` at load
  time.
- `actor=NAME` clause appended to a `seal` line — references a
  previously-declared actor group.
- A seal MAY have at most one `actor=` clause.
- An actor group MAY contain one or more binary paths.
- An actor group MAY be referenced by zero, one, or many seals.
- Forward references are NOT allowed: the `actor X = ...` declaration
  must precede any `seal ... actor=X` referencing it. Loader rejects
  forward references at parse time.
- `full` is shorthand for `no-write no-unlink no-rename no-chmod`.
  Use it in worked examples where the four flags would otherwise
  appear verbatim — most commonly on actor binary seals, which by
  E-6 must carry exactly this set. `full` and `actor=NAME` are
  independent and may appear on the same seal line.

---

## 4. Actor allowlist — numbered requirements

- **E-1.** Every seal MAY have an optional `actor=GROUP` clause.
  Seals without `actor=` retain current uniform-deny behavior.
- **E-2.** Actor identity is `task->mm->exe_file`'s `(dev, ino)`,
  resolved at LSM hook time via BTF CO-RE.
- **E-3.** If `task->mm` is NULL (kernel thread), the seal denies.
  Kernel threads have no exe and cannot match any actor group.
- **E-4.** Forked children share parent's exe inode until they
  exec a different binary. After exec, the child's actor identity
  is the new exe's inode. This matches the kernel's existing model
  for `exe_file` semantics.
- **E-5.** An actor group MAY contain multiple binaries. The check
  matches if ANY binary's `(dev, ino)` in the group matches the
  caller's exe.
- **E-6.** Every binary referenced by an actor group MUST itself be
  sealed `no-write no-unlink no-rename no-chmod`. Decision pending
  in §7.1 — strict (loader refuses) vs auto-seal (loader injects).
- **E-7.** Loader resolves actor paths via two-phase O_PATH+fstat
  resolution (same primitive as seal target paths). TOCTOU
  mitigation already in compartment-bpf v0 applies unchanged.
- **E-8.** Actor lookup at LSM hook time MUST be O(1) average case
  per seal. Implementation choice: inline small array per seal value
  vs external actor-group map keyed by group id. See §6.
- **E-9.** When a sealed access is denied due to actor mismatch, the
  deny event SHOULD carry the actor-group name and the actual
  caller's exe `(dev, ino)`. Audit consumers MUST be able to
  distinguish "denied — no actor list" from "denied — wrong actor."
- **E-10.** When a sealed access is allowed due to actor match, no
  event is generated. Current behavior: successful access is silent.
- **E-11.** The existing BPF `deny_total` counter increments on
  every deny regardless of cause. An additional per-CPU counter
  `actor_mismatch_total` MAY increment specifically when the deny
  was due to actor mismatch.

---

## 5. Actor allowlist — threat model

### 5.1 In scope

- **T-1.** Root (with `CAP_DAC_OVERRIDE` / `CAP_FOWNER`) attempting
  direct file modification via a binary that is not in the seal's
  actor group. Concretely: `vi /var/lib/aide/aide.db`,
  `cat > /var/lib/aide/aide.db`, `rm /var/lib/aide/aide.db`. Denied.
- **T-2.** Root replacing the actor binary on disk with a different
  binary. Mitigation: E-6 — actor binaries are themselves sealed
  against modification. Replacement attempt is itself denied.
- **T-3.** Root mount-namespace tricks attempting to make a
  different binary appear at the actor's path. The kernel's view of
  `task->mm->exe_file` is the post-mount-resolution inode of the
  actually-executed binary. `mount --bind /bin/cat /usr/sbin/oracle`
  followed by `exec /usr/sbin/oracle` makes the exe inode
  `/bin/cat`'s inode, which is not in `actor oracle`. Denied.

### 5.2 Out of scope (named for honesty)

- **T-X1. LD_PRELOAD / LD_AUDIT / LD_LIBRARY_PATH into the actor.**
  Root setting `LD_PRELOAD=/tmp/evil.so /usr/sbin/aide --update`
  runs the legitimate aide binary with attacker library injected.
  The kernel-side check sees `aide` as the caller (exe inode
  matches) and allows the operation. Subversion is in-process.
  *compartment-bpf does not address this.* The defense is at the
  sibling-tool level: compartment-user's env scrub, capability
  bounds, and seccomp filtering on `execve` envs. LIDS 2001 used
  setuid as a workaround (kernel strips LD_PRELOAD for setuid
  binaries); the compartment family does not rely on setuid.

- **T-X2. ptrace into the running actor process.** Root
  `ptrace`-ing the running aide process and injecting code:
  kernel sees aide as the caller. *Out of scope.* Addressed at
  sibling-tool level (kernel YAMA `ptrace_scope`,
  `no_new_privs`, seccomp filters on `ptrace(2)`).

- **T-X3. Compromise of the actor binary itself.** If the attacker
  can write to `/usr/sbin/aide` despite E-6 (e.g., they boot from
  rescue media and edit it offline), all bets are off.
  compartment-bpf does not address offline tampering.

- **T-X4. CAP_BPF process direct map mutation.** Root with
  `bpftool map update` against the seal map can bypass enforcement
  without a kernel-side gate. The v0 model assumes a trusted load
  phase. The defense is future `bpf_gate` work —
  *out of this spec's scope* but compatible with it.

- **T-X5. Exec via interpreter chain — NOT a bypass.** Actor
  `/usr/sbin/aide` exec's `/usr/bin/python /tmp/evil.py`. At the
  next LSM hook, `current->mm->exe_file` is `python`'s inode, not
  `aide`'s. python is not in `actor aide`, so the file access is
  correctly denied. This is the intended behavior — listing it
  here so future readers don't mistake it for a bypass.

---

## 6. Actor allowlist — BPF implementation sketch

For each LSM hook in the seal check chain, after the existing
"inode is sealed with flag X" lookup succeeds:

```c
struct seal_entry *sealed = lookup_seal(dev, ino);
if (!sealed) return 0;                          /* not sealed */
if (!(sealed->flags & FLAG_X)) return 0;        /* op not blocked */

if (sealed->actor_count == 0)
    return -EPERM;                              /* no actor list,
                                                   uniform deny */

struct task_struct *task = bpf_get_current_task_btf();
struct file *exe = BPF_CORE_READ(task, mm, exe_file);
if (!exe) return -EPERM;                        /* kernel thread */

dev_t  caller_dev = BPF_CORE_READ(exe, f_inode, i_sb, s_dev);
ino_t  caller_ino = BPF_CORE_READ(exe, f_inode, i_ino);

for (int i = 0; i < sealed->actor_count; i++) {
    if (caller_dev == sealed->actor[i].dev &&
        caller_ino == sealed->actor[i].ino) {
        return 0;                               /* actor match,
                                                   allow */
    }
}

/* actor mismatch — increment counter, emit audit, deny */
bump_actor_mismatch_counter();          /* per-CPU array lookup;
                                           see the equivalent
                                           helper for deny_total
                                           in compartment.bpf.c */
emit_audit_actor(ACTION_DENY_ACTOR_MISMATCH, dev, ino, caller_dev, caller_ino,
                 sv->actor_name);   /* ABI v0.3 — name carried in seal_value */
return -EPERM;
```

The counter bump is shown as a helper to match how the existing
v0 code increments `deny_total` and `audit_drop_total`: a
`BPF_MAP_TYPE_PERCPU_ARRAY` lookup with key 0, then `(*v)++` on
the returned pointer. Don't copy `per_cpu(...)` from this sketch
verbatim — that's kernel-side userland-helper syntax that has no
BPF equivalent.

### 6.1 Storage choices to resolve

- **Inline actor array in seal value** (fixed-size small array, e.g.
  `actor[4]`). Simple, O(1) bounded. Limits to ≤4 actors per seal.
  Matches OQ-1 default.
- **External actor-group map** referenced by group id in seal
  value. Allows arbitrary group size but adds a map lookup per
  check. Probably required if any actor group needs >4 binaries
  (postgres might).

Recommended: inline `actor[4]` for v0.x with explicit error if a
group exceeds the cap. Defer the external-map design to v0.y if
real groups need more.

### 6.2 Verifier-friendliness notes

- Linear actor scan with a compile-time-bounded loop (≤4) is
  verifier-friendly. No `bpf_loop` needed.
- `BPF_CORE_READ` chain through `task → mm → exe_file → f_inode`
  must handle each step's potential NULL via separate reads with
  guard checks; the BPF verifier requires each pointer access to
  be NULL-checked.
- Use per-CPU temporaries for `caller_dev` / `caller_ino` to keep
  the stack frame small.

---

## 7. Actor allowlist — lifecycle

### 7.1 Actor binary sealing (E-6 enforcement)

Two implementations under consideration; **strict** is recommended
for v0.x:

- **Strict (recommended).** Loader refuses to load any profile
  where a referenced actor binary is not itself sealed
  `no-write no-unlink no-rename no-chmod`. Operator must explicitly
  add the seal for each actor binary in the profile. Loud,
  transparent, matches existing "everything explicit" profile style.

- **Auto-seal (deferred opt-in).** Loader scans declared actors and
  injects default seals automatically, logging the injection.
  Convenient, by-construction. Risk: operator surprised on package
  upgrade when actor binary is silently re-sealed. Available behind
  a future `--auto-seal-actors` flag once the pattern is
  well-understood.

### 7.2 Pin / unpin interaction

- `--pin` captures the actor-group map alongside the seal map under
  the configured pin root (`/sys/fs/bpf/compartment/`).
- `--unpin` removes both, subject to the unpin protection (§7.3).
- Reload semantics: this is **new design work**, not a property
  inherited from v0. v0's `--pin` over an existing pin removes the
  prior maps and creates new ones; there is a brief window where
  no policy is active. With a single seal map and uniform-deny,
  that window is acceptable. With actor groups, two maps must
  swap in lock-step or a reload could leave the seal map referencing
  a stale actor-group id. The minimum needed is a double-buffer
  swap (allocate new pair → atomic pointer swap of both → free old
  pair) or a versioned-tuple in the seal value (`{actor_group_id,
  version}` and a generation counter in a sibling map). Pick a
  shape during ED-2 / ED-3 implementation; the choice belongs to
  this spec's deliverable, not to v0's pin lifecycle.
- Pin lifecycle still owned by the loader; the loader gains the
  double-buffer state machine.

### 7.3 Accidental-unpin guard (optional, not a security boundary)

The pin lifecycle gives root one easy command — `compartment-bpf
--unpin` — that disables every seal. An optional passphrase makes
the command harder to issue *by accident* (typo, runaway script,
copy-paste from documentation):

- `--pin` prompts for a passphrase at load time, or reads it from a
  root-readable file path configured via flag.
- Passphrase is hashed (Argon2id, parameters TBD) and stored as a
  sealed sentinel under the pin root.
- `--unpin` requires the same passphrase. Mismatch → refuse +
  audit event (`EVT_UNPIN_AUTH_FAIL`).

**Honest-framing reframe (2026-05-14).** The
v0 brief originally framed this as "not a security boundary —
accidental-unpin guard". Later review passes flagged the wording as
inconsistent with what was
actually built: libsodium Argon2id (`crypto_pwhash_str`,
`OPSLIMIT_INTERACTIVE` / `MEMLIMIT_INTERACTIVE`, ~70ms +
64MiB) + `sodium_mlock` + dual-channel audit + an ABI-versioned
action code (`ACTION_DENY_UNPIN_AUTH_FAIL = 7`). That is a
credential-gate-grade build.

The honest scope:

- **Against an attacker with CAP_BPF / CAP_SYS_ADMIN on the box,**
  this gate is bypassable. They own the sentinel, the bpffs pin
  tree, and `bpftool prog detach`. The recovery path
  (`rm /run/compartment-bpf/unpin-sentinel; --unpin`) is the
  documented bypass.
- **Against a non-CAP_BPF-restricted root attacker** (uid 0 but
  no CAP_BPF / CAP_SYS_ADMIN: setuid binary, container root with
  bounding-set drops, dropped-capability daemon), the unpin path
  is the only way to weaken seals on a pinned profile, and this
  gate is the wall. Argon2id sets a real work factor (~70 ms +
  64 MiB) on offline brute-force of a captured sentinel.

The dual-channel audit (stderr + syslog `LOG_AUTHPRIV`) makes
every failed unpin attempt durable — silent suppression requires
compromising both channels.

The real defense against malicious unpin by a CAP_BPF-equipped
attacker remains `bpf_gate` (see the future signed-policy work),
which puts an LSM gate on `BPF_PROG_DETACH` and `BPF_OBJ_GET`
from non-agent tasks. That is out of this spec's scope and is not
implemented in v0.x. Until `bpf_gate` lands, a CAP_BPF user can
always disable compartment-bpf on the host; this passphrase
raises the cost for non-CAP_BPF root and forces the bypass to
go through the audited recovery path.

---

## 8. Actor allowlist — bypass surface to test

New bypass cases that the actor allowlist introduces. Each must
have a witness test under `tests/bypass/exec-domain/`:

- **BX-1. Bind-mount-over actor binary.**
  `mount --bind /bin/cat /usr/sbin/oracle; exec /usr/sbin/oracle`.
  Caller's exe inode is `/bin/cat`'s, not in `actor oracle`, denied.

- **BX-2. Mount-namespace decoy.** Attacker creates a private
  mount namespace with a different binary at `/usr/sbin/oracle`,
  exec's, then attempts protected file access. Kernel view of exe
  inode is the new-namespace inode, not in actor group, denied.

- **BX-3. Hardlink of a non-actor binary at a misleading path.**
  Attacker creates `/usr/sbin/oracle.hl` as a hardlink to
  `/bin/sh` and exec's it. The caller's exe inode is `/bin/sh`'s
  (the path is just another directory entry pointing at the same
  inode), which is not in `actor oracle`, denied. The witness
  guards against any future implementation that mistakenly keys
  on a path-derived identity rather than inode identity. *Note:
  a hardlink to the actual actor binary's inode (`ln
  /usr/sbin/oracle /tmp/oracle-alias; /tmp/oracle-alias`) is
  allowed by design — identity is inode-based, and a hardlink
  shares the inode.*

- **BX-4. Exec via interpreter chain — should deny correctly.**
  `/usr/sbin/oracle` exec's `/usr/bin/python /tmp/script.py` which
  attempts to read the sealed dbf. At the LSM hook, current exe is
  python's, denied. (Not a bypass — correct behavior. Witness
  ensures it stays correct.)

- **BX-5. setuid binary as actor.** Actor binary has the setuid
  bit. The setuid bit does not change `exe_file`'s inode; the
  check still works. Witness: invoke `sudo`, `pkexec`, and
  `ssh-keysign` (all setuid-root on a typical Ubuntu install,
  none are sshd's own setuid path) — each exec'd directly, each
  should have an exe inode equal to its on-disk binary, and the
  actor allowlist check should fire correctly regardless of the
  setuid bit. If a small custom setuid fixture is easier to
  control in the test VM, that works too.

- **BX-6. Fork-without-exec children.** Actor forks a child that
  does not exec; child accesses sealed file. Child's exe inode is
  still the actor's (kernel preserves `mm->exe_file` across fork),
  allowed. Correct behavior; witness ensures it.

- **BX-7. In-place modification of the actor binary.** This is
  the case E-6 exists to defend. Without E-6, an attacker can
  open `/usr/sbin/oracle` for write and overwrite the binary's
  contents in place (`dd if=/path/to/attacker-code
  of=/usr/sbin/oracle conv=notrunc`, etc.). The inode does NOT
  change; the actor group still "matches"; but the bytes the
  kernel exec's are now the attacker's. With E-6, the binary
  carries its own `no-write no-unlink no-rename no-chmod` seal
  and the open-for-write fails before any data is written.
  (Note: a path replacement like `mv X /tmp; cp /bin/sh X` is
  *not* the bypass — that creates a NEW inode at the path,
  which the actor group doesn't recognize, so the caller is
  correctly denied. Witness: attempt both shapes; both must
  result in denial — in-place write blocked by E-6, path-swap
  blocked by inode-identity check.)

- **BX-8. exec-followed-by-fork-to-different-binary.**
  `/usr/sbin/aide` exec's, then forks a child that exec's
  `/bin/sh -c 'cat /var/lib/aide/aide.db'`. Child's exe inode is
  `/bin/sh`'s, not in `actor aide`. Denied.

Bypass-suite expansion: 8 new witness tests, modeled after the
existing `tests/bypass/01-..11-*.sh` layout.

---

## 9. Actor allowlist — build prerequisites

For implementation, in rough dependency order. Each is a discrete
piece that can be reviewed independently.

- **ED-1.** Profile parser: recognize `actor NAME = PATH [PATH ...]`
  syntax and `actor=NAME` clause on `seal` lines. Loader emits
  clear parse errors for forward references, unknown actor names,
  malformed lines.

- **ED-2.** Loader: resolve actor paths to `(dev, ino)` via two-
  phase O_PATH+fstat; build per-profile actor-group structure;
  attach to in-memory profile representation.

- **ED-3.** BPF-side data structure: extend `seal_entry` to include
  inline `actor[4]` array + `actor_count` field. Or external
  actor-group map design (§6.1).

- **ED-4.** BPF hook integration: at each of the 16 LSM hooks
  currently in `compartment.bpf.c`, after the existing seal+flag
  check passes, add the actor-match check per §6.

- **ED-5.** E-6 enforcement (strict mode): loader refuses to load
  any profile where a declared actor binary is not also explicitly
  sealed `no-write no-unlink no-rename no-chmod`. Clear error
  message naming the unsealed actor.

- **ED-6.** Audit event extension: deny event carries
  `ACTION_DENY_ACTOR_MISMATCH` reason code (named per
  `compartment-abi.h`; the v0 / pre-implementation drafts of this
  spec called it `EVT_ACTOR_MISMATCH`). Payload includes actor-group
  name (carried in `audit_event.actor_name`, ABI v0.3) and caller's
  exe `(dev, ino)` (carried in `caller_dev` / `caller_ino`, ABI
  v0.2). Schema-version word at offset 0 of `struct audit_event`
  (ABI v0.3 per the header MUST rule); consumer rejects events whose
  version does not match.

- **ED-7.** Per-CPU counter `actor_mismatch_total` alongside the
  existing `deny_total` and `audit_drop_total`. Userspace
  `--stats` reader prints all three.

- **ED-8.** Bypass-suite expansion: 8 new witness scripts per §8
  under `tests/bypass/exec-domain/`. Each script: setup, attempt,
  assert expected outcome, cleanup. `run-all.sh` updated to include
  the new directory.

- **ED-9.** AIDE actor-bound profile + functional test:
  `profiles/aide.conf` with `actor aide = /usr/sbin/aide` and the
  appropriate sealed paths; `tests/profile-e2e/aide.sh` exercising
  `aide --check` (succeeds) and `vi /var/lib/aide/aide.db`
  (denied).

- **ED-10.** PostgreSQL actor-bound profile + functional test
  (`profiles/postgres.conf` + `tests/profile-e2e/postgres.sh`).
  Shipped as the canonical data-directory + actor example because
  Oracle DBMS is not freely installable on a stock Ubuntu /
  virtme image (license-gated, manual download, heavyweight
  rpm-bridged install). The architectural property — one trusted
  writer, everyone else denied at the BPF LSM hook — is identical;
  only the binary path, data dir, and liveness probe differ. See
  `tests/results/exec-domain-decisions/DEC-ED10-A.md` for the
  full rationale. The author's 2001 LIDS Oracle deployment
  remains the historical reference point; an oracle.conf paper
  exercise can land later if a real Oracle-on-Linux deployment
  shows up in the issue tracker.

- **ED-11.** Unpin passphrase (Shape A per §7.3, promoted from
  the §9.1 optional bullet during Leader-7). Pin captures an
  Argon2id-hashed sentinel (libsodium `crypto_pwhash_str`,
  OPSLIMIT_INTERACTIVE / MEMLIMIT_INTERACTIVE); unpin reads
  `COMPARTMENT_BPF_PASSPHRASE` from env (or `getpass(3)` on a
  tty) and verifies with `crypto_pwhash_str_verify`. Mismatch
  produces `ACTION_DENY_UNPIN_AUTH_FAIL = 7` audit event via
  stderr + syslog `LOG_AUTHPRIV` (NOT the kernel BPF ringbuf
  — libbpf has no userspace producer; see
  `tests/results/exec-domain-decisions/DEC-LDR7-B.md`). Sentinel
  is stored at `/run/compartment-bpf/unpin-sentinel`, mode 0600,
  uid 0 (NOT under `${PIN_ROOT}` — bpffs rejects regular file
  creation; see DEC-LDR7-C). Argon2id implementation choice
  rationale: DEC-LDR7-A. §7.3 framing reworked during R2-F6 to
  "credential gate against non-CAP_BPF-restricted root attacker"
  (still not a cryptographic root of trust; that is v1.5
  sealed-agent scope).

- **ED-12.** Documentation: `HOWTO.md` exec-domain section with
  worked AIDE example + unpin-passphrase section; `README.md`
  threat-model paragraph names the actor allowlist explicitly as
  a property delivered by v0.x; `profiles/README.md` references
  the actor= clause + AIDE/postgres examples; this SPEC §9 row
  updated.

- **ED-13.** Regression check: run the full pyramid (smoke,
  pin-passphrase, profile-e2e aide + postgres, bypass legacy +
  exec-domain, matrix, dir-matrix, fuzz, stress, bench,
  profile-smoke, aggregate, pin-regression, counter-smoke)
  against the exec-domain implementation on the
  production-grade KVM (kernel 7.0.0-15 Ubuntu Resolute, BPF LSM
  active). All must remain green. Bench comparison against
  `phase0-v2-baseline` must stay within `NEXT-PHASE-PLAN.md` §2
  INV-3 tolerance for the hot-path open/deny rows.

ED-1 through ED-7 are the kernel + loader work. ED-8 is bypass
coverage. ED-9 + ED-10 are validation against real daemons.
ED-11 is the unpin-passphrase credential gate (promoted from
optional during Leader-7; framing demoted from "speed bump" to
honest "credential gate against non-CAP_BPF-restricted root
attacker" during R2-F6). ED-12 is documentation. ED-13 is the
non-regression gate.

Sizing estimate: ED-1..ED-7 are ~1 week of focused work; ED-8 is
~3 days (one witness per day); ED-9..ED-12 are ~1 week; ED-13 is
running existing tests + the bench comparison. Total: ~2–3 weeks
calendar.

### 9.1 Optional follow-up (not blocking)

(Unpin passphrase moved out of this subsection: promoted to ED-11
during Leader-7 because operator value is real and the
implementation slot stayed cheap. Action code 7 (`ACTION_DENY_UNPIN
_AUTH_FAIL`); see DEC-LDR7-A/B/C. Earlier drafts of this spec
listed it as ED-OPT-1 under this subsection — no longer accurate.)

### 9.2 Implementation handoff

This subsection is the operational orientation for the team
picking up the actor-allowlist work in this repo
(`nmicic/compartment-bpf`, the experimental track). Read §2–§9
in full before starting; §12.1, §12.3, and §14 are required
reading for what NOT to do.

#### Branch and starting point

- **Working branch:** `exec-domain` (single-trunk doctrine; see
  the repo's no-feature-branches rule). ED-1..ED-7 already landed
  here; ED-8..ED-13 land here too. The pre-implementation drafts
  of this spec proposed a `feat/actor-allowlist` branch name; that
  was superseded by `exec-domain` when work actually began.
- **Starting point:** Phase-0 V-N + multi-review-profiles-future
  16/20 (tag `phase0-multi-review-profiles-future`,
  DELIVERY 3e213df). Recorded in the ED-1 commit message for
  bench-baseline reproducibility.
- **Merge target:** `main` of this repo. ED-N work stays on
  `exec-domain` until the canary clears. The public sync to
  `nmicic/compartment-bpf-public` is the operator's responsibility,
  not the team's. Do not push to the public repo or its tags.

```sh
git fetch origin
git checkout exec-domain
git merge --ff-only origin/exec-domain
# ... ED-N work lands here, one commit at a time ...
# After canary passes (see below):
git checkout main && git merge --no-ff exec-domain
git push origin main
```

#### Hard NO-DOs

The most common ways this work goes wrong, captured here so the
implementer encounters them before writing code:

- **NEVER add `/lib/.../ld-linux-*.so.*` to any `allow-exec` or
  actor group.** Normal `execve` of a dynamic ELF does NOT
  trigger a second `bprm_check_security` for the loader (the
  kernel's `binfmt_elf` loads `PT_INTERP` inline). Allowlisting
  the loader turns direct-loader invocation into a bypass.
  See §12.1.
- **NEVER expand `DT_NEEDED` into `allow-exec`.** Shared
  libraries are loaded via `mmap`, not `execve`. Library
  policy belongs to a separate (currently unspecified) mmap-exec
  feature, NOT this work. See §12.3.
- **NEVER implement `scope=global` exec-trust enforcement.**
  System-wide `bprm` deny is deferred indefinitely. The only
  exec-trust shape this branch may add is `scope=cgroup:<path>
  default=audit`. See §11.
- **NEVER add behavioral-LSM (PPID-chain, TTY, env-var,
  open-socket) checks.** Different problem class; belongs in a
  sibling tool. See §14.
- **NEVER weaken E-6.** Every binary referenced by an actor
  group MUST itself be sealed `no-write no-unlink no-rename
  no-chmod`. If the loader can't seal an actor binary (e.g.,
  package upgrade in flight), it MUST refuse to load the
  profile, not silently skip the seal.
- **NEVER silently merge two `actor=GROUP` clauses on the same
  seal.** A seal has at most one `actor=` clause; a second is
  a parse error. The §11 / OQ-5 "multiple actor groups per
  seal" question is deferred to v0.y.

#### Build sequence

ED-1..ED-12 are listed in §9 in dependency order. Each is a
discrete, reviewable commit on `exec-domain`. The
commit boundaries the team should respect:

| Commits          | Scope                                                     | Reviewable as                |
|------------------|-----------------------------------------------------------|------------------------------|
| ED-1, ED-2       | Loader: parser + two-phase path resolution                | "actor= syntax accepted"     |
| ED-3, ED-4       | BPF-side data structures + hook integration               | "actor check fires in kernel" |
| ED-5             | E-6 strict enforcement at load time                       | "unsealed actor → refuse"    |
| ED-6, ED-7       | Audit ABI bump + per-CPU counter                          | "telemetry works"            |
| ED-8             | 8 bypass witness tests (BX-1..BX-8 per §8)                | "bypass surface covered"     |
| ED-9, ED-10      | AIDE + postgres actor-bound profiles + e2e tests          | "real daemon works"          |
| ED-11            | Unpin-passphrase Argon2id sentinel (libsodium)            | "credential gate vs non-CAP_BPF root" (R2-F6 reframe) |
| ED-12            | Documentation: HOWTO + README threat model + SPEC §9      | "operators can use it"       |
| ED-13            | Regression gate: full pyramid + bench comparison          | "ready to merge"             |

Each commit MUST stand on its own: the existing test pyramid
must pass at every commit on the branch, not just at the tip.
Bisect-friendliness is load-bearing for production debugging
later.

#### Verification gates

Run after every ED-N commit, before pushing:

```sh
# Build + unit-test the drafter on macOS or Linux:
make test-profile-draft-unit

# Build + smoke + check on a Linux VM with bpf LSM active:
sudo make smoke
sudo make check
sudo bash tests/pin-regression.sh
sudo bash tests/counter-smoke.sh

# Full regression pyramid (requires the VM to be configured per
# kvm/quickstart-vagrant/README.md or the operator's own setup):
sh tests/matrix.sh
sh tests/dir-matrix.sh
sh tests/bypass/run-all.sh
sh tests/fuzz.sh                 # optional but recommended
sh tests/bench.sh                # compare against starting-SHA baseline
```

**Bench-delta tolerance.** Hot-path open + deny rows must stay
within ±10 % of the starting-SHA baseline numbers (the SHA
recorded in the ED-1 commit message). A regression beyond that
is a HALT — fix before continuing, do not ship the slowdown.

**Counter discipline.** After ED-7, every test run that exits
clean MUST show `deny_total > 0` (the positive controls fire)
AND `audit_drop_total == 0` (the ringbuf keeps up) AND
`actor_mismatch_total > 0` (the new counter fires when actor
mismatch is exercised). If any of those is zero, a test isn't
exercising what it claims.

#### Canary discipline (before merge)

The branch is NOT ready to merge until it has run on at least
one production-like host for **two full weeks** with no
unexpected denies and no `audit_drop_total` increments:

1. Build from `exec-domain` HEAD on a Linux VM.
2. Deploy to a non-critical service on a production-like host
   (the operator will indicate which).
3. Run `compartment-bpf --pin <profile-with-actor-clauses>`.
4. Monitor `--stats` output and audit log for two weeks across
   at least one package-upgrade cycle, one log rotation, and
   one planned reboot.
5. Clean canary = `actor_mismatch_total` only increments on
   probes you ran intentionally. No surprise denies of the
   daemon's own legitimate operation.

If the canary surfaces a regression: fix on the branch,
re-canary the fix for another full cycle. The "two weeks" is a
floor — longer canaries are fine, shorter is not.

#### PR / handoff shape

If the team uses GitHub PRs against this repo
(`nmicic/compartment-bpf`):

- Open one PR per ED-N grouping from the build-sequence table,
  not one giant PR. Easier to review, easier to bisect.
- Each PR's description cites the relevant §9 ED-N bullet(s),
  shows the verification gate output for that scope, and
  includes a bench-delta line for ED-3 / ED-4 / ED-12.
- The merge PR (the final ED-12 regression gate) does the
  squash-vs-merge decision; preference is `--no-ff` so the
  branch shape stays bisectable in `main`'s history.

If the team is not using PRs: the same discipline applies to
commits directly on `exec-domain`. The branch is the
unit of work; `main` stays untouched until canary clears.

#### What "done" looks like

All of the following are true on `exec-domain`:

- ED-1..ED-13 each land as discrete commits, each green on the
  test pyramid.
- BX-1..BX-8 witness scripts all pass.
- AIDE profile e2e test passes; postgres profile e2e test passes.
- Bench delta vs the starting-SHA baseline is within ±10 % on
  hot-path rows.
- `--stats` reports the three counters; counter-smoke validates
  their semantics.
- Documentation (HOWTO actor section, README threat-model bullet)
  reads cleanly without referencing this spec by section number.
- Canary on at least one production-like host has run clean for
  ≥ 2 weeks.

When all of the above hold, the branch is ready for the
`--no-ff` merge to `main` of this (private/experimental) repo.
The operator handles the subsequent sync to the public repo and
the `v0.2.0` annotated tag there.

---

## 10. Exec-trust seal — separate experimental design

Where the actor allowlist (§2–§9) restricts *who* can act on a
sealed file, the exec-trust seal would restrict *what binaries the
kernel will `execve`*. It is a different feature in the same
"binary identity matters" family.

**Status: research / audit-only.** Two unresolved problems
(named in §1.2 and detailed in §12.1 and §12.3) keep this out of
the near-term implementation queue. The design space is recorded
here so the conversation is concrete, but no production deployment
of exec-trust enforcement is recommended from this spec.

The intended shape, if and when the unresolved problems are
addressed:

| | Actor allowlist (`actor=`) | Exec-trust |
|---|---|---|
| Gate | File-op LSM hooks (open, write, unlink, rename, chmod, …) | `bprm_check_security` (the `execve` LSM hook) |
| Condition | Caller's exe inode must be in the seal's actor group | The binary being exec'd must be in the trust allowlist |
| Protects | Specific sealed files from non-actor callers | The execution surface itself |
| Use case | "AIDE updates its DB; nothing else does" | "This cgroup only executes the sealed daemon binaries" |

### 10.1 Policy model — scope and default

Exec-trust is a *policy*, not a *per-inode flag*. Mixing the two
(as earlier drafts of this spec did) confuses two different
shapes — "this specific inode is forbidden" vs "everything in
this scope is forbidden except an allowlist" — that need to read
differently in a profile.

Proposed profile syntax (placeholder; revisit during XD-1):

```
exec-policy scope=cgroup:/system.slice/sshd.service default=deny
    allow-exec /usr/sbin/sshd
    # NOTE: ld-linux is intentionally NOT here. The kernel's
    # binfmt_elf loads PT_INTERP inline within the original
    # exec — no second bprm_check_security fires. Adding the
    # dynamic loader to allow-exec opens a direct-loader bypass
    # (see §12.1). The drafter MUST NOT generate one.
```

Three components, each required:

- **`scope=`** — what set of tasks the policy applies to. v0 of
  this feature SHOULD be `scope=cgroup:<path>` only; system-wide
  scope (`scope=global`) is **deferred** until the §12.1 problem
  has a kernel-side answer. Per-cgroup scope keeps the blast
  radius bounded.
- **`default=`** — the policy outside the allowlist. `default=deny`
  is the protective shape; `default=audit` is the shadow-mode
  shape (see §11.3) and MUST be the only mode in which the policy
  runs until the operator has converged the allowlist.
- **`allow-exec`** — one or more entries naming allowed `(dev,
  ino)` pairs by path. Loader resolves each at load time.

This makes the policy declaration affirmative: the operator states
the scope, the default, and the allowlist explicitly. There is no
"inode flag" hiding the deny-everything-else default behind a
per-line flag.

### 10.2 Numbered requirements

- **X-1.** A profile MAY declare zero or more `exec-policy`
  blocks. Each block carries a `scope`, a `default`, and a list
  of `allow-exec` entries. A profile without any `exec-policy`
  block has no exec-trust behavior; the v0 seal model continues
  unchanged.
- **X-2.** When a task within `scope` performs `execve(I)`, the
  hook returns `-EACCES` iff `default=deny` AND `(dev, ino)` of
  `I` is not in the block's allow-exec set.
- **X-3.** The hook covers ONLY `execve` of the binary itself
  (the `bprm` target) and its `PT_INTERP` loader if specified in
  the ELF header. It does NOT extend to subsequent `mmap` of
  shared libraries — those are file-op operations, not exec
  operations, and belong to a separate mmap-exec policy that this
  spec does not define (§12.3).
- **X-4.** `scope=cgroup:<path>` is the only supported scope in
  v0 of this feature. `scope=global` is deferred until the §12.1
  dynamic-loader problem has a real answer.
- **X-5.** `bprm_check_security` is mandatory in any LSM stack —
  there is no fall-through. A wrong allowlist denies all execs in
  the scope. **`default=audit` (shadow-mode) is therefore
  mandatory before any `default=deny` flip** (§11.3).
- **X-6.** Every binary listed in an allow-exec entry MUST also
  be sealed `no-write no-unlink no-rename no-chmod` — same
  invariant as actor binaries (E-6). A binary allowed to execute
  but not protected against modification is a trivial bypass:
  replace it on disk, the allowlist now blesses attacker code.
- **X-7.** Audit event: when `bprm_check_security` denies an
  exec, emit an event with reason `EVT_DENY_EXEC`, the attempted
  binary's `(dev, ino)`, and the calling cgroup-id. Same event
  shape with `default=audit` but the hook returns 0 (allow). Audit
  consumers MUST be able to distinguish "denied — binary not in
  allowlist" from "denied — wrong cgroup."
- **X-8.** Per-CPU counter `deny_exec_total` alongside
  `deny_total`, `audit_drop_total`, `actor_mismatch_total`.
  Userspace `--stats` reader prints all four. Shadow-mode
  increments a parallel `would_deny_exec_total` so an operator
  can see policy pressure without enforcement.

---

## 11. Exec-trust seal — recommended sequencing

### 11.1 What ships first, second, third

Reversing the order earlier drafts of this spec suggested,
because the system-wide hook is too aggressive for a near-term
public release:

1. **Actor allowlist (§2–§9).** Near-term. This is the bulk of
   the spec and the implementation the project is committed to
   after v0.1 stabilizes.
2. **Per-cgroup exec-trust, audit-only (`scope=cgroup:<path>
   default=audit`).** Experimental. Lets an operator point an
   audit-only allowlist at one service and observe what
   `execve`s actually happen, without risking enforcement
   breakage. No production guarantees.
3. **Per-cgroup exec-trust enforce (`default=deny`).** Only after
   the audit-only phase has converged AND a working recovery
   pathway exists (kernel-cmdline bypass, signed rollback, etc.
   — §12.4). Single-cgroup blast radius is the only acceptable
   first deployment shape.
4. **System-wide exec-trust (`scope=global`).** Deferred
   indefinitely. Not viable until the §12.1 dynamic-loader
   problem has a kernel-side resolution and the recovery tooling
   in step 3 is proven across multiple deployments.

### 11.2 Why per-cgroup first

The hook (`bprm_check_security`) is mandatory in the LSM stack —
a deny return blocks the exec for the affected task. With
`scope=global` and a misconfigured allowlist, the deny applies
to the whole system; recovery may require a serial console. With
`scope=cgroup:<one-service>`, the worst case is one service
unable to spawn workers — disruptive but bounded.

Per-cgroup scope also matches how compartment-bpf profiles are
already organized: one profile per daemon, loaded with that
daemon's `Before=` ordering. Adding an exec-policy block to an
existing daemon profile is incremental; bolting on a system-wide
allowlist is a different deployment shape.

### 11.3 Shadow-mode is mandatory before enforce

Before any `exec-policy` block enforces (`default=deny`):

1. **Audit-only deployment.** Same `exec-policy` block but with
   `default=audit`. The hook returns 0 (allow) but emits an
   audit event for every exec that *would have been* denied,
   and increments `would_deny_exec_total`.
2. **Observation window.** Leave audit-only running for at least
   one full operational cycle: package upgrade, log rotation,
   scheduled jobs, planned reboot. A week is a reasonable floor.
3. **Allowlist refinement.** Every audit event is either a
   legitimate exec the allowlist missed (add it) or an
   illegitimate exec the policy is meant to block (confirm
   before enforce).
4. **Enforce flip.** Only after the audit log is clean across a
   full cycle, change `default=audit` to `default=deny` and
   reload.

The shadow-mode discipline is not optional. A misconfigured
exec-policy is the single highest-risk bricking surface in
compartment-bpf — far above the actor allowlist (which only
denies file ops) or the existing seal flags (which deny
modifications, not new processes).

---

## 12. Exec-trust seal — open issues

§1.2 named two problems. §12.1 is the direct-loader case; §12.3
is the parallel mmap-exec policy. Both must be addressed before
any `default=deny` deployment is recommended.

### 12.1 Operator discipline: do not allowlist the dynamic loader

The Linux dynamic loader (`/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`
on glibc systems) is itself an ELF binary. It can be `execve`'d
directly with another path as `argv[1]`:

```
$ /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /tmp/attacker-binary
```

The kernel sees this as `execve` of the loader. If the loader's
inode is in the exec-policy allowlist, the exec is allowed; the
loader then `mmap`s and jumps into `/tmp/attacker-binary`, which
never went through `bprm_check_security` at all.

**The correct posture is therefore to NOT allowlist the loader.**
A normal `execve("/usr/bin/foo")` of a dynamically-linked ELF
does NOT trigger a second `bprm_check_security` for the loader:
the kernel's `binfmt_elf` reads PT_INTERP and loads the
interpreter inline within the original exec via `load_elf_interp`,
calling `kernel_read` + `elf_map` directly. No second LSM hook
fires. So:

- For normal binaries to run, ld-linux does NOT need to be in
  `allow-exec`. The drafter MUST NOT auto-emit it.
- Direct `/lib/.../ld-linux.so.2 /tmp/evil` *is* a separate exec
  with the loader as `bprm->file`. With ld-linux not in the
  allowlist, this is denied like any other un-allowlisted
  binary.

The risk this section flags is **operator error**: an operator
who adds ld-linux to the allowlist "to be safe" turns the
direct-loader invocation into a bypass. The drafter, the smoke
tests, and a load-time linter (XD-9 below) should reject any
profile that names the dynamic loader in `allow-exec`.

This is "operator discipline that must be enforced by tooling,"
not "unresolved kernel-side problem." The earlier framing in this
spec was wrong: the loader is not load-bearing for normal
exec, so excluding it from the allowlist is the natural shape,
not a workaround.

Note that the actor allowlist (§2–§9) is NOT affected by this
problem at all. The actor allowlist checks the caller's
`mm->exe_file` when a sealed *file* is touched; loader-as-argv0
invocations have the loader's inode as the caller's exe, which
won't be in any sensible actor group for AIDE / auditd /
journald / etc. The actor allowlist still denies correctly.

### 12.2 Bypass surface to witness

For the audit-only / single-cgroup deployment shape, the
following bypass cases still need witness tests under
`tests/bypass/exec-trust/`:

- **XB-1.** Hardlink of an allowed binary to an unprotected path
  + exec the hardlink. Caller's `bprm` references the same inode
  as the original, allowed (correct — inode identity is what's
  allowlisted, not path).
- **XB-2.** Bind-mount an attacker binary over an allowed binary's
  path. Post-mount exec inode is the attacker's, not the
  allowlisted one. Denied.
- **XB-3.** Mount-namespace decoy: a private namespace mounts a
  different binary at the allowed path. Same as XB-2; the kernel
  sees the post-namespace inode. Denied.
- **XB-4.** Direct dynamic-loader execution:
  `/lib/ld-linux-x86-64.so.2 /tmp/evil`. With the loader NOT in
  `allow-exec` (the correct posture; see §12.1), this is denied
  like any other un-allowlisted binary. The witness exercises
  both halves: (a) a normal dynamically-linked binary in the
  allowlist runs cleanly without the loader being allowlisted
  (because `binfmt_elf` loads PT_INTERP inline, no second bprm
  hook); (b) direct loader invocation with attacker code as
  `argv[1]` is denied.
- **XB-5.** Memory-resident exec (`memfd_create` + `execveat
  AT_EMPTY_PATH`, or the unlinked-tmpfs / `fexecve` variants):
  exec'd file is anonymous; its inode is allocated at exec time
  and is not enumerable in advance. Denied by default — desired
  outcome for a paranoid host. **Important caveat:** a paranoid
  host that *also* runs sealed-on-disk-binary distribution like
  `Exec_Enc` legitimately requires this path. The carve-out
  shape is recorded in §15 and `EXEC-DOMAIN-EXEC-ENC-ADDENDUM.md`
  rather than added to the base spec, because the design has
  cross-binary domain-isolation implications (one host running
  multiple encrypted workloads) that need an artifact-side
  declaration to resolve cleanly.
- **XB-6.** Setuid binary in the allowlist. The setuid bit does
  not change inode identity; check still works. Witness: sudo +
  pkexec + ssh-keysign all run if allowlisted.
- **XB-7.** Package upgrade replaces an allowed binary in-place.
  New inode is different; old allowlist entry stale. Either the
  package upgrade itself was denied by `no-unlink`/`no-rename`
  on the binary (per X-6, recommended), or the seal was lifted
  during upgrade and the binary's inode changed → reload
  required.
- **XB-8.** Privileged `unshare` + private mount namespace +
  exec a non-allowlisted binary brought in via the namespace.
  Same inode-identity check as XB-2/XB-3. Denied. Confirms
  namespace work doesn't bypass.

### 12.3 Out of scope here: shared-library / mmap-exec policy

Shared libraries (`libc.so.6`, `libcrypto.so.3`, etc.) are loaded
via `mmap` with `PROT_EXEC`, not via `execve`. The
`bprm_check_security` hook never sees them. A complete "no
unallowlisted code runs in this cgroup" story therefore also
needs an mmap-exec policy: deny `mmap(... PROT_EXEC, ...)` on
files whose `(dev, ino)` isn't on a parallel allow-mmap-exec
list.

That is a separate feature with its own design — different LSM
hook (`security_mmap_file`), different threat model (cover JIT
engines? mprotect-add-exec on existing mappings?), different
deployment posture. This spec does not specify it.

What this spec does NOT do:

- It does not list `DT_NEEDED` libraries in `allow-exec`. Earlier
  drafts of this section did, conflating `execve` with `mmap`.
  Libraries are not exec'd; allowlisting them under `allow-exec`
  is type-incorrect.
- The profile-drafting tool (`tools/profile-draft.py`) MUST NOT
  expand `DT_NEEDED` into `allow-exec`. If/when a parallel
  mmap-exec policy is specified, library expansion belongs there.

### 12.4 Build prerequisites

- **XD-1.** Profile parser: recognize the `exec-policy` block
  syntax (`scope=`, `default=`, `allow-exec`). Parser rejects
  unknown scope values, unknown default values, malformed paths.
- **XD-2.** BPF-side: attach `bpf_lsm_bprm_check_security`
  (kernel ≥ 5.7). Read `bprm->file->f_inode`'s `(dev, ino)`.
  Read calling task's cgroup id via `bpf_get_current_cgroup_id()`.
  Look up the scope's allow-exec set; deny iff
  `default=deny && !found`.
- **XD-3.** Audit ABI: extend `struct audit_event` with reason
  code `EVT_DENY_EXEC`. Reuse the existing `(dev, ino)` fields
  to carry the exec'd binary; add the cgroup-id where applicable.
- **XD-4.** Per-CPU `deny_exec_total` + `would_deny_exec_total`
  counters; `--stats` extended.
- **XD-5.** Shadow-mode (`default=audit`): hook returns 0,
  emits audit event, increments `would_deny_exec_total`. **This
  is a new requirement, not an inherited feature** — the v0
  public code does not currently implement an audit-only flag at
  any LSM hook; this work introduces it.
- **XD-6.** Recovery story: kernel-cmdline bypass for a bricked
  exec-policy. **This is also a new requirement.** v0 does not
  currently support a boot-time disable; the closest existing
  mechanism is "don't load the daemon on boot." Concretely:
  a `compartment.disable=1` kernel cmdline option, read by the
  daemon at attach time, makes it refuse to install any pinned
  link. This must land BEFORE any `default=deny` deployment
  outside the developer's own VM, because a bricked exec-policy
  on a remote server has no other recovery short of single-user
  console.
- **XD-7.** 8 new bypass witness tests per §12.2 under
  `tests/bypass/exec-trust/`. XB-4 stays in shadow-mode only —
  it documents the unresolved bypass, not an enforced check.
- **XD-8.** One worked audit-only profile for the smoke gate:
  sshd or chronyd with `exec-policy scope=cgroup:... default=audit`
  on a small surface, allowlist generated by the drafter.
  Demonstrates the shadow-mode discipline by example. No enforce
  smoke until §12.1 is resolved.

Sizing: XD-1..XD-4 are ~1 week of focused work. XD-5 and XD-6
are the new infrastructure (audit-flag plumbing, kernel-cmdline
bypass) — likely a separate week each because they touch the
loader and the daemon's lifecycle. XD-7 + XD-8 are ~3 days.
Total: ~3 weeks calendar for audit-only deployability. Enforce
mode is not on this estimate.

---

## 13. Discovery workflow

A useful exec-trust profile cannot be drafted by reading source.
The set of binaries a daemon legitimately needs at runtime depends
on the host's package version, the daemon's configuration, the
admin's ad-hoc tooling, and the maintenance windows the daemon
sees. Ground truth comes from observation.

### 13.1 Two strategies

**A. Audit-only deployment of compartment-bpf itself.** Install
an `exec-policy` block with `default=audit` on the daemon's cgroup
(or, for initial discovery, on a wide cgroup in a test
environment). The hook returns 0 on every exec but emits an audit
event recording the `(cgroup, exe_dev, exe_ino, ppid_chain)`.
Aggregate the events into the JSONL format (§13.2) to produce
the allowlist input.

Pros: uses compartment-bpf as its own discovery instrument; no
separate tool needed. Hooks the exact same paths the final
enforcement will hook, so observation has zero fidelity gap.

Cons: requires the BPF program + audit ringbuf to already be
correct enough to attach and emit events. Discovery is therefore
gated on the implementation of the rest of this spec.

**B. Sibling user-space discovery tool.** A user-space monitoring
process (the original shell-guard pattern, runnable via
`compartment-user` or as a dedicated tracer using `perf` /
`bpftrace`) logs every `execve` call without trying to block.
Aggregates by daemon. Produces the allowlist input as a static
artifact.

Pros: independent of compartment-bpf. Can be run on a host that
hasn't deployed the BPF LSM yet. Lower risk during discovery
(no kernel state involved).

Cons: a separate tool to build and maintain. May lose fidelity
relative to compartment-bpf's exact LSM-hook view of `execve`.

### 13.2 Output format

The discovery output is JSON Lines (JSONL) — one observation per
line, each line a self-contained JSON object. Paths, command
names, and parent-chain elements can all contain whitespace,
quotes, and unicode; whitespace-delimited formats are unsafe and
have been deliberately rejected here:

```jsonl
{"cgroup":"/system.slice/sshd.service","exe":"/usr/sbin/sshd","exe_dev":64769,"exe_ino":2228420,"ppid_chain":["systemd","sshd"],"count":4291,"first_seen":"2026-01-01T03:14:07Z","last_seen":"2026-01-14T23:51:02Z"}
{"cgroup":"/system.slice/sshd.service","exe":"/bin/login","exe_dev":64769,"exe_ino":2228612,"ppid_chain":["systemd","sshd"],"count":87,"first_seen":"2026-01-02T08:00:11Z","last_seen":"2026-01-14T18:22:04Z"}
{"cgroup":"/system.slice/sshd.service","exe":"/usr/bin/bash","exe_dev":64769,"exe_ino":2229001,"ppid_chain":["systemd","sshd","login"],"count":87,"first_seen":"2026-01-02T08:00:11Z","last_seen":"2026-01-14T18:22:04Z"}
```

Fields:

- `cgroup` — full cgroup path of the calling task at exec time.
- `exe` — absolute path of the binary as seen by the kernel.
- `exe_dev`, `exe_ino` — the resolved `(dev, ino)` pair that BPF
  will key on. This is the load-bearing field; `exe` is for
  human diagnostics.
- `ppid_chain` — array of parent process names back to PID 1.
  Names only (not paths); used for grouping similar invocations
  in the drafter's diff view.
- `count`, `first_seen`, `last_seen` — observation statistics so
  the operator can distinguish "ran once at install" from "runs
  every cron tick."

The drafting tool (a planned extension of `tools/profile-draft.py`)
ingests JSONL and emits an `allow-exec` block for each unique
`(exe_dev, exe_ino)` observed in the relevant cgroup, with the
observation count and date range carried into the generated
profile's comment header so the operator can see what's
load-bearing.

### 13.3 Convergence loop

The same loop runs for both shadow-mode refinement (§11.3) and
initial discovery:

1. Run with no policy / audit-only policy.
2. Collect exec records for a full operational cycle.
3. Filter: every record is either expected (add to allowlist) or
   suspicious (investigate, do not allowlist).
4. Generate or refine the profile from the expected set.
5. Re-deploy with the new profile in audit-only mode.
6. Loop until the audit log is silent.
7. Flip to enforce.

This is the LIDS `mklidsconf` discipline applied to
compartment-bpf. The historical reference is the LIDS 2001
deployment cycle: typically two to four iterations before a
production-ready profile.

---

## 14. Out of scope: behavioral-LSM / shell-guard

A natural-sounding next ask is "extend compartment-bpf to also
gate execs on properties of the *calling environment*: PPID chain,
controlling-TTY presence, open-socket policy, IP allowlist,
LD_PRELOAD-style env var rejection."

That property is genuinely useful (the original shell-guard tool
from the early 2000s implemented it in userspace). **It does NOT
belong in compartment-bpf.** It is a different problem class:

- compartment-bpf is a file-sealing LSM. Its primitive is
  `(dev, ino)` and its enforcement is binary-identity-keyed
  (caller exe inode for the actor allowlist, exec'd binary inode
  for the exec-trust seal).
- The behavioral-LSM property is per-task state about the *calling
  environment*, not file identity. It needs PPID-chain attestation,
  socket-fd inventory, signal-state inspection, environment-string
  filtering. Different data shapes, different lifecycle, different
  threat model.

Mixing the two under the same umbrella has been considered and
rejected. The right home is a sibling tool (`compartment-user`'s
shell-guard track, or a dedicated `compartment-exec-trust`).

### 14.1 Technical landmines for a future BPF behavioral-LSM

If anyone implements the behavioral-LSM property in BPF later —
whether in this repo, a sibling, or an unrelated project — the
following are non-trivial and have been mis-stated in prior
sketches. Capturing them here so the demarcation is informed
rather than dismissive:

- **`task->real_parent` walks need per-hop reference handling.**
  The BPF verifier does NOT catch a missing `bpf_task_acquire` /
  `bpf_task_release` pair statically. A naive PPID walk that
  reads `task->real_parent->real_parent->…` without per-hop
  acquire is incorrect even though it verifies; it can read freed
  memory if a parent task exits during the walk. Any such walk
  must use `bpf_task_acquire(parent)` at each hop and pair with
  `bpf_task_release` before the next dereference.

- **Verifier loop budget bounds the chain depth.** The BPF
  instruction-count limit and the verifier's per-program total
  bound the depth of any unbounded loop. In practice, the
  walkable PPID-chain depth is ~3–4 hops, not arbitrary. A spec
  that says "walk the full PPID chain" is wrong: the
  implementation must state the bound and the behavior when the
  bound is exceeded.

- **`task->signal->tty` is conditionally NULL.** A task without
  a controlling terminal (every daemon under systemd) has
  `task->signal->tty == NULL`. The `tty_struct` layout itself
  changed between kernel 5.15 and 6.1; BTF CO-RE handles the
  layout drift but the NULL handling has to be explicit per
  read. A behavioral-LSM design that relies on TTY presence
  must state its kernel-version floor and its handling of the
  NULL case (allow? deny? log-only?).

- **`real_parent` vs `parent` semantics.** Under ptrace, the
  kernel distinguishes the original parent (`real_parent`) from
  the tracer (`parent`). A behavioral-LSM design that fails to
  pick the right one is exploitable: an attacker who can
  `ptrace`-attach to a task can make `parent` be themselves
  while `real_parent` is the legitimate launcher.

- **The right primitive for per-task state is task-storage.**
  `bpf_lsm_task_alloc` + `BPF_MAP_TYPE_TASK_STORAGE` is the
  correct primitive for any "remember something per process from
  birth to exit" data. A global hash map keyed by pid has worse
  liveness semantics and is exploitable via pid reuse. A
  behavioral-LSM design that proposes pid-keyed global maps is
  drafting the wrong shape.

These notes are not blocking compartment-bpf v0.x in any way.
They are recorded here for the same reason the threat model lists
T-X1..T-X4: so the next reader who reaches "we should add this"
encounters the technical surface up front and can scope
accordingly.

---

## 15. Interop addendum — anonymous-inode exec (Exec_Enc)

The base spec assumes every exec target has a stable `(dev, ino)`
known at policy-load time. That assumption breaks for any system
that decrypts ELF binaries to memory-resident execution contexts:
the canonical case is `memfd_create` + `execveat(fd, "", argv,
envp, AT_EMPTY_PATH)`, where the inode is allocated at exec time
and is not enumerable in advance. The unlinked-tmpfs fallback
(`/dev/shm/elfdec-NNN`, then `unlink`, then `execveat`) has the
same property.

A strict `EXEC_ALLOW`-only deployment in enforcement mode denies
every such workload. Sibling project `Exec_Enc` (sealed-on-disk
ELF distribution for hosts where root is not trusted — see
references) is the concrete instance the addendum below was
written against, but the design generalizes to anything using
memfd / unlinked-tmpfs exec.

### 15.1 The cross-binary isolation point

A naive "anon-exec allowed for the unpacker" carve-out collapses
per-workload isolation: two encrypted workloads through the same
unpacker would land in one merged domain. The addendum's fix is
that the workload's domain is a property of the artifact (declared
in the AEAD-covered header and read by the kernel from a claim map
the unpacker writes between decrypt and `execveat`), not of the
unpacker. The unpacker is a transport.

### 15.2 What the addendum proposes

Two reserved TLVs in the future signed-policy design — `EXEC_DELEGATE`
(0x07) and `DOMAIN_CLAIM_MAP` (0x08) — plus `DOMAIN_FLAG_ALLOW_ANON_EXEC`
on `DOMAIN_DEF`. Six requirements (R-22..R-27 in the addendum's
numbering) wire `bpf_gate` to admit claim-map writes only from
unpacker-tagged tasks, set the `DOMAIN_UNPACKER` task-storage bit
in `bprm_check_security`, gate `bprm` on the unpacker tag plus a
valid claim, and apply one-shot deletion + `task_exit` reaping.
Three threats (T-7..T-9) cover compromised unpacker, forged
artifact, and operator domain-misdeclaration. Full design lives in
the addendum (§15.6).

### 15.3 Required changes to this spec if the proposal is adopted

If/when the addendum is accepted, the following edits are owed
to this document:

- **§12.2 XB-5** is already updated to cross-reference the
  addendum. The "denied by default — desired outcome" framing
  remains true for the bare exec-trust seal; the addendum
  provides the per-domain carve-out without removing the closure.
- **§12.4 build prerequisites** gain an XD-9 (claim-map BPF
  object + `bpf_gate` extension) and XD-10
  (`bprm_check_security` anon-exec carve-out + task-storage
  unpacker bit). These slot before any production deployment
  that hosts encrypted workloads.
- **§13 discovery workflow** gains a note that anonymous-inode
  exec records in the JSONL format will have `exe_dev` /
  `exe_ino` pointing at memfd / tmpfs storage; the drafter
  consuming them should recognize this class as
  "addendum-governed, not allow-exec-governed."
- **§18 What this is NOT** gains a bullet clarifying that even
  with the addendum, the spec does NOT verify the content of an
  anonymous-inode binary; trust is delegated to the unpacker's
  authenticated decrypt step. (Already added.)

### 15.4 Open questions the addendum names

The addendum's §6 lists five interop questions (one global claim
map vs per-unpacker; task-storage vs hash map; pin path; one
claim per task vs multi-domain; audit fan-out). Resolving them
belongs to compartment-bpf maintainers rather than the Exec_Enc
side. None block adoption in principle; all influence the wire
shape the verifier program will need to handle.

### 15.5 Relationship to §12.1 (dynamic-loader bypass)

The addendum's design partially mitigates §12.1 for the
encrypted-workload class: any task attempting an anon-exec must
both be unpacker-tagged AND have a non-zero claim. It does NOT
mitigate the loader-as-`argv[0]`-with-disk-binary-as-`argv[1]`
bypass (that case exec's a stable allowlisted inode — the
loader — with attacker code as data, not anon-exec). §12.1
remains unresolved for the disk-binary case; the addendum
explicitly does not claim to fix it.

### 15.6 Where to read the full proposal

`experimental/EXEC-DOMAIN-EXEC-ENC-ADDENDUM.md`. Self-contained;
includes the wire-format additions Exec_Enc commits to on its
side, the phased implementation table, and the threat model
additions (T-7 / T-8 / T-9 in the addendum's numbering).

---

## 16. Open questions

- **OQ-1.** Maximum actors per inline group. `actor[4]` is the
  recommended default for v0.x. Daemon ecosystems that ship
  multiple distinct binaries against shared state — dovecot's
  imap-login / pop3-login / lmtp / indexer-worker / auth all
  running against `/var/lib/dovecot/`, for example — would push
  past 4. (Postgres is NOT a multi-binary case: its worker
  processes all fork from the same `postgres` binary and rename
  themselves via `argv[0]`, so one actor entry covers the
  family.) Decide on whether to raise the cap or move to an
  external actor-group map (§6.1) based on the first real
  multi-binary profile attempt.

- **OQ-2.** Should `actor=GROUP` compose with a future `audit`
  flag (per-deny event without actually denying)? Useful for
  migration: declare an actor group, observe which other processes
  hit it, decide whether to expand the actor list before enforcing.
  Recommended: yes; `audit` is orthogonal to the actor check.

- **OQ-3.** Globbing in actor declarations
  (`actor X = /usr/lib/postgresql/15/bin/*`)? Risks: globs are
  expanded at load time, meaning new binaries added post-load are
  not in the actor set. Defer to per-binary explicit declaration
  in v0.x. Revisit in v0.y if package upgrades make this painful.

- **OQ-4.** Should fork-without-exec children drop actor identity?
  Currently they inherit (E-4). Probably not for v0.x — there's no
  concrete attack the inheritance enables, and dropping it would
  break legitimate daemons that fork workers.

- **OQ-5.** Multiple actor groups per seal?
  `seal /var/log/foo actor=daemon-A actor=daemon-B`. Allows two
  different daemons to write the same log file. Defer to v0.y
  unless concrete demand surfaces. Workaround in v0.x: union the
  binaries into one actor group.

- **OQ-6.** Should profile syntax support reading actor binaries
  from `/var/lib/dpkg/info/<pkg>.list` to auto-populate? "All
  binaries owned by package postgresql-15" is a common pattern.
  Defer to the profile-drafting tooling (`tools/profile-draft.py`);
  this spec stays explicit.

- **OQ-7.** Audit event ABI bump. Adding actor-mismatch reason and
  caller exe `(dev, ino)` to the audit event extends the struct.
  Land the ABI bump as part of ED-6 and reuse the same bump for
  the exec-trust seal (XD-5) so consumers handle one version
  change, not two.

- **OQ-8.** When (if ever) to lift the §11.1 ordering. v0.x of
  exec-trust ships per-cgroup audit-only only; `default=deny` and
  `scope=global` are explicitly later milestones. Trigger for
  revisiting either: §12.1 dynamic-loader problem has a
  kernel-side answer, AND the recovery tooling in XD-6 has been
  exercised on at least one real bricked deployment without data
  loss.

- **OQ-9.** Whether the mmap-exec policy (§12.3) lives in this
  spec or its own. Currently treated as "out of scope here,
  separate design." If the actor-allowlist v0 lands and the
  exec-trust audit-only phase converges, the mmap-exec piece
  becomes the next natural extension and may warrant pulling
  into this document. Decide based on whether the bprm-side and
  mmap-side designs end up sharing infrastructure.

---

## 17. References

- Future signed-policy / `bpf_gate` work — compatible with this
  spec; not required. Shape B for unpin protection.
- Broader compartment-bpf design rationale — this exec-domain family
  slots into the daemon's existing inode-keyed seal model without
  changing the management-plane assumptions.
- `tools/profile-draft.py` — drafting tool that this spec extends
  with discovery-input ingestion (§13). DT_NEEDED expansion is
  explicitly NOT part of this spec; libraries are loaded via
  mmap, not execve, and belong to a separate mmap-exec policy
  (§12.3).
- `experimental/EXEC-DOMAIN-EXEC-ENC-ADDENDUM.md` — third-party
  interop proposal from the sibling `Exec_Enc` project. Status:
  proposal, not adopted. §15 of this spec summarizes the
  proposal; the addendum is the long form. See also `Exec_Enc`
  itself (sealed-on-disk ELF distribution for hosts where root
  is not trusted) and its `SECURITY.md` for the threat model
  that motivates the anon-exec carve-out.
- LIDS `mklidsconf` (1998–2002) — convergence-based profile
  generation in the LIDS substrate; the conceptual ancestor of
  both this spec's exec-domain features and the
  `tools/profile-draft.py` direction.
- AIDE — `https://aide.github.io/`. Canonical use case for the
  actor allowlist: integrity-check baseline DB protected against
  root tampering.
- The kernel-side primitives this spec relies on:
  - `task->mm->exe_file` for caller-exe identity.
  - `bprm_check_security` LSM hook for exec-trust enforcement.
  - `BPF_CORE_READ` for CO-RE-safe pointer chains.
  - `bpf_get_current_cgroup_id()` if §11 alternative B is chosen.

---

## 18. What this spec is NOT

- **Not a sandbox.** Does not restrict what an actor binary or
  allowlisted binary can do once running. Caller behavior is in
  compartment-user / shell-guard territory.
- **Not capability filtering, not "make root non-root".** Does
  not restrict syscalls or capabilities. The LIDS family
  historically included a capability-dropping primitive
  ("make root non-root inside an exec domain"); that is
  historical motivation for the actor allowlist's *shape*, not
  a v0.x guarantee of this code. If a future companion tool
  delivers capability bounding, it lives outside compartment-bpf.
- **Not a complete "only allowlisted code runs" claim.** Even
  with exec-trust enforced, shared libraries are loaded via
  mmap and are not gated by `bprm_check_security`; the
  dynamic-loader direct-execution path (§12.1) is unresolved.
  An honest reading of the exec-trust feature is "denies
  `execve` of binaries not in the allowlist," not "no
  unallowlisted code ever runs in this cgroup."
- **Not a process-identity attestation system.** Trust in any
  binary's identity comes from the binary being itself sealed
  against modification (E-6 for actors, X-6 for exec-trust),
  not from cryptographic measurement. TPM / IMA integration is
  future signed-policy territory.
- **Not anonymous-inode content verification.** Even with the
  Exec_Enc addendum (§15) adopted, the spec does NOT verify what
  bytes the kernel runs from an anonymous inode; trust is
  delegated to the unpacker's authenticated decrypt step, which
  is the unpacker's contract, not the kernel's. A tampered
  unpacker is denied by the addendum's `bpf_gate` rule (R-23 in
  the addendum), but a legitimate unpacker that has been
  subverted in-process (via `LD_PRELOAD` etc., already named in
  T-X1) is in compartment-user / Exec_Enc-Mode-B territory.
- **Not LD_PRELOAD protection** (T-X1). compartment-user
  handles that strand.
- **Not behavioral-LSM** (§14). Different problem class; explicit
  technical landmines named so the demarcation is informed.
- **Not boot-time enforcement.** Same property as the rest of
  compartment-bpf: BPF LSM enforcement is runtime-only; reboot
  drops everything. Operator must reload before sealed services
  start. This spec inherits that property unchanged.
