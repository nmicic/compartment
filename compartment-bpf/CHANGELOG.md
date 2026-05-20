# Changelog

All notable changes to compartment-bpf are documented here.
Format is loosely based on [Keep a Changelog](https://keepachangelog.com).

## [v0.7] — 2026-05-18

### ABI bump 0x0006 → 0x0007

No struct layout change. `seal_value` remains 88 bytes; `audit_event` unchanged.

- **New audit action codes** (`495b1d6`): split the overloaded
  `ACTION_DENY_STRICT_LAUNCH_MISSING` into three distinct codes so audit consumers
  can distinguish strict-launch side-denies:
  - `ACTION_DENY_PRCTL_SET_MM = 11`
  - `ACTION_DENY_PTRACE_ACCESS = 12`
  - `ACTION_DENY_PTRACE_TRACEME = 13`
- **`_Static_assert` value-drift guards** (`495b1d6`): compile-time asserts on every
  `ACTION_DENY_*` numeric value. Renumbering a code without renaming the symbol now
  fails the build instead of silently shifting wire values.

### Recursive subtree depth cap

- **`COMPARTMENT_MAX_DIR_ANCESTORS` = 8** (`67d73b2`): the recursive-subtree ancestor
  walk is capped at 8 levels (previously 64). Cuts loader startup from ~2.5 s to
  ~630 ms on typical hosts. Overridable at build time via
  `make COMPARTMENT_MAX_DIR_ANCESTORS=<n>` with a `_Static_assert` enforcing the
  range 1..64.
- **Loader fail-closed on over-deep subtrees** (`2fa0d0a`): the loader rejects
  directory seals whose sealed subtree contains a descendant deeper than
  `COMPARTMENT_MAX_DIR_ANCESTORS` rather than silently truncating the walk.
- **Runtime recursive subtree growth guard** (`b265aef`): post-attach `mkdir` /
  `rename`-into-sealed-tree operations that would grow the sealed subtree past
  `COMPARTMENT_MAX_DIR_ANCESTORS` are denied at the BPF hook. Closes the
  time-of-check / time-of-use gap between loader validation and live enforcement for
  the depth cap.

### Alias invariant enforcement (`95bed7a`)

Prevents alias attacks against recursive no-write seals:

- **Symlink creation inside a sealed subtree** denied when the sealed dir carries
  `no-write`.
- **Hardlink create into or out of a sealed subtree** denied unconditionally.
- **Non-directory rename-import of symlinks or multiply-linked files** into a sealed
  subtree denied.
- **Same-seal subtree deepening rename** denied when the parent directory's no-write
  check fires.

### Test fixes

- **LSM-direct PTRACE_TRACEME witness** (`186d6c1`): static helper `slm_traceme`
  exercises the LSM hook directly so `ACTION_DENY_PTRACE_TRACEME` is testable without
  a live strict topology.
- **Depth-cap boundary tests** (`186d6c1`, `72b77cf`): boundary coverage at exactly
  the cap depth, plus a deep rename-into-sealed regression.
- **`--pin` candidate gate fidelity** (`6846312`): the negative path treats a silently
  missing pin path as `nok` rather than `skip`; `abi_version_map` value asserted via
  JSON.
- **`DENY_WRITE_PARENT_DIR` audit witness** (`7a3b9a6`): corrected a test that relied
  only on the return code, adding an audit-line grep to actually witness the deny action.

---

## [v0.6] — 2026-05-18

### ABI bump 0x0005 → 0x0006

No struct layout change; `seal_value`, `audit_event`, `launcher_actor`, `actor_marker`,
and `policy_state` are unchanged on the wire.

- **`abi_version_map` pinned map** (`64339a2`): new `ARRAY[1](__u32)` pinned with
  `LIBBPF_PIN_BY_NAME`. Loader writes `COMPARTMENT_ABI_VERSION` at key 0;
  `compartment-bpf observe` reads it for exact runtime ABI detection. Pre-v0.6 pins
  remain ambiguous (no `abi_version_map`) and are handled fail-safe in userspace
  rather than guessed from map shape.

### Recursive subtree directory seals (`64339a2`)

- **`DIR full` and `DIR no-write` seals** now apply recursively to all descendants
  at enforcement time: write / unlink / rename / create / metadata hooks walk ancestor
  dentries up to `COMPARTMENT_MAX_DIR_ANCESTORS` levels and enforce any matching
  `sealed_dirs` entry in the path to root.
- **`deny_dir_ancestor_action_from_dir_dentry`** helper in `compartment.bpf.c`:
  bounded ancestor walk used by every directory-affecting hook to surface a recursive
  deny consistently.
- **Audit**: recursive denies emit `ACTION_DENY_WRITE_PARENT_DIR` /
  `ACTION_DENY_CHMOD_PARENT_DIR`; the dentry source is in the audit record's path
  field.

### Observe pipeline (`d7b6daa`)

- **BPF ret propagation fixed**: write / unlink / rename hooks now consistently return
  the helper deny code so the observe mesh sees the correct outcome for recursive
  denies.

---

## [v0.5] — 2026-05-16

v0.5 delivers the full **exec-domain** feature set: per-actor identity enforcement,
strict-launch-marker, the observe pipeline, and directory-destination actor seals.

### ABI bump 0x0004 → 0x0005

- **`seal_value.actor_name`** in `compartment-abi.h`: actor-group name stored directly
  in the seal and carried into audit events by the BPF program without a userspace
  lookup that could drift across loader restarts.
- **Dir-destination**: parent-dir write and chmod hooks added; loader enforces symlink
  and hardlink child invariants on actor-sealed directories.

### Exec-domain actor identity

- **Actor-binary seals**: `seal <path> no-write actor=NAME` pins the seal to a specific
  actor group; the BPF hook denies access by any other actor.
- **`actor-strict` mode**: launcher-declared actor seals enforce that the process was
  actually launched through the declared launcher binary, defeating LD_PRELOAD and
  binary-swap attacks against the actor identity.
- **Strict-launch-marker**: five LSM hooks (`task_alloc`, `bprm_check_security`,
  `bprm_committed_creds`, `bprm_creds_from_file`, `task_free`) track whether each
  task was launched under a monitored launcher. Processes that reach sealed paths
  without a valid marker are denied and audited.
- **Observe pipeline**: `compartment-bpf observe` records the inode access pattern
  of a running process and emits a candidate profile for review. Candidate profiles
  carry a `#@compartment-bpf-profile-status: candidate` header so they cannot be
  pinned to enforcement without explicit promotion.

### Security hardening

- **`sanitize_observed_path` whitespace** (`f367c7f`): the `observe` candidate
  profile pipeline rejects space (0x20) and tab (0x09) in observed paths. The profile
  parser tokenizes on these characters; without this check an attacker could create a
  file with an embedded tab to redirect a seal target.
- **`sanitize_observed_path` newline / CR / `#`**: rejects `\n`, `\r`, `#` in
  observed paths, closing the newline-injection path where a crafted filename could
  inject additional `seal` lines into a candidate profile.
- **Launcher self-modification gate** (`f367c7f`): `enforce_actor_binaries_sealed`
  and `strict_validate_launchers` reject any actor-strict launcher seal carrying
  `actor=NAME`. Prevents the actor target from overwriting launcher bytes in-place,
  defeating the LD_PRELOAD-safety guarantee of `actor-strict`.
- **Actor-binary self-modification gate** (`73d51dd`): `enforce_actor_binaries_sealed`
  rejects actor binary seals carrying `actor=NAME`. Prevents the actor from
  overwriting its own binary inode in-place while preserving the (dev, ino) pair.
- **Candidate-profile `--pin` gate** (`daa452e`): `--pin` exits non-zero when the
  profile carries `candidate` status unless `--allow-candidate` is supplied. Prevents
  draft observe output from being pinned to enforcement without review.

### ABI / loader correctness

- **`detect_runtime_abi` probe** (`daa452e`): now probes `abi_version_map` (a map
  with `LIBBPF_PIN_BY_NAME`) rather than `sealed_dirs`; logs ENOENT as WARNING.
- **`libsodium-dev` provisioning** (`daa452e`): README, KVM cloud-init, and Vagrant
  provisioner list `libsodium-dev` as a mandatory build dependency.

### Stability harness (`a01f618`)

- `tests/stability/` landed: `pin-unpin-churn.sh` driver, 10 churn-cycle cases,
  `Makefile` `check-stability` and `check-stability-quick` targets.
- Two full 1024-cycle stability runs on Ubuntu 26.04 / kernel 7.0: 3275 mesh rows
  enforced across all cycles, no bpffs residue, no map leak, no audit drops.

### Hardening code cleanup

- `--unpin` authgate moved inside `pin_lifecycle_lock` to close a tree-swap TOCTOU.
- `dev_to_mountpoint` fallback sanitizes `/proc/mounts`-derived mountpoints
  symmetrically with the procfd branch.
- `tools/compartment-actor-build.sh` DANGEROUS env list now derives from the
  authoritative C header at run time; refuses non-statically-linked outputs.
- `--unpin` authgate and `pin_lifecycle_lock` ordering hardened.

---

## [v0.3] — 2026-05-14

### ABI bump 0x0002 → 0x0003

- **`__u32 version` at offset 0 of `struct audit_event`** (`ff51945`): closes the
  header's own MUST rule. Producer writes `COMPARTMENT_ABI_VERSION` on every event;
  consumer rejects events whose version does not match.
- **`char actor_name[16]` in `struct audit_event`**: carries the actor-group name on
  the actor-mismatch deny path. Truncated to 15 bytes + NUL.
- **`char actor_name[16]` in `struct seal_value`**: loader copies the actor-group
  name into the seal at map-update time so the BPF program can carry it into audit
  events without a userspace lookup that could drift across loader restarts.
- **Sizes**: `audit_event` 72 → 96 bytes; `seal_value` 72 → 88 bytes (LP64, natural
  alignment). `_Static_assert` literals updated.
- **Map compatibility**: v0.1/v0.2 pinned maps must be rebuilt. Repin via `--unpin`
  then `--pin`.

---

## [v0.1] — 2026-04-30

Initial release. Core BPF LSM sealing across 16 inode-level hooks.

### Fixed

- **Duplicate-path seal flags merge** (`eba54f0`): `seal_path` previously called
  `bpf_map_update_elem(..., BPF_ANY)` with only the new flags, silently dropping
  earlier flag bits when a path appeared twice in a profile. Now lookup-merge-update.
  Regression test: `tests/duplicate-seal-merge.sh`.

- **Empty / comment-only profile rejected by default** (`dddcc20`): daemon previously
  attached with zero rules and reached `[run] live` — fail-open indistinguishable from
  "policy not loaded yet." Now refuses unless `--allow-empty` is supplied. Regression
  test: `tests/empty-profile-witness.sh`.

- **`inode_rename` blocks rename INTO a `no-write` directory** (`1c49f4e`): the hook
  AND-masked only `SEAL_NO_RENAME` on `new_dir`, so `seal /etc no-write` did not stop
  `mv attacker_payload /etc/`. New_dir is now masked against
  `SEAL_NO_RENAME | SEAL_NO_WRITE`, emitting `ACTION_DENY_WRITE` for the no-write
  hit. Regression test: `tests/bypass/11-rename-into-no-write-dir.sh`.

- **Ringbuf created before pinning links** (`dcfb5b8`): `pin_links` ran before
  `ring_buffer__new`. A ringbuf failure left 16 pinned programs with no audit reader —
  enforcement live and silent. Reordered ringbuf-first; failure now fails closed with
  no orphan pins. Regression test: `tests/pin-ringbuf-failure.sh`.

- **`sealed_inodes` and `sealed_dirs` frozen after load** (`6554e5d`): both maps were
  left writable after the daemon went live. Root with `CAP_BPF` could
  `BPF_MAP_UPDATE_ELEM` to weaken or wipe seals silently. `bpf_map_freeze` is now
  called on both fds after policy load; subsequent updates return `EPERM`. Regression
  test: `tests/map-freeze-witness.sh`.

### Test pyramid (v0.1)

- 24-cell file-flag matrix (`tests/matrix.sh`)
- 11 bypass scenarios (`tests/bypass/run-all.sh`)
- 10 000-iteration fuzz with reproducible seeds (`tests/fuzz.sh`)
- Three-mode performance bench with 2σ confidence intervals (`tests/bench.sh`)
- Profile smoke, aggregate smoke, pin regression, counter smoke
