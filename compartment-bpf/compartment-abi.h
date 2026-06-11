// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
//
// compartment-abi.h — shared wire/ABI definitions between the BPF
// producer (compartment.bpf.c) and the userspace consumer
// (compartment-bpf.c). Single source of truth for SEAL_* / ACTION_* /
// struct inode_key / struct audit_event so the two translation units
// cannot drift silently.
//
// Both includers must supply __u32 / __u64 before including this
// header: the BPF side gets them via vmlinux.h, the userspace side via
// libbpf's <bpf/bpf.h> chain.
//
// ABI bump rule (audit_event): the FIRST schema change MUST add
// `__u32 version` at offset 0 so future consumers can detect layout,
// then bump the _Static_assert below. Do not ship a schema change that
// does not bump the version. v0.3 honours this rule (the v0.1/v0.2
// bumps did not, which the v0.3 rewrite closes).
//
// ABI v0.1 — exec-domain (actor allowlist) extension. Seal map value
// widened from __u32 to struct seal_value (72 bytes). actor_count == 0
// preserves v0 uniform-deny semantics; backward-compatible at the
// profile-grammar level (existing profiles parse unchanged),
// forward-incompatible at the map-shape level (old v0 pinned maps must
// be repinned).
//
// ABI v0.2 — exec-domain audit extension. struct audit_event
// grew 56 → 72 bytes: two new __u64 fields caller_dev / caller_ino
// carry the caller-exe identity on the actor-mismatch deny path. New
// ACTION_DENY_ACTOR_MISMATCH (=4) reclaimed the historical gap.
//
// ABI v0.3 — closes the MUST-rule violation and adds actor-group
// name to audit .
//  * struct audit_event grows 72 → 96 bytes:
//    - `__u32 version` at offset 0 per the MUST rule. Producer writes
//      COMPARTMENT_ABI_VERSION; consumer rejects mismatches loud and
//      skips the event (does not try to parse a foreign layout).
//    - `__u32 _pad0` explicit padding for ts_ns alignment (matches what
//      the compiler would emit; spelled out so layout is unambiguous).
//    - `char actor_name[16]` carries the actor-group name on the
//      actor-mismatch deny path; empty for all other event types.
//      Truncated to 15 bytes + NUL (matches comm[16] precedent).
//  * struct seal_value grows 72 → 88 bytes:
//    - `char actor_name[16]` alongside actor[4] + actor_count. Loader
//      populates from actor_group->name at map_update time, so
//      actor_check_or_deny copies the name into the audit event
//      WITHOUT a userspace-side lookup table that could drift across
//      loader restarts. Security: audit fidelity wins.
//  * Both _Static_assert literals updated to compiler-verified sizes
//    (96 and 88 on LP64 with natural alignment).
//  * Pinned maps and audit ringbuf consumers from v0.1/v0.2 must be
//    rebuilt — repin via `--unpin` then `--pin` cycle.
//
// ABI v0.4 — strict-launch-marker promotion. Adds the LD_PRELOAD-safe
// actor enforcement primitive (strict-launch markers); see
// HOWTO.md §2.3.x.
//  * New seal flag bit: SEAL_STRICT_LAUNCH = 1U << 5. When set, file
//    operations on the seal require a valid strict-launch marker in
//    addition to the existing actor= inode check. Closes LD_PRELOAD on
//    actor binaries (the SPEC §1 headline gap).
//  * New action code: ACTION_DENY_STRICT_LAUNCH_MISSING = 8. Emitted on
//    file-op denies when a strict-launch seal is hit without a valid
//    marker (missing, slot mismatch, generation mismatch, or exe-inode
//    mismatch). Distinct from ACTION_DENY_ACTOR_MISMATCH=4 so a false-
//    green test cannot confuse "normal actor deny" with "missing marker
//    deny" with "ringbuf loss".
//  * struct seal_value grows 88 → 96 bytes:
//    - `__u32 strict_actor_slot` (0 when SEAL_STRICT_LAUNCH not set).
//      The slot identifier the marker must match. The loader populates
//      it from the seal's bound actor group's stable slot id at
//      bpf_map_update_elem time.
//    - `__u32 strict_generation` (0 when SEAL_STRICT_LAUNCH not set).
//      Wraps at 255; loader rejects a strict actor whose marker
//      policy_generation does not match this value. Mirrors
//      policy_state.generation at load time. v0.4 is fresh-load-only
//      (SPEC §3a) — the loader never bumps
//      generation after the initial `--pin`. The dual-side check is
//      forward-compat scaffolding for a future hot-reload feature;
//      Stale markers
//      from a prior policy generation are rejected at re-pin time
//      because the per-task `actor_marker` storage is destroyed
//      alongside the policy maps at `--unpin`.
//  * struct launcher_actor (NEW, 16 bytes): value type for the
//    `launcher_to_actor` HASH map. Key is struct inode_key (file_id).
//    Loader populates from `actor-strict` declarations.
//  * struct actor_marker (NEW, 24 bytes): value type for the
//    `actor_marker` TASK_STORAGE map. The kernel marker carried per-task.
//  * audit_event stays 96 bytes. New action code distinguishes the
//    strict-launch path; the existing caller_dev/caller_ino/actor_name
//    payload is reused. _Static_assert(sizeof(audit_event) == 96) is
//    unchanged. The strict-launch deny carries the actor name in the
//    same slot as actor-mismatch denies for log-correlation continuity.
//  * Pinned maps from v0.3 must be rebuilt — the seal_value shape grew.
//    check_pinned_seal_map_shapes() will reject a 88-byte pinned map
//    fail-closed on v0.4.
//
// ABI v0.5 — directory-destination actor seals (DIR-DESTINATION-ACTOR-SEALS-SPEC.md).
//  * New action codes:
//    - ACTION_DENY_WRITE_PARENT_DIR  = 9. Emitted by the write-path hooks
//      (file_open, file_permission, file_truncate, mmap_file, file_mprotect)
//      when the *parent directory* of the target file has a SEAL_NO_WRITE
//      entry in sealed_dirs and the caller does not match the actor allowlist.
//      Distinct from ACTION_DENY_WRITE (=3) which fires on a per-inode seal;
//      the parent-dir action code lets operators/tests identify which policy
//      line fired without inspecting the deny target's inode.
//    - ACTION_DENY_CHMOD_PARENT_DIR  = 10. Emitted by inode_setattr
//      (for ATTR_MODE/ATTR_UID/ATTR_GID and any unclassified ATTR_* bit),
//      inode_setxattr, and inode_removexattr when the parent directory of the
//      target inode carries SEAL_NO_CHMOD in sealed_dirs. Distinct from
//      ACTION_DENY_CHMOD (=5) for the same reason.
//  * No struct layout change: audit_event and seal_value are unchanged.
//    The ABI version bump is required so a v0.4 audit consumer that does not
//    know the new action codes fails loud (version-mismatch warn path) rather
//    than silently logging "action=?".
//  * Two new BPF helpers in compartment.bpf.c:
//    - deny_file_parent_dir_action: for write hooks that receive struct file*.
//    - deny_dentry_parent_dir_action: for inode hooks that receive struct dentry*.
//  * Loader-side invariants (hard failures before attach for directory seals):
//    - No immediate symlink children (symlink resolution escapes the seal).
//    - No immediate non-directory children with st_nlink > 1 (hardlink alias
//      can bypass the parent-dir check via an unsealed parent path).
//
// ABI v0.6 — recursive subtree directory seals + exact runtime ABI probe.
//  * No struct layout change: audit_event, seal_value, launcher_actor,
//    actor_marker, and policy_state are unchanged.
//  * Directory seals now apply recursively to descendants at enforcement
//    time: write/unlink/rename/create/metadata hooks walk ancestor dentries
//    and enforce any matching sealed_dirs entry in the path to root.
//  * New pinned map `abi_version_map` (ARRAY[1](__u32), value written by the
//    loader at key 0). `compartment-bpf observe` uses it for exact runtime
//    ABI detection; legacy pre-v0.6 pins remain ambiguous and are handled
//    fail-safe in userspace rather than guessed from map shape.
//
// ABI v0.7 — distinct strict-launch side-deny audit actions.
//  * No struct layout change.
//  * New action codes:
//    - ACTION_DENY_PRCTL_SET_MM = 11
//    - ACTION_DENY_PTRACE_ACCESS = 12
//    - ACTION_DENY_PTRACE_TRACEME = 13
//  * These replace the prior overloading of
//    ACTION_DENY_STRICT_LAUNCH_MISSING for ancillary strict-launch side
//    denies, so audit consumers can distinguish “missing launch marker on a
//    sealed file op” from “global PR_SET_MM deny” and ptrace hardening
//    denies without parsing comments or inferring from counters.

#ifndef COMPARTMENT_ABI_H
#define COMPARTMENT_ABI_H

// Encoded as 8-bit major + 8-bit minor: 0x0007 == v0.7.
#define COMPARTMENT_ABI_VERSION 0x0007

// Recursive subtree enforcement walks ancestor dentries up to this many
// levels. The default is intentionally conservative for verifier/load-time
// cost, but custom deployments may override it at build time via
// `make COMPARTMENT_MAX_DIR_ANCESTORS=<n>`.
#ifndef COMPARTMENT_MAX_DIR_ANCESTORS
#define COMPARTMENT_MAX_DIR_ANCESTORS 8
#endif

#if COMPARTMENT_MAX_DIR_ANCESTORS < 1 || COMPARTMENT_MAX_DIR_ANCESTORS > 64
#error "COMPARTMENT_MAX_DIR_ANCESTORS must be in the range 1..64"
#endif

struct inode_key {
	__u64 dev;
	__u64 ino;
};

#define SEAL_NO_UNLINK    (1U << 0)
#define SEAL_NO_RENAME    (1U << 1)
#define SEAL_NO_WRITE     (1U << 2)
#define SEAL_NO_CHMOD     (1U << 3)
// Bit 4 is reserved (was scoped to SEAL_NO_CHMOD's historical sibling;
// keep dense to avoid sparse-bit confusion in future audit dumps).
#define SEAL_STRICT_LAUNCH (1U << 5)   // v0.4: requires valid launch marker
#define SEAL_FULL \
	(SEAL_NO_UNLINK | SEAL_NO_RENAME | SEAL_NO_WRITE | SEAL_NO_CHMOD)

// Code 4 was historically skipped; ABI v0.2 reclaims it for
// ACTION_DENY_ACTOR_MISMATCH so the value-drift asserts below remain
// dense and a future scan does not find the gap surprising.
#define ACTION_DENY_UNLINK         1
#define ACTION_DENY_RENAME         2
#define ACTION_DENY_WRITE          3
#define ACTION_DENY_ACTOR_MISMATCH 4
#define ACTION_DENY_CHMOD          5
#define ACTION_DENY_CREATE         6
// Loader-side denial. Emitted by the userspace --unpin
// path when an Argon2id sentinel exists under PIN_ROOT and the supplied
// passphrase (env COMPARTMENT_BPF_PASSPHRASE or getpass) fails to verify.
// Unlike the kernel-side ACTION_DENY_* codes 1..6 which originate from
// LSM hooks, code 7 is emitted by compartment-bpf's userspace --unpin
// driver via the audit ringbuf userspace API. dev/ino are
// the sentinel file's (dev, ino) so an auditor can correlate; caller_*
// fields are 0; actor_name is empty.
#define ACTION_DENY_UNPIN_AUTH_FAIL 7
// v0.4: strict-launch deny code. Emitted by comp_file_open (and any
// future strict-launch-gated hook) when the seal carries
// SEAL_STRICT_LAUNCH but the calling task has no valid marker (missing
// task storage, slot mismatch, generation mismatch, or exe-inode
// mismatch). Distinct from ACTION_DENY_ACTOR_MISMATCH=4: the file-op
// hook checks actor= first; strict-launch failure is reported only
// after actor= passes, so the action code unambiguously names which
// gate fired.
#define ACTION_DENY_STRICT_LAUNCH_MISSING 8
// v0.5: parent-directory destination deny codes. Emitted when the
// TARGET FILE's parent directory carries a seal in sealed_dirs and the
// caller does not match the actor allowlist. Distinct from the per-inode
// codes (DENY_WRITE=3, DENY_CHMOD=5) so an operator/test can tell which
// policy line fired: inode seal or directory-destination seal.
#define ACTION_DENY_WRITE_PARENT_DIR  9
#define ACTION_DENY_CHMOD_PARENT_DIR  10
// v0.7: strict-launch side-deny audit codes. These are emitted by the
// global task_prctl / ptrace hooks, distinct from file-op
// ACTION_DENY_STRICT_LAUNCH_MISSING.
#define ACTION_DENY_PRCTL_SET_MM      11
#define ACTION_DENY_PTRACE_ACCESS     12
#define ACTION_DENY_PTRACE_TRACEME    13

// Per-constant value-drift asserts. The struct-size assert on
// audit_event catches layout drift but not value drift on SEAL_*/ACTION_*;
// the explicit literals here mean a future edit that bumps a value on one
// side will fail to build because the header is shared.
_Static_assert(SEAL_NO_UNLINK    == (1U << 0), "SEAL_NO_UNLINK value drift");
_Static_assert(SEAL_NO_RENAME    == (1U << 1), "SEAL_NO_RENAME value drift");
_Static_assert(SEAL_NO_WRITE     == (1U << 2), "SEAL_NO_WRITE value drift");
_Static_assert(SEAL_NO_CHMOD     == (1U << 3), "SEAL_NO_CHMOD value drift");
_Static_assert(SEAL_STRICT_LAUNCH == (1U << 5), "SEAL_STRICT_LAUNCH value drift (v0.4)");
_Static_assert(ACTION_DENY_UNLINK         == 1, "ACTION_DENY_UNLINK value drift");
_Static_assert(ACTION_DENY_RENAME         == 2, "ACTION_DENY_RENAME value drift");
_Static_assert(ACTION_DENY_WRITE          == 3, "ACTION_DENY_WRITE value drift");
_Static_assert(ACTION_DENY_ACTOR_MISMATCH == 4, "ACTION_DENY_ACTOR_MISMATCH value drift");
_Static_assert(ACTION_DENY_CHMOD          == 5, "ACTION_DENY_CHMOD value drift");
_Static_assert(ACTION_DENY_CREATE         == 6, "ACTION_DENY_CREATE value drift");
_Static_assert(ACTION_DENY_UNPIN_AUTH_FAIL == 7, "ACTION_DENY_UNPIN_AUTH_FAIL value drift");
_Static_assert(ACTION_DENY_STRICT_LAUNCH_MISSING == 8, "ACTION_DENY_STRICT_LAUNCH_MISSING value drift (v0.4)");
_Static_assert(ACTION_DENY_WRITE_PARENT_DIR  ==  9, "ACTION_DENY_WRITE_PARENT_DIR value drift (v0.5)");
_Static_assert(ACTION_DENY_CHMOD_PARENT_DIR  == 10, "ACTION_DENY_CHMOD_PARENT_DIR value drift (v0.5)");
_Static_assert(ACTION_DENY_PRCTL_SET_MM   == 11, "ACTION_DENY_PRCTL_SET_MM value drift (v0.7)");
_Static_assert(ACTION_DENY_PTRACE_ACCESS  == 12, "ACTION_DENY_PTRACE_ACCESS value drift (v0.7)");
_Static_assert(ACTION_DENY_PTRACE_TRACEME == 13, "ACTION_DENY_PTRACE_TRACEME value drift (v0.7)");

// ABI v0.3 layout (gcc-verified sizeof on LP64, natural alignment):
//   off  0: __u32 version       — MUST be at offset 0; per the
//                                 header MUST rule; consumer rejects
//                                 events whose version != COMPARTMENT_ABI_VERSION.
//   off  4: __u32 _pad0         — explicit alignment pad for ts_ns;
//                                 the compiler would emit it anyway,
//                                 spelled here so layout is unambiguous.
//   off  8: __u64 ts_ns
//   off 16: __u32 pid
//   off 20: __u32 ppid
//   off 24: __u32 uid
//   off 28: __u32 action
//   off 32: __u64 dev
//   off 40: __u64 ino
//   off 48: __u64 caller_dev    — actor-mismatch path; 0 elsewhere.
//   off 56: __u64 caller_ino    — actor-mismatch path; 0 elsewhere.
//   off 64: char  comm[16]
//   off 80: char  actor_name[16]— v0.3: actor-group name on the
//                                 actor-mismatch path; truncated to
//                                 15 bytes + NUL; empty on all other
//                                 event types.
//   tot 96 bytes.
struct audit_event {
	__u32 version;
	__u32 _pad0;
	__u64 ts_ns;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 action;
	__u64 dev;
	__u64 ino;
	__u64 caller_dev;
	__u64 caller_ino;
	char  comm[16];
	char  actor_name[16];
};
_Static_assert(sizeof(struct audit_event) == 96,
	"audit_event size must match across BPF producer and userspace consumer (ABI v0.3)");

// ---------------- seal_value (exec-domain actor allowlist) ----------------
//
// v0 wrote a plain __u32 flags into sealed_inodes / sealed_dirs. v0.1
// widened the value to a struct so each seal can carry an optional
// actor allowlist.
//
// actor_count == 0 preserves v0 uniform-deny semantics: the seal
// applies to every caller. actor_count > 0 restricts the seal: the
// operation is allowed iff the caller's exe inode matches one of the
// actor[i] (dev, ino) pairs (actor_check_or_deny).
//
// Inline array of 4 actors per SPEC §6.1 default. Wider groups are an
// explicit profile-author error (loader and parser both cap at this
// value).
//
// v0.3: adds actor_name[16] so actor_check_or_deny can
// copy the actor-group name into audit_event.actor_name on the
// actor-mismatch deny path WITHOUT a userspace lookup table. Loader
// populates from actor_group->name at bpf_map_update_elem time
// (truncate to 15 + NUL). Empty for uniform-deny seals
// (actor_count == 0); harmless trailing bytes when present.
#define COMPARTMENT_MAX_ACTORS_PER_SEAL 4

struct actor_id {
	__u64 dev;
	__u64 ino;
};
_Static_assert(sizeof(struct actor_id) == 16,
	"actor_id layout must be stable across BPF and userspace");

struct seal_value {
	__u32 flags;
	__u8  actor_count;
	__u8  _pad[3];
	struct actor_id actor[COMPARTMENT_MAX_ACTORS_PER_SEAL];
	char  actor_name[16];   /* v0.3: actor-group name; empty when
				 * actor_count == 0. */
	__u32 strict_actor_slot; /* v0.4: 0 unless SEAL_STRICT_LAUNCH is
				  * set in flags. The marker check requires
				  * actor_marker.actor_slot to match this
				  * value. Loader populates from the bound
				  * actor group's stable slot id. */
	__u32 strict_generation; /* v0.4: 0 unless SEAL_STRICT_LAUNCH is
				  * set in flags. Wraps at 255; loader
				  * rejects strict actor on generation
				  * mismatch. Mirrors policy_state.generation
				  * at load time. v0.4 is fresh-load-only
				  * (SPEC §3a) — the
				  * loader never bumps this after `--pin`.
				  * Forward-compat scaffolding for future
				  * hot-reload. */
};
// 4 (flags) + 1 (actor_count) + 3 (_pad) + 4*16 (actor[]) + 16 (actor_name)
//   + 4 (strict_actor_slot) + 4 (strict_generation)
//   = 96 bytes (gcc-verified, LP64 natural alignment).
_Static_assert(sizeof(struct seal_value) == 96,
	"seal_value size must match across BPF producer and userspace consumer (ABI v0.4)");
_Static_assert(COMPARTMENT_MAX_ACTORS_PER_SEAL == 4,
	"seal_value sizeof assumes actor[4]; update both together");

// ---------------- ABI v0.4: strict-launch-marker types ----------------
//
// Two BPF state maps back the SEAL_STRICT_LAUNCH enforcement; their value
// types are declared here so the BPF producer (compartment.bpf.c) and
// the userspace loader (compartment-bpf.c) cannot drift.
//
// launcher_to_actor : BPF_MAP_TYPE_HASH, key=struct inode_key
//                     (the launcher binary's file_id), value=struct
//                     launcher_actor. Populated by the loader from
//                     `actor-strict NAME = TARGET launcher=PATH`
//                     directives. On `bprm_check_security`, a hit means
//                     "exec of a sealed launcher" and the kernel sets a
//                     marker on the new task.
//
// actor_marker      : BPF_MAP_TYPE_TASK_STORAGE, value=struct
//                     actor_marker. Per-task; set on launcher exec,
//                     cleared on foreign exec, copied on fork via the
//                     lsm/task_alloc hook.
//
// `state` in actor_marker is a small protocol tag — 0 = uninitialised
// (defensive; task storage create returns zeroed memory), 1 = valid.
// The BPF hooks treat state == 0 as "no marker" so a partly-written
// marker cannot authorize a file op.
struct launcher_actor {
	struct inode_key target;     /* the actor target the marker tags */
	__u32 actor_slot;            /* matches seal_value.strict_actor_slot */
	__u32 policy_generation;     /* matches policy_state.generation at load */
};
_Static_assert(sizeof(struct launcher_actor) == 24,
	"launcher_actor layout must be stable across BPF and userspace (v0.4)");

struct actor_marker {
	struct inode_key target;     /* the actor target the marker tags */
	__u32 actor_slot;            /* matches seal_value.strict_actor_slot */
	__u32 policy_generation;     /* matches seal_value.strict_generation */
	__u32 state;                 /* 0 = unset, 1 = valid */
	__u32 _pad;                  /* align to 8 for stable BPF compat */
};
_Static_assert(sizeof(struct actor_marker) == 32,
	"actor_marker layout must be stable across BPF and userspace (v0.4)");

// policy_state : BPF_MAP_TYPE_ARRAY[1]. Tracks the loaded policy's
// generation and a strict_loaded flag (1 when any seal carries
// SEAL_STRICT_LAUNCH; 0 otherwise). v0.4 is fresh-load-only (SPEC §3a;
// generation is set at `--pin` and never
// bumped in place; the `--unpin` + `--pin` reload cycle destroys the
// per-task marker storage and forces every protected actor to re-launch.
// The task_prctl / ptrace_access_check hooks early-out when strict_loaded
// == 0 to keep the cost-of-strict-mode at zero on a profile with no
// strict-launch seals.
struct policy_state {
	__u32 generation;
	__u32 strict_loaded;
};
_Static_assert(sizeof(struct policy_state) == 8,
	"policy_state layout must be stable across BPF and userspace (v0.4)");

#endif /* COMPARTMENT_ABI_H */
