// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
//
// compartment-bpf: kernel-side LIDS-style sealed paths using BPF LSM.
// Exec domains (the "actor allowlist" — bind a seal to specific caller
// exe inodes) shipped in ED-1..ED-7 (2026-05-14). Companion to
// compartment-user (Landlock+seccomp) and compartment-root (namespaces).
//
// Hooks (21 total as of ABI v0.6):
//   v0.x file/inode/path (16):
//     inode_unlink, inode_rename, inode_rmdir, inode_create, inode_mkdir,
//     inode_mknod, inode_symlink, inode_link, file_open, file_permission,
//     file_truncate, inode_setattr, mmap_file, file_mprotect,
//     inode_setxattr, inode_removexattr
//   v0.4 strict-launch (5):
//     lsm.s/bprm_check_security (sleepable; sets task-storage marker),
//     task_alloc (G6 marker copy on fork), task_prctl (PR_SET_MM_EXE_FILE
//     deny), ptrace_access_check, ptrace_traceme
//
// v0.1 maps:
//   sealed_inodes : (dev, ino) -> struct seal_value     (per-file)
//   sealed_dirs   : (dev, ino) -> struct seal_value     (per-dir, applies to subtree descendants)
//   audit_rb      : ringbuf of deny events
//
// ED-3 widens the map value from __u32 to struct seal_value (72 bytes).
// actor_count == 0 preserves v0 uniform-deny semantics; ED-4 adds the
// caller-exe actor check in actor_check_or_deny.
//
// Decision policy: any program returns -EACCES => deny. The conventional
// guard is "if (ret != 0) return ret;" so we don't override an earlier
// LSM module's decision.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "compartment-abi.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef EACCES
#define EACCES 13
#endif
#ifndef FMODE_WRITE
#define FMODE_WRITE 0x2
#endif
#ifndef MAY_WRITE
#define MAY_WRITE 0x00000002
#endif
#ifndef PROT_WRITE
#define PROT_WRITE 0x2
#endif
#ifndef MAP_SHARED
#define MAP_SHARED 0x01
#endif
#ifndef VM_SHARED
#define VM_SHARED 0x00000008UL
#endif
#ifndef ATTR_MODE
#define ATTR_MODE 1
#endif
#ifndef ATTR_UID
#define ATTR_UID 2
#endif
#ifndef ATTR_GID
#define ATTR_GID 4
#endif
#ifndef ATTR_SIZE
#define ATTR_SIZE 8
#endif
#ifndef S_IFMT
#define S_IFMT 00170000
#endif
#ifndef S_IFDIR
#define S_IFDIR 0040000
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif

// Recursive subtree enforcement walks ancestor dentries up to
// COMPARTMENT_MAX_DIR_ANCESTORS levels. The shared default lives in
// compartment-abi.h and may be raised for custom deployments at build
// time. The loader fail-closes on live subtrees that exceed the compiled
// budget so the cap cannot silently degrade into a runtime bypass.

// v0.4 strict-launch-marker locals.
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif
#ifndef PR_SET_MM
#define PR_SET_MM 35
#endif
#ifndef PR_SET_MM_EXE_FILE
#define PR_SET_MM_EXE_FILE 13
#endif
#ifndef EPERM
#define EPERM 1
#endif

// ---------------- Types ----------------
// Wire/ABI types and SEAL_*/ACTION_* constants live in compartment-abi.h
// (included above) so this BPF producer and the userspace consumer in
// compartment-bpf.c cannot drift.

// ---------------- Maps ----------------

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct inode_key);
	__type(value, struct seal_value);
} sealed_inodes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct inode_key);
	__type(value, struct seal_value);
} sealed_dirs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} audit_rb SEC(".maps");

// V-4b counters. Per-CPU arrays; userspace sums across all possible CPUs.
// deny_total            : incremented at every enforcement deny, BEFORE
//                         the ringbuf reserve attempt. Counts the policy
//                         decision, not the audit success.
// audit_drop_total      : incremented when bpf_ringbuf_reserve() returns
//                         NULL after deny_total was already counted. Soak
//                         evidence that the kernel saw the deny even when
//                         the audit stream is being dropped.
// actor_mismatch_total  : ED-7. Incremented at every actor-mismatch deny
//                         BEFORE the audit emit. Subset of deny_total
//                         records the actor-allowlist evictions specifically;
//                         records every actor-mismatch decision even when
//                         the audit ringbuf is dropped (mirrors V-4b
//                         invariant for audit_drop_total vs deny_total).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} deny_total SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} audit_drop_total SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} actor_mismatch_total SEC(".maps");

// ============================================================
// v0.4 strict-launch-marker (SLM) — production lift of
// experimental/strict-launch-marker/bpf/slm.bpf.c per SPEC §5/§6.
// ============================================================
//
// Maps:
//   launcher_to_actor : HASH(inode_key -> launcher_actor)
//                       set by loader from `actor-strict … launcher=…`.
//   actor_marker_map  : TASK_STORAGE(actor_marker)
//                       set on launcher exec, cleared on foreign exec,
//                       copied on fork via lsm/task_alloc (G6 Outcome B).
//   policy_state_map  : ARRAY[1](policy_state)
//                       loader writes { generation, strict_loaded } on
//                       load and bumps generation on reload.
//   abi_version_map   : ARRAY[1](__u32)
//                       loader writes COMPARTMENT_ABI_VERSION so
//                       userspace can probe the exact pinned runtime ABI.
//
// Counter convention matches the existing v0.1+ pattern: one
// BPF_MAP_TYPE_PERCPU_ARRAY[1] per counter, incremented BEFORE any
// ringbuf reserve so deny counts stay correct under audit pressure
// (the V-4b ordering invariant; SPEC §6.4 + G10).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct inode_key);
	__type(value, struct launcher_actor);
} launcher_to_actor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct actor_marker);
} actor_marker_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct policy_state);
} policy_state_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} abi_version_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} strict_launch_missing_total SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} strict_launch_allowed_total SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} marker_set_total SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} marker_clear_foreign_exec_total SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} marker_copy_fork_total SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} marker_stale_generation_total SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} prctl_set_mm_exe_file_denied_total SEC(".maps");

// v0.4 ptrace deny counters. SPEC §6.4 allows splitting `ptrace_denied_total`
// into per-hook variants (`ptrace_attach_denied_total` /
// `ptrace_traceme_denied_total`). Counter name correction:
// the original lift used a single `ptrace_access_denied_total` map for
// both `ptrace_access_check` and `ptrace_traceme`, which the spike
// witness scripts could not distinguish. Split into two counters here
// to match the spike's witness ordering + the SPEC-allowed per-hook
// granularity. `ptrace_access_denied_total` covers comp_ptrace_access_check
// (strace, process_vm_writev, pidfd_getfd, /proc/<pid>/mem all route
// through security_ptrace_access_check on Ubuntu 26.04 (kernel 7.0) — G9 4-vector).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} ptrace_access_denied_total SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} ptrace_traceme_denied_total SEC(".maps");

// ---------------- Helpers ----------------

static __always_inline void bump_counter(void *map)
{
	__u32 key = 0;
	__u64 *v = bpf_map_lookup_elem(map, &key);
	if (v)
		(*v)++;
}

static __always_inline struct inode_key
inode_key_of(struct inode *inode)
{
	struct inode_key k = {};
	if (!inode)
		return k;
	k.ino = BPF_CORE_READ(inode, i_ino);
	struct super_block *sb = BPF_CORE_READ(inode, i_sb);
	if (sb)
		k.dev = BPF_CORE_READ(sb, s_dev);
	return k;
}

static __always_inline void
emit_audit(__u32 action, __u64 dev, __u64 ino);

static __always_inline void
emit_audit_actor(__u32 action, __u64 dev, __u64 ino,
                 __u64 caller_dev, __u64 caller_ino,
                 const char *actor_name_src);

// Cache the caller's exe (dev, ino) once per hook
// invocation. Each hook declares a `struct caller_id cid = { 0 };` on
// its stack and passes `&cid` through deny_*/seal_decision/
// actor_check_or_deny. The lazy_resolve helper fills it on first
// non-uniform actor check; subsequent checks in the same hook reuse
// the cached value. For uniform-deny seals (actor_count == 0) the
// resolve never runs, so non-actor traffic pays no BTF-read cost.
// `valid` distinguishes "not resolved yet" (0) from "resolved but no
// exe available, e.g. kernel thread" (1, with dev=ino=0).
struct caller_id {
	__u64 dev;
	__u64 ino;
	__u8  resolved;  /* 0 = lazy not run; 1 = run (dev/ino reflect outcome) */
	__u8  valid;     /* 1 = exe inode resolved; 0 = no usable exe identity */
};

static __always_inline void
caller_id_resolve_locked(struct caller_id *cid)
{
	cid->resolved = 1;
	cid->valid    = 0;
	cid->dev      = 0;
	cid->ino      = 0;

	// LOAD-BEARING NULL DEFENSE.
	// bpf_get_current_task_btf() is declared to return a non-NULL
	// `struct task_struct *` and the verifier is allowed to optimize
	// out the NULL check on PTR_TO_BTF_ID return values. But the LSM
	// hook context is the only place we read it; if a future kernel
	// ever introduces a no-task LSM context (preempt-disabled IRQ
	// path, init phase, ...) the NULL would feed straight into
	// BPF_CORE_READ(t, mm, exe_file) below as a null-pointer
	// dereference inside a verified BPF program. The verifier would
	// reject the load, breaking enforcement everywhere.
	//
	// Keep this check as fail-closed defense-in-depth: the cost is
	// one branch; the benefit is graceful actor-mismatch deny on a
	// hypothetical future kernel surface that returns NULL here.
	// Fail-closed for a hypothetical future kernel surface returning NULL here.
	struct task_struct *t = (void *)bpf_get_current_task_btf();
	if (!t)
		return;
	struct file *exe = BPF_CORE_READ(t, mm, exe_file);
	if (!exe)
		return;
	struct inode *einode = BPF_CORE_READ(exe, f_inode);
	if (!einode)
		return;
	cid->ino = BPF_CORE_READ(einode, i_ino);
	struct super_block *esb = BPF_CORE_READ(einode, i_sb);
	cid->dev = esb ? (__u64)BPF_CORE_READ(esb, s_dev) : 0;
	cid->valid = 1;
}

// ---------------- ED-4 / ED-6 / ED-7: actor_check_or_deny ----------------
//
// Returns 0 if the caller is allowed (seal's actor allowlist matches the
// caller's exe inode), -EACCES otherwise. On any deny path emits exactly
// one audit event AND bumps the matching counter(s) BEFORE returning,
// so the caller in seal_decision/* must NOT emit again. This centralizes
// audit emission for seal-based denies and guarantees one event per
// decision (no double-audit when an actor-mismatch coincides with a
// no-write seal — the ACTION_DENY_ACTOR_MISMATCH wins).
//
// Defense-in-depth ordering:
//   1. sv == NULL → deny (defensive; callers already gate on this).
//   2. sv->actor_count == 0 ⇒ uniform deny (v0 semantics): emit with
//      `action` (the caller's natural action code) and zero caller
//      fields — preserves legacy audit shape for non-actor seals.
//   3. NULL task_struct / NULL exe_file / NULL exe inode → actor-mismatch
//      path with caller_dev=caller_ino=0 (no exe identity available;
//      cannot satisfy any actor allowlist).
//   4. No actor[] match in the compile-time-bounded scan → actor-mismatch
//      path with the resolved caller_dev/caller_ino.
//
// Loop bound is COMPARTMENT_MAX_ACTORS_PER_SEAL == 4, baked into the
// ABI; the verifier sees a fixed-bound unrolled scan per call site
// (SPEC §6.2). __always_inline is required so the verifier can reason
// across all 16 hook call sites.
//
// V-4b invariant preserved for actor mismatches: actor_mismatch_total is
// bumped BEFORE the audit ringbuf reserve so the counter records every
// actor-mismatch decision even when the audit stream is being dropped.
// Every actor-mismatch deny path bumps ED-7 then emits
// ACTION_DENY_ACTOR_MISMATCH with the caller's resolved (dev, ino).
// Hoist into one helper so the three call sites in actor_check_or_deny
// stay obviously identical and a future audit-side change touches one
// spot instead of three.
static __always_inline int
deny_actor_mismatch(struct seal_value *sv,
                    __u64 dev, __u64 ino, __u64 cdev, __u64 cino)
{
	bump_counter(&actor_mismatch_total);
	// v0.3 (Sec-12): pass sv->actor_name into the audit emit so the
	// event carries the actor-group name. NULL sv falls back to an
	// empty actor_name (defensive: the sv-NULL caller path below).
	emit_audit_actor(ACTION_DENY_ACTOR_MISMATCH, dev, ino, cdev, cino,
	                 sv ? sv->actor_name : (const char *)0);
	return -EACCES;
}

static __always_inline int
actor_check_or_deny(struct seal_value *sv, __u32 action,
		    __u64 dev, __u64 ino, struct caller_id *cid)
{
	if (!sv)
		// Defensive only — seal_decision already filters NULL.
		return deny_actor_mismatch(0, dev, ino, 0, 0);

	if (sv->actor_count == 0) {
		// Uniform-deny (v0 semantics): the seal applies to every caller.
		// Emit with the caller's natural action so legacy event types
		// remain stable; caller_dev/ino are 0.
		emit_audit(action, dev, ino);
		return -EACCES;
	}

	// F15: caller_id may already be resolved by a sibling seal check
	// in this hook invocation. Lazy-resolve only on first non-uniform
	// path; the BTF-read chain happens at most once per hook.
	if (!cid->resolved)
		caller_id_resolve_locked(cid);

	if (!cid->valid)
		return deny_actor_mismatch(sv, dev, ino, 0, 0);

	__u8 n = sv->actor_count;
	if (n > COMPARTMENT_MAX_ACTORS_PER_SEAL)
		n = COMPARTMENT_MAX_ACTORS_PER_SEAL;  // verifier-safety clamp

	#pragma unroll
	for (int i = 0; i < COMPARTMENT_MAX_ACTORS_PER_SEAL; i++) {
		if (i >= n)
			break;
		if (cid->dev == sv->actor[i].dev &&
		    cid->ino == sv->actor[i].ino)
			return 0;  // actor match — allow
	}

	// Actor mismatch with resolved caller identity.
	return deny_actor_mismatch(sv, dev, ino, cid->dev, cid->ino);
}

// Look up both the file-seal and dir-seal entries (if any) for a single
// inode_key. v0's lookup_inode_flags returned an OR of the flag bits;
// with actor allowlists each seal carries its own actor[] so we must
// keep the seals separate. The caller decides whether to enforce one
// or the other; in practice deny_inode_action below tries both.
static __always_inline int
lookup_inode_seals(struct inode *inode, struct inode_key *k,
		   struct seal_value **inode_sv,
		   struct seal_value **dir_sv)
{
	*inode_sv = NULL;
	*dir_sv = NULL;
	*k = inode_key_of(inode);
	if (!inode)
		return 0;
	if (k->dev == 0 && k->ino == 0)
		return 0;

	*inode_sv = bpf_map_lookup_elem(&sealed_inodes, k);
	*dir_sv   = bpf_map_lookup_elem(&sealed_dirs, k);

	return (*inode_sv != NULL) || (*dir_sv != NULL);
}

// v0.4: forward decl + helper. cur_strict_generation reads
// policy_state.generation; emit_audit_actor lives above so the
// strict-launch helper just calls it on deny. Defined here so
// seal_decision (the only caller) can dispatch to it.
static __always_inline __u32 cur_strict_generation(void)
{
	__u32 z = 0;
	struct policy_state *ps = bpf_map_lookup_elem(&policy_state_map, &z);
	return ps ? ps->generation : 0;
}

static __always_inline __u32 cur_strict_loaded(void)
{
	__u32 z = 0;
	struct policy_state *ps = bpf_map_lookup_elem(&policy_state_map, &z);
	return ps ? ps->strict_loaded : 0;
}

// v0.4 strict-launch enforcement. Called from seal_decision AFTER
// actor_check_or_deny returns 0 (allow) and only when the seal has
// SEAL_STRICT_LAUNCH set. Returns 0 if the calling task carries a valid
// marker matching the seal's strict_actor_slot + strict_generation;
// -EACCES otherwise.
//
// On deny:
//   - strict_launch_missing_total++ BEFORE any ringbuf reserve (G10).
//   - On generation mismatch specifically, marker_stale_generation_total++
//     in addition.
//   - emit ACTION_DENY_STRICT_LAUNCH_MISSING via emit_audit_actor with
//     caller_dev/caller_ino = resolved exe inode (cid), actor_name =
//     sv->actor_name so log correlation matches the actor-mismatch path.
//
// The check covers (per SPEC §6.2):
//   - marker present AND state == 1
//   - marker.target == current task exe inode
//   - marker.actor_slot == sv->strict_actor_slot
//   - marker.policy_generation == policy_state.generation
//                              AND == sv->strict_generation
static __always_inline int
strict_launch_check_or_deny(struct seal_value *sv, __u64 dev, __u64 ino,
                            struct caller_id *cid)
{
	struct task_struct *t;
	struct actor_marker *am;
	__u32 cur_gen;

	// Lazy-resolve caller exe id if not done. The actor-bound (i.e.
	// actor_count > 0) path always resolves cid; we still defend
	// against an unexpected NULL-cid invocation.
	if (!cid->resolved)
		caller_id_resolve_locked(cid);

	// Defensive entry guard: Today's
	// upstream call site is `seal_decision`, which dispatches here
	// only after `actor_check_or_deny` has already denied on
	// `!cid->valid` — so the marker-target equality check at
	// `if (cid->valid)` below is invariant-by-coincidence, not
	// invariant-by-design. A future refactor adding a new caller
	// that doesn't pre-validate `cid` would silently skip the
	// equality check and downgrade SPEC §3 prop 1 / §6.2 cond 4
	// from required-AND to optional. Belt-and-suspenders: deny
	// fail-closed at function entry on any `!cid->valid` path.
	if (!cid->valid) {
		bump_counter(&strict_launch_missing_total);
		emit_audit_actor(ACTION_DENY_STRICT_LAUNCH_MISSING, dev, ino,
		                 0, 0, sv ? sv->actor_name : (const char *)0);
		return -EACCES;
	}

	t = (void *)bpf_get_current_task_btf();
	if (!t) {
		// F26 cross-phase doctrine: defend against verifier-allowed
		// NULL on PTR_TO_BTF_ID; if it ever fires we cannot resolve
		// the task — fail-closed deny.
		bump_counter(&strict_launch_missing_total);
		emit_audit_actor(ACTION_DENY_STRICT_LAUNCH_MISSING, dev, ino,
		                 0, 0, sv ? sv->actor_name : (const char *)0);
		return -EACCES;
	}

	am = bpf_task_storage_get(&actor_marker_map, t, NULL, 0);
	if (!am || am->state == 0) {
		bump_counter(&strict_launch_missing_total);
		emit_audit_actor(ACTION_DENY_STRICT_LAUNCH_MISSING, dev, ino,
		                 cid->valid ? cid->dev : 0,
		                 cid->valid ? cid->ino : 0,
		                 sv ? sv->actor_name : (const char *)0);
		return -EACCES;
	}

	// Marker target must equal the current task's exe inode. This
	// closes the foreign-exec → re-exec-actor chain (SL-3, SL-5).
	// cid->valid is guaranteed true here (entry guard at line 516 denies
	// on !cid->valid before reaching this point — M-4: guard removed).
	if (am->target.dev != cid->dev || am->target.ino != cid->ino) {
		bump_counter(&strict_launch_missing_total);
		emit_audit_actor(ACTION_DENY_STRICT_LAUNCH_MISSING,
		                 dev, ino, cid->dev, cid->ino,
		                 sv ? sv->actor_name : (const char *)0);
		return -EACCES;
	}

	if (am->actor_slot != sv->strict_actor_slot) {
		bump_counter(&strict_launch_missing_total);
		emit_audit_actor(ACTION_DENY_STRICT_LAUNCH_MISSING, dev, ino,
		                 cid->valid ? cid->dev : 0,
		                 cid->valid ? cid->ino : 0,
		                 sv ? sv->actor_name : (const char *)0);
		return -EACCES;
	}

	cur_gen = cur_strict_generation();
	if (am->policy_generation != cur_gen ||
	    am->policy_generation != sv->strict_generation) {
		bump_counter(&strict_launch_missing_total);
		bump_counter(&marker_stale_generation_total);
		emit_audit_actor(ACTION_DENY_STRICT_LAUNCH_MISSING, dev, ino,
		                 cid->valid ? cid->dev : 0,
		                 cid->valid ? cid->ino : 0,
		                 sv ? sv->actor_name : (const char *)0);
		return -EACCES;
	}

	bump_counter(&strict_launch_allowed_total);
	return 0;
}

// One seal-level decision: if flags & mask matches, the seal applies;
// then actor_check_or_deny decides whether THIS caller is allowed by
// THIS seal. Returns -EACCES to deny, 0 if the seal does not match the
// mask or the caller's exe is on the seal's actor allowlist.
//
// ED-6: audit emission is OWNED by actor_check_or_deny on all deny
// paths (uniform-deny → emit_audit with `action`; actor-mismatch →
// emit_audit_actor with ACTION_DENY_ACTOR_MISMATCH). Callers MUST NOT
// emit again when this returns nonzero — that would double-audit a
// single decision and confuse the action code on the actor-mismatch
// path. The (action, dev, ino) args are threaded through so
// actor_check_or_deny knows the caller's natural action for the
// uniform-deny case.
//
// v0.4: after the actor check passes, if the seal has SEAL_STRICT_LAUNCH
// the strict-launch marker check runs. Strict-launch denies have their
// OWN audit emit (ACTION_DENY_STRICT_LAUNCH_MISSING) so an operator
// can distinguish "wrong actor" from "right actor, dirty launch".
static __always_inline int
seal_decision(struct seal_value *sv, __u32 mask,
              __u32 action, __u64 dev, __u64 ino, struct caller_id *cid)
{
	int r;
	if (!sv)
		return 0;
	if (!(sv->flags & mask))
		return 0;
	r = actor_check_or_deny(sv, action, dev, ino, cid);
	if (r)
		return r;
	if (sv->flags & SEAL_STRICT_LAUNCH)
		return strict_launch_check_or_deny(sv, dev, ino, cid);
	return 0;
}

static __always_inline int
deny_inode_action(struct inode *inode, __u32 mask, __u32 action,
		  struct caller_id *cid)
{
	struct inode_key k = {};
	struct seal_value *isv = NULL, *dsv = NULL;
	int r;

	if (!lookup_inode_seals(inode, &k, &isv, &dsv))
		return 0;

	r = seal_decision(isv, mask, action, k.dev, k.ino, cid);
	if (r)
		return r;
	r = seal_decision(dsv, mask, action, k.dev, k.ino, cid);
	if (r)
		return r;
	return 0;
}

struct dir_seal_hit {
	__u64 dev;
	__u64 ino;
	__u32 depth;
	__u8  found;
};

static __always_inline int
find_nearest_dir_seal_hit_from_dir_dentry(struct dentry *dir_dentry,
					  __u32 mask,
					  struct dir_seal_hit *hit)
{
	struct dentry *cur = dir_dentry;

	hit->dev = 0;
	hit->ino = 0;
	hit->depth = 0;
	hit->found = 0;

	for (int depth = 0; depth < COMPARTMENT_MAX_DIR_ANCESTORS; depth++) {
		struct dentry *parent;
		struct inode *dir_inode;
		struct inode_key dk;
		struct seal_value *sv;

		if (!cur)
			break;

		dir_inode = BPF_CORE_READ(cur, d_inode);
		if (dir_inode) {
			dk = inode_key_of(dir_inode);
			if (dk.dev != 0 || dk.ino != 0) {
				sv = bpf_map_lookup_elem(&sealed_dirs, &dk);
				if (sv && (sv->flags & mask)) {
					hit->dev = dk.dev;
					hit->ino = dk.ino;
					hit->depth = depth;
					hit->found = 1;
					return 1;
				}
			}
		}

		parent = BPF_CORE_READ(cur, d_parent);
		if (!parent || parent == cur)
			break;
		cur = parent;
	}
	return 0;
}

static __always_inline int
dir_seal_hit_same(const struct dir_seal_hit *a, const struct dir_seal_hit *b)
{
	return a && b && a->found && b->found &&
	       a->dev == b->dev && a->ino == b->ino;
}

static __always_inline int
deny_dir_ancestor_action_from_dir_dentry(struct dentry *dir_dentry,
					 __u32 mask, __u32 action,
					 struct caller_id *cid)
{
	struct dentry *cur = dir_dentry;

	for (int depth = 0; depth < COMPARTMENT_MAX_DIR_ANCESTORS; depth++) {
		struct dentry *parent;
		struct inode *dir_inode;
		struct inode_key dk;
		struct seal_value *sv;
		int r;

		if (!cur)
			break;

		dir_inode = BPF_CORE_READ(cur, d_inode);
		if (dir_inode) {
			dk = inode_key_of(dir_inode);
			if (dk.dev != 0 || dk.ino != 0) {
				sv = bpf_map_lookup_elem(&sealed_dirs, &dk);
				r = seal_decision(sv, mask, action,
						  dk.dev, dk.ino, cid);
				if (r)
					return r;
			}
		}

		/* d_parent is stable during LSM hook execution under the VFS RCU
		 * read-side critical section. */
		parent = BPF_CORE_READ(cur, d_parent);
		if (!parent || parent == cur)
			break;
		cur = parent;
	}
	return 0;
}

static __always_inline int
deny_runtime_subtree_depth_cap(__u32 action, const struct dir_seal_hit *hit)
{
	if (!hit || !hit->found)
		return 0;
	emit_audit(action, hit->dev, hit->ino);
	return -EACCES;
}

static __always_inline int
deny_subtree_invariant_on_child_dentry(struct dentry *dentry, __u32 action)
{
	struct dentry *parent;
	struct dir_seal_hit hit = {};

	if (!dentry)
		return 0;
	parent = BPF_CORE_READ(dentry, d_parent);
	if (!parent || parent == dentry)
		return 0;
	if (!find_nearest_dir_seal_hit_from_dir_dentry(parent, SEAL_NO_WRITE, &hit))
		return 0;
	return deny_runtime_subtree_depth_cap(action, &hit);
}

/* Runtime companion to the loader's recursive depth-cap validation:
 * once a recursive no-write seal is live, do not let an allowed actor create
 * a new directory at level == COMPARTMENT_MAX_DIR_ANCESTORS relative to the
 * nearest covering sealed ancestor. */
static __always_inline int
deny_mkdir_subtree_depth_cap(struct dentry *dentry)
{
	struct dentry *parent;
	struct dir_seal_hit hit = {};

	if (!dentry)
		return 0;
	parent = BPF_CORE_READ(dentry, d_parent);
	if (!parent || parent == dentry)
		return 0;
	if (!find_nearest_dir_seal_hit_from_dir_dentry(parent, SEAL_NO_WRITE, &hit))
		return 0;
	if (hit.depth + 1 >= COMPARTMENT_MAX_DIR_ANCESTORS)
		return deny_runtime_subtree_depth_cap(ACTION_DENY_CREATE, &hit);
	return 0;
}

/* Runtime companion to the loader's recursive depth-cap validation for
 * directory renames:
 *   - never allow a rename to create a level==cap directory under a
 *     recursive no-write seal; and
 *   - never import a directory from outside the covering sealed subtree; and
 *   - never deepen a directory within the same covering sealed subtree,
 *     because the BPF side cannot prove descendant max depth portably
 *     in-hook across filesystems without a subtree walk.
 */
static __always_inline int
deny_dir_rename_subtree_depth_cap(struct dentry *old_dentry,
				  struct dentry *new_dentry)
{
	struct inode *old_target;
	struct dentry *old_parent, *new_parent;
	struct dir_seal_hit old_hit = {}, new_hit = {};
	__u16 mode;

	if (!old_dentry || !new_dentry)
		return 0;
	old_target = BPF_CORE_READ(old_dentry, d_inode);
	if (!old_target)
		return 0;
	mode = BPF_CORE_READ(old_target, i_mode);
	if ((mode & S_IFMT) != S_IFDIR)
		return 0;

	new_parent = BPF_CORE_READ(new_dentry, d_parent);
	if (!new_parent || new_parent == new_dentry)
		return 0;
	if (!find_nearest_dir_seal_hit_from_dir_dentry(new_parent, SEAL_NO_WRITE,
							 &new_hit))
		return 0;
	if (new_hit.depth + 1 >= COMPARTMENT_MAX_DIR_ANCESTORS)
		return deny_runtime_subtree_depth_cap(ACTION_DENY_RENAME, &new_hit);

	old_parent = BPF_CORE_READ(old_dentry, d_parent);
	if (!old_parent || old_parent == old_dentry)
		return deny_runtime_subtree_depth_cap(ACTION_DENY_RENAME, &new_hit);
	if (!find_nearest_dir_seal_hit_from_dir_dentry(old_parent, SEAL_NO_WRITE,
							 &old_hit))
		return deny_runtime_subtree_depth_cap(ACTION_DENY_RENAME, &new_hit);
	if (!dir_seal_hit_same(&old_hit, &new_hit))
		return deny_runtime_subtree_depth_cap(ACTION_DENY_RENAME, &new_hit);
	if (new_hit.depth > old_hit.depth)
		return deny_runtime_subtree_depth_cap(ACTION_DENY_RENAME, &new_hit);
	return 0;
}

/* Preserve the loader's recursive subtree alias invariants after attach.
 * A live recursive no-write seal must not gain:
 *   - symlink descendants;
 *   - hardlink descendants; or
 *   - renamed-in non-directory aliases (symlink or nlink>1 file).
 */
static __always_inline int
deny_hardlink_subtree_alias_invariants(struct dentry *old_dentry,
				       struct dentry *new_dentry)
{
	int r;

	r = deny_subtree_invariant_on_child_dentry(old_dentry,
						   ACTION_DENY_WRITE_PARENT_DIR);
	if (r)
		return r;
	return deny_subtree_invariant_on_child_dentry(new_dentry,
						      ACTION_DENY_CREATE);
}

static __always_inline int
deny_non_dir_rename_subtree_alias_invariants(struct dentry *old_dentry,
					     struct dentry *new_dentry)
{
	struct inode *old_target;
	struct dentry *new_parent;
	struct dir_seal_hit new_hit = {};
	__u16 mode;
	__u32 nlink;

	if (!old_dentry || !new_dentry)
		return 0;
	old_target = BPF_CORE_READ(old_dentry, d_inode);
	if (!old_target)
		return 0;
	mode = BPF_CORE_READ(old_target, i_mode);
	if ((mode & S_IFMT) == S_IFDIR)
		return 0;

	new_parent = BPF_CORE_READ(new_dentry, d_parent);
	if (!new_parent || new_parent == new_dentry)
		return 0;
	if (!find_nearest_dir_seal_hit_from_dir_dentry(new_parent, SEAL_NO_WRITE,
							 &new_hit))
		return 0;
	if ((mode & S_IFMT) == S_IFLNK)
		return deny_runtime_subtree_depth_cap(ACTION_DENY_RENAME, &new_hit);
	nlink = BPF_CORE_READ(old_target, i_nlink);
	if (nlink > 1)
		return deny_runtime_subtree_depth_cap(ACTION_DENY_RENAME, &new_hit);
	return 0;
}

// v0.6: deny_file_parent_dir_action — for write hooks that receive a
// struct file *. Walks the file's parent directory and all ancestor
// directories up to root, enforcing recursive subtree directory seals.
static __always_inline int
deny_file_parent_dir_action(struct file *file, __u32 mask, __u32 action,
			    struct caller_id *cid)
{
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	struct dentry *parent;

	if (!dentry)
		return 0;
	parent = BPF_CORE_READ(dentry, d_parent);
	if (!parent || parent == dentry)
		return 0;
	return deny_dir_ancestor_action_from_dir_dentry(parent, mask, action, cid);
}

// v0.6: deny_dentry_parent_dir_action — for inode hooks that receive a
// struct dentry * directly. Checks the immediate parent and all ancestor
// directories, so a seal on /etc also covers /etc/ssh/sshd_config.
static __always_inline int
deny_dentry_parent_dir_action(struct dentry *dentry, __u32 mask, __u32 action,
			      struct caller_id *cid)
{
	struct dentry *parent;

	if (!dentry)
		return 0;
	parent = BPF_CORE_READ(dentry, d_parent);
	if (!parent || parent == dentry)
		return 0;
	return deny_dir_ancestor_action_from_dir_dentry(parent, mask, action, cid);
}

static __always_inline int
deny_file_write(struct file *file, struct caller_id *cid)
{
	if (!file)
		return 0;

	struct inode *inode = BPF_CORE_READ(file, f_inode);
	int r;

	r = deny_inode_action(inode, SEAL_NO_WRITE, ACTION_DENY_WRITE, cid);
	if (r)
		return r;
	// v0.5: also check the parent directory destination seal.
	return deny_file_parent_dir_action(file, SEAL_NO_WRITE,
					   ACTION_DENY_WRITE_PARENT_DIR, cid);
}

// ED-6 widened emit. Used directly by the actor-mismatch path so the
// caller_dev/caller_ino fields are populated; the legacy 3-arg
// emit_audit wrapper below preserves all v0 call sites unchanged by
// passing zeros for the caller fields.
//
// v0.3 (Sec-6 + Sec-12): writes the ABI version word at offset 0 of
// every emitted event (per the header MUST rule); copies the actor
// group name into e->actor_name when actor_name_src is non-NULL.
// Every field of audit_event is written explicitly here — the buffer
// returned by bpf_ringbuf_reserve is uninitialised, so any unwritten
// field would leak kernel-stack bytes to userspace.
static __always_inline void
emit_audit_actor(__u32 action, __u64 dev, __u64 ino,
                 __u64 caller_dev, __u64 caller_ino,
                 const char *actor_name_src)
{
	struct audit_event *e;

	// V-4b ordering invariant: count the deny BEFORE attempting the
	// ringbuf reserve. The counter records the policy decision; the
	// ringbuf is best-effort audit.
	bump_counter(&deny_total);

	e = bpf_ringbuf_reserve(&audit_rb, sizeof(*e), 0);
	if (!e) {
		bump_counter(&audit_drop_total);
		return;
	}

	// R2-M1 + cross-phase F26 uniform doctrine (Review-2 cross-phase
	// audit §8.3): guard bpf_get_current_task_btf() against a NULL
	// return the same way caller_id_resolve_locked does. The verifier
	// is allowed to optimize the NULL check out on PTR_TO_BTF_ID, but
	// if a future kernel ever introduces an LSM context where task is
	// NULL the BPF_CORE_READ(task, real_parent, tgid) below would
	// fault inside a verified BPF program — rejecting the load and
	// breaking enforcement everywhere. Fail-closed default: ppid=0
	// when task is unresolved.
	struct task_struct *task = (void *)bpf_get_current_task_btf();

	e->version     = COMPARTMENT_ABI_VERSION;
	e->_pad0       = 0;
	e->ts_ns       = bpf_ktime_get_ns();
	e->pid         = bpf_get_current_pid_tgid() >> 32;
	e->ppid        = task ? BPF_CORE_READ(task, real_parent, tgid) : 0;
	e->uid         = bpf_get_current_uid_gid() & 0xffffffff;
	e->action      = action;
	e->dev         = dev;
	e->ino         = ino;
	e->caller_dev  = caller_dev;
	e->caller_ino  = caller_ino;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// v0.3 (Sec-12): actor_name carries the group name on the actor-
	// mismatch path. NULL src → zero out (uniform-deny / legacy paths).
	// The userspace loader populates sv->actor_name with a NUL-
	// terminated string truncated to 15 bytes, so this fixed-size copy
	// is safe and self-terminating at the consumer.
	if (actor_name_src) {
		__builtin_memcpy(e->actor_name, actor_name_src,
		                 sizeof(e->actor_name));
	} else {
		__builtin_memset(e->actor_name, 0, sizeof(e->actor_name));
	}

	bpf_ringbuf_submit(e, 0);
}

// Thin wrapper preserving v0 call sites: action + (dev, ino), no
// caller-exe identity and no actor name. The ringbuf consumer prints
// caller_dev/caller_ino only when non-zero and actor_name only on
// ACTION_DENY_ACTOR_MISMATCH events.
static __always_inline void
emit_audit(__u32 action, __u64 dev, __u64 ino)
{
	emit_audit_actor(action, dev, ino, 0, 0, (const char *)0);
}

// ---------------- Hooks ----------------

// Block unlink if parent dir is sealed (NO_UNLINK), or target inode is
// sealed (NO_UNLINK). "rm /var/lib/oracle/data" passes dir=oracle/, dentry=data.
SEC("lsm/inode_unlink")
int BPF_PROG(comp_inode_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
	(void)dir;
	if (ret != 0)
		return ret;

	struct caller_id cid = {};
	if (deny_dentry_parent_dir_action(dentry, SEAL_NO_UNLINK,
					  ACTION_DENY_UNLINK, &cid))
		return -EACCES;

	struct inode *target = BPF_CORE_READ(dentry, d_inode);
	if (deny_inode_action(target, SEAL_NO_UNLINK, ACTION_DENY_UNLINK, &cid))
		return -EACCES;

	return 0;
}

// TODO(exec-domain F25, VM-equipped): explore folding comp_inode_rename
// into deny_parent_dir_action so the per-direction logic below collapses
// into reused helpers. The change is
// stylistic + verifier-sensitive (the unrolled per-direction scan keeps
// the rename hook obviously matching SPEC §6.3), so it needs a
// `clang -fsyntax-only -target bpf` round-trip on a clang+libbpf host
// before landing. Defer to the compartment-vng matrix host or another
// clang-capable build host; the local build host may lack clang.
SEC("lsm/inode_rename")
int BPF_PROG(comp_inode_rename,
             struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry, int ret)
{
	(void)old_dir;
	(void)new_dir;
	if (ret != 0)
		return ret;

	// Per-direction mask: a rename OUT of old_dir is gated by NO_RENAME
	// and NO_UNLINK because it removes a directory entry from old_dir. A
	// rename INTO new_dir is also a "create entry" of sorts, so NO_WRITE on
	// the destination directory must block it (Codex finding 3:
	// `seal /etc no-write` did not stop `mv payload /etc/payload` because
	// the loop only checked NO_RENAME on both dirs). The action emitted
	// reflects what was conceptually denied: rename-out vs. write-into.
	int r;
	struct caller_id cid = {};
	r = deny_dentry_parent_dir_action(old_dentry,
					  SEAL_NO_RENAME | SEAL_NO_UNLINK,
					  ACTION_DENY_RENAME, &cid);
	if (r)
		return r;
	/* v0.6: rename OUT of any sealed ancestor dir removes a descendant
	 * entry; treat it as a write on the source subtree. */
	r = deny_dentry_parent_dir_action(old_dentry, SEAL_NO_WRITE,
					  ACTION_DENY_WRITE_PARENT_DIR, &cid);
	if (r)
		return r;
	r = deny_dentry_parent_dir_action(new_dentry, SEAL_NO_RENAME,
					  ACTION_DENY_RENAME, &cid);
	if (r)
		return r;
	r = deny_dentry_parent_dir_action(new_dentry, SEAL_NO_WRITE,
					  ACTION_DENY_WRITE_PARENT_DIR, &cid);
	if (r)
		return r;
	r = deny_non_dir_rename_subtree_alias_invariants(old_dentry, new_dentry);
	if (r)
		return r;
	r = deny_dir_rename_subtree_depth_cap(old_dentry, new_dentry);
	if (r)
		return r;

	struct inode *old_target = BPF_CORE_READ(old_dentry, d_inode);
	if (deny_inode_action(old_target,
			      SEAL_NO_RENAME | SEAL_NO_UNLINK,
			      ACTION_DENY_RENAME, &cid))
		return -EACCES;

	// Rename-over is replacement of the destination inode. Treat it as
	// rename, unlink, or write destruction depending on the seal flags.
	struct inode *new_target = BPF_CORE_READ(new_dentry, d_inode);
	if (deny_inode_action(new_target,
			      SEAL_NO_RENAME | SEAL_NO_UNLINK | SEAL_NO_WRITE,
			      ACTION_DENY_RENAME, &cid))
		return -EACCES;

	return 0;
}

SEC("lsm/inode_rmdir")
int BPF_PROG(comp_inode_rmdir, struct inode *dir, struct dentry *dentry, int ret)
{
	(void)dir;
	if (ret != 0)
		return ret;

	struct caller_id cid = {};
	if (deny_dentry_parent_dir_action(dentry, SEAL_NO_UNLINK,
					  ACTION_DENY_UNLINK, &cid))
		return -EACCES;

	struct inode *target = BPF_CORE_READ(dentry, d_inode);
	if (deny_inode_action(target, SEAL_NO_UNLINK, ACTION_DENY_UNLINK, &cid))
		return -EACCES;

	return 0;
}

SEC("lsm/inode_create")
int BPF_PROG(comp_inode_create, struct inode *dir, struct dentry *dentry,
	     umode_t mode, int ret)
{
	(void)dir;
	(void)mode;
	if (ret != 0)
		return ret;

	struct caller_id cid = {};
	return deny_dentry_parent_dir_action(dentry, SEAL_NO_WRITE,
					     ACTION_DENY_CREATE, &cid);
}

SEC("lsm/inode_mkdir")
int BPF_PROG(comp_inode_mkdir, struct inode *dir, struct dentry *dentry,
	     umode_t mode, int ret)
{
	(void)dir;
	(void)mode;
	if (ret != 0)
		return ret;

	struct caller_id cid = {};
	int r = deny_dentry_parent_dir_action(dentry, SEAL_NO_WRITE,
					      ACTION_DENY_CREATE, &cid);
	if (r)
		return r;
	return deny_mkdir_subtree_depth_cap(dentry);
}

SEC("lsm/inode_mknod")
int BPF_PROG(comp_inode_mknod, struct inode *dir, struct dentry *dentry,
	     umode_t mode, dev_t dev, int ret)
{
	(void)dir;
	(void)mode;
	(void)dev;
	if (ret != 0)
		return ret;

	struct caller_id cid = {};
	return deny_dentry_parent_dir_action(dentry, SEAL_NO_WRITE,
					     ACTION_DENY_CREATE, &cid);
}

SEC("lsm/inode_symlink")
int BPF_PROG(comp_inode_symlink, struct inode *dir, struct dentry *dentry,
	     const char *old_name, int ret)
{
	(void)dir;
	(void)old_name;
	if (ret != 0)
		return ret;

	struct caller_id cid = {};
	int r = deny_dentry_parent_dir_action(dentry, SEAL_NO_WRITE,
					      ACTION_DENY_CREATE, &cid);
	if (r)
		return r;
	return deny_subtree_invariant_on_child_dentry(dentry, ACTION_DENY_CREATE);
}

SEC("lsm/inode_link")
int BPF_PROG(comp_inode_link, struct dentry *old_dentry, struct inode *dir,
	     struct dentry *new_dentry, int ret)
{
	(void)dir;
	if (ret != 0)
		return ret;

	struct caller_id cid = {};
	int r;

	// Also check the SOURCE inode's seals.
	// The original implementation only checked the destination
	// parent dir's SEAL_NO_WRITE — which means an attacker on a box
	// with fs.protected_hardlinks=0 (or where /tmp is unsealed and
	// writable) could `link("/usr/sbin/aide", "/tmp/aide-alias")`,
	// `exec /tmp/aide-alias`, and have `current->mm->exe_file`
	// resolve to the same (dev, ino) as /usr/sbin/aide — inheriting
	// actor identity. ED-9 strict mode requires every actor binary
	// to carry a `full` (=SEAL_NO_WRITE | SEAL_NO_UNLINK |
	// SEAL_NO_RENAME | SEAL_NO_CHMOD) seal, so we close the surface
	// at the LSM layer: deny the link if the source inode is
	// SEAL_NO_WRITE, regardless of where the new hardlink lives.
	// One additional bpf_map_lookup_elem on the source inode key;
	// verifier-load risk is small. R2-F10 covers the sysctl side
	// (protected_hardlinks=1 as defense-in-depth) and the
	// LIMITATIONS row.
	struct inode *src = BPF_CORE_READ(old_dentry, d_inode);
	if (src) {
		r = deny_inode_action(src, SEAL_NO_WRITE,
				      ACTION_DENY_CREATE, &cid);
		if (r)
			return r;
	}

	/* v0.5: also deny link-OUT of a DD-sealed source directory.
	 * link("/D/file", "/tmp/alias") would create a write alias outside /D's
	 * protection scope; treat it as a write on the source parent dir. */
	r = deny_dentry_parent_dir_action(old_dentry, SEAL_NO_WRITE,
					  ACTION_DENY_WRITE_PARENT_DIR, &cid);
	if (r)
		return r;

	r = deny_dentry_parent_dir_action(new_dentry, SEAL_NO_WRITE,
					  ACTION_DENY_CREATE, &cid);
	if (r)
		return r;

	return deny_hardlink_subtree_alias_invariants(old_dentry, new_dentry);
}

// Block write-open of sealed files.
SEC("lsm/file_open")
int BPF_PROG(comp_file_open, struct file *file, int ret)
{
	if (ret != 0)
		return ret;

	__u32 fmode = BPF_CORE_READ(file, f_mode);
	if (!(fmode & FMODE_WRITE))
		return 0;

	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;

	struct caller_id cid = {};
	return deny_file_write(file, &cid);
}

SEC("lsm/file_permission")
int BPF_PROG(comp_file_permission, struct file *file, int mask, int ret)
{
	if (ret != 0)
		return ret;

	if (!(mask & MAY_WRITE))
		return 0;

	struct caller_id cid = {};
	return deny_file_write(file, &cid);
}

SEC("lsm/file_truncate")
int BPF_PROG(comp_file_truncate, struct file *file, int ret)
{
	if (ret != 0)
		return ret;

	struct caller_id cid = {};
	return deny_file_write(file, &cid);
}

SEC("lsm/inode_setattr")
int BPF_PROG(comp_inode_setattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, struct iattr *attr, int ret)
{
	(void)idmap;
	if (ret != 0)
		return ret;

	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	struct inode_key k = {};
	struct seal_value *isv = NULL, *dsv = NULL;
	__u32 ia_valid = BPF_CORE_READ(attr, ia_valid);
	struct caller_id cid = {};
	int r;

	// Per-inode seal checks (existing path — only fires when the target
	// inode itself is sealed).
	if (lookup_inode_seals(inode, &k, &isv, &dsv)) {
		if (ia_valid & ATTR_SIZE) {
			r = seal_decision(isv, SEAL_NO_WRITE,
			                  ACTION_DENY_WRITE, k.dev, k.ino, &cid);
			if (r)
				return r;
			r = seal_decision(dsv, SEAL_NO_WRITE,
			                  ACTION_DENY_WRITE, k.dev, k.ino, &cid);
			if (r)
				return r;
		}

		if (ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID)) {
			r = seal_decision(isv, SEAL_NO_CHMOD,
			                  ACTION_DENY_CHMOD, k.dev, k.ino, &cid);
			if (r)
				return r;
			r = seal_decision(dsv, SEAL_NO_CHMOD,
			                  ACTION_DENY_CHMOD, k.dev, k.ino, &cid);
			if (r)
				return r;
		}
	}

	// v0.5: parent-directory destination checks. Run independently of the
	// per-inode seal path; the parent dir may carry a seal even when the
	// child inode is unsealed. SPEC §5.2 policy:
	//   ATTR_SIZE                → SEAL_NO_WRITE (truncate-class)
	//   any other ATTR_* bit     → SEAL_NO_CHMOD (fail-closed for
	//                              unclassified bits)
	if (ia_valid & ATTR_SIZE) {
		r = deny_dentry_parent_dir_action(dentry, SEAL_NO_WRITE,
		                                  ACTION_DENY_WRITE_PARENT_DIR,
		                                  &cid);
		if (r)
			return r;
	}
	if (ia_valid & ~ATTR_SIZE) {
		r = deny_dentry_parent_dir_action(dentry, SEAL_NO_CHMOD,
		                                  ACTION_DENY_CHMOD_PARENT_DIR,
		                                  &cid);
		if (r)
			return r;
	}

	return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(comp_mmap_file, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags, int ret)
{
	if (ret != 0)
		return ret;

	if (!file)
		return 0;

	if (!((prot | reqprot) & PROT_WRITE))
		return 0;
	if (!(flags & MAP_SHARED))
		return 0;

	struct caller_id cid = {};
	return deny_file_write(file, &cid);
}

SEC("lsm/file_mprotect")
int BPF_PROG(comp_file_mprotect, struct vm_area_struct *vma,
	     unsigned long reqprot, unsigned long prot, int ret)
{
	(void)reqprot;
	if (ret != 0)
		return ret;

	if (!(prot & PROT_WRITE))
		return 0;

	unsigned long vm_flags = BPF_CORE_READ(vma, vm_flags);
	if (!(vm_flags & VM_SHARED))
		return 0;

	struct file *file = BPF_CORE_READ(vma, vm_file);
	if (!file)
		return 0;

	struct caller_id cid = {};
	return deny_file_write(file, &cid);
}

SEC("lsm/inode_setxattr")
int BPF_PROG(comp_inode_setxattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name, const void *value,
	     size_t size, int flags, int ret)
{
	(void)idmap;
	(void)name;
	(void)value;
	(void)size;
	(void)flags;
	if (ret != 0)
		return ret;

	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	struct caller_id cid = {};
	if (deny_inode_action(inode, SEAL_NO_CHMOD, ACTION_DENY_CHMOD, &cid))
		return -EACCES;
	// v0.5: parent-directory destination check.
	if (deny_dentry_parent_dir_action(dentry, SEAL_NO_CHMOD,
	                                  ACTION_DENY_CHMOD_PARENT_DIR, &cid))
		return -EACCES;

	return 0;
}

SEC("lsm/inode_removexattr")
int BPF_PROG(comp_inode_removexattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name, int ret)
{
	(void)idmap;
	(void)name;
	if (ret != 0)
		return ret;

	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	struct caller_id cid = {};
	if (deny_inode_action(inode, SEAL_NO_CHMOD, ACTION_DENY_CHMOD, &cid))
		return -EACCES;
	// v0.5: parent-directory destination check.
	if (deny_dentry_parent_dir_action(dentry, SEAL_NO_CHMOD,
	                                  ACTION_DENY_CHMOD_PARENT_DIR, &cid))
		return -EACCES;

	return 0;
}

// ============================================================
// v0.4 strict-launch-marker hooks (SPEC §6.1, §6.3 + G6 Outcome B)
// ============================================================

// §6.1 bprm_check_security — marker set / keep / clear. NOT a deny hook
// in v0.4; the actual deny point is the seal_decision strict-launch
// extension above. Sleepable (`lsm.s/`) because bpf_task_storage_get
// with F_CREATE may sleep when allocating the per-task slot.
//
// Per SPEC §6.1:
//   1. Resolve exec target inode (via bprm->file).
//   2. If target inode is a declared launcher (launcher_to_actor hit):
//      create/overwrite current task marker with (target, slot, gen).
//      marker_set_total++.
//   3. Else if current task already has a marker:
//      3a. If exec target == marker.target → keep (slm-actor exec from
//          its sealed launcher; legitimate chain continuation).
//      3b. Else → foreign exec. marker_clear_foreign_exec_total++ before
//          clearing. Allow exec.
//   4. Else allow exec (no marker, not a launcher; ordinary process).
SEC("lsm.s/bprm_check_security")
int BPF_PROG(comp_bprm_check_security, struct linux_binprm *bprm, int ret)
{
	if (ret != 0)
		return ret;

	struct task_struct *t;
	struct file *f;
	struct inode *ino_p;
	struct super_block *sb;
	struct inode_key exec_id = {};
	struct launcher_actor *la;
	struct actor_marker *am;
	__u32 gen;

	// cur_strict_loaded() short-circuit
	// mirrors the comp_task_prctl / comp_ptrace_*_check hooks. Without
	// it, every execve() on the host pays the BPF_CORE_READ + map-lookup
	// chain even on a profile with no strict-launch seals. Asymmetric
	// guard application (3 of 5 hooks short-circuited, 2 didn't) was
	// caught by 4 reviewers as an oversight; closing it makes the
	// kernel-wide cost-of-strict-mode zero on a v0.3-style profile.
	if (!cur_strict_loaded())
		return 0;

	// Resolve exec target inode key.
	f = BPF_CORE_READ(bprm, file);
	if (!f)
		return 0;
	ino_p = BPF_CORE_READ(f, f_inode);
	if (!ino_p)
		return 0;
	exec_id.ino = BPF_CORE_READ(ino_p, i_ino);
	sb = BPF_CORE_READ(ino_p, i_sb);
	if (sb)
		exec_id.dev = (__u64)BPF_CORE_READ(sb, s_dev);

	t = (void *)bpf_get_current_task_btf();
	if (!t)
		return 0;

	gen = cur_strict_generation();

	la = bpf_map_lookup_elem(&launcher_to_actor, &exec_id);
	if (la) {
		// Step 2: launcher exec — create/overwrite marker.
		am = bpf_task_storage_get(&actor_marker_map, t, NULL,
		                          BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (am) {
			am->target = la->target;
			am->actor_slot = la->actor_slot;
			am->policy_generation = gen;
			am->state = 1;
			am->_pad = 0;
			bump_counter(&marker_set_total);
		}
		return 0;
	}

	// Step 3: not a launcher — examine existing marker.
	am = bpf_task_storage_get(&actor_marker_map, t, NULL, 0);
	if (!am || am->state == 0)
		return 0;

	// 3a: exec target == marker target → keep marker.
	if (am->target.dev == exec_id.dev && am->target.ino == exec_id.ino)
		return 0;

	// 3b: foreign exec → clear marker (after counter bump per G10).
	bump_counter(&marker_clear_foreign_exec_total);
	bpf_task_storage_delete(&actor_marker_map, t);
	return 0;
}

// G6 Outcome (B): copy parent marker to child on fork/clone so a
// fork-without-exec actor (postgres-prefork style; AIDE fork-write
// witness SL-4) keeps actor identity. SPEC §8 G6 alternative for
// kernels without BPF_F_INHERIT_TASK_STORAGE (Ubuntu 26.04 (kernel 7.0) has none —
// verified by `grep -ni 'inherit' /usr/include/linux/bpf.h`).
SEC("lsm/task_alloc")
int BPF_PROG(comp_task_alloc, struct task_struct *task, u64 clone_flags, int ret)
{
	struct task_struct *parent;
	struct actor_marker *p_am, *c_am;

	(void)clone_flags;
	if (ret != 0)
		return ret;

	// cur_strict_loaded() short-circuit
	// — see comp_bprm_check_security above. comp_task_alloc fires on
	// every clone() kernel-wide; without the early-out, the
	// bpf_task_storage_get probe on the parent runs even on a v0.3
	// profile where no actor_marker storage exists. Closes the
	// asymmetric-guard oversight flagged across 4
	// reviewers.
	if (!cur_strict_loaded())
		return 0;

	parent = (void *)bpf_get_current_task_btf();
	if (!parent)
		return 0;

	p_am = bpf_task_storage_get(&actor_marker_map, parent, NULL, 0);
	if (!p_am || p_am->state == 0)
		return 0;

	c_am = bpf_task_storage_get(&actor_marker_map, task, NULL,
	                            BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!c_am)
		return 0;

	c_am->target = p_am->target;
	c_am->actor_slot = p_am->actor_slot;
	c_am->policy_generation = p_am->policy_generation;
	c_am->state = p_am->state;
	c_am->_pad = 0;
	bump_counter(&marker_copy_fork_total);
	return 0;
}

// §6.3 task_prctl — globally deny PR_SET_MM whenever any strict policy
// is loaded. Deliberately not limited to marked tasks: an unmarked
// attacker must not be able to prepare a forged actor identity
// (current->mm->exe_file is what caller_id_resolve_locked reads) before
// reaching the file-op enforcement path. The deny short-circuits BEFORE
// strict-launch's file-op check sees a tampered exe inode, closing
// SL-7a/b.
//
// Broadened from `arg2 == PR_SET_MM_EXE_FILE`
// only to ALL PR_SET_MM sub-ops. PR_SET_MM_MAP (sub-op 14) accepts a
// `struct prctl_mm_map` whose `exe_fd` field overwrites
// current->mm->exe_file at the same CAP_SYS_RESOURCE privilege tier as
// PR_SET_MM_EXE_FILE — the narrow gate left a direct G8 bypass. Per-sub-op
// enumeration is fragile (new sub-ops have been added to the kernel
// between releases); legitimate userspace doesn't need PR_SET_MM under
// strict-launch, so deny the whole option family. The counter name
// preserves operator continuity — `prctl_set_mm_exe_file_denied_total`
// still names the protected resource (the exe_file pointer), even
// though the deny now covers MAP / AUXV / etc. sub-ops too.
SEC("lsm/task_prctl")
int BPF_PROG(comp_task_prctl, int option, unsigned long arg2,
             unsigned long arg3, unsigned long arg4, unsigned long arg5,
             int ret)
{
	(void)arg2; (void)arg3; (void)arg4; (void)arg5;
	if (ret != 0)
		return ret;
	if (!cur_strict_loaded())
		return 0;
	if (option == PR_SET_MM) {
		bump_counter(&prctl_set_mm_exe_file_denied_total);
		// v0.7: distinct side-deny audit action so operators can
		// distinguish the global PR_SET_MM hardening gate from
		// file-op ACTION_DENY_STRICT_LAUNCH_MISSING events.
		emit_audit_actor(ACTION_DENY_PRCTL_SET_MM,
		                 0, 0, 0, 0, (const char *)0);
		return -EPERM;
	}
	// PR_SET_MM_MAP etc. require CAP_SYS_RESOURCE; all sub-ops are denied
	// above via the PR_SET_MM family deny. All other prctl options (not
	// PR_SET_MM) are out of scope for compartment-bpf and treated as
	// allowed — CAP_SYS_RESOURCE is not typically granted to actors (M-25).
	return 0;
}

// §6.3 ptrace_access_check — deny ptrace targeting a marked strict
// actor task. Covers strace, process_vm_writev, pidfd_getfd,
// /proc/<pid>/mem read (all route through security_ptrace_access_check
// on Ubuntu 26.04 (kernel 7.0); G9 4-vector witness confirmed 2026-05-15).
SEC("lsm/ptrace_access_check")
int BPF_PROG(comp_ptrace_access_check, struct task_struct *child,
             unsigned int mode, int ret)
{
	struct actor_marker *am;
	(void)mode;
	if (ret != 0)
		return ret;
	if (!cur_strict_loaded())
		return 0;
	am = bpf_task_storage_get(&actor_marker_map, child, NULL, 0);
	if (am && am->state) {
		bump_counter(&ptrace_access_denied_total);
		// v0.7: distinct audit action for strict-launch ptrace hardening.
		emit_audit_actor(ACTION_DENY_PTRACE_ACCESS,
		                 0, 0, 0, 0, (const char *)0);
		return -EPERM;
	}
	return 0;
}

// §6.3 ptrace_traceme — deny PTRACE_TRACEME when caller has a strict
// marker. A marked actor calling traceme would invite a debugger to
// attach as parent and bypass the access_check above.
SEC("lsm/ptrace_traceme")
int BPF_PROG(comp_ptrace_traceme, struct task_struct *parent, int ret)
{
	struct task_struct *me;
	struct actor_marker *am;
	(void)parent;
	if (ret != 0)
		return ret;
	if (!cur_strict_loaded())
		return 0;
	me = (void *)bpf_get_current_task_btf();
	if (!me)
		return 0;
	am = bpf_task_storage_get(&actor_marker_map, me, NULL, 0);
	if (am && am->state) {
		bump_counter(&ptrace_traceme_denied_total);
		// v0.7: distinct audit action for strict-launch traceme hardening.
		emit_audit_actor(ACTION_DENY_PTRACE_TRACEME,
		                 0, 0, 0, 0, (const char *)0);
		return -EPERM;
	}
	return 0;
}
