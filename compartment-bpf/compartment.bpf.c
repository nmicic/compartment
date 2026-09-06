// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
//
// compartment-bpf: kernel-side LIDS-style sealed paths using BPF LSM.
// Exec domains (the "actor allowlist" — bind a seal to specific caller
// exe inodes). Companion to
// compartment-user (Landlock+seccomp) and compartment-root (namespaces).
//
// Hooks (27 attach points as of ABI v0.8; 29 SEC() entries, two of which are
// the mutually-exclusive inode_setattr signature wrappers):
//   v0.x file/inode/path (16):
//     inode_unlink, inode_rename, inode_rmdir, inode_create, inode_mkdir,
//     inode_mknod, inode_symlink, inode_link, file_open, file_permission,
//     file_truncate, inode_setattr, mmap_file, file_mprotect,
//     inode_setxattr, inode_removexattr
//   v0.4 strict-launch (5):
//     bprm_committed_creds (sets/keeps/clears the task-storage marker;
//     moved here from bprm_check_security in v0.8 — see the hook comment),
//     task_alloc (G6 marker copy on fork), task_prctl (PR_SET_MM deny),
//     ptrace_access_check, ptrace_traceme
//   v0.8 metadata + mount coverage (7):
//     inode_set_acl, inode_remove_acl (POSIX ACL writes bypass the xattr
//     hooks), file_ioctl + file_ioctl_compat (FS_IOC_SETFLAGS /
//     FSSETXATTR / SETVERSION, native and 32-bit compat entry points),
//     sb_mount, move_mount (no new mount on or under a sealed path),
//     sb_umount (no detaching the filesystem out from under one)
//   v0.8 self-protection (1, opt-in via --self-protect):
//     bpf_map (no fd to a compartment map for anything but the loader).
//     inode_unlink / inode_rename / inode_rmdir / sb_mount / sb_umount also
//     gain a pin-tamper branch; they are existing hooks, not new links.
//
// v0.1 maps:
//   sealed_inodes : (dev, ino) -> struct seal_value     (per-file)
//   sealed_dirs   : (dev, ino) -> struct seal_value     (per-dir, applies to subtree descendants)
//   audit_rb      : ringbuf of deny events
//
// ABI v0.1 widens the map value from __u32 to struct seal_value (72 bytes).
// actor_count == 0 preserves v0 uniform-deny semantics; the actor check adds the
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
#ifndef ATTR_ATIME
#define ATTR_ATIME 16
#endif
#ifndef ATTR_MTIME
#define ATTR_MTIME 32
#endif

// v0.8 file_ioctl gate. vmlinux.h carries no preprocessor macros, so the
// uapi encodings are spelled out (_IOW('f', 2, long) etc.; identical on
// every 64-bit arch Linux supports). Verified against <linux/fs.h> on the
// build host; tests/bypass/18-chattr-no-chmod.sh exercises SETFLAGS
// end-to-end.
#define COMP_FS_IOC_SETFLAGS      0x40086602UL
#define COMP_FS_IOC32_SETFLAGS    0x40046602UL
#define COMP_FS_IOC_FSSETXATTR    0x401c5820UL
#define COMP_FS_IOC_SETVERSION    0x40087602UL
#define COMP_FS_IOC32_SETVERSION  0x40047602UL

// v0.8 sb_mount gate: mount(2) flag bits that modify an existing mount
// and attach nothing new at the target path. Mirrors the dispatch order
// in fs/namespace.c:path_mount().
#ifndef MS_REMOUNT
#define MS_REMOUNT     0x20
#endif
#ifndef MS_BIND
#define MS_BIND        0x1000
#endif
#ifndef MS_UNBINDABLE
#define MS_UNBINDABLE  (1 << 17)
#endif
#ifndef MS_PRIVATE
#define MS_PRIVATE     (1 << 18)
#endif
#ifndef MS_SLAVE
#define MS_SLAVE       (1 << 19)
#endif
#ifndef MS_SHARED
#define MS_SHARED      (1 << 20)
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

// v0.8: the set of superblock devices that host at least one sealed inode
// or sealed directory. Populated by the loader as it writes sealed_inodes /
// sealed_dirs, and frozen with them.
//
// comp_sb_umount is handed a `struct vfsmount *`, not an inode, so the
// per-inode maps cannot answer the only question that hook needs to ask:
// "does this filesystem host anything sealed?". The value is a refcount of
// the seals on that device, kept for diagnostics; the hook only tests
// presence.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u32);
} sealed_devs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} audit_rb SEC(".maps");

// Deny counters. Per-CPU arrays; userspace sums across all possible CPUs.
// deny_total            : incremented at every enforcement deny, BEFORE
//                         the ringbuf reserve attempt. Counts the policy
//                         decision, not the audit success.
// audit_drop_total      : incremented when bpf_ringbuf_reserve() returns
//                         NULL after deny_total was already counted. Soak
//                         evidence that the kernel saw the deny even when
//                         the audit stream is being dropped.
// actor_mismatch_total  : incremented at every actor-mismatch deny
//                         BEFORE the audit emit. Subset of deny_total
//                         records the actor-allowlist evictions specifically;
//                         records every actor-mismatch decision even when
//                         the audit ringbuf is dropped (mirrors the
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
// v0.4 strict-launch-marker (SLM) — production lift of the
// strict-launch-marker spike. See HOWTO.md §2.3.x.
// ============================================================
//
// Maps:
//   launcher_to_actor : HASH(inode_key -> launcher_actor)
//                       set by loader from `actor-strict … launcher=…`.
//   actor_marker_map  : TASK_STORAGE(actor_marker)
//                       set on launcher exec, cleared on foreign exec,
//                       copied on fork via lsm/task_alloc.
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
// (the ordering invariant; SPEC §6.4).
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

// v0.8: bprm_committed_creds could not allocate the task-storage marker.
// Fail-closed (the actor is later denied with DENY_STRICT_LAUNCH_MISSING),
// but silent without this counter — an operator seeing strict-launch denies
// with no policy change needs to be able to tell "allocation pressure" from
// "someone is attacking the launcher chain".
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} marker_set_fail_total SEC(".maps");

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
// through security_ptrace_access_check on Ubuntu 26.04 (kernel 7.0)).
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

// ============================================================
// v0.8 self-protection maps.
// ============================================================
//
// Why any of this exists: bpf_map_freeze() is not map integrity. Measured on
// 6.8.0-139 and 7.0.0-31 — a CAP_BPF caller that gets ANY fd to a frozen
// compartment map (BPF_F_RDONLY is sufficient) can splice it into its own BPF
// program via bpf_map__reuse_fd() and write it with bpf_map_update_elem() from
// program context. freeze only gates map_get_sys_perms() on the syscall path.
// The single chokepoint that sees every fd handed out for a map is
// bpf_map_new_fd() -> security_bpf_map(), which is why comp_bpf_map below
// denies *fd creation* rather than writes.
//
//   protected_map_ids : map id -> 1. Every compartment map, including these
//                       four. Populated after __load() (ids exist then) and
//                       frozen before attach: it is the root of trust, so it
//                       must be immutable before the gate goes live.
//   loader_ids        : (dev, ino) of every binary allowed to maintain this
//                       policy. Frozen before attach for the same reason. A
//                       frozen loader_ids is deliberate: "the loader can add
//                       itself later" would mean anything that can make the
//                       loader run one more time can widen the allowlist.
//   protected_pins    : (dev, ino) of every bpffs pin object, the two pin
//                       directories, PIN_ROOT and the bpffs mount root. These
//                       inodes do not exist until pin_links() runs, which is
//                       AFTER attach, so this map is populated late and frozen
//                       late. It is safe in that window because its id is
//                       already in protected_map_ids and comp_bpf_map is
//                       already attached — no non-loader can get an fd to it.
//   self_protect_cfg  : { pin_dev, enabled }. Same late-write reason (pin_dev
//                       comes from the bpffs superblock).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} protected_map_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, COMPARTMENT_MAX_LOADER_IDS);
	__type(key, struct inode_key);
	__type(value, __u8);
} loader_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct inode_key);
	__type(value, __u8);
} protected_pins SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct self_protect_cfg);
} self_protect_cfg_map SEC(".maps");

// v0.8 counters. Same convention as every other counter: bumped BEFORE the
// ringbuf reserve so the count survives audit pressure.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} bpf_self_denied_total SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} pin_tamper_denied_total SEC(".maps");

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

// ---------------- actor_check_or_deny ----------------
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
// Counter invariant preserved for actor mismatches: actor_mismatch_total is
// bumped BEFORE the audit ringbuf reserve so the counter records every
// actor-mismatch decision even when the audit stream is being dropped.
// Every actor-mismatch deny path bumps the counter then emits
// ACTION_DENY_ACTOR_MISMATCH with the caller's resolved (dev, ino).
// Hoist into one helper so the three call sites in actor_check_or_deny
// stay obviously identical and a future audit-side change touches one
// spot instead of three.
static __always_inline int
deny_actor_mismatch(struct seal_value *sv,
                    __u64 dev, __u64 ino, __u64 cdev, __u64 cino)
{
	bump_counter(&actor_mismatch_total);
	// v0.3: pass sv->actor_name into the audit emit so the
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

	// caller_id may already be resolved by a sibling seal check
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

// ---------------- v0.8 self-protection helpers ----------------

// One ARRAY[1] lookup. Returns NULL when self-protection is off, so every
// gate below is a single branch in the default (flag-off) build.
static __always_inline struct self_protect_cfg *self_protect(void)
{
	__u32 z = 0;
	struct self_protect_cfg *c =
		bpf_map_lookup_elem(&self_protect_cfg_map, &z);
	if (!c || !c->enabled)
		return (struct self_protect_cfg *)0;
	return c;
}

// Is the calling task running one of the binaries allowed to maintain this
// policy?  Identity is the same (dev, ino) of mm->exe_file that the actor
// allowlist uses, so the two notions of "who is this" cannot drift, and the
// caller_id cache is shared with the seal path when both run in one hook.
//
// A task with no resolvable exe (kernel thread, exiting task) is NOT a
// loader: fail closed.
static __always_inline int caller_is_loader(struct caller_id *cid)
{
	if (!cid->resolved)
		caller_id_resolve_locked(cid);
	if (!cid->valid)
		return 0;
	struct inode_key k = { .dev = cid->dev, .ino = cid->ino };
	return bpf_map_lookup_elem(&loader_ids, &k) != (void *)0;
}

// Common deny tail for both self-protection actions: count first, then emit with the
// caller's exe identity so an operator can see WHICH binary tried it. Actor
// name is empty — these denies are not seal-scoped, they are tool-scoped.
//
// `err` is the caller's, because the two actions land on different syscalls and
// each has to answer in that syscall's dialect:
//
//   * the bpf_map gate returns -EPERM. bpf(2) reports every "you do not have
//     the right to this object" as EPERM — bpf_map_get_fd_by_id() itself does,
//     for a caller without CAP_BPF — so a BPF tool has an EPERM path and no
//     EACCES path. Measured: with -EACCES, bpftool reports "Permission denied"
//     and aborts; with -EPERM it reports "Operation not permitted" and aborts
//     the same way, but libbpf's own callers and anything matching on EPERM
//     see the errno the syscall is documented to produce. -ENOENT was measured
//     and rejected: it makes bpftool exit 0 with our maps simply absent, which
//     disguises a security decision as a missing object and makes an
//     unauthorised --stats say "no pinned counters found" — indistinguishable
//     from "no policy is pinned".
//   * the pin-tamper gate returns -EACCES, which is what every other
//     compartment deny returns on a path operation and what `rm`, `mv` and
//     `umount` print as "Permission denied".
static __always_inline int
deny_self_protect(__u32 action, void *counter, __u64 dev, __u64 ino,
                  struct caller_id *cid, int err)
{
	bump_counter(counter);
	emit_audit_actor(action, dev, ino,
	                 cid->valid ? cid->dev : 0,
	                 cid->valid ? cid->ino : 0,
	                 (const char *)0);
	return err;
}

// Guard the bpffs pin objects. Ordered so the common case (any inode op on any
// filesystem that is not the bpffs holding PIN_ROOT) costs one ARRAY lookup
// and one compare, with no hash lookup at all.
static __always_inline int
deny_pin_tamper(struct inode *inode, struct caller_id *cid)
{
	struct self_protect_cfg *cfg = self_protect();
	if (!cfg)
		return 0;
	if (!inode)
		return 0;
	struct inode_key k = inode_key_of(inode);
	if (k.dev == 0 || k.dev != cfg->pin_dev)
		return 0;
	if (!bpf_map_lookup_elem(&protected_pins, &k))
		return 0;
	if (caller_is_loader(cid))
		return 0;
	return deny_self_protect(ACTION_DENY_PIN_TAMPER,
	                         &pin_tamper_denied_total, k.dev, k.ino, cid,
	                         -EACCES);
}

static __always_inline int
deny_pin_tamper_dentry(struct dentry *dentry, struct caller_id *cid)
{
	if (!dentry)
		return 0;
	return deny_pin_tamper(BPF_CORE_READ(dentry, d_inode), cid);
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
//   - strict_launch_missing_total++ BEFORE any ringbuf reserve.
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
		// Cross-phase doctrine: defend against verifier-allowed
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
	// closes the foreign-exec → re-exec-actor chain.
	// cid->valid is guaranteed true here (entry guard at line 516 denies
	// on !cid->valid before reaching this point — redundant guard removed).
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
// Audit emission is OWNED by actor_check_or_deny on all deny
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

// ABI v0.2 widened emit. Used directly by the actor-mismatch path so the
// caller_dev/caller_ino fields are populated; the legacy 3-arg
// emit_audit wrapper below preserves all v0 call sites unchanged by
// passing zeros for the caller fields.
//
// v0.3: writes the ABI version word at offset 0 of
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

	// Ordering invariant: count the deny BEFORE attempting the
	// ringbuf reserve. The counter records the policy decision; the
	// ringbuf is best-effort audit.
	bump_counter(&deny_total);

	e = bpf_ringbuf_reserve(&audit_rb, sizeof(*e), 0);
	if (!e) {
		bump_counter(&audit_drop_total);
		return;
	}

	// Cross-phase uniform doctrine: guard bpf_get_current_task_btf() against a NULL
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

	// v0.3: actor_name carries the group name on the actor-
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
	/* v0.8: `rm /sys/fs/bpf/compartment/links/comp_file_open` is the real
	 * removal path for a BPF-LSM policy (BPF_LINK_DETACH returns
	 * -EOPNOTSUPP for LSM links on both 6.8 and 7.0 — measured). Gate it
	 * before the operator-seal logic so a pin-tamper deny is never
	 * mis-attributed to a profile seal. */
	if (deny_pin_tamper_dentry(dentry, &cid))
		return -EACCES;

	if (deny_dentry_parent_dir_action(dentry, SEAL_NO_UNLINK,
					  ACTION_DENY_UNLINK, &cid))
		return -EACCES;

	struct inode *target = BPF_CORE_READ(dentry, d_inode);
	if (deny_inode_action(target, SEAL_NO_UNLINK, ACTION_DENY_UNLINK, &cid))
		return -EACCES;

	return 0;
}

// TODO(exec-domain, VM-equipped): explore folding comp_inode_rename
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
	// the destination directory must block it: previously
	// `seal /etc no-write` did not stop `mv payload /etc/payload` because
	// the loop only checked NO_RENAME on both dirs. The action emitted
	// reflects what was conceptually denied: rename-out vs. write-into.
	int r;
	struct caller_id cid = {};
	/* v0.8: renaming a pin out of the way is unlink-equivalent (the pin
	 * object survives under the new name, but --unpin sweeps by name and
	 * would then leave it behind as an orphan). Gate both ends. */
	if (deny_pin_tamper_dentry(old_dentry, &cid))
		return -EACCES;
	if (deny_pin_tamper_dentry(new_dentry, &cid))
		return -EACCES;

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
	/* v0.8: `rm -rf /sys/fs/bpf/compartment` finishes with rmdir on
	 * links/, maps/ and the root. PIN_ROOT and both subdirectories are in
	 * protected_pins for exactly this. */
	if (deny_pin_tamper_dentry(dentry, &cid))
		return -EACCES;

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
	// actor identity. Strict mode requires every actor binary
	// to carry a `full` (=SEAL_NO_WRITE | SEAL_NO_UNLINK |
	// SEAL_NO_RENAME | SEAL_NO_CHMOD) seal, so we close the surface
	// at the LSM layer: deny the link if the source inode is
	// SEAL_NO_WRITE, regardless of where the new hardlink lives.
	// One additional bpf_map_lookup_elem on the source inode key;
	// verifier-load risk is small. The sysctl side
	// (protected_hardlinks=1 as defense-in-depth) and the
	// LIMITATIONS row document the complementary mitigation.
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

// The inode_setattr LSM hook signature differs across kernels: 7.0+ prepends a
// `struct mnt_idmap *idmap` argument (BTF func-proto vlen=3), while pre-7.0
// kernels (e.g. Ubuntu Noble, 6.8) have only (dentry, attr) (vlen=2). idmap is
// not used by our policy, so the decision logic lives in one inlined body and
// we expose TWO SEC("lsm/inode_setattr") entry wrappers below — a 3-arg
// (modern) and a 2-arg (legacy) form. The userspace loader autoload-gates the
// one matching the running kernel's BTF before load (see
// select_inode_setattr_variant() in compartment-bpf.c); the non-matching
// wrapper is never loaded, so the verifier never sees a bad ctx access.
static __always_inline int
comp_inode_setattr_impl(struct dentry *dentry, struct iattr *attr, int ret)
{
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

		// v0.8: explicit timestamp writes (utimensat / touch -d) on a
		// directly sealed inode are chmod-class, matching the v0.5
		// parent-dir rule below (anti-forensic mtime forgery on a sealed
		// file is a metadata mutation the seal promises to block).
		// Kernel-internal notify_change() callers never carry
		// ATTR_ATIME|ATTR_MTIME without ATTR_SIZE (do_truncate) or
		// carry them at all (chmod_common, chown_common,
		// file_remove_privs), so the ATTR_SIZE exclusion keeps
		// truncation classified as write, not chmod.
		if ((ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID)) ||
		    (!(ia_valid & ATTR_SIZE) &&
		     (ia_valid & (ATTR_ATIME | ATTR_MTIME)))) {
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

// Modern (kernel 7.0+) inode_setattr: (idmap, dentry, attr).
SEC("lsm/inode_setattr")
int BPF_PROG(comp_inode_setattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, struct iattr *attr, int ret)
{
	(void)idmap;
	return comp_inode_setattr_impl(dentry, attr, ret);
}

// Legacy (pre-7.0, e.g. 6.8) inode_setattr: (dentry, attr), no mnt_idmap.
SEC("lsm/inode_setattr")
int BPF_PROG(comp_inode_setattr_legacy, struct dentry *dentry,
	     struct iattr *attr, int ret)
{
	return comp_inode_setattr_impl(dentry, attr, ret);
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
// v0.4 strict-launch-marker hooks (SPEC §6.1, §6.3)
// ============================================================

// §6.1 marker set / keep / clear — attached at bprm_committed_creds.
//
// v0.8: moved from bprm_check_security. security_bprm_check() is called
// from search_binary_handler() (fs/exec.c) immediately BEFORE
// fmt->load_binary(), i.e. before load_elf_binary() has done anything. The
// exploitable window is between that call and begin_new_exec(), because
// every failure inside load_elf_binary() up to that point returns -errno to
// the caller's ORIGINAL image — the task keeps running its old code with
// whatever the check hook already wrote.
//
// Note this is NOT the window the first draft of this comment claimed:
// de_thread(), unshare_files()/dup_fd() and exec_mmap() all run inside
// begin_new_exec(), which sets bprm->point_of_no_return before any of them,
// and bprm_execve() turns a failure past that point into force_fatal_sig
// (SIGSEGV). Those paths kill the task; they can never return a marker to
// the caller. The genuine pre-commit failure points, in
// fs/binfmt_elf.c:load_elf_binary(), are:
//
//   - open_exec(elf_interpreter)  -> -ENOENT, and deterministically
//     forceable: an attacker who controls a mount namespace shadows the
//     interpreter path named in the launcher's PT_INTERP.
//   - load_elf_phdrs()            -> -ENOMEM
//   - the PT_INTERP sanity checks -> -ELIBBAD
//   - the -ENOEXEC binfmt retry loop
//
// With the marker written at check time, a task already executing the actor
// target (direct exec under LD_PRELOAD: exe == target, no marker) could
// execve() the sealed launcher, force one of those failures — the
// interpreter shadow is a single mount away and needs no race — and return
// to its own code carrying a valid marker whose target matched its exe,
// satisfying every strict-launch condition.
//
// bprm_committed_creds runs only once the new credentials and mm are
// installed, so a marker can never describe an image that did not actually
// replace the caller. bprm->file here is the final binary (for scripts, the
// interpreter) and is what set_mm_exe_file() installed as
// current->mm->exe_file — the same inode caller_id_resolve_locked reads at
// enforcement time.
//
// Per SPEC §6.1:
//   1. Resolve exec target inode (via bprm->file). Unresolvable → drop
//      any existing marker (fail closed) and return.
//   2. If target inode is a declared launcher (launcher_to_actor hit):
//      create/overwrite current task marker with (target, slot, gen).
//      marker_set_total++ (marker_set_fail_total++ if the task-storage
//      allocation fails; the actor then fails closed at op time).
//   3. Else if current task already has a marker:
//      3a. If exec target == marker.target → keep (slm-actor exec from
//          its sealed launcher; legitimate chain continuation).
//      3b. Else → foreign exec. marker_clear_foreign_exec_total++ before
//          clearing.
//   4. Else nothing (no marker, not a launcher; ordinary process).
// Attached sleepable (lsm.s/). bpf_lsm_bprm_committed_creds is in the
// kernel's sleepable_lsm_hooks allowlist on every supported kernel (6.8 and
// 7.0 both verified), and sleepable context is what makes the
// bpf_task_storage_get(F_CREATE) below a blocking allocation. A plain lsm/
// attach would work, but under memory pressure the marker allocation could
// fail without blocking, silently costing an actor its identity. The
// remaining failure is counted (marker_set_fail_total) rather than ignored.
//
// The hook is void (LSM_RET_VOID): the program is linked as BPF_TRAMP_FEXIT
// and its return value is discarded, so nothing here can deny. Every return
// is 0 and the BPF_PROG arity omits the trailing `int ret` — there is no
// return slot to read.
SEC("lsm.s/bprm_committed_creds")
int BPF_PROG(comp_bprm_committed_creds, struct linux_binprm *bprm)
{
	struct task_struct *t;
	struct file *f;
	struct inode *ino_p;
	struct super_block *sb;
	struct inode_key exec_id = {};
	struct launcher_actor *la;
	struct actor_marker *am;
	__u32 gen;

	// cur_strict_loaded() short-circuit mirrors comp_task_alloc /
	// comp_task_prctl / comp_ptrace_*: every execve() on the host would
	// otherwise pay the BPF_CORE_READ + map-lookup chain on a profile
	// with no strict-launch seals.
	if (!cur_strict_loaded())
		return 0;

	t = (void *)bpf_get_current_task_btf();
	if (!t)
		return 0;

	// Resolve exec target inode key.
	f = BPF_CORE_READ(bprm, file);
	ino_p = f ? BPF_CORE_READ(f, f_inode) : (struct inode *)0;
	if (!ino_p) {
		// Cannot classify the committed image: a marked task must not
		// keep actor identity across an exec we cannot attribute.
		bpf_task_storage_delete(&actor_marker_map, t);
		return 0;
	}
	exec_id.ino = BPF_CORE_READ(ino_p, i_ino);
	sb = BPF_CORE_READ(ino_p, i_sb);
	if (sb)
		exec_id.dev = (__u64)BPF_CORE_READ(sb, s_dev);

	gen = cur_strict_generation();

	la = bpf_map_lookup_elem(&launcher_to_actor, &exec_id);
	if (la) {
		// Step 2: launcher exec committed — create/overwrite marker.
		am = bpf_task_storage_get(&actor_marker_map, t, NULL,
		                          BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (am) {
			am->target = la->target;
			am->actor_slot = la->actor_slot;
			am->policy_generation = gen;
			am->state = 1;
			am->_pad = 0;
			bump_counter(&marker_set_total);
		} else {
			// Task-storage allocation failed. Fail-closed: without a
			// marker the actor is denied by strict_launch_check_or_deny
			// with DENY_STRICT_LAUNCH_MISSING. Count it so the deny has a
			// distinguishable root cause instead of looking like an
			// attack on the launcher chain.
			bump_counter(&marker_set_fail_total);
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

	// 3b: foreign exec → clear marker (after counter bump).
	bump_counter(&marker_clear_foreign_exec_total);
	bpf_task_storage_delete(&actor_marker_map, t);
	return 0;
}

// Copy parent marker to child on fork/clone so a
// fork-without-exec actor (postgres-prefork style; AIDE fork-write)
// keeps actor identity. SPEC §8 alternative for
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
// the exe-file-tampering bypass.
//
// Broadened from `arg2 == PR_SET_MM_EXE_FILE`
// only to ALL PR_SET_MM sub-ops. PR_SET_MM_MAP (sub-op 14) accepts a
// `struct prctl_mm_map` whose `exe_fd` field overwrites
// current->mm->exe_file at the same CAP_SYS_RESOURCE privilege tier as
// PR_SET_MM_EXE_FILE — the narrow gate left a direct bypass. Per-sub-op
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
	// allowed — CAP_SYS_RESOURCE is not typically granted to actors.
	return 0;
}

// §6.3 ptrace_access_check — deny ptrace targeting a marked strict
// actor task. Covers strace, process_vm_writev, pidfd_getfd,
// /proc/<pid>/mem read (all route through security_ptrace_access_check
// on Ubuntu 26.04 (kernel 7.0)).
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

// ============================================================
// v0.8 metadata + mount coverage
// ============================================================

// POSIX ACLs. Since Linux 6.2 (vfs_set_acl()/vfs_remove_acl()),
// setxattr(2)/removexattr(2) on system.posix_acl_{access,default} are
// routed by do_setxattr()/removexattr() to the ACL VFS entry points,
// which call security_inode_set_acl()/security_inode_remove_acl() and
// never security_inode_setxattr()/security_inode_removexattr(). On the
// project's kernel floor (>= 6.6) a `no-chmod` seal therefore did not
// stop `setfacl -m / -x / -b`, even though an ACL write rewrites the
// effective permission bits (posix_acl_update_mode derives the group
// bits from the ACL mask). Mirror comp_inode_setxattr /
// comp_inode_removexattr exactly: per-inode SEAL_NO_CHMOD, then the
// parent-dir / recursive-subtree SEAL_NO_CHMOD. kacl is declared void *
// so the program does not depend on struct posix_acl being in BTF.
SEC("lsm/inode_set_acl")
int BPF_PROG(comp_inode_set_acl, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *acl_name, void *kacl,
	     int ret)
{
	(void)idmap;
	(void)acl_name;
	(void)kacl;
	if (ret != 0)
		return ret;

	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	struct caller_id cid = {};
	if (deny_inode_action(inode, SEAL_NO_CHMOD, ACTION_DENY_CHMOD, &cid))
		return -EACCES;
	if (deny_dentry_parent_dir_action(dentry, SEAL_NO_CHMOD,
					  ACTION_DENY_CHMOD_PARENT_DIR, &cid))
		return -EACCES;
	return 0;
}

SEC("lsm/inode_remove_acl")
int BPF_PROG(comp_inode_remove_acl, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *acl_name, int ret)
{
	(void)idmap;
	(void)acl_name;
	if (ret != 0)
		return ret;

	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	struct caller_id cid = {};
	if (deny_inode_action(inode, SEAL_NO_CHMOD, ACTION_DENY_CHMOD, &cid))
		return -EACCES;
	if (deny_dentry_parent_dir_action(dentry, SEAL_NO_CHMOD,
					  ACTION_DENY_CHMOD_PARENT_DIR, &cid))
		return -EACCES;
	return 0;
}

// Inode flag ioctls. chattr(1) (FS_IOC_SETFLAGS: +i/+a/+A/+d/...),
// project quota / xfs_io (FS_IOC_FSSETXATTR) and FS_IOC_SETVERSION change
// inode metadata through ->fileattr_set with no inode_setattr or xattr
// hook in the path. Kernels >= 6.17 add security_inode_file_setattr();
// the project floor is 6.6, so gate at the ioctl hooks, which every
// ioctl(2) passes through. Only the five flag-writing commands are
// inspected; every other ioctl returns after the compares below.
//
// Data-writing ioctls (FICLONE / FICLONERANGE / FIDEDUPERANGE) are
// deliberately NOT listed: fs/remap_range.c calls security_file_permission()
// with MAY_WRITE on the destination, so comp_file_permission already covers
// them under no-write. Do not re-litigate.
static __always_inline int
comp_file_ioctl_impl(struct file *file, unsigned int cmd, int ret)
{
	if (ret != 0)
		return ret;
	if (cmd != COMP_FS_IOC_SETFLAGS && cmd != COMP_FS_IOC32_SETFLAGS &&
	    cmd != COMP_FS_IOC_FSSETXATTR &&
	    cmd != COMP_FS_IOC_SETVERSION && cmd != COMP_FS_IOC32_SETVERSION)
		return 0;

	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;
	struct caller_id cid = {};
	if (deny_inode_action(inode, SEAL_NO_CHMOD, ACTION_DENY_CHMOD, &cid))
		return -EACCES;
	if (deny_file_parent_dir_action(file, SEAL_NO_CHMOD,
					ACTION_DENY_CHMOD_PARENT_DIR, &cid))
		return -EACCES;
	return 0;
}

// Native ioctl(2): fs/ioctl.c SYSCALL_DEFINE3(ioctl) -> security_file_ioctl().
SEC("lsm/file_ioctl")
int BPF_PROG(comp_file_ioctl, struct file *file, unsigned int cmd,
	     unsigned long arg, int ret)
{
	(void)arg;
	return comp_file_ioctl_impl(file, cmd, ret);
}

// Compat ioctl(2): a 32-bit process on a 64-bit kernel enters through
// fs/ioctl.c COMPAT_SYSCALL_DEFINE3(ioctl), which calls
// security_file_ioctl_compat() and NEVER security_file_ioctl(). Without this
// program a 32-bit `chattr +i` walks straight past the gate above (the compat
// switch handles FS_IOC32_SETFLAGS itself). Same body, same commands.
//
// The hook was added upstream and backported into stable 6.6.y, so a kernel
// version test is unreliable; the loader BTF-probes for bpf_lsm_file_ioctl_compat
// and autoload-gates this program (select_file_ioctl_compat() in
// compartment-bpf.c). On a kernel without the hook, compat ioctls fall back
// through security_file_ioctl() and comp_file_ioctl covers them.
SEC("lsm/file_ioctl_compat")
int BPF_PROG(comp_file_ioctl_compat, struct file *file, unsigned int cmd,
	     unsigned long arg, int ret)
{
	(void)arg;
	return comp_file_ioctl_impl(file, cmd, ret);
}

// Mount shadowing. A mount attached ON a sealed inode or anywhere INSIDE
// a sealed subtree makes the path resolve to a foreign, unsealed inode:
// the sealed inode is untouched but the path guarantee is gone (the
// pre-v0.8 LIMITATIONS rows "bind-mount-OVER sealed path" and
// "Mount-inside-sealed-subtree bypass"). Deny when the mountpoint
// dentry's inode carries any seal flag, or any ancestor within the
// recursive walk budget does. Actor-bound seals keep their allowlist
// semantics through seal_decision (an actor may mount inside its own
// sealed tree). Bind-mounting FROM a sealed path to somewhere else stays
// allowed: the alias shares dentries with the original, so every seal
// (including the ancestor walk) still applies through it — the mesh
// §3.23 (b)/(c) rows witness that.
//
// The complementary shape — detaching the filesystem instead of mounting
// over it — is comp_sb_umount's job, below.
//
// Not covered by either: pivot_root, and a mount placed on the root of a
// nested mount that already sits inside a sealed tree (the d_parent walk
// stops at a mount root). See LIMITATIONS.md.
static __always_inline int
deny_mount_on_dentry(struct dentry *mp, struct caller_id *cid)
{
	struct inode *inode;

	if (!mp)
		return 0;
	inode = BPF_CORE_READ(mp, d_inode);
	/* v0.8: `mount -t bpf bpf /sys/fs/bpf` over the live bpffs neither
	 * detaches anything nor touches a seal, but it hides the pin tree:
	 * measured, --unpin then reports "does not exist; nothing to do" and
	 * exits 0 while enforcement stays live and unreachable. Gate the
	 * bpffs mount root the same way as the pins themselves. */
	if (deny_pin_tamper(inode, cid))
		return -EACCES;
	if (deny_inode_action(inode, SEAL_FULL, ACTION_DENY_MOUNT, cid))
		return -EACCES;
	return deny_dentry_parent_dir_action(mp, SEAL_FULL, ACTION_DENY_MOUNT,
					     cid);
}

// mount(2). fs/namespace.c:path_mount() calls security_sb_mount() with the
// caller's flags before it dispatches, and the exemptions below must mirror
// that dispatch order exactly, because the kernel tests the flag bits in a
// fixed sequence and the FIRST match wins:
//
//   security_sb_mount(...)                      <- this hook
//   may_mount()
//   if ((flags & (MS_REMOUNT|MS_BIND)) == (MS_REMOUNT|MS_BIND)) ...
//   if (flags & MS_REMOUNT)  -> do_remount()      attaches nothing
//   if (flags & MS_BIND)     -> do_loopback()     ATTACHES A NEW MOUNT
//   if (flags & (MS_SHARED|MS_PRIVATE|MS_SLAVE|MS_UNBINDABLE))
//                            -> do_change_type()  attaches nothing
//   if (flags & MS_MOVE)     -> do_move_mount_old() ATTACHES
//   return do_new_mount(...)                       ATTACHES
//
// MS_BIND is tested BEFORE the propagation bits, so a caller that passes
// `MS_BIND|MS_PRIVATE` (`mount --bind src dst -o private`) gets a bind mount,
// not a propagation change. Exempting on any propagation bit — as the first
// cut of this gate did — therefore let one extra flag bit attach a mount
// inside a sealed subtree, and neither hook caught it: do_loopback() reaches
// graft_tree() without ever calling security_move_mount(). Test the flags in
// the kernel's own order instead. tests/bypass/17 W5 is the regression
// witness.
SEC("lsm/sb_mount")
int BPF_PROG(comp_sb_mount, const char *dev_name, const struct path *path,
	     const char *type, unsigned long flags, void *data, int ret)
{
	(void)dev_name;
	(void)type;
	(void)data;
	if (ret != 0)
		return ret;
	/* do_remount(): modifies an existing mount, attaches nothing.
	 * MS_REMOUNT wins over MS_BIND in path_mount() (the combined
	 * REMOUNT|BIND case is a bind-flag remount, still attaching nothing). */
	if (flags & MS_REMOUNT)
		return 0;
	/* do_change_type(): propagation-only, attaches nothing — but ONLY when
	 * MS_BIND is clear, because path_mount() dispatches MS_BIND first. */
	if (!(flags & MS_BIND) &&
	    (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)))
		return 0;
	/* MS_BIND (do_loopback), MS_MOVE (do_move_mount_old) and a fresh
	 * filesystem mount (do_new_mount) all attach at `path`: gate them. */

	struct dentry *mp = BPF_CORE_READ(path, dentry);
	struct caller_id cid = {};
	return deny_mount_on_dentry(mp, &cid);
}

// A filesystem hosting sealed inodes must not be detached, and its own
// mount must not be moved away from under the sealed path.
//
// Gating the mount DESTINATION (comp_sb_mount / comp_move_mount above) only
// covers half the shadowing class. The other half needs no mount at all to
// start: `umount -l /data` detaches the filesystem, the sealed path then
// resolves to the (unsealed) mountpoint dentry in the PARENT filesystem, and
// a fresh `mount -t tmpfs none /data` sails past the destination gate
// because nothing at that dentry is sealed. Every sealed path now resolves
// to attacker content. The sealed inodes are still protected — they are just
// unreachable, which is not what an operator was promised.
//
// In daemon mode the held O_PATH fds make umount EBUSY, but that is an
// accident of implementation, not a control: `umount -l` detaches anyway,
// and in daemonless `--pin` mode the fds died with the loader.
//
// Precision matters here, because s_dev alone is far too coarse: seal one
// file on the root filesystem and every mount whose superblock is the root
// filesystem — every bind mount of a root-fs directory, every container
// setup — would become unmountable. So require BOTH:
//
//   (a) the superblock hosts at least one seal (sealed_devs hit), AND
//   (b) mnt->mnt_root == mnt->mnt_sb->s_root, i.e. this vfsmount is a mount
//       of the WHOLE filesystem, not a bind mount of some subdirectory of
//       it. Detaching a bind mount leaves the filesystem — and every path
//       into it through its real mount — exactly where it was.
//
// Residual: a bind mount at a sealed path is still unmountable-away
// (condition (b) fails, so it is allowed), which re-exposes the path at
// whatever the underlying dentry is. That is the same nested-mount class
// already documented for comp_sb_mount, and it is recorded in
// LIMITATIONS.md rather than papered over here.
static __always_inline int
deny_umount_of_sealed_dev(struct vfsmount *mnt)
{
	struct super_block *sb;
	struct dentry *mnt_root, *s_root;
	__u64 dev;
	__u32 *hit;

	if (!mnt)
		return 0;
	sb = BPF_CORE_READ(mnt, mnt_sb);
	if (!sb)
		return 0;

	dev = (__u64)BPF_CORE_READ(sb, s_dev);
	hit = bpf_map_lookup_elem(&sealed_devs, &dev);
	if (!hit) {
		/* v0.8: the bpffs holding PIN_ROOT is not in sealed_devs (it
		 * hosts no operator seal) but detaching it is the cheapest way
		 * to remove enforcement. Measured on 6.8: `umount /sys/fs/bpf`
		 * and `umount -l /sys/fs/bpf` both drop enforcement within 6s.
		 * Measured on 7.0 with a service holding a peer bpffs mount
		 * (polkitd, ProtectSystem): the host umount instead ORPHANS the
		 * policy — pins invisible, enforcement live, --unpin reports
		 * "nothing to do" and exits 0. Both outcomes are denied here. */
		struct self_protect_cfg *cfg = self_protect();
		if (!cfg || cfg->pin_dev == 0 || cfg->pin_dev != dev)
			return 0;
	}

	// (b): whole-filesystem mount only.
	mnt_root = BPF_CORE_READ(mnt, mnt_root);
	s_root   = BPF_CORE_READ(sb, s_root);
	if (!mnt_root || mnt_root != s_root)
		return 0;

	struct caller_id cid = {};
	caller_id_resolve_locked(&cid);
	/* One action for both reasons (a sealed filesystem, or the bpffs that
	 * holds the pins): the operator-visible fact is the same — this
	 * filesystem cannot be detached while policy is live — and splitting
	 * it would add an action code with no distinct response. */
	emit_audit_actor(ACTION_DENY_UMOUNT, dev, 0,
	                 cid.valid ? cid.dev : 0,
	                 cid.valid ? cid.ino : 0,
	                 (const char *)0);
	return -EACCES;
}

// umount(2) / umount2(2), including MNT_DETACH (`umount -l`).
// fs/namespace.c:do_umount() calls security_sb_umount(&mnt->mnt, flags) as
// its first statement, before any of the may_umount / propagation work, and
// the signature is identical on 6.8 and 7.0.
SEC("lsm/sb_umount")
int BPF_PROG(comp_sb_umount, struct vfsmount *mnt, int flags, int ret)
{
	(void)flags;   /* MNT_DETACH and MNT_FORCE are denied like a plain umount */
	if (ret != 0)
		return ret;
	return deny_umount_of_sealed_dev(mnt);
}

// move_mount(2), including the tail of the new mount API flows
// (open_tree(OPEN_TREE_CLONE) + move_mount, fsopen/fsmount + move_mount):
// the mount at from_path is attached at to_path. Gate the destination the
// same way. Note this hook is NOT on the MS_MOVE path: `mount --move` runs
// do_move_mount_old(), which calls do_move_mount() directly and never
// security_move_mount(), so MS_MOVE is covered by comp_sb_mount above and
// only there. util-linux >= 2.39 increasingly uses the new mount API, so on
// recent distributions a plain `mount` may never call security_sb_mount() at
// all — both hooks are needed.
SEC("lsm/move_mount")
int BPF_PROG(comp_move_mount, const struct path *from_path,
	     const struct path *to_path, int ret)
{
	if (ret != 0)
		return ret;

	// FROM side: moving the whole filesystem that hosts the seals away
	// from its current mountpoint breaks the path guarantee exactly like
	// unmounting it. Same two conditions as comp_sb_umount, plus a third:
	// from_path must BE the mount root, otherwise this is a bind-style
	// move of a subtree and the filesystem stays where it is.
	//
	// RESIDUAL: this only covers move_mount(2). The classic
	// mount(2)+MS_MOVE spelling runs do_move_mount_old(), which calls
	// do_move_mount() directly and never security_move_mount() (verified in
	// fs/namespace.c on both 6.8 and 7.0), while security_sb_mount() sees
	// only the DESTINATION path plus the source as a char* string it cannot
	// resolve. There is no hook that can see the source mount on that path.
	// LIMITATIONS.md carries the row; tests/bypass/20 W3 therefore drives
	// move_mount(2) directly rather than `mount --move`, which would be a
	// false pass (a shared-propagation parent returns EINVAL of its own).
	struct vfsmount *from_mnt = BPF_CORE_READ(from_path, mnt);
	struct dentry *from_dentry = BPF_CORE_READ(from_path, dentry);
	if (from_mnt && from_dentry &&
	    from_dentry == BPF_CORE_READ(from_mnt, mnt_root)) {
		int r = deny_umount_of_sealed_dev(from_mnt);
		if (r)
			return r;
	}

	// TO side: attaching anything on or under a sealed path.
	struct dentry *mp = BPF_CORE_READ(to_path, dentry);
	struct caller_id cid = {};
	return deny_mount_on_dentry(mp, &cid);
}

// ---------------- v0.8: lsm/bpf_map — the tool protects its own maps ----
//
// LSM_HOOK(int, 0, bpf_map, struct bpf_map *map, fmode_t fmode) is byte
// identical on 6.8 and 7.0 (vmlinux BTF: bpf_lsm_bpf_map FUNC_PROTO vlen=2 on
// both), it is in sleepable_lsm_hooks on both, and it is NOT in 7.0's
// bpf_lsm_disabled_hooks. So, unlike lsm/bpf (vlen 3 on 6.8, 4 on 7.0 — the
// added `bool kernel` argument), this one needs no dual wrapper. The loader
// still autoload-gates it on a BTF probe (select_bpf_map_variant) so a kernel
// that ever drops the hook fails loudly at load rather than silently
// fail-open at runtime.
//
// It is called from bpf_map_new_fd(), which is the single point every map fd
// passes through: BPF_MAP_GET_FD_BY_ID, BPF_OBJ_GET on a pinned map, and
// BPF_MAP_CREATE. Denying here denies fd creation, which is the only thing
// that actually works — see the map-block comment above for why denying
// writes (or trusting bpf_map_freeze) does not.
//
// DELIBERATE: this denies READ-ONLY fds too. A read-only fd is a complete
// attack: bpf_map__reuse_fd() + a one-instruction BPF program writes the map
// from program context, measured working on both kernels. Allowing read-only
// access so `--stats` and `bpftool map dump` keep working was considered and
// rejected for exactly that reason: it would leave every seal map writable
// through a one-instruction program and make the whole gate decorative. The
// cost is real and is documented: with --self-protect in force,
// `bpftool map dump` on a compartment map fails, and `compartment-bpf --stats`
// works only when run from an authorised loader binary (it is the same
// executable, so the normal case is unaffected).
//
// BPF_MAP_CREATE is unaffected: a map that has just been created cannot
// already be in protected_map_ids.
SEC("lsm/bpf_map")
int BPF_PROG(comp_bpf_map, struct bpf_map *map, fmode_t fmode, int ret)
{
	(void)fmode;   /* both modes are denied — see the DELIBERATE note above */
	if (ret != 0)
		return ret;

	struct self_protect_cfg *cfg = self_protect();
	if (!cfg)
		return 0;
	if (!map)
		return 0;

	__u32 id = BPF_CORE_READ(map, id);
	if (!bpf_map_lookup_elem(&protected_map_ids, &id))
		return 0;

	struct caller_id cid = {};
	if (caller_is_loader(&cid))
		return 0;

	// dev = 0 signals "this ino is not a filesystem inode"; ino carries the
	// bpf map id so the audit line names the object. See compartment-abi.h.
	return deny_self_protect(ACTION_DENY_BPF_SELF, &bpf_self_denied_total,
	                         0, (__u64)id, &cid, -EPERM);
}
