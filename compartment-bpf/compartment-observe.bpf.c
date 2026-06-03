// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
// compartment-bpf observe BPF program — actor marker + lineage
// and filesystem event aggregation.
//
// Production port from experimental/actor-fs-observe/bpf/observe.bpf.c.
// SPEC: experimental/ACTOR-FS-OBSERVE-SPEC.md
//
// DEFERRED: global compact mode (--global all-task marker mode with aggressive aggregation).
// DEFERRED: deny-first bridge / documented handoff to compartment-bpf genprofile.
//
// FEASIBILITY.md known limitations addressed:
// 1. bprm/file_open ordering: actor binary open during exec fires before
//    bprm_check_security — not recorded in observed_files (correct semantics).
// 2. inode_create key is parent dir: child ino unavailable at hook time.
//    Profile transform documents this explicitly.
// 3. Thread marker propagation: all clones get current_actor_markers copy.
// 4. task_free cleanup: explicit delete is pre-emptive; kernel also
//    auto-cleans TASK_STORAGE after task_free.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef O_TRUNC
#define O_TRUNC  00001000
#endif
#ifndef O_RDWR
#define O_RDWR   00000002
#endif
#ifndef O_ACCMODE
#define O_ACCMODE 00000003
#endif
#ifndef FMODE_WRITE
#define FMODE_WRITE 0x2
#endif
#ifndef CLONE_THREAD
#define CLONE_THREAD 0x10000
#endif

/* Event type codes */
#define AO_EV_ACTOR_EXEC         1u
#define AO_EV_ACTOR_EXEC_HELPER  3u
#define AO_EV_FS_FIRST_SIGHTING  6u
#define AO_EV_FS_CREATE          7u
#define AO_EV_FS_UNLINK          8u
#define AO_EV_FS_RENAME          9u
#define AO_EV_FS_MKDIR           10u
#define AO_EV_FS_RMDIR           11u
#define AO_EV_FS_LINK            12u
#define AO_EV_FS_MKNOD           13u
#define AO_EV_FS_SYMLINK         14u

/* op_class values (SPEC §7.1) */
#define AO_OP_OPEN_R     1u
#define AO_OP_OPEN_W     2u
#define AO_OP_OPEN_RW    3u
#define AO_OP_OPEN_TRUNC 4u
#define AO_OP_CREATE     5u
#define AO_OP_UNLINK     6u
#define AO_OP_RENAME     7u
#define AO_OP_MKDIR      8u
#define AO_OP_RMDIR      9u
#define AO_OP_LINK       10u
#define AO_OP_MKNOD      11u
#define AO_OP_SYMLINK    12u
#define AO_OP_RENAME_DST 13u

/* Counter slots (SPEC §7.2) */
#define C_EVENTS_SEEN_TOTAL              0
#define C_EVENTS_SAMPLED_TOTAL           1
#define C_EVENTS_RINGBUF_DROP_TOTAL      2
#define C_OBSERVED_FILES_TOTAL           3
#define C_OBSERVED_FILES_OVERFLOW_TOTAL  4
#define C_CURRENT_ACTOR_COPY_FORK_TOTAL  5
#define C_LINEAGE_COPY_FORK_TOTAL        6
#define C_LINEAGE_EXEC_HELPER_TOTAL      7
#define C_PATH_RESOLVE_FAIL_TOTAL        8
#define C_MAX                            9

/* ----- data structures ----- */

struct file_id {
	__u64 dev;
	__u64 ino;
};

/* SPEC §5.1: structurally separate current-actor and lineage maps.
 * Enforcement code must NEVER read lineage_markers — the structural
 * separation enforces this at the type level. */
struct current_actor_marker {
	__u32 actor_slot;
	__u32 generation;
};

struct lineage_marker {
	__u32 origin_actor_slot;
	__u32 generation;
	__u8  observation_only;
	__u8  _pad[3];
};

/* SPEC §7.1 observed_key / observed_value */
struct observed_key {
	__u32 actor_slot;
	__u32 op_class;
	__u64 dev;
	__u64 ino;
	__u64 parent_dev;
	__u64 parent_ino;
};

struct observed_value {
	__u64 count;
	__u64 first_ns;
	__u64 last_ns;
	__u32 sample_pid;
	__u32 sample_tgid;
	__u32 flags_seen;
	__u8  under_current_actor;
	__u8  under_actor_lineage;
	__u8  _pad[2];
	/* spinlock guards last_ns update against SMP torn writes. */
	struct bpf_spin_lock lock;
};

/* launcher_key / launcher_value for observed_launchers (SPEC §5.2) */
struct launcher_key {
	__u32 actor_slot;
	__u32 _pad;
	__u64 parent_dev;
	__u64 parent_ino;
};

struct launcher_value {
	__u64 count;
	__u32 sample_pid;
	__u32 sample_ppid;
	__u64 sample_cgroup_id;
};

struct ao_event {
	__u32 type;
	__u32 actor_slot;
	__u64 dev;
	__u64 ino;
	__u64 parent_dev;
	__u64 parent_ino;
	__u32 op_class;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u64 timestamp_ns;
	__u64 cgroup_id;
	__u8  under_current_actor;
	__u8  under_actor_lineage;
	__u8  _pad[6];
};

/* ----- maps ----- */

/* actor_targets: file_id → actor_slot (max 64 actor binaries) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key,   struct file_id);
	__type(value, __u32);
	__uint(max_entries, 64);
} actor_targets SEC(".maps");

/* per-task: current_actor_markers (structurally separate from lineage) */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key,   int);
	__type(value, struct current_actor_marker);
} current_actor_markers SEC(".maps");

/* per-task: lineage_markers — observation-only; enforcement MUST NOT read */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key,   int);
	__type(value, struct lineage_marker);
} lineage_markers SEC(".maps");

/* aggregated file observations — 65536 for production (spike used 4096) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key,   struct observed_key);
	__type(value, struct observed_value);
	__uint(max_entries, 65536);
} observed_files SEC(".maps");

/* launcher aggregation per (actor_slot, parent_dev, parent_ino) (SPEC §5.2) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key,   struct launcher_key);
	__type(value, struct launcher_value);
	__uint(max_entries, 256);
} observed_launchers SEC(".maps");

/* SPEC §7.2 counters (renamed from spike's 'counters' to 'event_counters') */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key,   __u32);
	__type(value, __u64);
	__uint(max_entries, C_MAX);
} event_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} events SEC(".maps");

/* ----- knobs ----- */
const volatile __u32 enable_lane2 = 1;
const volatile __u32 generation   = 1;

/* ----- helpers ----- */

static __always_inline void cnt_inc(__u32 k)
{
	__u64 *v = bpf_map_lookup_elem(&event_counters, &k);
	if (v) __sync_fetch_and_add(v, 1);
}

static __always_inline int file_to_id(struct file *f, struct file_id *out)
{
	struct inode *ino_p;
	struct super_block *sb;

	if (!f) return -1;
	ino_p = BPF_CORE_READ(f, f_inode);
	if (!ino_p) return -1;
	out->ino = BPF_CORE_READ(ino_p, i_ino);
	sb = BPF_CORE_READ(ino_p, i_sb);
	out->dev = sb ? BPF_CORE_READ(sb, s_dev) : 0;
	return 0;
}

static __always_inline int inode_to_id(struct inode *ino_p, struct file_id *out)
{
	struct super_block *sb;

	if (!ino_p) return -1;
	out->ino = BPF_CORE_READ(ino_p, i_ino);
	sb = BPF_CORE_READ(ino_p, i_sb);
	out->dev = sb ? BPF_CORE_READ(sb, s_dev) : 0;
	return 0;
}

/*
 * resolve_lane2_actor: return actor_slot for current task, or -1 if none.
 *
 * Priority order:
 *  1. current_actor_markers for this task (direct actor or thread clone).
 *     Threads receive their own copy in ao_task_alloc (no CLONE_THREAD guard)
 *     so no leader-pointer lookup is needed here (the BPF verifier
 *     rejects BPF_CORE_READ pointers as bpf_task_storage_get keys).
 *  2. lineage_markers for this task: helper execs (fork children
 *     that have exec'd a non-actor binary) carry only lineage_markers.
 */
/* resolve_lane2_actor: return actor_slot for current task, or -1 if none.
 * Sets *is_lineage_out to 1 if attribution came from lineage_markers. */
static __always_inline __s32 resolve_lane2_actor(struct task_struct *t,
						  __u8 *is_lineage_out)
{
	*is_lineage_out = 0;
	struct current_actor_marker *cam =
		bpf_task_storage_get(&current_actor_markers, t, NULL, 0);
	if (cam)
		return (__s32)cam->actor_slot;

	struct lineage_marker *lm =
		bpf_task_storage_get(&lineage_markers, t, NULL, 0);
	if (lm) {
		*is_lineage_out = 1;
		return (__s32)lm->origin_actor_slot;
	}

	return -1;
}

static __always_inline void emit(__u32 type, __u32 actor_slot,
				 __u64 dev, __u64 ino,
				 __u64 pdev, __u64 pino,
				 __u32 op_class,
				 __u8 under_cur, __u8 under_lin)
{
	struct ao_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		cnt_inc(C_EVENTS_RINGBUF_DROP_TOTAL);
		return;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->type               = type;
	e->actor_slot         = actor_slot;
	e->dev                = dev;
	e->ino                = ino;
	e->parent_dev         = pdev;
	e->parent_ino         = pino;
	e->op_class           = op_class;
	e->under_current_actor = under_cur;
	e->under_actor_lineage = under_lin;
	e->timestamp_ns       = bpf_ktime_get_ns();
	e->cgroup_id          = bpf_get_current_cgroup_id();

	__u64 pt = bpf_get_current_pid_tgid();
	e->tgid = (__u32)(pt >> 32);
	e->pid  = (__u32)pt;
	struct task_struct *t = bpf_get_current_task_btf();
	if (t) {
		struct task_struct *p = BPF_CORE_READ(t, real_parent);
		if (p) e->ppid = BPF_CORE_READ(p, tgid);
	}
	cnt_inc(C_EVENTS_SAMPLED_TOTAL);
	bpf_ringbuf_submit(e, 0);
}

/* SPEC §7.3 map-full behavior: preserve existing, count overflow.
 * is_lineage: 1 if attribution came from lineage_markers.
 * last_ns protected by spinlock against SMP torn writes.
 * overflow counted only on -ENOSPC; -EEXIST race silently ignored. */
static __always_inline void agg_obs(struct observed_key *key,
				    __u32 pid, __u32 tgid,
				    __u32 ev_type, __u32 actor_slot,
				    __u64 ev_dev, __u64 ev_ino,
				    __u64 ev_pdev, __u64 ev_pino,
				    __u32 op_class, __u8 is_lineage)
{
	__u64 ts = bpf_ktime_get_ns();
	struct observed_value *ex = bpf_map_lookup_elem(&observed_files, key);
	if (ex) {
		__sync_fetch_and_add(&ex->count, 1);
		bpf_spin_lock(&ex->lock);
		ex->last_ns = ts;
		ex->under_current_actor |= !is_lineage;
		ex->under_actor_lineage |= is_lineage;
		bpf_spin_unlock(&ex->lock);
		return;
	}
	struct observed_value nv = {};
	nv.count               = 1;
	nv.first_ns            = ts;
	nv.last_ns             = ts;
	nv.sample_pid          = pid;
	nv.sample_tgid         = tgid;
	nv.under_current_actor = !is_lineage;
	nv.under_actor_lineage = is_lineage;
	int r = bpf_map_update_elem(&observed_files, key, &nv, BPF_NOEXIST);
	if (r == 0) {
		cnt_inc(C_OBSERVED_FILES_TOTAL);
		emit(ev_type, actor_slot,
		     ev_dev, ev_ino, ev_pdev, ev_pino,
		     op_class, !is_lineage, is_lineage);
	} else if (r == -28 /* -ENOSPC: map full */) {
		/* map full: refuse new, preserve old (SPEC §7.3) */
		cnt_inc(C_OBSERVED_FILES_OVERFLOW_TOTAL);
	}
	/* -EEXIST: lost race with sibling CPU — silently ignore */
}

/* ----- Lane 1 hooks ----- */

/*
 * bprm_check_security (sleepable): resolve exec inode; if in actor_targets,
 * set both marker maps and record launcher; if not and task has
 * current_actor_markers, clear it (helper exec) but preserve lineage_markers.
 *
 * LIMITATION 1 (FEASIBILITY.md): file_open fires during exec before
 * bprm_check_security.  The actor binary's own open is NOT recorded in
 * observed_files — correct semantics: the binary is the actor identity.
 */
SEC("lsm.s/bprm_check_security")
int BPF_PROG(ao_bprm, struct linux_binprm *bprm, int ret)
{
	if (ret != 0)
		return ret;

	struct task_struct *t = bpf_get_current_task_btf();
	if (!t) return 0;  /* null guard */
	struct file *f = BPF_CORE_READ(bprm, file);
	struct file_id exec_id = {};

	cnt_inc(C_EVENTS_SEEN_TOTAL);

	if (file_to_id(f, &exec_id) < 0) return 0;

	__u32 *slot_p = bpf_map_lookup_elem(&actor_targets, &exec_id);
	if (slot_p) {
		__u32 slot = *slot_p;
		__u32 gen  = generation;

		struct current_actor_marker *cam =
			bpf_task_storage_get(&current_actor_markers, t, NULL,
					     BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (cam) {
			cam->actor_slot = slot;
			cam->generation = gen;
		}

		struct lineage_marker *lm =
			bpf_task_storage_get(&lineage_markers, t, NULL,
					     BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (lm) {
			lm->origin_actor_slot = slot;
			lm->generation        = gen;
			lm->observation_only  = 1;
		}

		/* record launcher (parent dev/ino) in observed_launchers (SPEC §5.2) */
		struct task_struct *parent = BPF_CORE_READ(t, real_parent);
		if (parent) {
			struct mm_struct *pmm = BPF_CORE_READ(parent, mm);
			if (pmm) {
				struct file *pexe = BPF_CORE_READ(pmm, exe_file);
				if (pexe) {
					struct file_id pfid = {};
					if (file_to_id(pexe, &pfid) == 0) {
						struct launcher_key lk = {};
						lk.actor_slot = slot;
						lk.parent_dev = pfid.dev;
						lk.parent_ino = pfid.ino;
						struct launcher_value *lv =
							bpf_map_lookup_elem(&observed_launchers, &lk);
						if (lv) {
							__sync_fetch_and_add(&lv->count, 1);
						} else {
							struct launcher_value nv = {};
							__u64 pt = bpf_get_current_pid_tgid();
							nv.count          = 1;
							nv.sample_pid     = (__u32)pt;
							nv.sample_ppid    = BPF_CORE_READ(parent, tgid);
							nv.sample_cgroup_id = bpf_get_current_cgroup_id();
							bpf_map_update_elem(&observed_launchers, &lk,
									    &nv, BPF_NOEXIST);
						}
					}
				}
			}
		}

		emit(AO_EV_ACTOR_EXEC, slot,
		     exec_id.dev, exec_id.ino, 0, 0, 0, 1, 1);
		return 0;
	}

	/* Not an actor target: helper exec — clear current marker, keep lineage */
	struct current_actor_marker *cam =
		bpf_task_storage_get(&current_actor_markers, t, NULL, 0);
	if (!cam) return 0;

	__u32 prev_slot = cam->actor_slot;
	bpf_task_storage_delete(&current_actor_markers, t);
	cnt_inc(C_LINEAGE_EXEC_HELPER_TOTAL);
	emit(AO_EV_ACTOR_EXEC_HELPER, prev_slot,
	     exec_id.dev, exec_id.ino, 0, 0, 0, 0, 1);
	return 0;
}

/*
 * task_alloc: copy both marker maps to child on fork.
 * Reuses the same fork-marker-copy pattern as the strict-launch hooks,
 * proven on Ubuntu 26.04 (kernel 7.0).
 *
 * All clones including threads get their own current_actor_markers copy
 * (BPF_CORE_READ of group_leader yields a scalar that the
 * verifier rejects as bpf_task_storage_get key; per-thread copy is correct).
 * lineage_markers is copied for all clones.
 */
SEC("lsm/task_alloc")
int BPF_PROG(ao_task_alloc, struct task_struct *task, u64 clone_flags, int ret)
{
	if (ret != 0)
		return ret;

	struct task_struct *parent = bpf_get_current_task_btf();
	if (!parent) return 0;

	/* current_actor_markers: copy to all clones including threads.
	 * Threads need their own storage slot because bpf_task_storage_get
	 * requires a trusted task pointer — BPF_CORE_READ of group_leader
	 * yields a scalar that the verifier rejects. Each thread gets the
	 * same actor_slot value; ao_task_free cleans up per-task. */
	{
		struct current_actor_marker *p_cam =
			bpf_task_storage_get(&current_actor_markers, parent, NULL, 0);
		if (p_cam) {
			struct current_actor_marker *c_cam =
				bpf_task_storage_get(&current_actor_markers, task, NULL,
						     BPF_LOCAL_STORAGE_GET_F_CREATE);
			if (c_cam) {
				c_cam->actor_slot = p_cam->actor_slot;
				c_cam->generation = p_cam->generation;
				cnt_inc(C_CURRENT_ACTOR_COPY_FORK_TOTAL);
			}
		}
	}

	/* lineage_markers: copy for all clones including threads */
	struct lineage_marker *p_lm =
		bpf_task_storage_get(&lineage_markers, parent, NULL, 0);
	if (p_lm) {
		struct lineage_marker *c_lm =
			bpf_task_storage_get(&lineage_markers, task, NULL,
					     BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (c_lm) {
			c_lm->origin_actor_slot = p_lm->origin_actor_slot;
			c_lm->generation        = p_lm->generation;
			c_lm->observation_only  = p_lm->observation_only;
			cnt_inc(C_LINEAGE_COPY_FORK_TOTAL);
		}
	}

	return 0;
}

/*
 * task_free: explicit cleanup (pre-emptive; kernel also auto-cleans
 * TASK_STORAGE after task_free returns).
 */
SEC("lsm/task_free")
void BPF_PROG(ao_task_free, struct task_struct *task)
{
	bpf_task_storage_delete(&current_actor_markers, task);
	bpf_task_storage_delete(&lineage_markers, task);
}

/* ----- Lane 2 hooks ----- */

/*
 * file_open: classify open and aggregate into observed_files.
 * Only records tasks with current_actor_markers (SPEC §12: no per-open
 * path string copy, no unbounded loops).
 * Emits exactly one ringbuf event per first sighting (SPEC §6.2).
 */
SEC("lsm/file_open")
int BPF_PROG(ao_file_open, struct file *file, int ret)
{
	if (ret != 0)
		return ret;
	if (!enable_lane2) return 0;

	struct task_struct *t = bpf_get_current_task_btf();
	__u8 is_lineage = 0;
	__s32 actor_slot = resolve_lane2_actor(t, &is_lineage);
	if (actor_slot < 0) return 0;

	struct file_id fid = {}, pfid = {};
	if (file_to_id(file, &fid) < 0) {
		cnt_inc(C_PATH_RESOLVE_FAIL_TOTAL);
		return 0;
	}

	struct dentry *dentry  = BPF_CORE_READ(file, f_path.dentry);
	struct dentry *pdentry = BPF_CORE_READ(dentry, d_parent);
	struct inode  *pinode  = BPF_CORE_READ(pdentry, d_inode);
	inode_to_id(pinode, &pfid);

	__u32 fmode = BPF_CORE_READ(file, f_mode);
	__u32 op_class;
	if (fmode & FMODE_WRITE) {
		__u32 flags = BPF_CORE_READ(file, f_flags);
		if (flags & O_TRUNC)
			op_class = AO_OP_OPEN_TRUNC;
		else if ((flags & O_ACCMODE) == O_RDWR)
			op_class = AO_OP_OPEN_RW;  /* distinguish O_RDWR */
		else
			op_class = AO_OP_OPEN_W;
	} else {
		op_class = AO_OP_OPEN_R;
	}

	struct observed_key key = {};
	key.actor_slot = (__u32)actor_slot;
	key.op_class   = op_class;
	key.dev        = fid.dev;
	key.ino        = fid.ino;
	key.parent_dev = pfid.dev;
	key.parent_ino = pfid.ino;

	__u64 pt = bpf_get_current_pid_tgid();
	agg_obs(&key, (__u32)pt, (__u32)(pt >> 32),
		AO_EV_FS_FIRST_SIGHTING, (__u32)actor_slot,
		fid.dev, fid.ino, pfid.dev, pfid.ino, op_class, is_lineage);
	return 0;
}

/*
 * inode_create: aggregate creates keyed by parent directory.
 * LIMITATION 2 (FEASIBILITY.md): child inode not yet allocated at
 * hook time; key by parent dir so multiple creates under the same
 * directory aggregate into one entry per parent.
 */
SEC("lsm/inode_create")
int BPF_PROG(ao_inode_create, struct inode *dir,
	     struct dentry *dentry, umode_t mode, int ret)
{
	(void)dentry;
	(void)mode;
	if (ret != 0)
		return ret;
	if (!enable_lane2) return 0;

	struct task_struct *t = bpf_get_current_task_btf();
	__u8 is_lineage = 0;
	__s32 actor_slot = resolve_lane2_actor(t, &is_lineage);
	if (actor_slot < 0) return 0;

	struct file_id dfid = {};
	if (inode_to_id(dir, &dfid) < 0) return 0;

	struct observed_key key = {};
	key.actor_slot = (__u32)actor_slot;
	key.op_class   = AO_OP_CREATE;
	key.dev        = dfid.dev;
	key.ino        = dfid.ino;
	/* parent_dev/parent_ino = 0: child ino unknown pre-alloc */

	__u64 pt = bpf_get_current_pid_tgid();
	agg_obs(&key, (__u32)pt, (__u32)(pt >> 32),
		AO_EV_FS_CREATE, (__u32)actor_slot,
		dfid.dev, dfid.ino, 0, 0, AO_OP_CREATE, is_lineage);
	return 0;
}

/*
 * inode_unlink: aggregate unlinks keyed by victim inode.
 */
SEC("lsm/inode_unlink")
int BPF_PROG(ao_inode_unlink, struct inode *dir, struct dentry *victim, int ret)
{
	if (ret != 0)
		return ret;
	if (!enable_lane2) return 0;

	struct task_struct *t = bpf_get_current_task_btf();
	__u8 is_lineage = 0;
	__s32 actor_slot = resolve_lane2_actor(t, &is_lineage);
	if (actor_slot < 0) return 0;

	struct inode  *vinode = BPF_CORE_READ(victim, d_inode);
	struct file_id fid = {}, dfid = {};
	if (inode_to_id(vinode, &fid) < 0) return 0;
	inode_to_id(dir, &dfid);

	struct observed_key key = {};
	key.actor_slot = (__u32)actor_slot;
	key.op_class   = AO_OP_UNLINK;
	key.dev        = fid.dev;
	key.ino        = fid.ino;
	key.parent_dev = dfid.dev;
	key.parent_ino = dfid.ino;

	__u64 pt = bpf_get_current_pid_tgid();
	agg_obs(&key, (__u32)pt, (__u32)(pt >> 32),
		AO_EV_FS_UNLINK, (__u32)actor_slot,
		fid.dev, fid.ino, dfid.dev, dfid.ino, AO_OP_UNLINK, is_lineage);
	return 0;
}

SEC("lsm/inode_rename")
int BPF_PROG(ao_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry, int ret)
{
	(void)new_dentry;
	if (ret != 0)
		return ret;
	if (!enable_lane2) return 0;

	struct task_struct *t = bpf_get_current_task_btf();
	__u8 is_lineage = 0;
	__s32 actor_slot = resolve_lane2_actor(t, &is_lineage);
	if (actor_slot < 0) return 0;

	struct inode *ino = BPF_CORE_READ(old_dentry, d_inode);
	struct file_id fid = {}, old_dfid = {}, new_dfid = {};
	if (inode_to_id(ino, &fid) < 0) return 0;
	inode_to_id(old_dir, &old_dfid);
	inode_to_id(new_dir, &new_dfid);

	struct observed_key key = {};
	key.actor_slot = (__u32)actor_slot;
	key.op_class   = AO_OP_RENAME;
	key.dev        = fid.dev;
	key.ino        = fid.ino;
	key.parent_dev = old_dfid.dev;
	key.parent_ino = old_dfid.ino;

	__u64 pt = bpf_get_current_pid_tgid();
	agg_obs(&key, (__u32)pt, (__u32)(pt >> 32),
		AO_EV_FS_RENAME, (__u32)actor_slot,
		fid.dev, fid.ino, old_dfid.dev, old_dfid.ino,
		AO_OP_RENAME, is_lineage);

	if (new_dfid.dev || new_dfid.ino) {
		struct observed_key dst = {};
		dst.actor_slot = (__u32)actor_slot;
		dst.op_class   = AO_OP_RENAME_DST;
		dst.dev        = fid.dev;
		dst.ino        = fid.ino;
		dst.parent_dev = new_dfid.dev;
		dst.parent_ino = new_dfid.ino;
		agg_obs(&dst, (__u32)pt, (__u32)(pt >> 32),
			AO_EV_FS_RENAME, (__u32)actor_slot,
			fid.dev, fid.ino, new_dfid.dev, new_dfid.ino,
			AO_OP_RENAME_DST, is_lineage);
	}
	return 0;
}

SEC("lsm/inode_mkdir")
int BPF_PROG(ao_inode_mkdir, struct inode *dir, struct dentry *dentry,
	     umode_t mode, int ret)
{
	(void)dentry;
	(void)mode;
	if (ret != 0)
		return ret;
	if (!enable_lane2) return 0;

	struct task_struct *t = bpf_get_current_task_btf();
	__u8 is_lineage = 0;
	__s32 actor_slot = resolve_lane2_actor(t, &is_lineage);
	if (actor_slot < 0) return 0;

	struct file_id dfid = {};
	if (inode_to_id(dir, &dfid) < 0) return 0;

	struct observed_key key = {};
	key.actor_slot = (__u32)actor_slot;
	key.op_class   = AO_OP_MKDIR;
	key.dev        = dfid.dev;
	key.ino        = dfid.ino;

	__u64 pt = bpf_get_current_pid_tgid();
	agg_obs(&key, (__u32)pt, (__u32)(pt >> 32),
		AO_EV_FS_MKDIR, (__u32)actor_slot,
		dfid.dev, dfid.ino, 0, 0, AO_OP_MKDIR, is_lineage);
	return 0;
}

SEC("lsm/inode_rmdir")
int BPF_PROG(ao_inode_rmdir, struct inode *dir, struct dentry *dentry, int ret)
{
	if (ret != 0)
		return ret;
	if (!enable_lane2) return 0;

	struct task_struct *t = bpf_get_current_task_btf();
	__u8 is_lineage = 0;
	__s32 actor_slot = resolve_lane2_actor(t, &is_lineage);
	if (actor_slot < 0) return 0;

	struct inode *target = BPF_CORE_READ(dentry, d_inode);
	struct file_id fid = {}, dfid = {};
	if (inode_to_id(target, &fid) < 0) return 0;
	inode_to_id(dir, &dfid);

	struct observed_key key = {};
	key.actor_slot = (__u32)actor_slot;
	key.op_class   = AO_OP_RMDIR;
	key.dev        = fid.dev;
	key.ino        = fid.ino;
	key.parent_dev = dfid.dev;
	key.parent_ino = dfid.ino;

	__u64 pt = bpf_get_current_pid_tgid();
	agg_obs(&key, (__u32)pt, (__u32)(pt >> 32),
		AO_EV_FS_RMDIR, (__u32)actor_slot,
		fid.dev, fid.ino, dfid.dev, dfid.ino, AO_OP_RMDIR, is_lineage);
	return 0;
}

SEC("lsm/inode_link")
int BPF_PROG(ao_inode_link, struct dentry *old_dentry, struct inode *dir,
	     struct dentry *new_dentry, int ret)
{
	(void)new_dentry;
	if (ret != 0)
		return ret;
	if (!enable_lane2) return 0;

	struct task_struct *t = bpf_get_current_task_btf();
	__u8 is_lineage = 0;
	__s32 actor_slot = resolve_lane2_actor(t, &is_lineage);
	if (actor_slot < 0) return 0;

	struct inode *src = BPF_CORE_READ(old_dentry, d_inode);
	struct file_id fid = {}, dfid = {};
	if (inode_to_id(src, &fid) < 0) return 0;
	inode_to_id(dir, &dfid);

	struct observed_key key = {};
	key.actor_slot = (__u32)actor_slot;
	key.op_class   = AO_OP_LINK;
	key.dev        = fid.dev;
	key.ino        = fid.ino;
	key.parent_dev = dfid.dev;
	key.parent_ino = dfid.ino;

	__u64 pt = bpf_get_current_pid_tgid();
	agg_obs(&key, (__u32)pt, (__u32)(pt >> 32),
		AO_EV_FS_LINK, (__u32)actor_slot,
		fid.dev, fid.ino, dfid.dev, dfid.ino, AO_OP_LINK, is_lineage);
	return 0;
}

SEC("lsm/inode_mknod")
int BPF_PROG(ao_inode_mknod, struct inode *dir, struct dentry *dentry,
	     umode_t mode, dev_t dev, int ret)
{
	(void)dentry;
	(void)mode;
	(void)dev;
	if (ret != 0)
		return ret;
	if (!enable_lane2) return 0;

	struct task_struct *t = bpf_get_current_task_btf();
	__u8 is_lineage = 0;
	__s32 actor_slot = resolve_lane2_actor(t, &is_lineage);
	if (actor_slot < 0) return 0;

	struct file_id dfid = {};
	if (inode_to_id(dir, &dfid) < 0) return 0;

	struct observed_key key = {};
	key.actor_slot = (__u32)actor_slot;
	key.op_class   = AO_OP_MKNOD;
	key.dev        = dfid.dev;
	key.ino        = dfid.ino;

	__u64 pt = bpf_get_current_pid_tgid();
	agg_obs(&key, (__u32)pt, (__u32)(pt >> 32),
		AO_EV_FS_MKNOD, (__u32)actor_slot,
		dfid.dev, dfid.ino, 0, 0, AO_OP_MKNOD, is_lineage);
	return 0;
}

SEC("lsm/inode_symlink")
int BPF_PROG(ao_inode_symlink, struct inode *dir, struct dentry *dentry,
	     const char *old_name, int ret)
{
	(void)dentry;
	(void)old_name;
	if (ret != 0)
		return ret;
	if (!enable_lane2) return 0;

	struct task_struct *t = bpf_get_current_task_btf();
	__u8 is_lineage = 0;
	__s32 actor_slot = resolve_lane2_actor(t, &is_lineage);
	if (actor_slot < 0) return 0;

	struct file_id dfid = {};
	if (inode_to_id(dir, &dfid) < 0) return 0;

	struct observed_key key = {};
	key.actor_slot = (__u32)actor_slot;
	key.op_class   = AO_OP_SYMLINK;
	key.dev        = dfid.dev;
	key.ino        = dfid.ino;

	__u64 pt = bpf_get_current_pid_tgid();
	agg_obs(&key, (__u32)pt, (__u32)(pt >> 32),
		AO_EV_FS_SYMLINK, (__u32)actor_slot,
		dfid.dev, dfid.ino, 0, 0, AO_OP_SYMLINK, is_lineage);
	return 0;
}
