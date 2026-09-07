# Changelog

All notable changes to compartment-bpf are documented here.
Format is loosely based on [Keep a Changelog](https://keepachangelog.com).

## [v0.8.0] — 2026-09-06

Security review pass over the BPF enforcement surface: four coverage gaps
closed, one strict-launch design flaw fixed, one documented protection
withdrawn because it was never real, one opt-in self-protection feature added,
and one behaviour change (see below). No struct layout change.

### Security — `bpf_map_freeze()` is not map integrity (documentation was wrong)

The `CAP_BPF + direct map mutation` row in `LIMITATIONS.md` said the seal maps
were immune to a `CAP_BPF` attacker because `freeze_seal_maps()` freezes them.
That was wrong, and wrong in the reassuring direction. `bpf_map_freeze()` gates
only the **syscall** path (`map_get_sys_perms()`). Measured on 6.8.0-139 and
7.0.0-31: a caller holding `CAP_BPF` that obtains **any** fd to a frozen
compartment map — `BPF_MAP_GET_FD_BY_ID` with `BPF_F_RDONLY` is sufficient —
can splice it into a BPF program of its own with `bpf_map__reuse_fd()` and
write it with `bpf_map_update_elem()` from program context. The syscall write
stayed `EPERM`; the program write returned 0 and the value read back.

So every compartment map — `sealed_inodes`, `sealed_dirs`, `sealed_devs`,
`launcher_to_actor`, `policy_state_map` and all the counters — is mutable by an
unconfined root holding `CAP_BPF`, not just the unfreezable
`actor_marker_map`, and wiping `sealed_inodes` removes policy with no unlink,
no umount and **no audit event at all**. The mitigation that always applied and
now covers every map: keep `CAP_BPF` off every workload and every root login
(`CapabilityBoundingSet=`, a limited-root profile), and alert on enforcement
stopping. `tests/bypass/26-frozen-map-honesty.sh` measures the gap on every
run so it cannot quietly return to prose.

Two further measurements that change the threat model, both now in
`LIMITATIONS.md`:

* `umount /sys/fs/bpf` and `umount -l /sys/fs/bpf` both removed enforcement
  within 6 s on a box where nothing else held that superblock — a lazy unmount
  does **not** leave a usefully long-lived superblock. On a box where another
  mount namespace held a peer bpffs mount (observed: `polkitd` with
  `ProtectSystem=`), the host-side umount instead **orphaned** the policy: pins
  invisible, enforcement live and unreachable, `--unpin` reporting "does not
  exist; nothing to do" with exit 0. `mount -t bpf bpf /sys/fs/bpf` over the
  live bpffs produces the same orphan with no unmount at all.
* Removing **one** link pin is a surgical single-hook disarm, not
  all-or-nothing; the remaining hooks keep enforcing.
* The `actor_marker_map` forgery is real when driven with the correct
  primitive: the userspace key for a task-storage map is a **pidfd**, not a
  `/proc/<pid>` directory fd. An earlier probe using the wrong key returned
  `EBADF` and was read as "not exploitable".

### Added — opt-in self-protection (`--pin --self-protect`)

Off by default. Once armed, a root process with `CAP_BPF`/`CAP_SYS_ADMIN` that
is not the loader cannot remove, detach, forge or shadow the enforcement.

* `--self-protect` (with `--pin`) and `--authorize-loader PATH` (repeatable,
  implies `--self-protect`, at most 8 images including the pinning one).
* The running loader and every `--authorize-loader` successor must be a
  root-owned regular file with no group/world write bits. Both ownership and
  mode are checked before their inode identities enter the maintenance set.
* `SEC("lsm/bpf_map")` → `comp_bpf_map`: denies `bpf_map_new_fd()` — the single
  chokepoint for `BPF_MAP_GET_FD_BY_ID`, `BPF_OBJ_GET` on a pin and
  `BPF_MAP_CREATE` — for any task whose `mm->exe_file` inode is not an
  authorised loader image, with `-EPERM` (the errno `bpf(2)` uses for every
  other "not yours"). Read-only fds are denied too, deliberately: see the
  correction above. Autoloaded **only** with the flag, and only on a kernel
  whose BTF has `bpf_lsm_bpf_map` (`select_bpf_map_variant`); the hook is
  `FUNC_PROTO vlen=2` on both 6.8 and 7.0, verified, so no dual wrapper is
  needed. `--self-protect` refuses to load on a kernel without it.
* Pin-tamper gate on the existing `inode_unlink` / `inode_rename` /
  `inode_rmdir` / `sb_mount` / `move_mount` / `sb_umount` hooks (no new links
  beyond `comp_bpf_map`), returning `-EACCES` like every other path deny: the
  pin objects, both pin directories, `/sys/fs/bpf/compartment` and the bpffs
  mount root are recorded in `protected_pins` and cannot be unlinked, renamed,
  rmdir'd or over-mounted by a non-loader. Those five emit
  `ACTION_DENY_PIN_TAMPER`. `sb_umount` is the odd one out twice over: it keeps
  `ACTION_DENY_UMOUNT`, because "this filesystem cannot be detached while
  policy is live" is exactly what that code already means and a second code
  would carry no distinct operator response, and it has **no loader
  exemption** — nobody detaches that bpffs while a policy is live, which is
  the same rule v0.8 already applies to a filesystem holding sealed paths. All
  of them increment `deny_total`.
* Action codes `ACTION_DENY_BPF_SELF` (16) and `ACTION_DENY_PIN_TAMPER` (17),
  both inside ABI `0x0008` — no second bump, because v0.8 is unreleased and no
  consumer has ever seen a `0x0008` stream without them. The `audit_event`
  layout is unchanged.
* Counters `bpf_self_denied_total` and `pin_tamper_denied_total` (catalogue
  now 15).
* Maps `protected_map_ids`, `loader_ids` (both frozen before attach — they are
  the root of trust), `protected_pins` and `self_protect_cfg_map` (populated
  after `pin_links()` and frozen then; safe in that gap because their ids are
  already protected and the gate is already attached). None of the four is
  pinned: nothing outside the kernel reads them.
* `--unpin` now warns instead of reporting success when the pin tree is not
  visible but compartment programs are still loaded — the observable signature
  of an over-mounted bpffs or the wrong mount namespace.
* Witnesses `tests/bypass/22-self-protect-map.sh`, `23-pin-unlink.sh`,
  `24-bpffs-umount.sh`, `25-loader-upgrade.sh`, `26-frozen-map-honesty.sh`,
  and helpers `bpf_map_fd_sweep.c` / `frozen_map_write{,.bpf}.c`.

**Upgrade semantics — read before enabling.** The maintenance right is the
`(dev, ino)` of a binary image, so a rebuild or a package upgrade produces an
image that cannot unpin the old policy. `--unpin` before replacing the binary,
or pre-authorise the successor with `--authorize-loader`. The failure is loud
and names the remedy; the worst case is bounded by a reboot, because bpffs is
not persistent. Do not `--pin --self-protect` on a build host and then run
`make`. See `HOWTO.md` §3.6.

**Cost.** While a self-protected policy is live, `bpftool map show` aborts its
**host-wide** listing at the first compartment map instead of skipping it, so
maps after ours in id order are not listed either. `bpftool prog show`,
`link show` and `cgroup tree` are unaffected; unrelated maps and pins remain
fully usable. Measured on bpftool 7.4 and 7.7. Returning `-ENOENT` would avoid
it (measured: exit 0, our maps simply absent) at the cost of making an
unauthorised `--stats` indistinguishable from "no policy pinned"; the honest
errno was kept. Runtime cost, from `make bench-bpf-syscall`: of order
100-250 ns per map-fd creation with the flag on, roughly 10-17 % of the
thinnest `bpf(2)` call that hands one out; read the nanoseconds, since the
percentage moves with the baseline. With the flag off it is nil.

**Unchanged without the flag.** `comp_bpf_map` is not autoloaded, the pinned
link set is the same 28 links, the two new action codes never fire, and both
new counters stay 0. `bpf_map_freeze()` is not map integrity in that build —
see the correction above — so the load-bearing control is keeping `CAP_BPF`
off every workload and every root login.

**What it does not close**, in six lines: a reboot with `lsm=` changed or a
`kexec`; a map fd stolen from a *running* loader via `pidfd_getfd(2)` or
`SCM_RIGHTS`, neither of which calls `bpf_map_new_fd()`; a pin tree stranded
by an unauthorised loader change, which costs a reboot; the host-wide
`bpftool map show` listing, whose upstream fix is one line (`continue` on
`EPERM`/`EACCES` in its map-listing loop); an operator in a mount namespace
that cannot see the pin tree; and `CAP_BPF` itself, which is the limited-root
profile's job. The two controls compose and neither replaces the other. Full
table in `LIMITATIONS.md`.

### Behaviour change — timestamp writes are now `no-chmod`-class

**Read this before upgrading a host with `no-chmod` seals in the field.**

`inode_setattr` now treats `ATTR_ATIME|ATTR_MTIME` without `ATTR_SIZE` as a
chmod-class operation on a **directly sealed** inode. That is correct
anti-forensics hardening — rewriting mtime on a sealed file is exactly what an
attacker does to defeat an integrity baseline, and the v0.5 parent-dir rule
had classified it this way for DD-sealed children since v0.5 — but it changes
the meaning of every existing `no-chmod` seal.

Concretely, on a directly `no-chmod`-sealed file a non-actor now gets
`EACCES` from `touch`, `touch -d`, `touch -a`, `utimensat(2)`, and from the
timestamp-restoring tail of `cp -p`, `rsync -a`, `tar -x`, `install -p` and
`unzip`. Any liveness sentinel that `touch`es a sealed file will start
failing. Truncation is unaffected: `ATTR_SIZE` stays write-class, so a
`no-chmod`-only seal still permits `truncate` (regression-guarded by
`tests/bypass/19` R).

If you need the old behaviour for a specific path, add the writer to that
seal's `actor=` list. A dedicated `no-times` seal flag (SEAL bit 4 is free
and reserved) is the principled fix and is a follow-up, not part of v0.8.

### ABI bump 0x0007 → 0x0008

- **New action codes** `ACTION_DENY_MOUNT = 14` and
  `ACTION_DENY_UMOUNT = 15`, each with a value-drift `_Static_assert`;
  `action_name()` prints `DENY_MOUNT` / `DENY_UMOUNT`.
- **New map** `sealed_devs` (`__u64 s_dev` → `__u32` refcount), populated by
  the loader alongside `sealed_inodes` / `sealed_dirs` and frozen with them.
  Not pinned (like the other seal maps); listed in `KNOWN_MAP_NAMES` for
  forward compatibility.
- **Two further action codes** `ACTION_DENY_BPF_SELF = 16` and
  `ACTION_DENY_PIN_TAMPER = 17` for the opt-in self-protection above, also
  inside `0x0008` — a second bump inside one unreleased version would publish
  a `0x0008` that exists in no artefact. Code 16 is the one action whose
  `(dev, ino)` pair is not a filesystem object: `dev` is 0 and `ino` carries
  the BPF map id, so a consumer must not try to resolve it as an inode.
- **Two further maps** `protected_map_ids` and `loader_ids`, plus
  `protected_pins` and `self_protect_cfg_map`. None of the four is pinned.
- The bump makes a v0.7 audit consumer reject v0.8 events loud instead of
  printing `action=?` for code 14.

### Closed: `no-chmod` bypass via POSIX ACLs (`inode_set_acl` / `inode_remove_acl`)

- Since Linux 6.2, `setxattr(2)`/`removexattr(2)` on `system.posix_acl_*` are
  routed to `vfs_set_acl()`/`vfs_remove_acl()`, which call
  `security_inode_set_acl()`/`security_inode_remove_acl()` and never the
  xattr hooks. On the project's ≥ 6.6 floor `setfacl -m/-x/-b` rewrote the
  effective permission bits of a `no-chmod` sealed file while `chmod` was
  denied. Two new programs mirror the xattr pair (per-inode `SEAL_NO_CHMOD`
  + recursive parent-dir rule). Witness: `tests/bypass/16-setfacl-no-chmod.sh`.

### Closed: mount shadowing of sealed paths (`sb_mount` / `move_mount`)

- A new mount whose mountpoint is a sealed inode, or lies inside a
  recursively sealed subtree, is denied with `ACTION_DENY_MOUNT`. Covers
  `mount --bind`, `mount --move` / `MS_MOVE`, `move_mount(2)`,
  `open_tree(OPEN_TREE_CLONE)`+`move_mount`, `fsmount`+`move_mount` and fresh
  filesystem mounts. `MS_REMOUNT` and propagation-only changes attach nothing
  and pass. Actor-bound seals keep their allowlist (an actor may mount inside
  its own tree). Bind-mounting *from* a sealed path elsewhere stays allowed —
  the alias shares dentries, so every seal still applies through it.
- The flag exemptions mirror `path_mount()`'s dispatch order exactly. The
  kernel tests `MS_BIND` **before** the propagation bits, so exempting on any
  propagation bit would let `MS_BIND|MS_PRIVATE` attach a bind mount inside a
  sealed subtree — and `do_loopback()` reaches `graft_tree()` without calling
  `security_move_mount()`, so the second hook would not catch it either.
  Witnessed by `tests/bypass/17` W5 through a raw `mount(2)`.
- `mount --move` is dispatched by `sb_mount` and **only** there:
  `do_move_mount_old()` calls `do_move_mount()` directly and never
  `security_move_mount()`. `tests/bypass/17` W6 therefore drives
  `open_tree(OPEN_TREE_CLONE)`+`move_mount(2)`, the only shape that reaches
  the `move_mount` hook without first passing `sb_mount`.
- Retires the LIMITATIONS rows "bind-mount-OVER sealed path" and
  "Mount-inside-sealed-subtree bypass"; a residual row lists what is still
  open (`pivot_root`, mounts on the root of a pre-existing nested mount,
  and unmounting a bind mount that was itself the sealed path).
- `tests/bypass/07-mount-bind-decoy.sh` now asserts the deny (it used to
  document the gap); new `tests/bypass/17-mount-inside-sealed-dir.sh`; mesh
  §3.23 row (a) flips from KNOWN-GAP to ENFORCED.

### Closed: path shadowing by detaching the filesystem (`sb_umount`)

- Gating the mount *destination* covers only half the shadowing class. The
  other half needs no mount to start: `umount -l /data` detaches the
  filesystem, the sealed path then resolves to the mountpoint dentry in the
  **parent** filesystem — which carries no seal — and the follow-up
  `mount -t tmpfs none /data` sails straight through the destination gate.
  The sealed inodes are untouched and completely unreachable; every sealed
  path reads attacker content.
- The loader's held `O_PATH` fds made a plain `umount` return `EBUSY` in
  daemon mode, but that was an implementation accident, not a control: it
  never blocked `MNT_DETACH`, and in daemonless `--pin` mode the fds die
  with the loader.
- `sb_umount` now denies `umount` and `umount -l` on any filesystem that
  hosts sealed inodes, and `move_mount`'s new from-side gate denies moving
  such a filesystem away from its mountpoint, both with a new
  `ACTION_DENY_UMOUNT = 15`. (Residual: the classic `mount(2)`+`MS_MOVE`
  spelling of `mount --move` is not gated on the source side — no hook can
  see it. `do_move_mount_old()` bypasses `security_move_mount()` and
  `security_sb_mount()` gets the source only as an unresolvable string.
  Recorded in LIMITATIONS.) The hook is handed a `struct vfsmount`
  and has no route back to an inode, so it needs its own state: a new
  `sealed_devs` HASH (`__u64 s_dev` → refcount) that the loader populates as
  it writes `sealed_inodes` / `sealed_dirs`, frozen with them. The freeze
  table moves 18 → 19.
- Precision matters, because `s_dev` alone is far too coarse — seal one file
  on `/` and every bind mount of a root-filesystem directory would become
  unmountable. The hook therefore also requires `mnt->mnt_root ==
  sb->s_root`, i.e. it denies only detaches of the **whole filesystem**.
  Unmounting a bind mount of a subdirectory detaches nothing and stays
  allowed; `tests/bypass/20` G is the over-deny guard for exactly that.
- **Operational consequence:** while a policy is live you cannot unmount a
  filesystem that holds sealed paths. Run `compartment-bpf --unpin` first.
  `tests/inode-seal-witness.sh` W4 changes shape accordingly: it used to
  infer the held-fd pin from `EBUSY`, but `security_sb_umount()` is the
  opening statement of `do_umount()` and now answers first, so W4 asserts the
  deny (with the `DENY_UMOUNT` audit line proving it is ours) and W3's direct
  `/proc/<pid>/fd` read carries the held-fd proof.
- Witness: `tests/bypass/20-umount-shadow.sh`; mesh §3.23(e) flips from
  "unmount succeeds, entries orphaned" to "unmount denied, seal still
  enforced".

### Closed: inode-flag ioctls and timestamp forgery under `no-chmod`

- New `file_ioctl` program gates `FS_IOC_SETFLAGS` / `FS_IOC32_SETFLAGS` /
  `FS_IOC_FSSETXATTR` / `FS_IOC_SETVERSION` (`chattr +i/+a`, project ids) on
  `no-chmod` seals; every other ioctl returns after a few compares.
- A companion `file_ioctl_compat` program covers 32-bit callers. A compat
  process enters `COMPAT_SYSCALL_DEFINE3(ioctl)`, which calls
  `security_file_ioctl_compat()` and **never** `security_file_ioctl()`, so
  without it an i386 `chattr +i` walked past the gate. The hook was
  backported into stable 6.6.y, so the loader BTF-probes
  `bpf_lsm_file_ioctl_compat` and autoload-gates the program rather than
  testing the kernel version. Witness: `tests/bypass/18-chattr-no-chmod.sh`
  (W1/W2 native, W3 via `gcc -m32`).
- `inode_setattr` per-inode rule: `ATTR_ATIME|ATTR_MTIME` without
  `ATTR_SIZE` (`utimensat`, `touch -d`) is now chmod-class, matching the
  v0.5 parent-dir rule. See the Behaviour change section above.
  Witness: `tests/bypass/19-utimes-no-chmod.sh`.

### Fixed: strict-launch marker written before the exec point of no return

- The marker was set in `bprm_check_security`, which `search_binary_handler()`
  calls immediately before `fmt->load_binary()`. Every failure inside
  `load_elf_binary()` **before** `begin_new_exec()` returns `-errno` to the
  caller's original image, which keeps running its old code with whatever the
  check hook already wrote. The most usable of those failures is
  `open_exec(elf_interpreter)` → `-ENOENT`: an attacker who controls a mount
  namespace shadows the path in the launcher's `PT_INTERP` and forces it
  deterministically, with no race. A task already running the actor target
  under `LD_PRELOAD` could `execve()` the sealed launcher, force that
  failure, and return to its own code holding a valid marker whose target
  matched its exe — satisfying every strict-launch condition.
- (Failures *inside* `begin_new_exec()` and later — `de_thread()`,
  `unshare_files()`/`dup_fd()`, `exec_mmap()` — are past
  `bprm->point_of_no_return`, and `bprm_execve()` converts them to a fatal
  `SIGSEGV`. They never return to the caller and were never the window.)
- Marker set/keep/clear now lives in `bprm_committed_creds`, which runs only
  for a committed image; an unresolvable exec target drops any existing
  marker (fail closed).
- The hook is attached **sleepable** (`lsm.s/`). `bpf_lsm_bprm_committed_creds`
  is in the kernel's `sleepable_lsm_hooks` allowlist on both 6.8 and 7.0, and
  sleepable context is what makes `bpf_task_storage_get(F_CREATE)` a blocking
  allocation. The residual failure is now counted rather than silent — see
  the new counter below.
- Pin link name: `comp_bprm_check_security` → `comp_bprm_committed_creds`.
  `--unpin` still sweeps the legacy name, so a v0.4..v0.7 pin tree can be
  torn down before re-pinning.
- Known and unchanged: a `#!`-script launcher has never worked. `bprm->file`
  at commit time is the interpreter, and `mm->exe_file` for a script exec is
  the interpreter too, so `launcher=` must name an ELF binary.

### New counter: `marker_set_fail_total`

- Bumped when `bprm_committed_creds` cannot allocate the task-storage
  marker. The behaviour is fail-closed — the actor is denied at its first
  protected operation — but it was silent. A nonzero value tells an operator
  the denies came from allocation pressure, not from an attack on the
  launcher chain. Expected to stay 0; strict-launch SL-11 is the negative
  witness. `TM_MIN_COUNTERS` floor moves 12 → 13, and 13 → 15 with the two
  self-protection counters; the freeze table moves 17 → 18, and 18 → 23 with
  the four self-protection maps.

### Loader

- `pin_links()` pins 28 links (16 v0.3 + 5 v0.4 + 7 v0.8), or 29 with
  `--self-protect`; `KNOWN_LINK_NAMES` extended; `tests/expected-links.txt`
  marks `comp_bpf_map` `self-protect` and pin-regression T4.6 keys off the
  loader's own probe line, so the assertion is exact in both modes.
  `make check-actor-hook` gains grep gates for every v0.8 hook, its
  `PIN_LINK`, its unpin-table entry, the `file_ioctl_compat` BTF probe, the
  `sb_mount` `MS_BIND` dispatch-order guard, and every self-protection site
  that could turn the gate into a no-op while still printing "ARMED".
- `select_file_ioctl_compat()` joins `select_inode_setattr_variant()` as an
  autoload gate that runs between `__open()` and `__load()`.

### Documentation

- `LIMITATIONS.md` gains rows for ACL/xattr coverage, ioctl/`chattr` (with
  the compat residual), timestamps (with the behaviour-change warning),
  pre-existing writable fds, and `mount_setattr(2)`/`open_tree_attr(2)`
  (unhooked upstream). Three factual corrections: `bpf_map_freeze()` closes
  the `BPF_MAP_UPDATE_ELEM` **syscall** path but is **not** map integrity —
  a `CAP_BPF` holder with any fd to a frozen map, `BPF_F_RDONLY` included,
  writes it from a BPF program of its own (measured on 6.8.0-139 and
  7.0.0-31), so every compartment map is mutable by an unconfined root and
  the row no longer claims the seal maps are immune;
  `bpf(BPF_LINK_DETACH)` returns
  `-EOPNOTSUPP` for an LSM link (the removal path is `unlink()` of the bpffs
  pin); and `fallocate(2)` — which v0.8 recorded as *not* covered by
  `security_file_permission()`, corrected in 1.4 after
  `tests/limitations-witness.sh` measured it denied and audited on
  6.8.0-139 and 7.0.0-31, on tmpfs and on ext4.
- `README.md` hook table lists the v0.8 hooks explicitly and drops
  `task_free` (observe-only). `HOWTO.md` §7.1 names the hooks that actually
  implement `no-chmod` instead of two symbols that never existed.
- `HOWTO.md` gains §3.6: what `--self-protect` refuses, the two prerequisites,
  the errno an operator sees for each refused operation, the identity model,
  both upgrade ceremonies, the verbatim message printed when an operator
  strands themselves, the reboot escape, and the measured cost to
  `bpftool map show`. `LIMITATIONS.md` gains a section stating what the flag
  does **not** close: reboot with `lsm=` changed or `kexec`, a map fd stolen
  from a running loader via `pidfd_getfd`/`SCM_RIGHTS`, a stranded pin tree,
  the `bpftool map show` cost, mount-namespace reachability, and `CAP_BPF`
  itself. `COUNTERS.md` documents both new counters and states plainly that
  they are bounded-below rather than exact-delta, with the reason: they count
  denies triggered by third-party tools whose syscall counts are not ours to
  predict. The exact invariant that *is* asserted is that both are subsets of
  `deny_total`.

---

## [v0.7.3] — 2026-06-11

No ABI change (`0x0007` unchanged). Usability, a non-root validation fix,
new fail-closed test coverage, and documentation-residue cleanup surfaced
by an independent multi-angle review of the public tree.

- **Usability:** the `observe` subcommand is now documented in `--help`
  (synopsis + description). It already worked; it was just undocumented.
- **Fix (non-root `--dry-run`):** the pinned-seal-shape check treats
  `EACCES`/`EPERM` from the bpffs pin tree (mode 700) as "cannot verify,
  warn and continue" instead of fatal, restoring the "safe for non-root"
  contract for `--dry-run`/`--parse-only`. The real `--pin` path still runs
  as root and catches a genuine wrong-shape pin.
- **Tooling:** added `tools/seal-binary-closure.sh`, which emits seal
  directives for a binary plus its `ldd` shared-library closure (version
  symlinks resolved to real inodes) — fully tamper-proofing an executable
  pulls in its library closure. See `HOWTO.md` §2.8.
- **Testing (test to the failure):** two fail-closed witnesses wired into
  `make check`: `check-loader-refusal` (the recursive directory-seal
  refusals — symlink / hardlink / over-depth in the subtree — via
  `--dry-run`, no root) and `check-limit-stress` (large fan-out validation
  plus an over-capacity profile that must fail closed, never silently
  truncating enforcement).
- **Docs:** removed dangling references to the (unpublished) `experimental/`
  design specs left by the v0.7.2 sanitization — including a runtime
  filesystem-refusal error string that pointed at a non-existent path —
  fixed a stale `HOWTO.md §6.4` → §4.1 cross-reference, corrected the audit
  ringbuf capacity to 256 KiB and the v0.5 strict-launch hook list, and the
  `ACTOR_NAME_MAX` comment.

## [v0.7.2] — 2026-06-09

No ABI change (`0x0007` unchanged). Portability, a correctness fix, and
tooling/telemetry additions surfaced by a Noble 6.8 bring-up and an
independent multi-angle review.

- **Portability (Noble 6.8):** the `inode_setattr` LSM hook now ships as a
  dual wrapper (2-arg and 3-arg signatures) selected at load time, with the
  unused variant gated off via `bpf_program__set_autoload`. Variant selection
  uses a BTF probe of the hook's function prototype, autoloaded in the
  `__open() → set_autoload → __load()` window. Wrong-variant selection is
  fail-closed (verifier reject at load, never a partially-attached hook set).
  Ubuntu 24.04 LTS (Noble, kernel 6.8) is now a tested platform.
- **Fix (inode-reuse stale-seal window):** the loader now holds one `O_PATH`
  fd per sealed inode for the daemon's whole lifetime, pinning each inode
  against kernel inode-number recycling so a freed-and-reused inode number can
  no longer inherit a stale `(dev, ino)` seal (a spurious fail-closed deny,
  reproduced on Noble 6.8). `RLIMIT_NOFILE` is raised to the hard limit to
  afford one fd per seal.
  - **Side-effect (security-positive):** each held fd pins its filesystem, so
    any filesystem containing seals returns `EBUSY` on `umount` /
    `mount -o remount,ro` while the daemon runs. This blocks a
    remount/umount-to-bypass vector; run `--unpin` before relocating a sealed
    filesystem. (`umount -l` lazy-detach is unaffected — see `LIMITATIONS.md`.)
  - **Known limitation:** in `--pin` daemonless mode the held fds die with the
    loader process while pinned enforcement persists, so the reuse window
    re-opens. Pair `no-write` with `no-unlink` to make it inert by policy. See
    `LIMITATIONS.md`.
- **Telemetry:** added `COUNTERS.md` documenting the full counter surface and a
  `smoke-telemetry` gate (`telemetry-smoke.sh`) that checks pinned-counter
  parity/drift in `make check`.
- **Tooling:** added the deny-to-candidate tool (`check-deny-candidate`), which
  turns observed `DENY` audit events into a commented candidate profile.
- **Testing (coverage-accountability):** added a static code-surface vs.
  test-witness gate (`tools/coverage-map.py` + `tests/coverage/coverage-manifest.tsv`
  + `make check-coverage-static`) — every LSM hook, `ACTION_DENY_*` action, and
  `*_total` counter must be referenced by a test or carry an explicit
  exemption-with-reason, so a new un-witnessed surface fails the build. Wired
  six previously-orphaned witnesses into `make check` (`check-bypass` via a new
  in-place `tests/bypass/run-local.sh`, `check-codex-witnesses`,
  `check-dir-matrix`) and added `make check-release`, a strict gate that fails
  on critical environment skips for VM/release validation. The wiring surfaced
  and fixed two stale-test drifts (a map-freeze witness using an outdated value
  size; a directory-matrix prediction that lagged the recursive write-protection
  semantic).
- **Build (new Makefile targets):** `bench-overhead`, `bench-concurrency`,
  `check-counter-longevity`, `smoke-telemetry`, `check-deny-candidate`,
  `check-coverage-static`, `check-bypass`, `check-codex-witnesses`,
  `check-dir-matrix`, `check-release`.
- **Docs:** removed the in-tree `experimental/*.md` design/feasibility specs
  from the published tree; operator-facing behavior is documented in
  `HOWTO.md` / `LIMITATIONS.md` / `COUNTERS.md`.
- **Lab tooling:** added `kvm/ubuntu-noble*.sh` for a Noble 6.8 VM spin-up.

## [v0.7.1] — 2026-05-19

Patch release (no ABI change; `0x0007` unchanged). Fixes surfaced by an
external review and a full end-to-end VM run of the public tree.

- **Security (loader):** close a `--pin` over an already-pinned tree that
  left the live tree without its Argon2id unpin sentinel, downgrading the
  next `--unpin` to the no-passphrase path. A new up-front + under-lock
  stale-pin check refuses re-pin before any side effect.
- **Fix (actor-wrapper):** restore a dropped `*/` that had commented out
  the wrapper's entire exec + hardening sequence (env scrub, seccomp,
  fd-close, `execveat`), leaving it non-functional.
- **Tests:** add a liveness gate so a non-functional wrapper fails loudly
  instead of passing negative assertions vacuously; vendor the
  strict-launch fixtures so that suite runs (15 witnesses) instead of
  skipping; re-point parser/bypass/pin-regression checks at the current
  loader diagnostics.
- **Hygiene:** finish removing internal tracking tags from comments,
  messages, the demo config, and dev-box paths.

## [v0.7] — 2026-05-18

### ABI bump 0x0006 → 0x0007

No struct layout change. `seal_value` remains 96 bytes (the ABI header's
`_Static_assert(sizeof(struct seal_value) == 96, ...)` is authoritative);
`audit_event` unchanged.

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
- **Strict-launch-marker**: five LSM hooks (`bprm_check_security`, `task_alloc`,
  `task_prctl`, `ptrace_access_check`, `ptrace_traceme`) set a per-task launch
  marker (copied across fork via `task_alloc`) and deny the `PR_SET_MM` and ptrace
  vectors that could forge or escape it. Processes that reach sealed paths
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
