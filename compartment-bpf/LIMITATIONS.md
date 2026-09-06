# compartment-bpf — operator-facing limitations

This file lists threats that compartment-bpf v0.8 (seal-path engine
+ exec-domain actor allowlist + strict-launch-marker + metadata/mount
coverage) does **not** address on its own. This document is the operator-facing summary of
threats out of scope, intended to be read alongside the README's
Limitations section before deploying actor-bound profiles in
production.

## Hard caveat — built for small high-value targets, not whole trees like `/usr`

compartment-bpf is designed to seal a **small set of high-value targets** — a
credential or config file, or an actor binary such as AIDE — making them immutable
even to root, with audit. It is **not** a whole-system read-only tool. Sealing a
large tree such as `/usr` is impractical and is refused at load, for two reasons:

- **Scale.** Seals are per-inode; the seal map caps at 65,536 entries, which a
  tree like `/usr` blows past.
- **Symlinks / hardlinks.** A recursive directory seal fails closed on any symlink
  or hardlink in the subtree, and `/usr/lib` is full of both — so the seal will
  not load. (This is a current limitation, not a permanent one.)

For whole-tree read-only, use an OS facility instead (read-only mount, overlayfs,
`systemd ProtectSystem=strict`, dm-verity, or `chattr -R +i` with
`CAP_LINUX_IMMUTABLE` dropped from the system bounding set). Use compartment-bpf
for the specific high-value files those mechanisms don't individually protect with
per-actor exec policy + audit.

## Hard caveat — `actor=` vs `actor-strict` (ABI v0.4)

ABI v0.4 (2026-05-15) adds `actor-strict NAME = TARGET launcher=PATH`
declarations and the `strict-launch` seal flag. **The safe release
shape is `actor-strict` alongside the static wrapper, with legacy
`actor=` documented as binary-identity only.** Releasing strict-launch
does NOT retroactively make plain `actor=` clean-launch-safe — it
gives the operator a separate primitive for actors that need
LD_PRELOAD-safe protection (AIDE in particular).

Concretely:

- `actor NAME = PATH` (legacy v0.3): the kernel matches by exe inode
  only. An attacker that exec's PATH with `LD_PRELOAD=evil.so` sees
  the same exe inode as the legitimate actor and inherits actor
  identity. The wrapper closes the operational hygiene channel
  (`clearenv()` + dangerous-name reject) but cannot retroactively
  protect a *direct* exec that bypasses the wrapper.

- `actor-strict NAME = TARGET launcher=PATH` (v0.4): the kernel
  *additionally* requires a marker that is set only when the task
  reached TARGET through the declared sealed `launcher`. A direct
  `LD_PRELOAD=evil.so /usr/sbin/aide` fails the marker check;
  protected writes are denied with `ACTION_DENY_STRICT_LAUNCH_MISSING`.

For any actor whose profile claims LD_PRELOAD-safe protection, use
`actor-strict`. Keep `actor=` for legacy actors whose threat model is
limited to root-with-different-binary (the v0.3 surface).

## Hard caveat — ABI upgrades are forward-only

ABI upgrades are forward-only, but the *shape* of protection differs across
adjacent ABI versions. `seal_value` was 88 bytes in v0.3 and grew to 96 bytes
in v0.4 (adding `strict_actor_slot` + `strict_generation`); v0.5 keeps the
96-byte layout and reuses the trailing slack for `ACTION_DENY_WRITE_PARENT_DIR`
/ `ACTION_DENY_CHMOD_PARENT_DIR`.

* **v0.3 ↔ v0.4+**: the `seal_value` size grew 88 → 96. `check_pinned_seal_map_shapes()`
  in the loader is the shape gate that catches this fail-closed; the loader refuses
  with a clear diagnostic. The `tests/bypass/exec-domain/BX-12-abi-size-gate.sh`
  witness validates this gate.
* **v0.4 ↔ v0.5**: both versions use a 96-byte `seal_value`; the shape gate
  **cannot** distinguish a v0.4 pin tree from a v0.5 one. The actual cross-version
  protection comes from two independent mechanisms:
    1. `bpf_link__pin` returns `EEXIST` if a v0.4 loader tries to attach over
       a v0.5-pinned set (or vice versa) — the BPF link path refuses to
       double-attach.
    2. The userspace audit consumer checks `audit_event.version` for equality
       against its compile-time ABI; events from a mismatched producer are
       dropped rather than misinterpreted.

Downgrading requires deleting and recreating the BPF PIN root:

```sh
compartment-bpf --unpin   # removes /sys/fs/bpf/compartment
compartment-bpf --pin profiles/myprofile.conf  # fresh maps at current ABI
```

---

## Hard caveat — policy reload (ABI v0.4)

**Policy hot-reload is not supported in v0.4.** The supported operator
flow for changing a profile is:

1. `compartment-bpf --unpin` (destroys per-task marker storage)
2. edit the profile
3. `compartment-bpf --pin <new-profile>` (fresh generation, fresh markers)

In step 3, every protected actor must re-launch through its declared
sealed launcher before it can write to a `strict-launch` seal again.
The first such launch sets a marker against the new policy generation.

Concretely: a long-running marked actor that survives `--unpin` is
left with stale marker storage destroyed; its next write to a sealed
file is denied with `ACTION_DENY_STRICT_LAUNCH_MISSING` until it
re-execs through the launcher. This is the correct fail-closed
behavior — no release up to and including v0.8 provides a
hot-reload path that keeps a marked actor running across a policy
change.

The detection machinery (`marker_stale_generation_total` counter,
dual-side `policy_state.generation` check) is wired in the BPF program
as forward-compat scaffolding for a future hot-reload feature. It costs nothing at
runtime today because the loader never bumps `policy_state.generation`
after the initial `--pin`; both v0.4 and v0.5 leave it pinned at 1.

The actor-relaunch requirement is a load-bearing property of
`strict-launch` in both v0.4 and v0.5: enforcement markers are
per-task and do not survive exec across a policy reload. If a
deployment cannot tolerate the actor-relaunch interruption inherent
in the `--unpin` + `--pin` cycle, the alternative is legacy `actor=`
with the wrapper, which provides binary-identity actor protection
without the marker requirement and can be hot-reloaded by SIGHUP-aware
daemons because it does not rely on per-task state. Hot-reload for
`strict-launch` itself is a deferred capability and is not scoped for
any currently planned release.

The framing is defense-in-depth. compartment-bpf is one layer; each
row below names the companion control that closes the gap. Deploy
with at least one companion mitigation per row that matches your
threat surface.

## What exec-domain v0.3 alone does NOT protect against

(See the hard-caveat block above. For v0.4 with `actor-strict`,
LD_PRELOAD and the ptrace classes below are closed by the in-kernel
marker check + the `task_prctl` / `ptrace_*` hooks. The legacy
`actor=` rows below still apply when an operator uses the v0.3
syntax.)

| Threat                                       | Mitigation gap                                                                                                                                                          | Companion control                                                                                                  |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| **LD_PRELOAD / LD_AUDIT injection** into actor  | The kernel sees the legitimate actor binary as caller (exe inode matches). Library injection is in-process; compartment-bpf cannot distinguish in-process tampering.    | `tools/compartment-actor-wrapper` (static-linked clean-exec wrapper: `clearenv()` + opt-in `--allow-env` allowlist + DANGEROUS-name guard rejecting LD_PRELOAD/LD_AUDIT/GLIBC_TUNABLES/PYTHONPATH/...); systemd unit `UnsetEnvironment=`; setuid not used. The default is no env survives the wrapper boundary; the guard catches operator mistakes adding dangerous names via `--allow-env`. **Note:** `UnsetEnvironment=LD_PRELOAD` alone leaves `LD_AUDIT`, `LD_DEBUG`, and the other 30+ glibc dynamic-loader vectors active. Use `UnsetEnvironment=~LD_` (the `~` prefix matches by pattern in systemd ≥ v243) or enumerate all `LD_*` names explicitly. The wrapper's clearenv-then-allowlist is the load-bearing control; the systemd directive is defense in depth.             |
| **ptrace attach + memory write** of running actor | Once the actor process is running, an attacker with `CAP_SYS_PTRACE` can attach and write its memory. The kernel still sees the actor as caller for any subsequent ops. | `yama.ptrace_scope=2` (kernel cmdline); `no_new_privs`; seccomp filter on `ptrace(2)` for production daemons. The actor-wrapper installs a seccomp denylist that blocks ptrace + `process_vm_{readv,writev}` + `pidfd_getfd` + `kcmp` from the wrapped process itself (does NOT stop a third party from ptracing the actor — pair with Yama). |
| **CAP_BPF + direct map mutation**            | **Corrected v0.8 — the seal maps are already immune.** `freeze_seal_maps()` calls `bpf_map_freeze()` on `sealed_inodes`, `sealed_dirs` and all 13 counters after load, and the kernel's `map_get_sys_perms()` strips `FMODE_CAN_WRITE` from any fd opened on a frozen map, so `bpftool map update` on a sealed map fails with `EPERM` regardless of `CAP_BPF`. What is **not** frozen is `actor_marker_map`: `BPF_MAP_TYPE_TASK_STORAGE` is per-task-allocated and the kernel API has no freeze for it — see the strict-launch marker forgery row below, which is the real residual. | Nothing further needed for `sealed_inodes` / `sealed_dirs`. For `actor_marker_map`, restrict `CAP_BPF` as described in the marker-forgery row. v1.x candidate: an `lsm/bpf_map` self-protection gate keyed on a loader-recorded map-id set (the hook signature is identical on 6.8 and 7.0 and it is still called from `bpf_map_new_fd()`, so `BPF_MAP_GET_FD_BY_ID` and `BPF_OBJ_GET` are both chokepointed). |
| **Privileged removal of the LSM links** (bpffs pin unlink) | **Corrected v0.8 — `bpf(BPF_LINK_DETACH)` does not work here.** `bpf_tracing_link_lops` (the link ops for every BPF-LSM / tracing link) defines only `.release`, `.dealloc`, `.show_fdinfo` and `.fill_link_info` — there is **no `.detach`** — so `link_detach()` returns `-EOPNOTSUPP` on both 6.8 and 7.0. Hardening against that syscall protects nothing. The one removal path is `unlink()` of the pins under `/sys/fs/bpf/compartment/links/` plus dropping the last held fd (which, in daemonless `--pin` mode, means only the pins keep enforcement alive). A privileged user with write access to the bpffs pin directory can therefore remove enforcement entirely, leaving the system fail-OPEN. | Guard the **pin tree**, not the syscall: keep `/sys/fs/bpf` out of containers, restrict `CAP_BPF` and write access to the pin directory to the loader and operator accounts (systemd `AmbientCapabilities=` / `CapabilityBoundingSet=`); ingest the `audit_event` ringbuf into a SIEM that alerts on enforcement-stop. v1.x candidate: have the loader seal its own link-pin inodes with `no-unlink,no-rename actor=<the compartment-bpf binary>` — `comp_inode_unlink` already fires on bpffs, so this needs no new hooks. |
| **Out-of-band kernel writes**                | Direct `kmem` writes, kprobe overwrites, or kernel-module loads can disable the LSM hook chain entirely.                                                                | Kernel `lockdown=integrity` or `lockdown=confidentiality` (kernel cmdline); `kernel.modules_disabled=1`; Secure Boot. |
| **Offline tampering of the actor binary**    | If the attacker boots from rescue media and edits `/usr/sbin/aide` on the unmounted disk, E-6 cannot fire — enforcement is only active at runtime.                       | LUKS full-disk encryption; signed kernel modules; IMA/EVM file signatures; locked-down boot firmware.              |
| **Exec via interpreter chain** (NOT a bypass) | Actor exec's `python /tmp/evil.py` → `current->mm->exe_file` becomes `python`. File access is then correctly denied because python is not in `actor aide`. This is the intended behavior, listed here so readers don't mistake it for a bypass. | None needed — this is intended fail-closed semantics.                                                              |
| **Unprivileged hardlink to canonical actor binary** (R2-F10) | Without `fs.protected_hardlinks=1`, any unprivileged user on the box can `ln /usr/sbin/aide /tmp/myactor; /tmp/myactor` and have `current->mm->exe_file` resolve to the same (dev, ino) as the canonical actor binary — inheriting actor identity. No CAP_BPF needed; no root needed. v0.x R2-F11 closes the surface at the LSM layer via `comp_inode_link`'s source-inode SEAL_NO_WRITE check, and the loader emits a startup `[loader] WARNING` line when `fs.protected_hardlinks=0` is detected. Operator-side defense remains required. | Kernel sysctl `fs.protected_hardlinks=1` (the v0 BX-10 witness probes both states; the LSM-layer check + sysctl together bracket the class). |
| **PR_SET_MM_EXE_FILE actor-identity swap** (R2-M18) | A process with `CAP_SYS_RESOURCE` can call `prctl(PR_SET_MM_EXE_FILE, fd)` to point its `current->mm->exe_file` at a different file inode. Compartment-bpf reads `current->mm->exe_file` for actor identity; a CAP_SYS_RESOURCE-equipped process could swap to an actor's inode and inherit identity without exec'ing the actor binary. CAP_SYS_RESOURCE is normally constrained to root/system contexts (it gates `setrlimit` overrides too), but containers or daemons that retain it are an exposed surface. | Drop CAP_SYS_RESOURCE in the bounding set of any process that does not need it; capability-bound the actor binary itself; sealed-agent mode (v1.5) will additionally restrict the loader's own caps after attach. |
| **Dual-channel audit drops** (R2-M26) | The kernel-side audit ringbuf has finite capacity (256 KiB default; the V-4b counter `audit_drop_total` records reservation failures). The ED-11 userspace-side audit emits go through stderr + syslog `LOG_AUTHPRIV`. A SIEM that monitors only one of {ringbuf, syslog, stderr} will miss events on the other channels. Cross-channel correlation is required for complete coverage. | Configure log shippers to ingest BOTH `auth.log` (syslog `LOG_AUTHPRIV`) AND the daemon's systemd-journal output AND `bpftool prog show` ringbuf via the V-4b reader. Alert on `audit_drop_total > 0` (any ringbuf drops). |
| **Recursive subtree ancestor-walk depth cap** (v0.6+, default `COMPARTMENT_MAX_DIR_ANCESTORS=8`) | The BPF ancestor walk is an unrolled loop bounded at compile time. Each increment adds ~300 B of xlated code per hook; 64 levels caused ~2.5 s BPF load time on Resolute 7.0 (21 KB xlated per hook). The default cap is **8** levels, but custom deployments may rebuild with a larger value. To avoid a silent runtime bypass, the loader now **refuses recursive directory seals** when the live subtree already exceeds the compiled budget: any descendant directory at depth `>= cap`, or any non-directory descendant deeper than `cap`, aborts attach. After attach, the kernel denies `mkdir`, symlink/hardlink creation, non-directory rename-import, and directory rename operations that would violate the compiled recursive-subtree invariants. In particular, directory imports from outside the covering sealed subtree, and same-seal directory deepening renames, fail closed because the BPF hook cannot prove descendant depth portably in-hook across filesystems. | Keep sealed subtrees within the compiled depth budget, split deep layouts into intermediate `seal` rules, or rebuild with a larger `COMPARTMENT_MAX_DIR_ANCESTORS` (for example `make COMPARTMENT_MAX_DIR_ANCESTORS=32`). If an actor must reorganize a large subtree, move files directly or stage changes outside the sealed tree before attach; deepening/importing directories under a live recursive seal is intentionally conservative. v1.x scope: bounded-loop improvements upstream may make larger caps cheaper without linear verifier/load-time cost. |
| **Loader depth-check to attach race window** (v0.7, P2-9) | `validate_recursive_dir_seal` (the `nftw` callback in `compartment-bpf.c`) walks the sealed subtree and rejects descendants past `COMPARTMENT_MAX_DIR_ANCESTORS` before the BPF programs are attached. A concurrent writer with `mkdir`/`rename` access to the subtree could grow the tree past the cap during the validation→attach window before enforcement goes live, then the runtime walk would silently truncate at the cap (the kernel-side loop has no way to know it didn't reach the seal). The window itself is not closed; commit `b265aef` (runtime recursive subtree growth guard) only closes the **post-attach** widening path via `mkdir`/`rename` denies. | Treat the validation→attach window as a narrow race; serialize policy load with quiescent subtree state in operational workflows (e.g. mount target dir read-only during load, or fence privileged writers under `--pin` for the millisecond-scale window). `bpf_map_freeze` after attach does not help (the race is on the FS, not the map). v1.x scope: pin the subtree shape into a hash-keyed map at validation time and gate runtime denies on a subtree-version mismatch. |
| **Mount shadowing — residual surface** (v0.8) | v0.8 attaches `sb_mount`, `move_mount` and `sb_umount`. **Attaching:** a new mount whose mountpoint is a sealed inode, or lies inside a recursively sealed subtree within the ancestor-walk budget, is denied with `ACTION_DENY_MOUNT` (actor= allowlists honoured, so an actor may mount inside its own tree). `mount --bind`, `mount --move` / `MS_MOVE`, `move_mount(2)`, `open_tree(OPEN_TREE_CLONE)`+`move_mount`, `fsmount`+`move_mount` and fresh filesystem mounts are all covered; `MS_REMOUNT` and propagation-only changes attach nothing and pass. The flag exemptions mirror `path_mount()`'s dispatch order, in which `MS_BIND` is tested *before* the propagation bits — exempting on a propagation bit alone would let `MS_BIND\|MS_PRIVATE` through, and `do_loopback()` never calls `security_move_mount()`, so nothing else would catch it. Bind-mounting *from* a sealed path elsewhere stays allowed — the alias shares dentries with the original, so every seal (including the ancestor walk) still applies through it (mesh §3.23 b/c). **Detaching:** `umount`, `umount -l` (`MNT_DETACH`) and `mount --move` of a filesystem that hosts sealed inodes are denied with `ACTION_DENY_UMOUNT`, keyed on a loader-populated `sealed_devs` (`s_dev`) set. Without this, `umount -l /data` detached the filesystem, the sealed path resolved to the unsealed mountpoint dentry in the parent filesystem, and a follow-up mount there passed the attach gate — the sealed inodes stayed protected and became unreachable. The held `O_PATH` fds made a plain `umount` EBUSY in daemon mode, but that never blocked `MNT_DETACH` and evaporates entirely in `--pin` mode. **Operational consequence:** while a policy is live you cannot unmount a filesystem holding sealed paths; run `compartment-bpf --unpin` first. **Four shapes remain open to `CAP_SYS_ADMIN`:** (0) `mount --move` in its classic `mount(2)`+`MS_MOVE` spelling, when the *source* is the sealed filesystem: `do_move_mount_old()` calls `do_move_mount()` directly and never `security_move_mount()`, and `security_sb_mount()` receives only the destination `path` plus the source as an unresolvable `char *` — so no hook can see which mount is being moved. `move_mount(2)`, which recent util-linux increasingly uses, **is** gated (`tests/bypass/20` W3 drives it directly, because a `mount --move` shell probe cannot be told apart from the `EINVAL` a shared-propagation parent returns). (1) `pivot_root(2)`; (2) a mount placed on the **root of a nested mount** that already existed inside a sealed tree at load time — the BPF `d_parent` walk stops at a mount root and never sees the sealed ancestor (the loader's `nftw(FTW_MOUNT)` skips such nested mounts during validation for the same reason); (3) unmounting a **bind mount** that was itself the sealed path — `sb_umount` deliberately requires `mnt->mnt_root == sb->s_root` so that it denies only whole-filesystem detaches, because keying on `s_dev` alone would make every bind mount of a root-filesystem directory unmountable on any host that seals a single file on `/`. Witnesses: `tests/bypass/07-mount-bind-decoy.sh`, `17-mount-inside-sealed-dir.sh` (W5 `MS_BIND\|MS_PRIVATE`, W6 `open_tree`+`move_mount`), `20-umount-shadow.sh`, mesh §3.23. | Drop `CAP_SYS_ADMIN` from daemons; `systemd MountFlags=private`; keep sealed trees free of nested mounts at load time; `--unpin` before planned maintenance that unmounts a sealed filesystem. v1.x candidate: an `sb_pivotroot` deny. |
| **In-place writes to files under a sealed directory** (R2-F5, updated v0.6) | **ABI v0.4 and earlier:** a directory seal blocked structural mutations (create/unlink/rename/link/mkdir/etc.) but did NOT block in-place writes to existing files inside the dir. **ABI v0.5 (dir-destination):** `ACTION_DENY_WRITE_PARENT_DIR` (action=9) additionally blocked writes, truncates, and write-mode opens of **immediate children** of a DD-sealed directory only — grandchildren and deeper paths were not covered. **ABI v0.6+ (recursive subtree):** the enforcement hooks now walk ancestor dentries at runtime (`deny_dir_ancestor_action_from_dir_dentry`, bounded by `COMPARTMENT_MAX_DIR_ANCESTORS`, default 8), so a `no-write` / `no-chmod` directory seal covers the **entire subtree** up to the compiled depth cap, not just immediate children. Concrete impact for a no-write DD seal on the postgres data dir: heap files (`base/<oid>/<n>`), WAL segments (`pg_wal/<seg>`), and files nested in subdirectories are ALL write-denied for non-actors, provided they sit within `COMPARTMENT_MAX_DIR_ANCESTORS` levels of the sealed directory. The remaining limit is the depth cap, not the one-level boundary — see the `Recursive subtree ancestor-walk depth cap` row above. | Use `seal DIR no-write actor=NAME` for recursive subtree write protection. Keep sealed subtrees within the compiled depth budget, or rebuild with a larger `COMPARTMENT_MAX_DIR_ANCESTORS` (e.g. `make COMPARTMENT_MAX_DIR_ANCESTORS=32`). |
| **btrfs / FUSE seal enforcement failure** | compartment-bpf v0 does NOT enforce seals on btrfs or FUSE filesystems. The BPF hook reads `inode->i_sb->s_dev` (real subvolume / FUSE-internal block dev) while userspace `stat` returns the anon_bdev — map lookup misses silently and every outsider write through a sealed btrfs/FUSE path receives ALLOW. **Bi-directional**: actor binaries on these filesystems also break (caller-id resolution sees real s_dev; userspace resolved anon_bdev → no match → silent DENY). v1 fix is BPF-side; v0 fix is the loader refuse below. | Keep all sealed paths and actor binaries on ext4 / xfs / tmpfs. Loader refuses btrfs and FUSE paths at `seal_path()` and `actor_resolve_paths()` via `anon_bdev_refuse()` (fail-closed). |
| **overlayfs copy-up bypass** | A write through an overlay merged path triggers copy-up → kernel opens a NEW upper inode that is not in the seal map → `file_open` fires on the upper, not the sealed lower → outsider ALLOW. Wider: ANY writer can trigger the copy-up itself (the bypass is pre-modification). overlayfs also presents anon_bdev s_dev to userspace so the seal-load gate would miss the lower inode if it were on a merged mount. Requires CAP_SYS_ADMIN to mount the overlay. | Keep sealed files outside overlay mount targets (don't seal anything visible through `lowerdir`/`upperdir`); CAP_SYS_ADMIN is the defensive boundary against operator-attacker mounts. Loader refuses overlayfs paths at `seal_path()` / `actor_resolve_paths()` (fail-closed). |
| **Privileged-tenant strict-launch marker forgery** (A2-P2-1 / A4-P2-1, hardening Tier-2, 2026-05-16) | A user with `CAP_BPF` can update a TASK_STORAGE map entry directly via `bpf(BPF_MAP_UPDATE_ELEM)`, forging a strict-launch marker (`actor_marker_map`) for an arbitrary task. The marker drives the in-kernel actor-identity check on sealed-launcher exec, so a forged marker grants a process the actor identity its `current->mm->exe_file` does not earn. TASK_STORAGE is not freezable at the kernel API level (per-task allocation); we cannot lock the map post-load the way we freeze `sealed_inodes`. | Treat the `CAP_BPF` exclusion in the row above as the load-bearing control. The link-removal row above already excludes `CAP_BPF` from daemons; the same `AmbientCapabilities=` / `CapabilityBoundingSet=` removal closes this surface. SIEM that monitors `marker_set_total` for out-of-band growth without a matching `bprm_committed_creds` exec event is the visibility companion (and `marker_set_fail_total`, new in v0.8, separates allocation pressure from an attack on the chain). |
| **io_uring write transitive coverage** (A1-P2-2, hardening Tier-2, 2026-05-16) | `io_uring` write submissions are blocked transitively via the MAY_WRITE path (no `io_uring`-specific LSM hook is installed). Correctness depends on the kernel routing every write-intent through `security_file_permission(MAY_WRITE)`, which today is true for all `IORING_OP_WRITE*` submissions (kernel ≥ 5.6 wires the LSM check into the prep/issue path) and for the buffered/registered-buffer variants. A future kernel change that bypasses `security_file_permission` for a new io_uring op would silently re-open the surface. | Track upstream `io_uring` LSM coverage changes alongside the v0 release; a visibility witness that exercises a write through io_uring against a sealed file and asserts a deny is still to be written — the BX-17 slot named in earlier drafts is now taken by `BX-17-strict-launcher-runtime.sh`, so it needs a free number. |
| **VFS write-class transitive coverage** (B-1, corrected v0.8) | `copy_file_range(2)`, `FICLONERANGE`, `FIDEDUPERANGE` and `splice(2)` write into a destination inode without a dedicated LSM hook, but they **do** route through `security_file_permission(MAY_WRITE)` — `copy_file_range` and `splice` via `rw_verify_area(WRITE, …)`, the two remap ioctls via the explicit `security_file_permission()` call in `fs/remap_range.c` — so a `no-write` seal on the destination denies them transitively. **`fallocate(2)` was listed here as an exception, and that was wrong — measured, on both shipped kernels.** `tests/limitations-witness.sh` L2-L4 drives `fallocate(FALLOC_FL_PUNCH_HOLE)` through a descriptor opened *before* the daemon starts: the punch succeeds with no policy loaded, is refused with `EACCES` and a `DENY_WRITE` audit line once the seal is live, and still succeeds on an unsealed sibling in the same run. Reproduced on 6.8.0-139 and 7.0.0-31, on tmpfs and on ext4. So `fallocate` is covered transitively like the rest of this row. The witness fails loudly if that ever stops being true, and its message says to restore this text and name the kernels it applies to. | Load policy **before** the protected services start, so no writable fd predates the seal (the same advice this file gives for mmap). Do not hand writable fds to untrusted processes. v1.x candidate: `lsm/file_receive` closes the `SCM_RIGHTS` / `pidfd_getfd` half — it is `comp_file_open`'s body on a different hook, identical on 6.8 and 7.0 — but it changes fd-passing semantics for every sealed file and needs its own survey of the shipped profiles first. |
| **fanotify / inotify listener interaction** (A1-P2-3, hardening Tier-2, 2026-05-16) | `fanotify` and `inotify` listeners only observe filesystem events; they cannot trigger a write on behalf of a watcher actor. No bypass class. Listed explicitly so a reviewer does not infer a missing hook from the absence of dedicated `fanotify_*` / `inotify_*` LSM coverage. No dedicated hook is installed. | None required — surface is observation-only at the kernel API level. |
| **32-bit (compat) ioctl callers** (closed v0.8) | `file_ioctl` gates `FS_IOC_SETFLAGS` / `FS_IOC32_SETFLAGS` / `FS_IOC_FSSETXATTR` / `FS_IOC_SETVERSION` (`chattr +i/+a`, project ids) on `no-chmod` seals; these mutate inode metadata through `->fileattr_set` with no `inode_setattr` or xattr hook, so through v0.7 nothing saw them. A **32-bit process on a 64-bit kernel never reaches that hook**: `fs/ioctl.c` `COMPAT_SYSCALL_DEFINE3(ioctl)` calls `security_file_ioctl_compat()` and the native `SYSCALL_DEFINE3` calls `security_file_ioctl()`, and the compat switch handles `FS_IOC32_SETFLAGS` itself. v0.8 therefore ships a second program on `lsm/file_ioctl_compat` sharing the same body. Because the hook was backported into stable 6.6.y, a kernel-version test is unreliable — the loader BTF-probes `bpf_lsm_file_ioctl_compat` and autoload-gates the program, printing which way it decided. On a kernel that genuinely lacks the hook, compat callers hit `file_ioctl` with the `FS_IOC32_*` encodings, which are covered. Residual: neither program sees `FS_IOC_SETFSLABEL`, the fscrypt policy ioctls, or `FS_IOC_ENABLE_VERITY` — those are outside the seal model. Witnesses: `tests/bypass/18-chattr-no-chmod.sh` W1/W2 (native) and W3 (`gcc -m32`, skipped in-line when multilib is absent). | None needed on a hooked kernel. Kernels ≥ 6.17 additionally offer `inode_file_setattr`, a single chokepoint for both entry points; that is the v1.x replacement for the ioctl cmd table. |
| **Strict-launch marker vs. failed exec** (closed v0.8) | Through v0.7 the marker was written in `bprm_check_security`, which `search_binary_handler()` calls immediately before `fmt->load_binary()`. Every failure inside `load_elf_binary()` **before** `begin_new_exec()` returns `-errno` to the caller's ORIGINAL image, which keeps running its old code holding whatever the check hook wrote. The most usable of those failures is `open_exec(elf_interpreter)` → `-ENOENT`: shadowing the path in the launcher's `PT_INTERP` inside a mount namespace forces it deterministically, with no race. (`load_elf_phdrs()` `-ENOMEM`, the `-ELIBBAD` PT_INTERP checks and the `-ENOEXEC` binfmt retry loop are the others.) A task already running the actor target under `LD_PRELOAD` (exe == target, no marker) could therefore `execve()` the sealed launcher, force such a failure, and acquire a valid marker whose target matched its exe — satisfying every strict-launch condition without ever having run the launcher. Failures *inside* `begin_new_exec()` and later — `de_thread()`, `unshare_files()`/`dup_fd()`, `exec_mmap()` — are past `bprm->point_of_no_return` and `bprm_execve()` converts them to a fatal `SIGSEGV`, so they never returned a marker to anyone and were **not** the window. v0.8 moves marker set/keep/clear to `bprm_committed_creds` (attached sleepable, `lsm.s/`, so the task-storage allocation blocks), which runs only once the new image is installed; an unresolvable exec target drops any existing marker. No residual is known. | Upgrade to v0.8: `--unpin` (the loader still sweeps the legacy `comp_bprm_check_security` pin) then `--pin`. Any exec-*deny* policy added later (exec ACL) still belongs at `bprm_check_security`; only marker *mutation* moved. Watch `marker_set_fail_total` — nonzero means a committed launcher exec could not allocate its marker and the actor will fail closed. |
| **ACL and xattr writes under `no-chmod`** (coverage note, v0.8) | `no-chmod` denies `setxattr(2)`/`removexattr(2)` (`inode_setxattr` / `inode_removexattr`) and, from v0.8, POSIX ACL writes (`inode_set_acl` / `inode_remove_acl`), which since Linux 6.2 are routed by `do_setxattr()` to `vfs_set_acl()`/`vfs_remove_acl()` and never reach the xattr hooks. What is **not** hooked: `inode_get_acl` and the xattr *read* paths (read-only, out of the model), and the `inode_post_setxattr`-class notification hooks on ≥ 6.9 (not needed for a deny model). Security xattrs written by the kernel itself (`security.*` on a `no-chmod` seal, e.g. an SELinux relabel) are denied like any other xattr write — that is intended, but it means relabelling a sealed tree requires unpinning first. Witness: `tests/bypass/16-setfacl-no-chmod.sh`. | None. If a management tool must relabel or re-ACL a sealed path, add it to that seal's `actor=` list or unpin, change, re-pin. |
| **Timestamp writes are `no-chmod`-class from v0.8** (behaviour change) | `inode_setattr` classifies `ATTR_ATIME\|ATTR_MTIME` without `ATTR_SIZE` as chmod-class on a **directly sealed** inode. `vfs_utimes()` sets `ATTR_CTIME\|ATTR_MTIME\|ATTR_ATIME` (plus `ATTR_TOUCH` for `UTIME_NOW`, or `ATTR_*_SET`+`ATTR_TIMES_SET` for explicit times) and never `ATTR_SIZE`, so `touch`, `touch -d`, `touch -a` and `utimensat(2)` are all covered; ordinary writes update mtime through `file_update_time()`, which bypasses `notify_change()` entirely and is unaffected. **This changes the meaning of every pre-v0.8 `no-chmod` seal in the field:** `cp -p`, `rsync -a`, `tar -x`, `install -p`, `unzip` and any `touch`-based liveness sentinel now get `EACCES` on a directly sealed file. Truncation stays write-class (`ATTR_SIZE` is excluded), so a `no-chmod`-only seal still permits `truncate` — regression-guarded by `tests/bypass/19` R, and the `cp -p` over-deny guard is `tests/bypass/19` G. | Add the legitimate writer to that seal's `actor=` list. v1.x candidate: a dedicated `no-times` flag on the free, explicitly reserved SEAL bit 4, so operators opt in rather than inheriting the reclassification. |
| **Pre-existing writable file descriptors** (upstream gap) | A seal keys on `(dev, ino)` and is enforced at operation time, so an fd opened for writing **before** policy load is still gated for ordinary `write`/`pwrite`/`writev` — those reach `security_file_permission(MAY_WRITE)` and `comp_file_permission` resolves the caller from `current->mm->exe_file`, so a non-actor is denied even through a handed-over fd (`tests/bypass/05-old-fd-write.sh`, `06-splice-old-fd.sh`). `fallocate(2)` was documented here as the exception; it is not. `FALLOC_FL_PUNCH_HOLE` through a pre-seal writable fd is refused with `EACCES` and audited on both shipped kernels — see the VFS write-class row above for the measurement and the witness. | Load policy before the protected services start. Do not pass writable fds to untrusted processes. `lsm/file_receive` (v1.x candidate) would close the `SCM_RIGHTS` / `pidfd_getfd` handover half at open time; the operation-time coverage above already applies to a handed-over descriptor, because `comp_file_permission` resolves the caller from `current->mm->exe_file` rather than from who opened the fd. |
| **`mount_setattr(2)` / `open_tree_attr(2)` are unhooked upstream** (v0.8 note) | `do_mount_setattr()` — reached by `mount_setattr(2)` on 6.8+ and additionally by `open_tree_attr(2)` on 7.0 — contains **no `security_*` call whatsoever**, so `MOUNT_ATTR_RDONLY` can be cleared and `MOUNT_ATTR_IDMAP` applied on a mount hosting sealed inodes with no LSM visibility. This is **not** a seal bypass: compartment keys on `(dev, ino)`, which is idmap-independent, and its denies are LSM-layer and fire regardless of the superblock's or mount's read-only state. It is listed because it is an unhooked mount-mutation primitive that belongs in the threat model. Related and also not a gap: `mount -o remount,rw` on a filesystem holding seals defeats nothing, for the same reason — which is why `sb_remount` is deliberately **not** attached (unlike `sb_umount`, which v0.8 does attach, because detaching the filesystem really does break the path guarantee). | None available — there is nothing to hook. Drop `CAP_SYS_ADMIN` from daemons. Track upstream for an LSM hook on the mount-attribute path. |

## How to use this list

When you deploy a profile with `actor=NAME` clauses, walk this list
row by row against your environment and document which companion
control closes each row. A deployment without LD_PRELOAD scrub +
ptrace_scope + lockdown is a deployment that has actor-allowlist
but is missing the layers that make it load-bearing against a
motivated attacker.

The SPEC's §5.1 (in-scope) lists the threats compartment-bpf v0.3
**does** address (root-with-different-binary, root-replaces-actor,
mount-namespace-tricks against the actor path). Read both sections
together — neither stands alone.

## G11 combined-mode overhead unmeasured (M-6)

G11 benchmarks were conducted with the enforcement-only BPF program
(`compartment.bpf.c`) loaded. When both enforcement and observe programs are
loaded simultaneously, the `lsm/file_open` hook fires twice per file open —
once for enforcement and once for observation. The combined-mode overhead is
unmeasured. In practice, the observe program is intended for short profiling
sessions rather than steady-state co-load; operators running both simultaneously
should benchmark their specific workload.

## Post-seal directory recreation (M-21)

If an actor can delete and recreate a sealed directory, the replacement
directory has a new inode number and is **not sealed**. The original seal in
`sealed_dirs` references the old inode number (dev, ino); after recreation,
operations on the new directory are not protected.

This is a policy and threat-model issue, not a code bug. Preventing it
requires:
1. A `no-unlink` seal on the **parent** directory (grandparent protection) to
   block the `rmdir` of the sealed directory itself.
2. A `no-rename` seal on the parent directory to block rename-in of a
   replacement directory.

Deploy grandparent protection for any directory whose continued sealed identity
is security-load-bearing.

## Inode-reuse stale-seal window in `--pin` daemonless mode (P1-1)

Seals are keyed by `(dev, ino)`. A `no-write` seal still permits `unlink`
(`no-write` != `no-unlink`), so a sealed file can be removed, its inode freed,
and that inode number **reused** by an unrelated new file — which then inherits
the stale `(dev, ino)` seal and receives a spurious deny. This is
fail-**CLOSED** (an unexpected DENY on the new file, never a bypass), but it is
a real correctness defect, reproduced on kernels whose inode allocator recycles
immediately (e.g. Noble 6.8).

The daemon mitigates this by holding one `O_PATH` fd per sealed inode for its
**whole lifetime**, which pins each inode struct so the kernel cannot reuse its
number. **This closes the window ONLY in daemon-resident mode.** In `--pin`
persistent (daemonless) mode the pinned enforcement survives process exit while
the held fds die with the process, so the reuse window **re-opens** for a
pinned-but-daemonless tree — the exact persistence mode the README describes.

* **Mitigation today (policy):** pair `no-write` with `no-unlink` on any file
  that must not be replaced. With `no-unlink` the sealed inode can never be
  freed, so its number can never be recycled and the window is inert by policy.
* **Follow-up (tracked):** nlink-aware seal eviction when an inode is actually
  freed. The eviction **must** be nlink-aware — dropping a seal while a
  hardlink to the inode still exists would be fail-**OPEN**. It is deferred
  precisely because a naive implementation trades a fail-closed defect for a
  fail-open one.

## Filesystem `umount` / `remount,ro` returns EBUSY while the daemon runs (P1-2)

Because the daemon holds an `O_PATH` fd per sealed inode (see the inode-reuse
row above), each held fd pins its filesystem. Any filesystem containing seals
therefore returns **EBUSY** on `umount` or `mount -o remount,ro` while the
daemon is alive.

This is **security-positive**: it blocks a remount/umount-to-bypass vector
(an attacker cannot detach or downgrade the fs out from under live enforcement)
and it interacts with the `bind-mount-OVER sealed path` and
`mount-inside-sealed-subtree` rows above. It is documented here so an operator
performing routine maintenance (LVM snapshot, volume detach, `remount,ro` for
`fsck`) understands the otherwise-opaque EBUSY.

* **Caveat — do not oversell:** `umount -l` (lazy) still detaches the
  namespace view; the superblock stays pinned but the mountpoint disappears
  from the namespace, so this does **not** absolutely "block umount."
* **Operator action:** run `compartment-bpf --unpin` before unmounting,
  remounting-ro, or otherwise relocating any filesystem that holds seals.

---

## Pointers

- `README.md` Limitations section — high-level v0 / v0.3 capability
  surface and threat-model rationale.
- Future signed-policy design notes — cryptographic policy signing,
  sealed-agent mode, and future exec-trust seal work not yet shipped.
