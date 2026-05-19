# compartment-bpf — operator-facing limitations

This file lists threats that compartment-bpf v0.4 (seal-path engine
+ exec-domain actor allowlist + strict-launch-marker) does **not**
address on its own. The authoritative threat-model section lives in
`experimental/EXEC-DOMAIN-SPEC.md` §5.2; this document is the
operator-facing summary intended to be read alongside the README's
Limitations section before deploying actor-bound profiles in
production.

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
behavior — neither v0.4 nor the current v0.5 release provides a
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
| **CAP_BPF + direct map mutation**            | A privileged user can `bpftool map update` against `sealed_inodes` / `sealed_dirs` and weaken or wipe seals. The v0 model assumes a trusted load phase.                  | Future signed-policy / `bpf_gate` work; `bpf_map_freeze` after load (already enforced in v0.3 loader).     |
| **Privileged BPF link detach** (`bpf(BPF_LINK_DETACH)` / bpffs link unlink) | A privileged user with `CAP_BPF` can detach the compartment-bpf LSM links at runtime via the `bpf(BPF_LINK_DETACH)` UAPI or by `unlink()`ing the bpffs link pin, removing every hook from the kernel chain in one syscall. This is distinct from `bpftool map update` (which weakens individual seals): a successful detach removes enforcement entirely until the next `--pin`, leaving the system fail-OPEN. | Restrict `CAP_BPF` to the loader and operator accounts (drop from all daemons via systemd `AmbientCapabilities=` / `CapabilityBoundingSet=`); ingest `audit_event` ringbuf into a SIEM that alerts on enforcement-stop; future signed-policy / `bpf_gate` work is the kernel-layer closure. |
| **Out-of-band kernel writes**                | Direct `kmem` writes, kprobe overwrites, or kernel-module loads can disable the LSM hook chain entirely.                                                                | Kernel `lockdown=integrity` or `lockdown=confidentiality` (kernel cmdline); `kernel.modules_disabled=1`; Secure Boot. |
| **Offline tampering of the actor binary**    | If the attacker boots from rescue media and edits `/usr/sbin/aide` on the unmounted disk, E-6 cannot fire — enforcement is only active at runtime.                       | LUKS full-disk encryption; signed kernel modules; IMA/EVM file signatures; locked-down boot firmware.              |
| **Exec via interpreter chain** (NOT a bypass) | Actor exec's `python /tmp/evil.py` → `current->mm->exe_file` becomes `python`. File access is then correctly denied because python is not in `actor aide`. This is the intended behavior, listed here so readers don't mistake it for a bypass. | None needed — this is intended fail-closed semantics.                                                              |
| **Unprivileged hardlink to canonical actor binary** (R2-F10) | Without `fs.protected_hardlinks=1`, any unprivileged user on the box can `ln /usr/sbin/aide /tmp/myactor; /tmp/myactor` and have `current->mm->exe_file` resolve to the same (dev, ino) as the canonical actor binary — inheriting actor identity. No CAP_BPF needed; no root needed. v0.x R2-F11 closes the surface at the LSM layer via `comp_inode_link`'s source-inode SEAL_NO_WRITE check, and the loader emits a startup `[loader] WARNING` line when `fs.protected_hardlinks=0` is detected. Operator-side defense remains required. | Kernel sysctl `fs.protected_hardlinks=1` (the v0 BX-10 witness probes both states; the LSM-layer check + sysctl together bracket the class). |
| **PR_SET_MM_EXE_FILE actor-identity swap** (R2-M18) | A process with `CAP_SYS_RESOURCE` can call `prctl(PR_SET_MM_EXE_FILE, fd)` to point its `current->mm->exe_file` at a different file inode. Compartment-bpf reads `current->mm->exe_file` for actor identity; a CAP_SYS_RESOURCE-equipped process could swap to an actor's inode and inherit identity without exec'ing the actor binary. CAP_SYS_RESOURCE is normally constrained to root/system contexts (it gates `setrlimit` overrides too), but containers or daemons that retain it are an exposed surface. | Drop CAP_SYS_RESOURCE in the bounding set of any process that does not need it; capability-bound the actor binary itself; sealed-agent mode (v1.5) will additionally restrict the loader's own caps after attach. |
| **Dual-channel audit drops** (R2-M26) | The kernel-side audit ringbuf has finite capacity (16 MiB default; the V-4b counter `audit_drop_total` records reservation failures). The ED-11 userspace-side audit emits go through stderr + syslog `LOG_AUTHPRIV`. A SIEM that monitors only one of {ringbuf, syslog, stderr} will miss events on the other channels. Cross-channel correlation is required for complete coverage. | Configure log shippers to ingest BOTH `auth.log` (syslog `LOG_AUTHPRIV`) AND the daemon's systemd-journal output AND `bpftool prog show` ringbuf via the V-4b reader. Alert on `audit_drop_total > 0` (any ringbuf drops). |
| **Recursive subtree ancestor-walk depth cap** (v0.6+, default `COMPARTMENT_MAX_DIR_ANCESTORS=8`) | The BPF ancestor walk is an unrolled loop bounded at compile time. Each increment adds ~300 B of xlated code per hook; 64 levels caused ~2.5 s BPF load time on Resolute 7.0 (21 KB xlated per hook). The default cap is **8** levels, but custom deployments may rebuild with a larger value. To avoid a silent runtime bypass, the loader now **refuses recursive directory seals** when the live subtree already exceeds the compiled budget: any descendant directory at depth `>= cap`, or any non-directory descendant deeper than `cap`, aborts attach. After attach, the kernel denies `mkdir`, symlink/hardlink creation, non-directory rename-import, and directory rename operations that would violate the compiled recursive-subtree invariants. In particular, directory imports from outside the covering sealed subtree, and same-seal directory deepening renames, fail closed because the BPF hook cannot prove descendant depth portably in-hook across filesystems. | Keep sealed subtrees within the compiled depth budget, split deep layouts into intermediate `seal` rules, or rebuild with a larger `COMPARTMENT_MAX_DIR_ANCESTORS` (for example `make COMPARTMENT_MAX_DIR_ANCESTORS=32`). If an actor must reorganize a large subtree, move files directly or stage changes outside the sealed tree before attach; deepening/importing directories under a live recursive seal is intentionally conservative. v1.x scope: bounded-loop improvements upstream may make larger caps cheaper without linear verifier/load-time cost. |
| **Loader depth-check to attach race window** (v0.7, P2-9) | `validate_recursive_dir_seal` (the `nftw` callback in `compartment-bpf.c`) walks the sealed subtree and rejects descendants past `COMPARTMENT_MAX_DIR_ANCESTORS` before the BPF programs are attached. A concurrent writer with `mkdir`/`rename` access to the subtree could grow the tree past the cap during the validation→attach window before enforcement goes live, then the runtime walk would silently truncate at the cap (the kernel-side loop has no way to know it didn't reach the seal). The window itself is not closed; commit `b265aef` (runtime recursive subtree growth guard) only closes the **post-attach** widening path via `mkdir`/`rename` denies. | Treat the validation→attach window as a narrow race; serialize policy load with quiescent subtree state in operational workflows (e.g. mount target dir read-only during load, or fence privileged writers under `--pin` for the millisecond-scale window). `bpf_map_freeze` after attach does not help (the race is on the FS, not the map). v1.x scope: pin the subtree shape into a hash-keyed map at validation time and gate runtime denies on a subtree-version mismatch. |
| **Mount-inside-sealed-subtree bypass** (v0.6) | After policy load, a process with `CAP_SYS_ADMIN` may mount a filesystem whose mountpoint is inside a sealed subtree. The BPF ancestor walk (`d_parent`) is bounded to a single superblock; writes to the nested mount follow the nested FS's dentry tree and never encounter the sealed parent inode. The loader's `nftw(..., FTW_MOUNT)` prevents descending into *existing* nested mounts during validation, but does not guard against mounts created after policy load. | Use an `sb_mount`/`path_mount` deny policy at the OS level (e.g. mount namespaces, seccomp) to prevent new mounts inside sealed trees. A future release may add an LSM `sb_mount` hook. |
| **In-place writes to files under a sealed directory** (R2-F5, updated v0.5) | **ABI v0.4 and earlier:** a directory seal blocks structural mutations (create/unlink/rename/link/mkdir/etc.) but does NOT block in-place writes to existing files inside the dir. **ABI v0.5 (dir-destination):** `ACTION_DENY_WRITE_PARENT_DIR` (action=9) additionally blocks writes, truncates, and write-mode opens of **immediate children** of a DD-sealed directory. Files at deeper levels (grandchildren and below) are NOT covered by the parent-dir seal — they are only blocked by their own direct inode seal. Concrete impact for `profiles/postgres.conf` with a v0.5 no-write DD seal on the data dir: direct heap files (`base/<oid>/<n>`) and WAL segments (`pg_wal/<seg>`) in the sealed dir root ARE write-denied for non-actors; files nested in subdirectories (e.g. `base/<oid>/`) are not. | v0.5: use `seal DIR no-write actor=NAME` for immediate-child write protection. Add per-file seals for any specific nested file that must freeze (e.g. PG_VERSION). v1.x scope: recursive-subtree-seal — single declaration covers every file under a subtree. |
| **btrfs / FUSE seal enforcement failure** | compartment-bpf v0 does NOT enforce seals on btrfs or FUSE filesystems. The BPF hook reads `inode->i_sb->s_dev` (real subvolume / FUSE-internal block dev) while userspace `stat` returns the anon_bdev — map lookup misses silently and every outsider write through a sealed btrfs/FUSE path receives ALLOW. **Bi-directional**: actor binaries on these filesystems also break (caller-id resolution sees real s_dev; userspace resolved anon_bdev → no match → silent DENY). v1 fix is BPF-side; v0 fix is the loader refuse below. | Keep all sealed paths and actor binaries on ext4 / xfs / tmpfs. Loader refuses btrfs and FUSE paths at `seal_path()` and `actor_resolve_paths()` via `anon_bdev_refuse()` (fail-closed). |
| **overlayfs copy-up bypass** | A write through an overlay merged path triggers copy-up → kernel opens a NEW upper inode that is not in the seal map → `file_open` fires on the upper, not the sealed lower → outsider ALLOW. Wider: ANY writer can trigger the copy-up itself (the bypass is pre-modification). overlayfs also presents anon_bdev s_dev to userspace so the seal-load gate would miss the lower inode if it were on a merged mount. Requires CAP_SYS_ADMIN to mount the overlay. | Keep sealed files outside overlay mount targets (don't seal anything visible through `lowerdir`/`upperdir`); CAP_SYS_ADMIN is the defensive boundary against operator-attacker mounts. Loader refuses overlayfs paths at `seal_path()` / `actor_resolve_paths()` (fail-closed). |
| **bind-mount-OVER sealed path** | `mount --bind /unsealed /sealed` of an unsealed source over a sealed-path destination redirects path lookups to the unsealed inode for any process that crosses the bind — seal bypassed without modifying the sealed inode itself. The sibling primitives `move_mount(2)` and `mount(MS_MOVE)` produce the same effect: an existing mount can be re-rooted on top of a sealed path with the same CAP_SYS_ADMIN gate. CAP_SYS_ADMIN required. The mesh §3.23 row witnesses the class on the existing host. | Drop CAP_SYS_ADMIN from actor; `systemd MountFlags=private` so each unit gets a private mount namespace; mount-namespace-private profiles on systemd ≥ v247. |
| **Privileged-tenant strict-launch marker forgery** (A2-P2-1 / A4-P2-1, hardening Tier-2, 2026-05-16) | A user with `CAP_BPF` can update a TASK_STORAGE map entry directly via `bpf(BPF_MAP_UPDATE_ELEM)`, forging a strict-launch marker (`actor_marker_map`) for an arbitrary task. The marker drives the in-kernel actor-identity check on sealed-launcher exec, so a forged marker grants a process the actor identity its `current->mm->exe_file` does not earn. TASK_STORAGE is not freezable at the kernel API level (per-task allocation); we cannot lock the map post-load the way we freeze `sealed_inodes`. | Treat the `CAP_BPF` exclusion in the row above as the load-bearing control. The `bpf(BPF_LINK_DETACH)` row (LSM-detach class) already excludes `CAP_BPF` from daemons; the same `AmbientCapabilities=` / `CapabilityBoundingSet=` removal closes this surface. SIEM that monitors `marker_set_total` for out-of-band growth without a matching `bprm_check_security` exec event is the visibility companion. |
| **io_uring write transitive coverage** (A1-P2-2, hardening Tier-2, 2026-05-16) | `io_uring` write submissions are blocked transitively via the MAY_WRITE path (no `io_uring`-specific LSM hook is installed). Correctness depends on the kernel routing every write-intent through `security_file_permission(MAY_WRITE)`, which today is true for all `IORING_OP_WRITE*` submissions (kernel ≥ 5.6 wires the LSM check into the prep/issue path) and for the buffered/registered-buffer variants. A future kernel change that bypasses `security_file_permission` for a new io_uring op would silently re-open the surface. | Track upstream `io_uring` LSM coverage changes alongside the v0 release; the recommended visibility witness `tests/bypass/exec-domain/BX-17-io-uring-write.sh` (planned) exercises a write through io_uring against a sealed file and asserts a deny. |
| **VFS write-class transitive coverage** (B-1, hardening Tier-2, 2026-05-16) | `copy_file_range(2)`, `FICLONERANGE`, `FIDEDUPERANGE`, `fallocate(FALLOC_FL_PUNCH_HOLE)`, and `splice(2)` write into a destination inode without a dedicated LSM hook. They route through `security_file_permission(MAY_WRITE)` in the kernel VFS, so a no-write seal on the destination denies them transitively. No dedicated bypass-class witness yet; planned `tests/bypass/exec-domain/BX-17-vfs-write-class.sh` exercises one operation per primitive against a sealed file and asserts a deny per row. | The seal flag set is correct as documented; this row exists so a reviewer does not infer missing coverage from the absence of `copy_file_range_*` hooks. |
| **fanotify / inotify listener interaction** (A1-P2-3, hardening Tier-2, 2026-05-16) | `fanotify` and `inotify` listeners only observe filesystem events; they cannot trigger a write on behalf of a watcher actor. No bypass class. Listed explicitly so a reviewer does not infer a missing hook from the absence of dedicated `fanotify_*` / `inotify_*` LSM coverage. No dedicated hook is installed. | None required — surface is observation-only at the kernel API level. |

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

---

## Pointers

- `experimental/EXEC-DOMAIN-SPEC.md` §5 — full threat model with
  rationale per row.
- `README.md` Limitations section — high-level v0 / v0.3 capability
  surface.
- Future signed-policy design notes — cryptographic policy signing,
  sealed-agent mode, and future exec-trust seal work not yet shipped.
