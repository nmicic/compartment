# compartment-bpf — kernel-side path sealing via BPF LSM

compartment-bpf is a BPF LSM tool that seals file-system paths so that even
root cannot unlink, rename, write, or chmod the sealed inodes. Decisions are
made in-kernel from in-kernel data — no userspace daemon needs to stay alive
for enforcement.

> **Scope note on daemonless mode.** In `--pin` (persistent, daemonless) mode
> the inode-reuse stale-seal window re-opens: the daemon's inode-pinning
> `O_PATH` fds die when the loader process exits while pinned enforcement
> lives on. This is fail-closed (a spurious deny, never a bypass) and is made
> inert by pairing `no-write` with `no-unlink`. See `LIMITATIONS.md`.

This is part of the [Compartment](https://github.com/compartment) toolkit;
it complements `compartment-user` (Landlock + seccomp) and `compartment-root`
(namespace containers) with kernel-side inode-level enforcement.

> **Honesty note.** This is a personal project, not a commercially validated
> security product. The enforcement model has well-defined limits (see
> `LIMITATIONS.md`). The test pyramid is substantial (see below), but real
> deployments carry operational risk — read LIMITATIONS.md before using this
> on anything that matters.

**Getting started:** see [ON-RAMP.md](ON-RAMP.md) for path A/B/C selection
(KVM VM, cloud instance, or local host).

---

## What it does

Loads a `.conf` profile listing paths to *seal*, resolves each path to a
`(dev, ino)` key, populates BPF maps, then attaches BPF LSM hooks. The kernel
enforces the seal on every matching operation regardless of uid or capability.

| Hook | Denies |
|------|--------|
| `inode_unlink` | unlink of sealed file or child of sealed dir |
| `inode_rename` | rename of sealed file/dir, rename-over, or rename into sealed dir |
| `inode_create` / `link` / `mkdir` / `mknod` / `symlink` / `rmdir` | create inside sealed dir |
| `file_open` / `file_permission` / `file_truncate` | write-open, write through old FD, truncation |
| `mmap_file` / `file_mprotect` | new shared-writable mapping of sealed file |
| `inode_setattr` / xattr hooks / `inode_set_acl` / `inode_remove_acl` / `file_ioctl` (+ `file_ioctl_compat`) | size / mode / owner / timestamp / xattr / POSIX-ACL / inode-flag (`chattr`) changes, native and 32-bit callers |
| `sb_mount` / `move_mount` | new mount on a sealed inode or inside a sealed subtree (path shadowing) |
| `sb_umount` | detaching a filesystem that hosts sealed inodes (`umount`, `umount -l`; `move_mount(2)` is gated by `move_mount`'s from-side) |
| `bprm_committed_creds` / `task_alloc` / `task_prctl` / `ptrace_*` | actor-strict marker lifecycle and identity-swap hardening |
| `bpf_map` (opt-in, `--pin --self-protect` only) | any fd — read-only included — to this tool's own BPF maps, for a task that is not an authorised loader image. The same flag adds a pin-tamper branch to `inode_unlink` / `inode_rename` / `inode_rmdir` / `sb_mount` / `move_mount` covering its own bpffs pins, and makes `sb_umount` refuse to detach the bpffs holding them (under the existing `DENY_UMOUNT`); those are existing hooks, not new links. See `HOWTO.md` §3.6. |

Seal flags: `no-unlink`, `no-rename`, `no-write`, `no-chmod` (or `full` for all four).

---

## Key properties

- **Inode-based, not path-based.** Sealed by `(dev, ino)`. Hard links to a
  sealed inode inherit the seal; bind-mount aliases of a sealed path share
  its dentries and stay enforced; and since v0.8 no new mount can be placed
  on or under a sealed path at all (`sb_mount` / `move_mount`).

- **Recursive directory seals.** A `DIR full` or `DIR no-write` seal on a
  directory applies to all descendants — the BPF hooks walk ancestor dentries
  at enforcement time (bounded to `COMPARTMENT_MAX_DIR_ANCESTORS = 8`).

- **Actor allowlist.** `seal <path> no-write actor=NAME` restricts writes to
  that path to processes launched through a declared actor binary. The
  `actor-strict` mode enforces that the process carries a valid launch marker,
  defeating LD_PRELOAD and binary-swap attacks against actor identity.

- **Observe pipeline.** `compartment-bpf observe` records the inode access
  pattern of a running process and emits a candidate profile. Candidate
  profiles cannot be pinned to enforcement without explicit promotion
  (`--allow-candidate`).

- **Fail-closed lifecycle.** `--pin` persists BPF links to bpffs; the loader
  rejects a new `--pin` if stale pins exist. Maps are frozen after policy load
  (`bpf_map_freeze`), which closes the `bpf(BPF_MAP_UPDATE_ELEM)` **syscall**
  path against a caller that reaches a pin. **Freeze is not map integrity.** It
  does not gate the program path: a caller holding `CAP_BPF` that obtains any fd
  to a frozen map — `BPF_F_RDONLY` is enough — can splice it into a BPF program
  of its own and write the map from program context (measured on 6.8.0-139 and
  7.0.0-31). So a `CAP_BPF` holder can still wipe the seal maps, or `unlink()`
  the link pins, and disable enforcement. The mitigation is to keep `CAP_BPF`
  off every workload and every root login (see the
  `CAP_BPF + direct map mutation` and `Privileged removal of the LSM links`
  rows in [LIMITATIONS.md](LIMITATIONS.md)).

---

## Requirements

- Linux kernel ≥ 6.6 with `CONFIG_BPF_LSM=y` and `bpf` in the active LSM list.
  Check with:
  ```sh
  cat /sys/kernel/security/lsm   # must include "bpf"
  zgrep BPF_LSM /proc/config.gz  # CONFIG_BPF_LSM=y
  ```
  Tested on Ubuntu 24.04 LTS (kernel `6.8.0-139-generic`) and Ubuntu 26.04
  LTS (kernel `7.0.0-31-generic`).

- Toolchain: `clang` ≥ 12, `libbpf-dev`, `bpftool`, `libsodium-dev`.
  `make check-env` verifies presence.

- BTF at `/sys/kernel/btf/vmlinux` (default on most distros).

---

## Build

```sh
make vmlinux.h        # one-time — generates from running kernel BTF
make
sudo make smoke       # quick enforcement check
sudo make check       # full unit test suite
sudo make check-release  # the release gate: check, plus no unexplained SKIP
```

`tests/docs/RUNNING.md` documents every suite individually, with the
tally each one prints on a healthy guest; `ON-RAMP.md` covers getting a
guest that can run them.

Produces `compartment-bpf` (loader + daemon) and `compartment-bpf-observe`
(observe pipeline).

---

## Quick demo

```sh
sudo mkdir -p /var/lib/oracle
sudo dd if=/dev/urandom of=/var/lib/oracle/data bs=1M count=1
sudo ./compartment-bpf oracle.conf &

# as root:
sudo rm /var/lib/oracle/data
# rm: cannot remove '/var/lib/oracle/data': Permission denied

# audit trail on daemon stderr:
# [audit] DENY_UNLINK pid=... uid=0 comm=rm ino=...
```

See `oracle.conf` for the example profile. See `HOWTO.md` for the full
operator walkthrough including actor seals, observe, and `--pin` lifecycle.

---

## Profile format

```
# Seal a single file
seal /var/lib/oracle/data    full

# Seal a directory and all descendants (recursive in v0.6+)
seal /etc                    no-write

# Restrict writes to a specific actor binary
seal /var/lib/postgres/data  no-write  actor=postgres
```

`<path>` must be absolute. The loader opens paths with `O_PATH | O_NOFOLLOW`,
fstats, then maps `(dev, ino) → flags`. Symlink leaves are rejected. See
`HOWTO.md` §3 for the full syntax reference.

---

## Test pyramid

| Suite | Coverage |
|-------|----------|
| `make check` | loader negative-path, multi-actor, error-path, regression (24+ checks) |
| `tests/bypass/run-all.sh` | 44 bypass scenarios (25 seal-class + 19 exec-domain; kernel hook coverage per flag class) |
| `tests/strict-launch/run.sh` | 17 strict-launch-marker witnesses |
| `tests/observe/run.sh` | 22 observe pipeline witnesses; 21 pass and 1 skips where AIDE is not installed |
| `tests/mesh/run-mesh.sh` | 3284 (actor × operation × flag) enforcement matrix trials |
| `tests/dir-matrix.sh` | 40-cell directory-destination matrix (`make check-dir-matrix`) |
| `tests/actor-wrapper/run.sh` | 21 wrapper/actor-identity witnesses (`make check-wrapper`) |
| `tests/matrix.sh` | file-flag matrix, 4 flags x every op the runner lists (28 cells today; the gate reads the op list rather than a literal) |
| `tests/bench-runner.sh` | three-mode performance bench with 2σ confidence intervals |
| `tests/bench/bpf-syscall-overhead.sh` | what `--self-protect` costs `bpf(2)`: three legs (no policy / `--pin` / `--pin --self-protect`), `make bench-bpf-syscall` |
| `tests/stability/` | pin/unpin churn stability: 8 witnesses quick, 1024 cycles full |
| `tests/fuzz.sh` | 10 000-iteration fuzz with reproducible seeds |

The per-suite tallies above are the ones measured on kernel 6.8.0-139 and
7.0.0-31 for v0.8.0; `tests/docs/RUNNING.md` is the authoritative copy and
is updated with each release.

---

## Known limits

See `LIMITATIONS.md` for the full table. Highlights:

- **Mount shadowing (residual)**: v0.8 denies new mounts on or under sealed
  paths, and denies detaching or moving away the filesystem that hosts them.
  A consequence worth knowing before you load a policy: **you cannot
  `umount` a filesystem holding sealed paths without `--unpin` first.** Still
  open for `CAP_SYS_ADMIN`: `pivot_root`, mounting on the root of a nested
  mount that already sat inside a sealed tree at load time, and unmounting a
  bind mount that was itself the sealed path (the filesystem is not detached
  by that, so it is deliberately allowed). The sealed inodes stay protected
  in every case; only the path guarantee breaks.
- **`chattr`-class ioctls**: gated on `no-chmod` seals for native *and*
  32-bit compat callers (`file_ioctl` + `file_ioctl_compat`). The compat
  program is autoload-gated on a BTF probe; on a kernel that lacks
  `security_file_ioctl_compat()` compat ioctls route through the native hook
  anyway. See LIMITATIONS.md.
- **Existing writable mappings**: a shared-writable mmap established *before*
  policy attach is not revoked. Load before protected services start.
- **BPF LSM detach**: a root process with `CAP_BPF` and write access to the
  bpffs pin directory can `unlink()` the link pins and, once the last fd
  drops, remove enforcement. Note `bpf(BPF_LINK_DETACH)` does **not** work on
  an LSM link — it returns `-EOPNOTSUPP` — so the pin tree is the surface to
  guard. Combine with capability dropping and bpffs namespace lockdown.
- **`bpf_map_freeze()` is not map integrity**: freeze closes the syscall write
  path, but a `CAP_BPF` holder with any fd to a frozen map — `BPF_F_RDONLY` is
  enough — writes it from a BPF program of its own (measured on 6.8.0-139 and
  7.0.0-31). So the seal maps are mutable by an unconfined root, and wiping
  them removes policy with no unlink and no audit event.
- **Opt-in self-protection** closes both of the two above: `--pin
  --self-protect` denies map fds and pin removal to anything that is not the
  loader image. It is off by default because the maintenance right is the
  loader's `(dev, ino)`, so a rebuilt or upgraded binary cannot unpin the old
  policy — unpin before upgrading, or pre-authorise the successor with
  `--authorize-loader` at pin time; a stranded tree costs a reboot. While it is
  on, `bpftool map show` aborts its host-wide listing at the first compartment
  map. See `HOWTO.md` §3.6 and `LIMITATIONS.md`.
- **btrfs / overlayfs anon_bdev**: on these filesystems, `(dev, ino)` can be
  reused across bind-mount views of the same inode; see LIMITATIONS.md.
- **No cryptographic policy signing** yet.

---

## License

`compartment.bpf.c` and `compartment-observe.bpf.c` — **GPL-2.0** (required
for BPF LSM helper access; see `LICENSE-GPL`).

Everything else — **Apache-2.0** (see `LICENSE`).

---

## Lineage

```
LIDS (1998–2002)        shell-guard (2003)       compartment (2026)
  capability bounding ─▶  PPID-chain audit  ─▶   Landlock + seccomp + ns
  sealed files             syscall=trace logs       zero-dep, single-file
  exec ACLs                                        (compartment-user/-root)
                                                          │
                                                          ▼
                                                   compartment-bpf (2026)
                                                     BPF LSM, kernel-side
                                                     sealed paths, domains
```
