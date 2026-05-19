# compartment-bpf — kernel-side path sealing via BPF LSM

compartment-bpf is a BPF LSM tool that seals file-system paths so that even
root cannot unlink, rename, write, or chmod the sealed inodes. Decisions are
made in-kernel from in-kernel data — no userspace daemon needs to stay alive
for enforcement.

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
| `inode_setattr` / xattr hooks | size / mode / owner / xattr changes |
| `task_alloc` / `bprm_*` / `ptrace` / `task_free` | actor-strict marker lifecycle |

Seal flags: `no-unlink`, `no-rename`, `no-write`, `no-chmod` (or `full` for all four).

---

## Key properties

- **Inode-based, not path-based.** Sealed by `(dev, ino)`. Hard links to a
  sealed inode inherit the seal; bind-mount shadowing of the path does not
  bypass the underlying inode's protection.

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
  (`bpf_map_freeze`); no root process can weaken a seal in place.

---

## Requirements

- Linux kernel ≥ 6.6 with `CONFIG_BPF_LSM=y` and `bpf` in the active LSM list.
  Check with:
  ```sh
  cat /sys/kernel/security/lsm   # must include "bpf"
  zgrep BPF_LSM /proc/config.gz  # CONFIG_BPF_LSM=y
  ```
  Tested on Ubuntu 26.04 LTS (kernel `7.0.0-15-generic`).

- Toolchain: `clang` ≥ 12, `libbpf-dev`, `bpftool`, `libsodium-dev`.
  `make check-env` verifies presence.

- BTF at `/sys/kernel/btf/vmlinux` (default on most distros).

---

## Build

```sh
make vmlinux.h     # one-time — generates from running kernel BTF
make
sudo make smoke    # quick enforcement check
sudo make check    # full unit test suite
```

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
| `tests/bypass/run-all.sh` | 33 bypass scenarios (kernel hook coverage per flag class) |
| `tests/strict-launch/run.sh` | 15 strict-launch-marker witnesses |
| `tests/observe/run.sh` | 25 observe pipeline witnesses |
| `tests/mesh/run-mesh.sh` | 3276 (actor × operation × flag) enforcement matrix rows |
| `tests/matrix.sh` | 24-cell file-flag matrix |
| `tests/bench-runner.sh` | three-mode performance bench with 2σ confidence intervals |
| `tests/stability/` | 1024-cycle pin/unpin churn stability |
| `tests/fuzz.sh` | 10 000-iteration fuzz with reproducible seeds |

---

## Known limits

See `LIMITATIONS.md` for the full table. Highlights:

- **Bind-mount shadowing**: `CAP_SYS_ADMIN` can `mount --bind` a decoy over
  a sealed path, making the path resolve to an unsealed inode. The original
  sealed inode remains protected; the path guarantee breaks.
- **Existing writable mappings**: a shared-writable mmap established *before*
  policy attach is not revoked. Load before protected services start.
- **BPF LSM detach**: a root process with `CAP_BPF` and access to the bpffs
  link can detach the programs. Combine with capability dropping and bpffs
  namespace lockdown for stronger guarantees.
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
