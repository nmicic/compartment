<!-- Copyright (c) 2026 Nenad Micic -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# compartment-bpf — operator HOWTO

This file walks through the day-to-day operator surface for
compartment-bpf v0.x: writing seal directives, the exec-domain actor
allowlist (ABI v0.3), strict-launch declarations (ABI v0.4),
directory-destination seals (ABI v0.5, see §7), and the unpin-passphrase
credential gate.

For the design rationale see `README.md`. For the limitations
envelope see `LIMITATIONS.md`. For the on-ramp to build/run see
`ON-RAMP.md`.

---

## 1. Seal directives — the baseline

```
seal <absolute-path> <flagspec>
```

`<flagspec>` is `full` or any comma/space-separated combination of
`no-unlink`, `no-rename`, `no-write`, `no-chmod`. Unknown directives
and unknown flags are fatal at load time. `oracle.conf` is the
minimal worked example; the per-daemon profiles under `profiles/`
are richer examples.

`no-chmod` covers every inode-metadata write path the kernel exposes:
`chmod`/`chown` (`inode_setattr`), xattrs, POSIX ACLs
(`inode_set_acl` / `inode_remove_acl` — a separate hook since Linux 6.2,
covered from v0.8), inode-flag ioctls such as `chattr +i/+a`
(`file_ioctl`, v0.8) and explicit timestamp changes (`touch -d`,
`utimensat`; v0.8). Truncation remains write-class (`no-write`). Any
seal flag also refuses new mounts on or under the sealed path
(`sb_mount` / `move_mount`, v0.8) so the path cannot be shadowed, and
refuses to let the filesystem hosting the sealed path be detached or moved
away from under it (`sb_umount`, v0.8). Note the operational consequence:
while a policy is loaded, `umount` of a filesystem holding sealed paths is
denied — run `compartment-bpf --unpin` first.

The loader resolves paths once at load time via
`open(O_PATH | O_NOFOLLOW)` + `fstat`, then keys the seal by
`(dev, ino)`. A symlink at the leaf is refused with a clear message;
deeper symlinks resolve normally. Hard links to a sealed file inherit
the seal (the protected property is the inode, not the path).

Load policy *before* the protected service starts. There is a
narrow window between map update and BPF attach during which
enforcement is not yet live.

**Recommended pairing — `no-write` + `no-unlink`.** For any file that
must not be replaced, seal it with both `no-write` and `no-unlink`
(not `no-write` alone). `no-write` permits `unlink`, so a `no-write`-only
file can be removed, its inode freed, and its inode number reused by an
unrelated new file that then inherits the stale `(dev, ino)` seal
(a spurious fail-closed deny — see the inode-reuse row in
`LIMITATIONS.md`). Adding `no-unlink` makes the sealed inode
unremovable, so its number can never be recycled and the reuse window
is inert by policy. This matters most in `--pin` daemonless mode, where
the daemon's inode-pinning fds do not survive process exit.

### Preflight: kernel sysctls

Before deploying actor-bound profiles to production, set
`fs.protected_hardlinks=1`:

```sh
sysctl -w fs.protected_hardlinks=1
echo 'fs.protected_hardlinks = 1' > /etc/sysctl.d/99-compartment-bpf.conf
```

This sysctl prevents unprivileged users from hardlinking arbitrary
files they don't own — the surface that lets an attacker
`ln /usr/sbin/aide /tmp/myactor` and inherit actor identity via
`exec /tmp/myactor`. The `comp_inode_link` hook closes this at the LSM layer,
and the loader emits a
`[loader] WARNING` if it detects `fs.protected_hardlinks=0` at
startup — but the sysctl is the defense-in-depth row in
`LIMITATIONS.md`. See the BX-10 witness
(`tests/bypass/exec-domain/BX-10-hardlink-to-canonical-actor.sh`)
for the empirical demonstration.

---

## 2. Exec-domain (actor allowlist)

As of ABI v0.3, a seal line can
restrict which binary may perform the operation. The classic
"trusted writer" pattern: AIDE may update its baseline; anyone
else with root cannot.

### 2.1 Syntax

Two clauses, both at the top of a profile:

```
actor NAME = PATH [PATH ...]                # declare an actor group
seal <path> <flags> actor=NAME              # restrict by group
```

Rules (parser, ED-1):

- An `actor NAME = PATH ...` declaration MUST come before any
  `seal ... actor=NAME` line that references it (no forward
  references; fail-closed).
- Each `actor` line names exactly one group. Up to four binary
  paths per group (`COMPARTMENT_MAX_ACTORS_PER_SEAL = 4`); paths
  must be absolute.
- A seal line carries at most one `actor=` clause. A second is a
  parse error.
- `actor_count == 0` on a seal preserves the legacy v0 uniform-deny
  semantics — every caller is denied, identical to pre-ABI-v0.3
  behaviour.

### 2.2 Strict mode (ED-5)

Every binary path named on an `actor` line MUST itself be sealed
`full` (i.e. `no-write no-unlink no-rename no-chmod`) at that
exact path in the same profile. The loader refuses the profile
otherwise, naming the unsealed actor. Rationale: if an attacker
can swap the actor binary on disk, the actor identity becomes
forgeable.

### 2.3 Hook-side semantics (ED-4 / ED-6)

At each of the 28 LSM hooks `compartment.bpf.c` attaches (the 16
file/inode/path hooks of v0.3; the five v0.4 strict-launch hooks
`bprm_committed_creds`, `task_alloc`, `task_prctl`,
`ptrace_access_check`, `ptrace_traceme`; and the seven v0.8
metadata/mount hooks `inode_set_acl`, `inode_remove_acl`,
`file_ioctl`, `file_ioctl_compat`, `sb_mount`, `sb_umount`,
`move_mount`),
after the
existing seal+flag check passes the kernel runs an actor match
against `current->mm->exe_file`'s `(dev, ino)`. On mismatch the
operation is denied with reason code
`ACTION_DENY_ACTOR_MISMATCH = 4` (per `compartment-abi.h`), and a
single audit event is emitted via the kernel BPF ringbuf with:

| audit field    | meaning                                            |
|----------------|----------------------------------------------------|
| `action`       | `ACTION_DENY_ACTOR_MISMATCH` (4)                   |
| `dev` / `ino`  | the sealed file inode                              |
| `caller_dev`   | caller's exe inode device                          |
| `caller_ino`   | caller's exe inode number                          |
| `actor_name`   | the group name from the profile (NUL-terminated)   |

The per-CPU counter `actor_mismatch_total` (ED-7) increments on
every such deny, alongside the existing `deny_total` and
`audit_drop_total`. `compartment-bpf --stats` prints all three.

### 2.3.x ABI v0.4 — `actor-strict` (LD_PRELOAD-safe actor protection)

ABI v0.4 (2026-05-15) introduces a stronger actor primitive that
closes the LD_PRELOAD class. Use it for any actor whose profile
claims clean-launch protection.

Syntax:

```
actor-strict aide = /usr/sbin/aide launcher=/usr/libexec/compartment-actors/aide

seal /usr/sbin/aide full
seal /usr/libexec/compartment-actors/aide full
seal /var/lib/aide/aide.db no-write actor=aide strict-launch
```

`actor-strict` mandates:

- the declared launcher binary is **statically linked** (a dynamic
  launcher has the same LD_PRELOAD problem before its own main());
- the launcher path and the target path are both sealed `full` in
  the same profile;
- env policy is the wrapper's responsibility, not the loader's
  see §4.1 below). The 68
  dangerous dynamic-loader/interpreter env names are rejected by the
  wrapper at build time via the shared
  `tools/compartment-dangerous-env.h` table.
- the **launcher** binary seal must NOT carry an `actor=` clause. If it
  did, the actor target could appear in the launcher's own seal
  allowlist and overwrite the launcher bytes in-place (preserving
  (dev,ino)), defeating the LD_PRELOAD-safety guarantee. The loader
  rejects this shape at load time — see also the analogous rule for the
  actor-binary seal in §7.2.

The `strict-launch` flag on a seal turns on the in-kernel marker
check. A protected file operation on such a seal requires:

1. existing actor= inode check (v0.3 binding) — and
2. a valid task-storage marker (`bprm_committed_creds` sets one once an
   exec of the sealed launcher has *committed*; v0.8 moved this off
   `bprm_check_security`, which runs before the point of no return and
   left a marker behind when the exec failed afterwards), and
3. the marker's target inode equals the current task's exe inode, and
4. the marker's actor_slot matches the seal's strict_actor_slot, and
5. the marker's policy_generation equals the loaded generation.

Failure to satisfy 2-5 emits `ACTION_DENY_STRICT_LAUNCH_MISSING`
(action code 8) with the same caller_dev/caller_ino/actor_name payload
shape as the actor-mismatch path, so SIEM correlation continues to
work.

**Hard caveat (FEASIBILITY 2026-05-15):** The safe release shape is
`actor-strict` **alongside** the static wrapper. Releasing strict-
launch does NOT retroactively make plain `actor=` clean-launch-safe.
For actors that ship a v0.3 profile, `LIMITATIONS.md` continues to
describe `actor=` as binary-identity only; migrate to `actor-strict`
to claim LD_PRELOAD-safe protection.

Build the launcher binary with `tools/compartment-actor-build.sh`
(emits a statically-linked per-actor wrapper with the target path baked
in; see §7.1 for a worked example invocation).

Worked profile: `profiles/aide-strict.conf`.

### 2.4 Worked example — AIDE

`profiles/aide.conf` is the canonical worked example for the
"trusted writer" pattern:

```
actor aide = /usr/sbin/aide

seal /usr/sbin/aide                       full
seal /var/lib/aide/aide.db                no-write,no-unlink,no-rename actor=aide
seal /var/lib/aide/aide.db.new            no-write,no-unlink,no-rename actor=aide
```

Load and exercise it:

```sh
sudo ./compartment-bpf profiles/aide.conf &

# Legitimate path: aide updates the baseline through itself.
sudo aide --check       # → succeeds (binary's exe inode is in the group)

# Off-binary tampering: root with a different binary cannot edit the db.
sudo vi /var/lib/aide/aide.db
# error: cannot open /var/lib/aide/aide.db: Permission denied
# (audit: action=4 ACTION_DENY_ACTOR_MISMATCH actor_name=aide
#         caller_dev=… caller_ino=… (the vi binary's exe inode))
```

`tests/profile-e2e/aide.sh` is the regression witness for this
property.

#### 2.4.1 LD_PRELOAD hardening — clean-exec wrapper (2026-05-15)

The bare actor allowlist tells the kernel "only the aide binary may
write `aide.db`". It does NOT stop someone from launching aide with a
hostile environment (`LD_PRELOAD=/tmp/evil.so aide --update`), because
the kernel still sees aide's inode as the caller — the `.so` runs
in-process. `tools/compartment-actor-wrapper.c` is the userspace
mitigation:

```sh
# Build (static link is mandatory):
cc -Wall -O2 -static -o /usr/local/sbin/compartment-actor-wrapper \
    tools/compartment-actor-wrapper.c

# Use as a clean launch entry point. Profile still names /usr/sbin/aide
# as the actor (after execve, current->mm->exe_file is aide's inode,
# NOT the wrapper's — see profiles/aide-wrapper.conf comments).
/usr/local/sbin/compartment-actor-wrapper --actor aide -- \
    /usr/sbin/aide --update
```

The wrapper: `clearenv()` + fixed `PATH` + `PR_SET_NO_NEW_PRIVS=1` +
`PR_SET_DUMPABLE=0` + close fds≥3 + seccomp denylist (ptrace,
`process_vm_*`, `pidfd_getfd`, `kcmp`, `bpf`, `perf_event_open`,
`userfaultfd`, key*, *_handle_at, mount/fs*, `prctl(PR_SET_MM)`).
Generator: `tools/compartment-actor-build.sh` produces a per-actor
binary with the target path baked in. Empirical close on Resolute VM:
`tests/results/actor-wrapper-vm-20260515T025445Z/`.

Companion controls (none replace the wrapper, all should be deployed):

- `kernel.yama.ptrace_scope=2` (third party → actor ptrace, which the
  wrapper's in-process seccomp cannot block);
- systemd unit: `NoNewPrivileges=yes`, `UnsetEnvironment=LD_PRELOAD …`,
  `CapabilityBoundingSet=` without `CAP_SYS_PTRACE`/`CAP_BPF`/
  `CAP_SYS_ADMIN`.

### 2.5 Worked example — postgres (structural guard + PG_VERSION sentinel)

`profiles/postgres.conf` is the second shipped example. **Scope
of v0.x protection (R2-F5):**

* **Structural mutation guard** on `/var/lib/postgresql/<v>/main/`.
  The dir seal blocks create / link / unlink / rename / mkdir
  / rmdir / mknod / symlink of entries under the data dir to
  any caller that is not the `postgres` actor. Stops `rm`,
  `mv old new`, `ln -s`, etc.
* **Per-file write protection** on `PG_VERSION`. The sentinel
  is sealed `no-write,no-unlink,no-rename actor=postgres`, so
  its contents are immutable to non-actor callers.

**What directory seals cover (v0.6+):** the dir seal gates
writes AND metadata changes (`no-write`, `no-chmod`) on the
**entire subtree** beneath the sealed directory in addition to
the structural mutation set (create/link/unlink/rename/mkdir/
rmdir/mknod/symlink). `deny_file_write()` calls both
`deny_inode_action()` and `deny_file_parent_dir_action()`; the
latter walks ancestor dentries at runtime, so a non-actor
`cat > /var/lib/postgresql/<v>/main/PG_VERSION` and a non-actor
write to a nested heap file at `base/<oid>/<relfilenode>` are
both blocked by the single seal on `main/`, with no per-file
seal required. (Under the original v0.5 dir-destination model
the gate was only one level deep — immediate children — and
grandchildren were not covered; v0.6 supersedes that.)

**The remaining limit is the depth cap, not one level.** The
ancestor walk is bounded to `COMPARTMENT_MAX_DIR_ANCESTORS`
(default 8) levels of nesting. A descendant deeper than the
compiled cap from its covering sealed directory is not reached
by the runtime walk. To keep this fail-closed, the loader
refuses to attach a recursive directory seal whose live subtree
already exceeds the compiled budget. Keep sealed subtrees within
the depth budget, or rebuild with a larger cap
(`make COMPARTMENT_MAX_DIR_ANCESTORS=32`). See the
recursive-subtree ancestor-walk depth-cap row in LIMITATIONS.md.

**Per-file seals** remain the precise tool when you want to
freeze one specific file's content (e.g. the `PG_VERSION`
sentinel) independent of any directory seal:

```
seal /var/lib/postgresql/18/main/<file> no-write,no-unlink,no-rename actor=postgres
```

Regression witness: `tests/profile-e2e/postgres.sh`. The witness
discovers the installed PostgreSQL major via `pg_lsclusters`, sed-
substitutes the profile to match the deployment, loads
compartment-bpf, asserts `sealprobe open-write PG_VERSION` denies
(the per-file sentinel write-protection), and confirms
`pg_isready` against the live cluster succeeds. The witness is
intentionally narrow: it asserts the per-file sentinel surface
directly rather than enumerating every file in the recursively
sealed subtree.

### 2.6 Multi-binary actor groups

The actor cap is four paths per group. Use it when a
"trusted writer" is actually a small set of helpers — e.g. an
apt-style updater that legitimately calls `dpkg` and `dpkg-deb`:

```
actor pkgmgr = /usr/bin/dpkg /usr/bin/dpkg-deb /usr/bin/apt /usr/bin/apt-get
```

All four binaries must be `full`-sealed at their declared paths
under strict mode.

### 2.7 Legacy semantics preserved

A profile with no `actor=` clauses is byte-for-byte equivalent to
the same profile under pre-v0.3 compartment-bpf: every caller is
uniformly denied (`actor_count == 0` path). v0 profiles continue
to load and enforce identically.

### 2.8 Sealing a binary's dynamic-link closure

Sealing only an executable leaves the shared libraries it loads
writable — tampering a `.so` reported by `ldd` is as effective as
tampering the binary. To fully tamper-proof an executable, seal it
**and** its library closure. `tools/seal-binary-closure.sh` emits the
seal directives, resolving version symlinks (e.g. `libfoo.so` →
`libfoo.so.1.2.3`) to their real inodes:

```
$ tools/seal-binary-closure.sh /usr/sbin/sshd full >> sshd.conf
# review sshd.conf, then load it
```

Re-run it after package upgrades: an upgrade replaces files with new
inodes, so the previous (dev, ino) seals would no longer match. Note
the libraries live under `/usr/lib`, which is exactly why a recursive
`seal /usr` is impractical — see `LIMITATIONS.md`.

---

## 3. Unpin passphrase (ED-11)

Pinning the BPF links (`--pin`) makes seals survive loader exit;
unpinning (`--unpin`) takes them off. The unpin passphrase is a
**credential gate** that the `--unpin` path must clear before it
will tear down a passphrase-protected pin tree.

**Filesystem maintenance — run `--unpin` first.** While the daemon
runs it holds an `O_PATH` fd per sealed inode (to prevent inode-number
reuse), which pins every filesystem containing seals. `umount` and
`mount -o remount,ro` on such a filesystem therefore return **EBUSY**.
Run `compartment-bpf --unpin` before unmounting or remounting-ro any
filesystem that holds seals (LVM snapshot, volume detach, `fsck`, etc.).
See the EBUSY row in `LIMITATIONS.md` for the security rationale and the
`umount -l` caveat.

**R2-F6 honest framing (post-Review-2, 2026-05-14):** the
implementation is libsodium Argon2id (`crypto_pwhash_str`,
`OPSLIMIT_INTERACTIVE` / `MEMLIMIT_INTERACTIVE`, ≈ 70 ms + 64 MiB
on x86_64) + `sodium_mlock` on every passphrase buffer + dual-
channel audit (stderr + syslog `LOG_AUTHPRIV`) on
`DENY_UNPIN_AUTH_FAIL` + an ABI-versioned action code
(`ACTION_DENY_UNPIN_AUTH_FAIL = 7`, stable since ABI v0.3 and
unchanged through the current v0.8 ABI). That is a
credential-gate-grade build, not the "speed bump" wording the
v0 brief originally used. The honest threat-model framing:

* **Against an attacker with CAP_BPF / CAP_SYS_ADMIN on the box,**
  this gate is bypassable — they own the sentinel file, the bpffs
  pin tree, and can `unlink()` the link pins (note `bpf(BPF_LINK_DETACH)`
  does not work on an LSM link — it returns `-EOPNOTSUPP`; the pin tree is
  the surface). The recovery path in
  §3.4 documents this directly. They can also rewrite the policy maps
  without touching the pin tree at all: `freeze_seal_maps()` calls
  `bpf_map_freeze()` after load, but freeze gates only the **syscall**
  path. Measured on 6.8.0-139 and 7.0.0-31, a `CAP_BPF` caller that
  obtains any fd to a frozen compartment map — `BPF_F_RDONLY` is enough
  — can splice it into a BPF program of its own and write it from
  program context, so wiping `sealed_inodes` removes policy with no
  unlink, no umount and no audit event. Do not read the freeze as map
  integrity; it is not, and the `CAP_BPF + direct map mutation` row in
  `LIMITATIONS.md` carries the measurement.
* **Against a non-CAP_BPF-restricted root attacker** (an
  unconfined process running as uid 0 but without CAP_BPF /
  CAP_SYS_ADMIN — e.g. a setuid binary, a confined container
  root, a daemon dropped to a capability set), the unpin path is
  the only way to weaken seals on a pinned profile, and this
  passphrase gate is the wall. The Argon2id work factor blocks
  offline brute-force on a captured sentinel.

The dual-channel audit makes every failed attempt durable —
silent suppression requires compromise of both stderr capture
(systemd journal) and syslog (`LOG_AUTHPRIV` → `auth.log` → SIEM
shipper).

It is not a cryptographic root of trust — that requires
sealed-agent mode (drop CAP_BPF post-pin; lockdown=integrity;
signed loader binary) and is v1.5 scope.

### 3.1 Setting a passphrase at pin time

```sh
export COMPARTMENT_BPF_PASSPHRASE='<high-entropy-string>'
sudo -E ./compartment-bpf --pin profiles/aide.conf
```

The loader hashes the passphrase with Argon2id via libsodium
(`crypto_pwhash_str`, `OPSLIMIT_INTERACTIVE` / `MEMLIMIT_INTERACTIVE`,
≈ 70 ms + 64 MiB on x86_64) and writes the self-describing hash
string to `/run/compartment-bpf/unpin-sentinel`, mode 0600, owner
uid 0. The `/run/...` path is used because bpffs rejects regular
file creation.

If `stdin` is a tty and the env var is unset, the loader prompts
via `getpass(3)`. Use a high-entropy passphrase: short or
predictable strings reduce the gate's work factor against
offline brute-force on a captured sentinel — Argon2id's
~70 ms + 64 MiB per attempt is meaningful only when the
passphrase has enough bits to make iterations matter. The
passphrase buffers are `sodium_mlock`'d (out of swap) and
`sodium_memzero`'d on every exit path.

#### Env-var ingestion ordering (R2-F9)

The loader copies `COMPARTMENT_BPF_PASSPHRASE` into a
`sodium_mlock`'d heap buffer, then immediately
`sodium_memzero()`s the original env string in place and calls
`unsetenv("COMPARTMENT_BPF_PASSPHRASE")` before any other work.
Between the `exec()` of `compartment-bpf` and that scrub (a few
syscalls; libsodium init; an `argv` walk; the `getenv()` call
itself), the env-var string is readable to anything with
`PTRACE_MODE_READ` on the loader pid:

* `/proc/<pid>/environ` (same-uid reader only by default)
* `ptrace(PTRACE_PEEKDATA, ...)`
* a synchronously captured core dump

Once the scrub runs, the original buffer holds NUL bytes and
the env-table entry is gone. For workflows where even this
sub-millisecond window matters (e.g. an untrusted same-uid
sidecar on the same host), pipe the passphrase via `getpass(3)`
on a tty instead, or write it to a runtime-injected file your
service unit reads through an fd. Both paths bypass `environ[]`.

The dual-channel audit (stderr + syslog) emitted on
`DENY_UNPIN_AUTH_FAIL` (R2-F2 + R2-M23 unified format) lets the
operator detect a sentinel-tamper attempt even if the env scrub
race were exploited — the next legitimate `--unpin` will trip
the gate and emit `[audit] DENY_UNPIN_AUTH_FAIL …` to both
channels.

### 3.2 Unpinning with the passphrase

```sh
export COMPARTMENT_BPF_PASSPHRASE='<same-passphrase>'
sudo -E ./compartment-bpf --unpin
```

The loader reads `/run/compartment-bpf/unpin-sentinel`, verifies
mode 0600 / uid 0 / `S_ISREG`, then runs
`crypto_pwhash_str_verify`. On success the unpin proceeds. On
verify fail or sentinel tamper the loader refuses with
`ACTION_DENY_UNPIN_AUTH_FAIL = 7` (per `compartment-abi.h`).

### 3.3 Audit channel

ACTION_DENY_UNPIN_AUTH_FAIL events are emitted to **both** the
loader's stderr (parseable, single-line) and syslog
`LOG_AUTHPRIV / LOG_WARNING` with ident `compartment-bpf`. They do
NOT flow through the kernel BPF audit ringbuf — libbpf has no
userspace producer API for `BPF_MAP_TYPE_RINGBUF`, so this
loader-side event uses syslog. Operators route `auth.log` to their
SIEM already; the dual channel makes it harder for a local
adversary to silently suppress.


### 3.4 Recovery path

If the passphrase is lost:

```sh
sudo rm /run/compartment-bpf/unpin-sentinel
sudo ./compartment-bpf --unpin              # legacy path, no passphrase required
```

This recovery is the documented bypass for an operator with
CAP_BPF / CAP_SYS_ADMIN on the box: delete the sentinel, then
take the legacy unpin path. It is the safety valve for the
"lost passphrase" failure mode and the load-bearing reason this
gate is positioned as a credential gate against *non-CAP_BPF*
root rather than a cryptographic root of trust. A privileged
user who owns the sentinel file does own the gate; the audit
trail (stderr + syslog) records every removal/unpin attempt so
the bypass is observable, not silent.

### 3.5 Legacy (`--pin` without env var)

Calling `--pin` with no `COMPARTMENT_BPF_PASSPHRASE` set and no
tty available preserves pre-ED-11 behaviour: no sentinel is
created and `--unpin` runs unauthenticated. v0.x profiles
continue to work without the passphrase opt-in.

---

### 3.6 Self-protection (`--self-protect`) and the upgrade ceremony

`--self-protect` is opt-in, off by default, and only meaningful with `--pin`.
It answers a different question from the unpin passphrase. The passphrase asks
*"does the operator running `--unpin` know the secret?"*. `--self-protect` asks
*"is this even the loader?"* — and it is enforced in the kernel, so it also
covers the paths that never call `--unpin` at all: `rm` of a pin, `umount` of
the bpffs, and `bpf(BPF_MAP_GET_FD_BY_ID)` on the seal maps.

```sh
export COMPARTMENT_BPF_PASSPHRASE='<high-entropy-string>'
sudo -E /usr/sbin/compartment-bpf --pin --self-protect profiles/aide.conf
```

What it refuses, for every task whose `mm->exe_file` is not an authorised
loader image:

* any fd to a compartment BPF map — read-only included, because a read-only fd
  is enough to write the map from a BPF program (`bpf_map_freeze()` gates only
  the syscall path);
* `unlink`, `rename` and `rmdir` of the pin objects, the two pin directories,
  `/sys/fs/bpf/compartment` and the bpffs mount root;
* `umount` (including `umount -l`) of the bpffs holding the pins, and mounting
  a second bpffs over it.

Two prerequisites, both enforced at pin time with a clear refusal:

1. The kernel must have `bpf_lsm_bpf_map` (it does on 6.8 and 7.0). Without it
   the loader refuses to start rather than claim protection it does not have.
2. The loader binary must be root-owned and **not** group- or world-writable.
   A group-writable maintenance binary means the maintenance right belongs to
   that group, not to root. Install it `root:root 0755`; a binary sitting in a
   build tree usually is not.

Without the flag, nothing changes: the `comp_bpf_map` program is not even
loaded, the pin set is the same 28 links v0.8 pinned, and both new counters
stay 0.

#### The errno an operator sees

All five lines below are the verbatim text measured on 6.8.0-139 and
7.0.0-31 with bpftool 7.4 and 7.7.

| operation, refused | errno | what it looks like |
|---|---|---|
| any `bpf()` that would hand out a map fd (`BPF_MAP_GET_FD_BY_ID`, `BPF_OBJ_GET` on a pin) | `EPERM` | `Error: can't get map by id (N): Operation not permitted` |
| `rm` / `mv` / `rmdir` on a pin object or pin directory | `EACCES` | `rm: cannot remove '/sys/fs/bpf/compartment/links/comp_file_open': Permission denied` |
| `umount` / over-mount of the bpffs holding the pins | `EACCES` | `umount: /sys/fs/bpf: block devices are not permitted on filesystem.` — util-linux's rendering of `EACCES` from `umount2(2)`, which is unhelpful but is not ours to change; the audit stream carries `DENY_UMOUNT` |
| `--unpin` from an unauthorised image | `EACCES` on the first pin | `unlinkat /sys/fs/bpf/compartment/links/comp_bpf_map: Permission denied`, then the paragraph below |
| `--stats` from an unauthorised image | `EPERM` | `open pinned /sys/fs/bpf/compartment/maps/deny_total: Operation not permitted`, then one paragraph naming the remedy — printed once, not once per counter, and never as "no pinned counters found" |

`EPERM` on the `bpf()` side is that syscall's own dialect: `bpf(2)` reports
every "you do not have the right to this object" as `EPERM`, including
`BPF_MAP_GET_FD_BY_ID` without `CAP_BPF`, so tools have an `EPERM` path and no
`EACCES` path. `EACCES` on the path side is what every other compartment deny
returns and what `rm`, `mv` and `umount` print. `ENOENT` was measured as an
alternative — it makes `bpftool map show` skip our maps and exit 0 — and
rejected: it disguises a security decision as a missing object, and it makes an
unauthorised `--stats` print "no pinned counters found", which an operator
cannot tell from "no policy is pinned".

#### Identity, and why a rebuild matters

The maintenance right is the `(dev, ino)` of an executable image — the same
identity the `actor=` allowlist uses, for the same reason: `--pin`, `--unpin`
and `--stats` are three different processes running the same binary.

The set is fixed when the policy is pinned and frozen. The loader deliberately
cannot extend it afterwards: if it could, anything that can make the loader run
one more time could widen it.

**A rebuild or a package upgrade replaces the binary and therefore its inode.
The new binary is a different image and cannot unpin the old policy.** This is
the whole cost of the feature. There are two supported ceremonies:

```sh
# (a) the normal one — unpin before you replace the binary
sudo -E /usr/sbin/compartment-bpf --unpin
sudo apt install ./compartment-bpf_amd64.deb           # or: make && make install
sudo -E /usr/sbin/compartment-bpf --pin --self-protect profiles/aide.conf

# (b) pre-authorise the successor, if you need zero policy gap
sudo -E /usr/sbin/compartment-bpf --pin --self-protect \
        --authorize-loader /usr/sbin/compartment-bpf.next profiles/aide.conf
# ...later, the successor can take the old policy down:
sudo -E /usr/sbin/compartment-bpf.next --unpin
```

`--authorize-loader` resolves the path to `(dev, ino)` at pin time. Replacing
the file afterwards does **not** carry the authorisation over — that is the
point. At most 8 images in total, including the pinning one.

**The rule, in one line: unpin before upgrading the loader, or authorize the
new binary at pin time; a stranded tree costs a reboot.**

#### If you strand yourself

Running `--unpin` from an unauthorised image fails loudly and tells you so:

```
unlinkat /sys/fs/bpf/compartment/links/comp_bpf_map: Permission denied
unpin: the running policy was pinned with --self-protect and this
       executable is not in its authorised loader set, so the kernel
       refused to remove the pin (ACTION_DENY_PIN_TAMPER in the audit
       stream). Run --unpin from the binary image that pinned it, or
       from one authorised with --authorize-loader at pin time. If that
       image no longer exists (rebuild, package upgrade), the pin tree
       can only be cleared by rebooting: bpffs is not persistent.
```

The escape hatch is a reboot, and the worst case is bounded by it: bpffs is
memory-backed, so the pin tree and every attached program are gone after a
restart. That is the same reboot an unconfined root can perform anyway, which
is why stranding is no worse than the residual risk the threat model already
accepts — but it *is* a reboot, so treat `--self-protect` on a host you cannot
restart as a decision, not a default.

**On a build host, do not `--pin --self-protect` and then rebuild.** `make`
relinks `compartment-bpf` into a fresh inode on every invocation (`vmlinux.h`
depends on the `.PHONY` `check-env` target), so `sudo make check` after a
self-protected `--pin` leaves a tree that only a reboot can clear.

#### What it costs

`bpftool map show` — the host-wide listing, not just ours — aborts at the first
compartment map (`Error: can't get map by id (N): Operation not permitted`,
exit 255) instead of skipping it, so maps *after* ours in id order are not
listed either. This affects the whole host while a self-protected policy is
live, and it is the single most visible cost of the feature.

Unaffected: `bpftool prog show`, `bpftool link show`, `bpftool cgroup tree`,
`bpftool map show id <N>` for a specific non-compartment id, and creating,
writing, dumping, pinning and unlinking unrelated maps and pins. Use
`compartment-bpf --stats` — run from an authorised loader image, which is the
same executable — for this tool's own counters.

Read-only map access is **not** carved out for `--stats` or `bpftool map dump`.
It was considered and rejected on measurement: a read-only fd is a complete
attack, because a map spliced into a BPF program with `bpf_map__reuse_fd()` is
writable from program context regardless of `bpf_map_freeze()`. A read-only
carve-out would have left every seal map mutable and the gate decorative.

See the `LIMITATIONS.md` self-protection section for the measurement and for
what the flag does **not** close.

---

## 4. Counters and audit (operator surface)

`compartment-bpf --stats` prints the v0.3 baseline counters and (since
ABI v0.4) the strict-launch-marker counters:

| counter                  | meaning                                                 |
|--------------------------|---------------------------------------------------------|
| `deny_total`             | every action denied by any LSM hook                     |
| `audit_drop_total`       | ringbuf reservation failures (should stay at 0)         |
| `actor_mismatch_total`   | denies attributable to `ACTION_DENY_ACTOR_MISMATCH`     |

### v0.4 strict-launch counters

| counter                              | meaning                                                                                       |
|--------------------------------------|-----------------------------------------------------------------------------------------------|
| `strict_launch_missing_total`        | file-op denies emitted by `strict_launch_check_or_deny` (any failure mode)                    |
| `strict_launch_allowed_total`        | file-op operations passed by `strict_launch_check_or_deny` (positive observability)           |
| `marker_set_total`                   | tasks marker'd by `bprm_committed_creds` on a committed sealed-launcher exec                 |
| `marker_set_fail_total`              | committed sealed-launcher execs whose task-storage marker could not be allocated (fail-closed; expect 0) |
| `marker_clear_foreign_exec_total`    | tasks whose marker was cleared on a foreign exec (chain break — visibility signal)            |
| `marker_copy_fork_total`             | child tasks that inherited a parent marker via `task_alloc` (G6 Outcome B)                    |
| `marker_stale_generation_total`      | denies whose root cause was generation mismatch (always 0 in v0.4 fresh-load-only; see §3a)  |
| `prctl_set_mm_exe_file_denied_total` | `PR_SET_MM` denies emitted by `task_prctl` while strict mode is loaded (gates ALL `PR_SET_MM` sub-ops — see note below)               |
| `ptrace_access_denied_total`         | denies emitted by `ptrace_access_check` (strace, process_vm_writev, pidfd_getfd, /proc/mem)   |
| `ptrace_traceme_denied_total`        | denies emitted by `ptrace_traceme` (a marked actor calling PTRACE_TRACEME)                    |

### Self-protection counters (`--self-protect` only)

| counter                     | meaning                                                                                          |
|-----------------------------|--------------------------------------------------------------------------------------------------|
| `bpf_self_denied_total`     | map-fd requests refused by `comp_bpf_map` for a task that is not an authorised loader image (read-only requests included) |
| `pin_tamper_denied_total`   | unlink / rename / rmdir / mount attempts on this policy's own bpffs pins, refused for a non-loader |

Both stay 0 unless the policy was pinned with `--self-protect` (without the
flag `comp_bpf_map` is not loaded at all). `bpf_self_denied_total` picking up a
small non-zero value is normal on a box where something enumerates BPF map ids
— `bpftool map show` does. A **sustained** non-zero `pin_tamper_denied_total`
is the one to alert on: it means something is actively trying to take
enforcement off.

`audit_drop_total > 0` means the ringbuf consumer fell behind and
events were dropped — investigate before trusting the audit log
on that run. `actor_mismatch_total` should be zero in steady state
on a clean canary and only increment on intentional probes. The
strict-launch deny counters are observability for the SPEC §1
LD_PRELOAD-safe protection class; SIEM integrations that scrape
`--stats` should treat any of the `strict_launch_missing_total` /
`prctl_set_mm_exe_file_denied_total` / `ptrace_*_denied_total`
non-zero as a strict-mode enforcement event.

Despite its name, `prctl_set_mm_exe_file_denied_total` counts denies of
**every** `PR_SET_MM` sub-operation, not just `PR_SET_MM_EXE_FILE`. The
`task_prctl` hook was broadened to gate the whole `PR_SET_MM` family —
`PR_SET_MM_MAP` (sub-op 14) accepts a `struct prctl_mm_map` whose `exe_fd`
field overwrites `mm->exe_file` exactly like `PR_SET_MM_EXE_FILE`, so the
narrow per-sub-op gate left a direct actor-identity-swap bypass. The
counter name is retained for operator continuity.

---

### 4.1 Env policy is sourced from the wrapper (HIGH-7 amend, 2026-05-15)

ABI v0.4 does **not** parse `env NAME=VALUE` / `env NAME=*` directives
in profiles. Env policy is the wrapper's responsibility:

1. The wrapper (`tools/compartment-actor-wrapper.c`, built statically
   via `tools/compartment-actor-build.sh`) `clearenv()`s before
   `execve()`-ing the actor target. Nothing in the launcher's
   environment reaches the actor process by default.
2. Each invocation of the build script can pass `--allow-env NAME`
   one or more times to add specific variable names to the wrapper's
   allowlist; only those names survive the clearenv-then-allowlist
   filter at runtime.
3. The 68 dangerous dynamic-loader / interpreter names
   (LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH, GLIBC_TUNABLES, GCONV_PATH,
   LOCPATH, NLSPATH, BASH_ENV, ENV, PYTHONPATH, PYTHONSTARTUP,
   PERL5LIB, PERL5OPT, RUBYLIB, RUBYOPT, NODE_OPTIONS) are
   hard-rejected at wrapper build time even if the operator passes
   `--allow-env LD_PRELOAD`. The list is shared with the loader's
   `STRICT_DANGEROUS_ENV_NAMES` parse-time table via
   `tools/compartment-dangerous-env.h` (HIGH-6 shared header).

A profile containing an `env` directive is rejected by the loader
with:

```
$ compartment-bpf --parse-only my.conf
N: 'env' directive removed in v0.4; env policy
is sourced from the wrapper. Use `tools/compartment-actor-build.sh
--allow-env NAME` to customize the wrapper's env allowlist. See HOWTO.md §4.1.
```

Migration for v0.3 profiles that wrote `env` directives: drop the
lines from the profile and pass the desired allowlist to the wrapper
build instead. See `profiles/aide-strict.conf` for a worked example.

The reason path (b) won is simple: environment policy must live in the
wrapper so the loader and launcher cannot silently diverge.

---

## 5. Generating candidate profiles with compartment-bpf observe

The `observe` subcommand instruments a running actor with BPF hooks and
generates a candidate seal profile reflecting its actual filesystem access
patterns. This is the AO-1..AO-5 workflow (AO-6/AO-7 are deferred).

### 5.1 Basic usage

```sh
sudo ./compartment-bpf observe --actor aide=/usr/sbin/aide \
    --duration 30 -- aide --check
```

- `--actor NAME=PATH` registers an actor by inode. Repeatable for multi-binary
  actors. At least one actor is required.
- `--pid PID` is **reserved and not implemented** — passing it exits with
  status 2. Seed from a spawned command instead.
- `-- COMMAND [ARGS...]` spawns the command and stops observation when it exits
  (or after `--duration` seconds, whichever comes first).
- `--duration N` sets a hard timeout in seconds; omit to run until SIGINT.
- `--format profile|compact|jsonl|audit` selects the output format
  (default: `profile`).
- `--verbose` adds parent chain, dev/ino, and cgroup to each record.
- `--include-stat` is **reserved and not implemented** — passing it exits
  with status 2. It is intended to record stat/metadata activity, which is
  off by default because it can saturate maps on busy hosts.
- `--no-resolve-paths` emits raw dev/ino only; skips path resolution.
- `--no-dir-dest` forces per-file fallback rules (testing/compat path).
- `-o PATH` writes output to PATH (`-` for explicit stdout; default: stdout).
- `--provenance-out PATH` writes a provenance JSON sidecar.

### 5.2 Output format

The default output format (`--format profile`) emits a candidate profile to
stdout:

```
# generated by compartment-bpf observe
#@compartment-bpf-profile-status: candidate
# generated: 2026-05-16T00:00:00Z
# actors: aide
# observed_at: 2026-05-16T00:00:00Z
# validation: candidate only; run deny-first before enforcing

# target: aide
actor aide = /usr/sbin/aide
seal /usr/sbin/aide full
# directory seal; recursive subtree protection bounded to
# COMPARTMENT_MAX_DIR_ANCESTORS (default 8) levels.
seal /var/lib/aide no-write no-unlink no-rename no-chmod actor=aide
```

The profile header includes:
- `# generated:` — ISO-8601 timestamp of the observation session.
- `# actors:` — comma-separated list of observed actor names.
- `#@compartment-bpf-profile-status: candidate` — signals that this profile
  requires operator review before use with `--pin`.

### 5.3 Workflow

1. **Observe**: run the command under observation to capture its file access
   pattern.
2. **Review**: inspect the candidate profile. Check that directory-destination
   rules match the intended scope. Look for unexpected paths (tmp dirs, /proc,
   etc.) that should be excluded.
3. **Apply deny-first**: load the candidate profile with the marker still
   in place and exercise the actor under enforcement so any missing seal
   surfaces as a `deny_total` increment (rather than as a production
   outage):

   ```sh
   sudo -E ./compartment-bpf --allow-candidate --pin profiles/candidate.conf
   # in another shell: drive the actor through its normal workflow
   sudo ./compartment-bpf --stats   # watch deny_total / actor_mismatch_total
   ```

   Tune narrow seals until the actor succeeds with no denies; then unpin
   and proceed to step 4. The `--allow-candidate` flag keeps the marker
   audit-visible in `dmesg` for the duration of the test.
4. **Enforce**: load the reviewed profile. After operator review, there are
   two paths:
   - **Strip the marker** (recommended): remove or comment out the
     `#@compartment-bpf-profile-status: candidate` line at the top of the
     file, then run `./compartment-bpf --pin profiles/reviewed.conf`. The
     loader treats a profile without the candidate marker as production-
     ready.
   - **Override on first load** (audit-visible): run
     `./compartment-bpf --allow-candidate --pin profiles/reviewed.conf`.
     The candidate marker is preserved in the file; the WARNING line is
     logged (auditable). Use when you want to track that the profile
     originated from `observe` without editing the file.

   Without one of these, `--pin` exits non-zero with the diagnostic
   "refusing to --pin without --allow-candidate" (BX-13 witness).

### 5.4 Whitespace and special-character handling

`observe` silently drops any observed path containing a newline (`\n`),
carriage return (`\r`), `#`, space (0x20), or tab (0x09) character. Paths
with embedded whitespace are excluded from the candidate profile because
they cannot be safely emitted as seal directives: the profile parser
tokenizes on these characters. If the actor regularly accesses paths
with spaces (e.g. user-data directories with display names), consider
whether the seal scope can be expressed as a parent-dir seal at the
nearest whitespace-free ancestor, or run a full filesystem scan
(`find <root> -name '* *'`) to confirm whether dropped paths matter for
the actor's threat model.

### 5.5 AO-6/AO-7 deferred

`--global` (observe all execs as actor candidates) is not yet implemented
(AO-6, deferred); the CLI argument parser will reject it with rc=2 and
print `observe: unknown option: --global`. `--include-stat` is wired and
enables stat/metadata event recording, off by default because it can
saturate maps on busy hosts. AO-7 (deny-first bridge from observe output
directly into enforcement) is also deferred.

---

## 7. ABI v0.5 — directory-destination seals

ABI v0.5 (DD-1) extends seal semantics so that `no-write` and
`no-chmod` flags attached to a *directory* gate operations on the
directory's **immediate children** in addition to the existing
structural mutation set (`no-unlink`, `no-rename`, etc.). The
goal is to cover an entire data dir's contents in one declaration
without enumerating every file, while keeping the model fail-closed.

> **v0.6+ supersedes the one-level limit.** The text below describes the
> original v0.5 immediate-child behaviour. As of ABI v0.6 the enforcement
> hooks walk ancestor dentries at runtime, so a directory seal applies
> **recursively to the whole subtree**, bounded to
> `COMPARTMENT_MAX_DIR_ANCESTORS` (default 8) levels of nesting — a write
> to `<dir>/sub/file` is denied by the seal on `<dir>`. See §7.3 and the
> recursive-subtree row in LIMITATIONS.md for the current behaviour and
> the depth cap.

### 7.1 What a dir-destination seal does

Every hook that can mutate a file calls **both** `deny_inode_action()`
(the file's own inode seal — the v0.3 behaviour) and one of
`deny_file_parent_dir_action()` / `deny_dentry_parent_dir_action()` (the
covering directory's seal, emitting `ACTION_DENY_WRITE_PARENT_DIR=9` or
`ACTION_DENY_CHMOD_PARENT_DIR=10`). A non-actor write or metadata change
against a child of a DD-sealed dir is denied even if the child has no
per-file seal.

The write-class hooks are `file_open`, `file_permission` and
`file_truncate`. The chmod-class hooks — what `no-chmod` actually covers —
are:

| hook | denies |
|------|--------|
| `inode_setattr` | `chmod`, `chown`, and (v0.8) explicit timestamp writes: `ATTR_ATIME\|ATTR_MTIME` without `ATTR_SIZE`, i.e. `touch` / `touch -d` / `touch -a` / `utimensat(2)`. `ATTR_SIZE` is excluded so truncation stays write-class. |
| `inode_setxattr` / `inode_removexattr` | extended-attribute writes |
| `inode_set_acl` / `inode_remove_acl` (v0.8) | POSIX ACL writes (`setfacl -m/-x/-b`). Since Linux 6.2 these are routed by `vfs_set_acl()` / `vfs_remove_acl()` and never reach the xattr hooks. |
| `file_ioctl` + `file_ioctl_compat` (v0.8) | `FS_IOC_SETFLAGS` / `FS_IOC32_SETFLAGS` / `FS_IOC_FSSETXATTR` / `FS_IOC_SETVERSION` — `chattr +i/+a`, project ids. Both the native and the 32-bit compat ioctl entry points are separate LSM hooks in the kernel, so both are attached. |

(There is no `path_chmod` program and no `deny_file_chmod()` helper; earlier
revisions of this section named symbols that do not exist in
`compartment.bpf.c`.)

### 7.2 Syntax

A dir-destination seal is just a seal on a directory inode with
the relevant flags:

```
actor postgres = /usr/lib/postgresql/18/bin/postgres
seal /usr/lib/postgresql/18/bin/postgres no-write,no-unlink,no-rename,no-chmod
seal /var/lib/postgresql/18/main         no-write,no-unlink,no-rename,no-chmod actor=postgres
```

Two seals are needed and they are deliberately asymmetric:

* **The actor-binary seal** (`/usr/lib/postgresql/18/bin/postgres`) carries
  the four required flags but **no `actor=` clause**. ED-5 strict-mode
  (SPEC §7.1 E-6) requires every declared actor binary to itself be
  sealed at its declared path with `no-write,no-unlink,no-rename,no-chmod`;
  the loader refuses to attach otherwise. The seal must *not* carry
  `actor=postgres`, because then the postgres process would appear in
  its own seal's allowlist and could overwrite its own bytes in-place
  (preserving the (dev,ino) the kernel pins as the actor identity).
  The loader rejects this self-modification shape at load time.
* **The data-dir seal** (`/var/lib/postgresql/18/main`) carries the
  four flags **with** `actor=postgres`. `no-unlink,no-rename` cover
  the structural mutations on the directory inode itself, while
  `no-write,no-chmod` pull in the v0.5 parent-dir gates that extend
  to immediate children. The `actor=NAME` clause permits the
  declared actor to perform these operations on the dir's children;
  non-actor callers are denied.

Note that a second `seal` directive on the same path with an `actor=`
clause is rejected by the loader — declare all flags for a given path
on one line.

The loader also checks symlink-child and hardlink-child invariants
when applying a dir-destination seal: symlinks pointing into the dir
from outside, and hard links into the dir from elsewhere, are rejected
at load time.

### 7.3 What a dir-destination seal does NOT cover

* **Paths deeper than the depth cap.** As of v0.6 the gate is no
  longer one level deep: the enforcement hooks walk ancestor dentries,
  so `<dir>/sub/file` *is* checked against `<dir>/`'s seal. The walk is
  bounded to `COMPARTMENT_MAX_DIR_ANCESTORS` (default 8) levels — a
  descendant nested deeper than the compiled cap from its covering
  sealed directory is not reached by the runtime walk. To keep this
  fail-closed, the loader refuses to attach a recursive directory seal
  whose live subtree already exceeds the compiled budget. Keep sealed
  subtrees within the depth budget, or rebuild with a larger
  `COMPARTMENT_MAX_DIR_ANCESTORS`. See the recursive-subtree
  ancestor-walk depth-cap row in LIMITATIONS.md for the canonical
  description. (Under the original v0.5 one-level model, grandchildren
  were not covered at all; v0.6 supersedes that.)
* **Symlinks crossing into the dir from outside** the kernel
  hooks see only the inode at the resolved leaf; a symlink under
  `/tmp/foo → /var/lib/postgresql/18/main/PG_VERSION` is rejected
  at load time when a DD seal is in effect (loader invariant).
* **Directory creation under the parent of the sealed dir.** The
  DD seal is on `<dir>`'s inode, not on `<dir>`'s parent. To
  prevent siblings of `<dir>` being created, seal that ancestor
  separately.

### 7.4 Version requirement

The runtime kernel module must be at ABI v0.5 or higher. The current ABI
is v0.8 (`0x0008`).

`compartment-bpf observe` calls `detect_runtime_abi()`, which since
v0.6 reads the exact runtime ABI from `PIN_ROOT/maps/abi_version_map`
(an `ARRAY[1](__u32)` pinned with `LIBBPF_PIN_BY_NAME`; the loader
writes `COMPARTMENT_ABI_VERSION` to cell 0 when it pins). If the
returned value is in the supported range (`0x0004` ≤ abi ≤ the
compile-time `COMPARTMENT_ABI_VERSION`), it is used verbatim.

`seal_value` is **96 bytes** in v0.5 and remains 96 bytes through
v0.8 (ABI v0.6, v0.7 and v0.8 introduce new behaviour, new audit
actions and new hooks without changing the on-wire struct layout; the ABI header's
`_Static_assert(sizeof(struct seal_value) == 96, ...)` is the
authoritative size). The earlier
`seal_value` size probe (96-byte v0.4/v0.5 vs newer) is no longer
used: legacy pre-v0.6 pins that lack `abi_version_map` cannot be
disambiguated from map shape alone, so `detect_runtime_abi()`
fails safe to `0x0004` and emits only per-file fallback rules.

If `abi_version_map` is absent but a legacy pin is present
(`policy_state_map` exists), the helper emits a `WARNING` naming
the missing map and the safe fallback. If no pinned runtime is
detected at all, the helper falls back to the compile-time
`COMPARTMENT_ABI_VERSION` and warns that the emitted profile may
not match the running module.

The loader itself (`compartment-bpf --pin`) does not consult
`detect_runtime_abi()`. If a v0.5+ profile is loaded against a
kernel module built at an older ABI, the loader does **not**
refuse the profile — newer action bits will be present in the
seal records but the older module's `is_denied_action()` will not
recognise them, so they will be silently ignored. To avoid this
mismatch in practice, run a host where the kernel module and the
loader were built from the same checkout (the standard
`make && sudo make smoke` workflow guarantees this).

---

## 8. Cross-references

- `README.md` — design rationale + threat model overview.
- `LIMITATIONS.md` — threats out of scope, including LD_PRELOAD
  and ptrace.
- `profiles/README.md` — daemon profile collection + cocktail rule.
- `CHANGELOG.md` — release-oriented summary per ABI version.

---

## 9. Kernel stability test

The stability test suite (`tests/stability/`) validates that
compartment-bpf's BPF LSM enforcement remains stable under sustained
pin/unpin lifecycle churn concurrent with mesh trial execution. This
test class exists because synthetic code review cannot exercise
sustained kernel-state lifecycle stress against a real BPF substrate
— kernel races, memory leaks, and lifecycle bugs only manifest under
high-frequency real-substrate operation.

### 9.1 When to run

Run before any release and after any of the changes listed below.

Run after any change to: the `--pin`/`--unpin` lifecycle, BPF map
initialisation, task storage map management, audit ringbuf
configuration, the marker bridge lifecycle, or the loader's
attach→pin→exit sequence.

### 9.2 Running

```bash
# Quick smoke (64 cycles, ~1-2 min):
make check-stability-quick

# Full run (1024 cycles, ~45-60 min):
make check-stability

# Dual-profile variation (alternates between two profiles per cycle):
sudo DUAL_PROFILE=1 STAB_CYCLES=1024 bash tests/stability/pin-unpin-churn.sh

# Ad-hoc cadence (e.g. 16-cycle VM smoke):
sudo STAB_CYCLES=16 bash tests/stability/pin-unpin-churn.sh
```

All stability tests require root (for `--pin`/`--unpin`, dmesg access,
and bpffs cleanup). The harness `stab_skip`s with rc=77 on hosts
without root or BPF LSM, matching the project SKIP convention.

Two things the harness now does for you, because getting them wrong
produced a run that looked healthy and tested nothing:

* **It drives `--pin` the way the loader actually behaves.** `--pin`
  does not daemonise, fork or detach, and there is no
  `--daemonize`/`--background` flag: it attaches, writes the pins under
  `PIN_ROOT`, prints `[run] compartment-bpf live. ^C to exit.` and then
  blocks in the ringbuf poll loop. The pins outlive the process — that
  is the point — so each cycle starts it, waits for the pins to appear
  on bpffs, then signals and reaps it. The old harness waited for
  `--pin` to *exit* and declared a hang at cycle 0 of 64 on a perfectly
  healthy box.
* **It renders the profile against a real binary.**
  `tests/stability/baseline-profile{,-b}.conf` are templates:
  `@STAB_ACTOR@` / `@STAB_ACTOR_B@` are substituted with a purpose-built
  regular-file ELF (`tests/lib-realbin.sh`). They used to name
  `/usr/bin/true` and `/usr/bin/false`, which are symlinks on any distro
  shipping uutils coreutils (Ubuntu 26.04); the loader refuses a symlink
  leaf, so every seal failed to resolve and all 64 cycles pinned nothing
  while the run still reported the churn as healthy. T-STAB-8 now fails
  the run unless every cycle observed a live pin.

Loop B runs `tests/mesh/run-mesh.sh` concurrently, and its ME-10 phase
pins a daemon to read counter deltas back through `--stats`. `PIN_ROOT`
is one global namespace and `--unpin` sweeps all of it, so both sides
take the advisory mutex in `tests/lib-pinlock.sh` around their pinned
window. Without it, the churn deleted the maps ME-10 was measuring and
the run failed with `deny_total-delta(exp=1,got=0)` rows that had
nothing to do with enforcement.

### 9.3 Acceptance criteria

| ID | Check | Gate |
|----|-------|------|
| T-STAB-1 | No kernel taint, oops, BUG, soft_lockup, hung_task, RCU stall during run | Hard FAIL |
| T-STAB-2 | compartment-bpf RSS growth < 50 MB; kernel `bpf_*` slab plateaus | FAIL |
| T-STAB-3 | `/sys/fs/bpf/compartment/` empty after final `--unpin` | FAIL |
| T-STAB-4 | Mesh trials ≥ 99% pass-rate during churn | FAIL |
| T-STAB-5 | All 10 corner-case witnesses pass or documented-skip | FAIL on any FAIL |
| T-STAB-6 | No stuck-state (D-state survivor, mesh outer timeout) | FAIL |
| T-STAB-7 | BPF prog/map counts return to baseline (±4) — the harness prints this assertion under the `T-STAB-4` label, alongside the mesh aggregate | FAIL |
| T-STAB-8 | Every churn cycle observed a live pin under `PIN_ROOT/links` | FAIL |

### 9.4 Failure handling

Evidence for any T-STAB-* FAIL is captured to
`tests/stability/results/<UTC>/`:

- `loop-a.log` — every pin/unpin cycle's rc and timing
- `mesh-iter-*.log` — per-iteration mesh runner output
- `dmesg-new.txt` — kernel log lines added during the run
- `bpffs-residue.txt` — listing of leftover pinned objects
- `dstate.txt` — D-state process survey
- `RESULTS.md` — human-readable summary

Do not ship a release while any T-STAB-* is in FAIL.
Classify a FAIL as either a v0.x bug or
a v0.5 documented limit (add to `LIMITATIONS.md` and re-evaluate the
gate language).
