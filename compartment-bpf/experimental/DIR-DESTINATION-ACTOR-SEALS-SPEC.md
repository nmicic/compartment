# compartment-bpf - Directory Destination Actor Seal SPEC

> Status: draft v0.1, 2026-05-15
> Audience: implementers, reviewers, mesh-test authors
> Companions:
> - `experimental/EXEC-DOMAIN-SPEC.md`
> - `experimental/exec-domain-mesh/EXEC-DOMAIN-MESH-DRAFT.md`
> - `experimental/ACTOR-FS-OBSERVE-SPEC.md`
> - `compartment-abi.h`
> Goal: align directory seal semantics with the intended exec-domain
> model: DENY on destination, ACCEPT for declared actor.

## 1. Problem

The intended mental model is iptables-like:

```
default: DENY operation on destination
rule:    ACCEPT source actor -> destination directory
```

For a database directory, the operator wants:

```
actor mysqld = /usr/sbin/mysqld
seal /var/lib/mysql no-write no-unlink no-rename no-chmod actor=mysqld
```

Meaning:

> Only `mysqld` can create files in `/var/lib/mysql`, write existing
> direct child files in `/var/lib/mysql`, structurally mutate entries
> in `/var/lib/mysql`, or change metadata on direct children in
> `/var/lib/mysql`.

Current code and docs do not fully provide that meaning.

## 2. Current behavior

Current parent-directory enforcement covers structural operations:

- create file in sealed dir
- mkdir/mknod/symlink/link into sealed dir
- rename into/out of sealed dir
- unlink/rmdir child of sealed dir

But current write-open/truncate/mmap/mprotect enforcement checks the
target file inode, not the target file's parent directory. In code:

```
deny_file_write(file):
    inode = file->f_inode
    deny_inode_action(inode, SEAL_NO_WRITE, ...)
```

So:

```
seal /var/lib/mysql no-write actor=mysqld
```

blocks non-actor creation under `/var/lib/mysql`, but does not block a
non-actor write to an already-existing `/var/lib/mysql/ibdata1` unless
`ibdata1` itself is also sealed.

The mesh suite currently reflects this non-hierarchical model in
`ME-16`: it explicitly records that a write to a grandchild under a
sealed directory is allowed. That is useful as a regression witness for
the old model, but it is not the destination-directory model requested
here.

## 3. Desired v0.x semantics

Directory seals should apply to the sealed directory as a destination
for immediate children.

### 3.1 `no-write` on directory

For:

```
seal /D no-write actor=A
```

These operations on immediate children of `/D` are denied unless the
caller matches actor `A`:

- `open(O_WRONLY)`
- `open(O_RDWR)`
- `open(O_TRUNC)`
- `open(O_APPEND)` when write-capable
- `write` through an fd that reaches `file_permission`
- `truncate`
- `ftruncate`
- shared writable `mmap`
- `mprotect` adding shared write
- create/link/rename into `/D` (already mostly implemented)

Actor `A` is allowed through the same actor allowlist path used for
file seals.

If the directory seal also carries `strict-launch`, both conditions
must hold for immediate-child write operations:

- caller matches actor `A`;
- caller has a valid strict-launch marker for `A`.

`no-write` on `/D` does not itself define operations on `/D` as an
inode. Metadata on `/D` belongs to `no-chmod` on `/D`; rename/unlink
of `/D` belongs to seals on `/D`'s parent or an explicit inode seal on
`/D`.

### 3.2 `no-chmod` on directory

For:

```
seal /D no-chmod actor=A
```

These operations on `/D` itself and immediate children of `/D` are
denied unless caller matches actor `A`:

- chmod
- chown
- setxattr
- removexattr

### 3.3 `no-unlink` and `no-rename` on directory

Current parent-directory handling is already close to the desired
model:

- `no-unlink` blocks unlink/rmdir/removal of entries from `/D`.
- `no-rename` blocks rename out of `/D`.
- `no-write` blocks rename into `/D`.

The implementation should keep these semantics.

### 3.4 `full` on directory

`full` remains shorthand for:

```
no-write no-unlink no-rename no-chmod
```

On a directory, `full` composes all four directory-destination
semantics:

- structural denies under the directory;
- write denies on immediate child files;
- metadata denies on the directory and immediate child files;
- actor/strict-launch allowlist behavior when present.

### 3.5 No syntax change

No new profile syntax is required. Existing lines:

```
seal /D no-write actor=A
seal /D full actor=A strict-launch
```

automatically receive directory-destination semantics when `/D` is a
directory. The loader's existing file-vs-directory split
(`sealed_inodes` vs. `sealed_dirs`) is preserved. The change is in the
file-operation and metadata hooks consulting `sealed_dirs` in addition
to `sealed_inodes`.

## 4. Scope decision: one-level now, recursive later

This SPEC intentionally defines one-level destination semantics.

`seal /var/lib/mysql ...` applies to:

```
/var/lib/mysql/file
/var/lib/mysql/newfile
/var/lib/mysql/subdir       # metadata/structural entry in parent
```

It does not automatically apply to:

```
/var/lib/mysql/db1/table.ibd
```

unless `/var/lib/mysql/db1` is also sealed or a future recursive
subtree primitive is implemented.

This keeps v0.x KISS and matches the phrase "destination directory"
without silently adding expensive recursive ancestry walks to every
write operation.

For database trees, profile generation can emit one directory seal per
observed data subdirectory:

```
seal /var/lib/mysql       no-write no-unlink no-rename no-chmod actor=mysqld
seal /var/lib/mysql/db1   no-write no-unlink no-rename no-chmod actor=mysqld
seal /var/lib/mysql/db2   no-write no-unlink no-rename no-chmod actor=mysqld
```

Future work can add:

```
seal /var/lib/mysql recursive no-write actor=mysqld
```

but that is a separate feature with separate performance and mount
namespace review.

## 5. Implementation sketch

### 5.1 Parent directory lookup for file write hooks

Add a helper:

```
deny_file_parent_dir_action(file, mask, action, cid):
    dentry = BPF_CORE_READ(file, f_path.dentry)
    if (!dentry)
        return 0

    parent = BPF_CORE_READ(dentry, d_parent)
    if (!parent || parent == dentry)
        return 0

    dir_inode = BPF_CORE_READ(parent, d_inode)
    if (!dir_inode)
        return 0

    return deny_parent_dir_action(dir_inode, mask, action, cid)
```

Then change:

```
deny_file_write(file):
    deny_inode_action(file->f_inode, SEAL_NO_WRITE, ACTION_DENY_WRITE)
    deny_file_parent_dir_action(file, SEAL_NO_WRITE,
                                ACTION_DENY_WRITE_PARENT_DIR)
```

This automatically covers:

- `file_open`
- `file_permission`
- `file_truncate`
- `mmap_file`
- `file_mprotect`

because all of them already flow through `deny_file_write()`.

Destination semantics use the parent dentry at the time of the
file-operation check. They do not snapshot the open-time parent. A file
renamed during an open-fd lifetime can therefore change which directory
seal applies to later writes. This is the KISS v0.x choice; open-time
parent capture would require per-file storage and a separate review.

### 5.2 Parent directory lookup for inode metadata hooks

For `inode_setattr`, after checking the target inode seal:

- if `ATTR_SIZE`, check parent directory `SEAL_NO_WRITE` with
  `ACTION_DENY_WRITE_PARENT_DIR`;
- if `ATTR_MODE | ATTR_UID | ATTR_GID`, check parent directory
  `SEAL_NO_CHMOD` with `ACTION_DENY_CHMOD_PARENT_DIR`;
- if any other `ATTR_*` bit is set, default to parent directory
  `SEAL_NO_CHMOD` with `ACTION_DENY_CHMOD_PARENT_DIR`.

For `inode_setxattr` and `inode_removexattr`, after checking the
target inode seal, check parent directory `SEAL_NO_CHMOD` with
`ACTION_DENY_CHMOD_PARENT_DIR`.

Defaulting unclassified `ATTR_*` bits to `no-chmod` keeps future
metadata flags fail-closed without redefining `no-write`. Timestamp
updates (`utimensat`, `touch`) are metadata in this model; use
`no-chmod` or `full` if timestamp mutation must be denied.

### 5.3 Audit target

When a parent-directory rule denies a child operation, the audit event
should identify the directory seal that made the decision, not only the
child inode. This matches existing `deny_parent_dir_action()` behavior
and keeps "which policy line fired?" diagnosable.

If later users need child-path visibility too, add optional sampled
observe output. Do not overload the enforcement audit event first.

Parent-directory destination denies need distinct action codes so
operators and tests can tell which rule fired:

```
ACTION_DENY_WRITE_PARENT_DIR
ACTION_DENY_CHMOD_PARENT_DIR
```

This requires the normal ABI cascade:

- bump `COMPARTMENT_ABI_VERSION`;
- add action constants and static asserts in `compartment-abi.h`;
- update userspace `action_name()`;
- update ringbuf decoder tests;
- update the ABI-version mismatch witness in the same style as the
  v0.4 strict-launch promotion.

## 6. Mesh and matrix changes

The existing mesh does not currently gate this desired behavior.

Required new rows:

### 6.1 Direct child write under sealed dir

```
actor a1 = /path/to/a1
seal /tmp/D no-write actor=a1

a1 writes /tmp/D/leaf        -> ALLOW
b1 writes /tmp/D/leaf        -> DENY
b1 truncates /tmp/D/leaf     -> DENY
b1 mmap-writes /tmp/D/leaf   -> DENY
```

### 6.2 Direct child metadata under sealed dir

```
seal /tmp/D no-chmod actor=a1

a1 chmod /tmp/D/leaf         -> ALLOW
b1 chmod /tmp/D/leaf         -> DENY
b1 chown /tmp/D/leaf         -> DENY
b1 setxattr /tmp/D/leaf      -> DENY
```

### 6.3 Grandchild remains explicit no-go for v0.x

```
seal /tmp/D no-write actor=a1

b1 writes /tmp/D/sub/leaf    -> ALLOW in v0.x unless /tmp/D/sub is also sealed
```

This row must be loud, not hidden. It documents the one-level scope and
keeps future recursive-subtree work from silently changing semantics.

### 6.4 Current ME-16 update

ME-16 currently says:

> Grandchild file is not sealed; writes ALLOW regardless of caller.

Keep that row for grandchild behavior, but add a new direct-child row
that must deny for non-actors. The old row is not wrong for recursive
scope; it is incomplete for one-level destination directory scope.

Concrete fixture amendment:

```
existing: /me16/hier/sealed-root/child/leaf.txt   # grandchild, stays ALLOW
new:      /me16/hier/sealed-root/leaf.txt         # direct child

a1 write /me16/hier/sealed-root/leaf.txt -> ALLOW
b1 write /me16/hier/sealed-root/leaf.txt -> DENY
```

### 6.5 Symlink child invariant witness

Pre-stage:

```
mkdir /tmp/D
touch /tmp/outside
ln -s /tmp/outside /tmp/D/link
seal /tmp/D no-write actor=a1
```

Without the loader invariant in section 8, opening `/tmp/D/link` for
write resolves to `/tmp/outside`; the parent directory check sees
`/tmp`, not `/tmp/D`. The enforcement hook cannot recover the original
symlink path.

Expected result: loader refuses the profile before attach.

### 6.6 Hardlink child invariant witness

Pre-stage:

```
mkdir /tmp/D
touch /tmp/D/leaf
ln /tmp/D/leaf /tmp/alias
seal /tmp/D no-write actor=a1
```

Without the loader invariant in section 8, writing via `/tmp/alias`
uses parent `/tmp`, not `/tmp/D`, and bypasses the destination check.
Runtime `inode_link` source checks prevent new aliases after policy
load; this witness covers aliases that already exist before load.

Expected result: loader refuses the profile before attach.

## 7. Profile-generation impact

`ACTOR-FS-OBSERVE-SPEC.md` should prefer directory destination rules
once this feature lands:

```
seal /var/lib/mysql no-write no-unlink no-rename no-chmod actor=mysqld
```

for immediate children, and additional directory seals for observed
subdirectories. It should not emit one per-file seal for every existing
child if a one-level directory destination rule is sufficient.

For recursive data trees, observe mode should emit:

```
# observed subdirectories:
seal /var/lib/mysql/db1 no-write no-unlink no-rename no-chmod actor=mysqld
seal /var/lib/mysql/db2 no-write no-unlink no-rename no-chmod actor=mysqld
```

until a real recursive-subtree feature exists.

The generator should also surface section 8 load-time invariants. If
observed directories contain symlinks or non-directory children with
`st_nlink > 1`, the candidate profile must carry a review warning or
refuse strict destination output.

## 8. Load-time invariants

Directory-destination semantics require two loader-side checks before
the BPF program attaches. These are strict-mode invariants, not runtime
best-effort warnings.

### 8.1 No symlink children

For every sealed directory `/D`, the loader must scan immediate
children and refuse the profile if any child is a symlink.

Reason: `open("/D/link", O_WRONLY)` resolves the symlink before the
file hook sees `file->f_path`. If the link points outside `/D`, the
parent-dentry check observes the external parent and cannot know that
the original path was under `/D`.

Future designs may allow symlinks only after proving target containment
and race safety. v0.x should refuse all immediate symlink children for
KISS and security.

### 8.2 No hardlinked non-directory children

For every sealed directory `/D`, the loader must scan immediate
children and refuse the profile if any non-directory child has
`st_nlink > 1`.

Reason: an alias outside `/D` can write the same inode through an
unsealed parent path. Runtime `inode_link` checks prevent creation of
new aliases after policy load, but they do not remove pre-existing
aliases.

Directories normally have link counts greater than one because of
subdirectories; do not reject directories solely because of `st_nlink`.
The invariant applies to regular files and other non-directory child
inodes.

Both invariants are operator-fixable before pinning:

- replace symlinks with real files/directories or seal the real target
  directory explicitly;
- replace hardlinked files with copies or seal every known alias parent.

## 9. Performance expectation

The one-level implementation adds one parent-dentry read and one
`sealed_dirs` map lookup to write/metadata hooks. On actor-bound seals
it can also run the bounded actor scan, capped at
`COMPARTMENT_MAX_ACTORS_PER_SEAL`.

This is far cheaper than recursive ancestry walking and only affects
write-capable and metadata-mutating paths.

Required benchmark:

- existing file write/open baseline;
- file write/open with direct file seal;
- file write/open with parent directory destination seal;
- actor match vs actor mismatch;
- no matching parent directory seal.

Regression gate:

- goal: incremental write-path overhead <= 3% vs current exec-domain
  enforcement;
- halt/review: >5% incremental overhead on the same kernel and VM.

## 10. Decision

Yes, this is a real gap relative to the desired exec-domain model.

The current implementation is internally consistent with the current
docs, but the docs/code/tests do not match the stronger directory
destination rule the operator intended.

Recommended next step:

1. Add section 8 loader invariants.
2. Add parent-dir destination action codes and ABI bump.
3. Implement one-level parent-directory write/metadata checks with the
   null/root-dentry guards in section 5.
4. Add mesh rows in section 6.
5. Run the section 9 benchmark gate.
6. Update `EXEC-DOMAIN-SPEC.md` directory semantics.
7. Update observe/profile-generation docs to emit directory
   destination rules instead of per-file rules when one-level scope is
   sufficient.
