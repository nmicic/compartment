// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
//
// mesh_stub_main — shared op dispatcher for exec-domain mesh stubs.
//
// argv: <op> <target_path> [arg2]
//
// Exit codes (collapsed subset of tests/sealprobe.c):
//   0  ALLOW    — syscall succeeded
//   1  DENY     — EACCES or EPERM (compartment-bpf denial path)
//   2  ERROR    — usage error, stage failure, or unexpected errno
//
// The mesh harness consults the §2.2 4-quadrant predict table and
// compares the predicted ALLOW/DENY against the stub's exit code.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include "mesh_stub_main.h"

enum { RC_ALLOW = 0, RC_DENY = 1, RC_ERROR = 2 };

static int do_op(int argc, char **argv);
static void uniq_suffix(char *out, size_t n, const char *tag);

static int classify(int rc, int err)
{
	if (rc == 0)
		return RC_ALLOW;
	if (err == EACCES || err == EPERM)
		return RC_DENY;
	return RC_ERROR;
}

static int op_open_ro(const char *p)
{
	int fd = open(p, O_RDONLY | O_CLOEXEC);
	int err = errno;
	if (fd >= 0) { close(fd); return RC_ALLOW; }
	return classify(-1, err);
}

static int op_open_wronly(const char *p)
{
	int fd = open(p, O_WRONLY | O_CLOEXEC);
	int err = errno;
	if (fd >= 0) { close(fd); return RC_ALLOW; }
	return classify(-1, err);
}

static int op_open_rdwr(const char *p)
{
	int fd = open(p, O_RDWR | O_CLOEXEC);
	int err = errno;
	if (fd >= 0) { close(fd); return RC_ALLOW; }
	return classify(-1, err);
}

static int op_write(const char *p)
{
	int fd = open(p, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return classify(-1, errno);
	ssize_t n = write(fd, "x", 1);
	int err = errno;
	close(fd);
	if (n == 1)
		return RC_ALLOW;
	return classify(-1, err);
}

static int op_truncate(const char *p)
{
	int rc = truncate(p, 0);
	return classify(rc, errno);
}

static int op_ftruncate(const char *p)
{
	int fd = open(p, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return classify(-1, errno);
	int rc = ftruncate(fd, 0);
	int err = errno;
	close(fd);
	return classify(rc, err);
}

static int op_mmap_write(const char *p)
{
	int fd = open(p, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return classify(-1, errno);
	void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			  MAP_SHARED, fd, 0);
	int err = errno;
	close(fd);
	if (addr == MAP_FAILED)
		return classify(-1, err);
	munmap(addr, 4096);
	return RC_ALLOW;
}

static int op_unlink(const char *p)
{
	int rc = unlink(p);
	return classify(rc, errno);
}

static int op_open_trunc(const char *p)
{
	int fd = open(p, O_WRONLY | O_TRUNC | O_CLOEXEC);
	int err = errno;
	if (fd >= 0) { close(fd); return RC_ALLOW; }
	return classify(-1, err);
}

static int op_open_append(const char *p)
{
	int fd = open(p, O_WRONLY | O_APPEND | O_CLOEXEC);
	int err = errno;
	if (fd >= 0) { close(fd); return RC_ALLOW; }
	return classify(-1, err);
}

// op_mprotect: open RDWR, mmap MAP_SHARED PROT_READ, mprotect to add
// PROT_WRITE. file_mprotect hook fires only on MAP_SHARED + PROT_WRITE
// addition. Seal with SEAL_NO_WRITE → DENY at mprotect (EACCES).
static int op_mprotect(const char *p)
{
	int fd = open(p, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return classify(-1, errno);
	void *addr = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
	int err = errno;
	close(fd);
	if (addr == MAP_FAILED)
		return classify(-1, err);
	int rc = mprotect(addr, 4096, PROT_READ | PROT_WRITE);
	err = errno;
	munmap(addr, 4096);
	return classify(rc, err);
}

// op_use_fd_write_op: open(O_RDWR) + write via fd. Distinguishes from
// op_write (O_WRONLY) by file mode — exercises file_permission on a
// RDWR fd's MAY_WRITE check.
static int op_use_fd_write_op(const char *p)
{
	int fd = open(p, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return classify(-1, errno);
	ssize_t n = write(fd, "z", 1);
	int err = errno;
	close(fd);
	if (n == 1)
		return RC_ALLOW;
	return classify(-1, err);
}

// op_link_src: link(p, p.linked-XXXXXX). The SOURCE inode is sealed
// with SEAL_NO_WRITE; R2-F11 makes inode_link check the source's
// SEAL_NO_WRITE flag and DENY if caller is not in the seal's actor
// list. Destination is a fresh path under /tmp (not sealed).
static int op_link_src(const char *p)
{
	char dst[4096];
	int n = snprintf(dst, sizeof(dst), "%s.linked-%d", p, (int)getpid());
	if (n < 0 || (size_t)n >= sizeof(dst))
		return RC_ERROR;
	unlink(dst);  // best-effort cleanup; ignore rc.
	int rc = link(p, dst);
	int err = errno;
	if (rc == 0) {
		unlink(dst);
		return RC_ALLOW;
	}
	return classify(-1, err);
}

static int op_rename(const char *src, const char *dst)
{
	int rc = rename(src, dst);
	return classify(rc, errno);
}

// op_link_src_dst: link(src, dst_parent/uniq). Used by ME-17(b) BOTH-sealed
// where src is sealed AND dst-parent dir is sealed (different dirs). Both
// source and dest-parent checks fire in comp_inode_link; source check
// evaluated first per compartment.bpf.c L656-664. Single-trial witness of
// the AND-of-both ordering.
static int op_link_src_dst(const char *src, const char *dst_parent)
{
	char dst[4096], suf[64];
	uniq_suffix(suf, sizeof(suf), "linkboth");
	if (snprintf(dst, sizeof(dst), "%s/%s", dst_parent, suf) >= (int)sizeof(dst))
		return RC_ERROR;
	int rc = link(src, dst);
	int err = errno;
	if (rc == 0) {
		unlink(dst);
		return RC_ALLOW;
	}
	return classify(-1, err);
}

// Per-call unique suffix for child-path ops below. Embeds pid + ns clock so
// concurrent invocations from different stubs and back-to-back same-pid
// trials all pick distinct names (the harness's mkdir-then-rmdir trial
// can otherwise collide if a previous DENY left the subdir behind).
static void uniq_suffix(char *out, size_t n, const char *tag)
{
	struct timespec ts = {0};
	clock_gettime(CLOCK_REALTIME, &ts);
	snprintf(out, n, "%s-%d-%ld%09ld",
		 tag, (int)getpid(), (long)ts.tv_sec, (long)ts.tv_nsec);
}

// Dir-level ops below operate on a SEALED PARENT DIR `p`. The stub
// constructs a unique child path under `p` and exercises the relevant
// LSM hook. Predict: ALLOW iff caller is in the parent dir's seal's
// actor allowlist (and the seal flag fires on this op).

// op_mkdir_in: mkdir(p/child-<unique>). Hooks: inode_mkdir → parent NO_WRITE.
static int op_mkdir_in(const char *p)
{
	char sub[4096], suf[64];
	uniq_suffix(suf, sizeof(suf), "mkdir");
	if (snprintf(sub, sizeof(sub), "%s/%s", p, suf) >= (int)sizeof(sub))
		return RC_ERROR;
	int rc = mkdir(sub, 0755);
	int err = errno;
	if (rc == 0) {
		rmdir(sub);                   // best-effort cleanup.
		return RC_ALLOW;
	}
	return classify(-1, err);
}

// op_rmdir_in: mkdir(sub) then rmdir(sub). Hooks: inode_mkdir is allowed
// because the parent seal carries NO_UNLINK (not NO_WRITE); inode_rmdir
// → parent NO_UNLINK → DENY for non-actor callers. The two-step setup-
// then-test pattern requires the parent's seal to OMIT NO_WRITE; the
// harness builds a dedicated `no-unlink` dir pool for rmdir trials.
static int op_rmdir_in(const char *p)
{
	char sub[4096], suf[64];
	uniq_suffix(suf, sizeof(suf), "rmdir");
	if (snprintf(sub, sizeof(sub), "%s/%s", p, suf) >= (int)sizeof(sub))
		return RC_ERROR;
	if (mkdir(sub, 0755) < 0) {
		int err = errno;
		// Setup mkdir failed — if it's EACCES the parent seal blocked
		// CREATE (test misconfigured: should be NO_UNLINK-only); surface
		// as ERROR so harness sees the misclassification, not a fake DENY.
		(void)err;
		return RC_ERROR;
	}
	int rc = rmdir(sub);
	int err = errno;
	if (rc == 0)
		return RC_ALLOW;
	// rmdir DENIED: subdir is left behind. Cleanup is impossible for
	// outsiders; the harness's tmpdir reap on exit clears it.
	return classify(-1, err);
}

// op_mknod_in: mknod(p/fifo-<unique>, S_IFIFO|0644). Non-root mknod with
// S_IFIFO is permitted by the kernel (it's `mkfifo`); the LSM hook
// inode_mknod still fires → parent NO_WRITE.
static int op_mknod_in(const char *p)
{
	char sub[4096], suf[64];
	uniq_suffix(suf, sizeof(suf), "fifo");
	if (snprintf(sub, sizeof(sub), "%s/%s", p, suf) >= (int)sizeof(sub))
		return RC_ERROR;
	int rc = mknod(sub, S_IFIFO | 0644, 0);
	int err = errno;
	if (rc == 0) {
		unlink(sub);
		return RC_ALLOW;
	}
	return classify(-1, err);
}

// op_symlink_in: symlink(some-target, p/sym-<unique>). Hooks: inode_symlink
// → parent NO_WRITE. Symlink target string is arbitrary and not resolved
// at create time.
static int op_symlink_in(const char *p)
{
	char sub[4096], suf[64];
	uniq_suffix(suf, sizeof(suf), "sym");
	if (snprintf(sub, sizeof(sub), "%s/%s", p, suf) >= (int)sizeof(sub))
		return RC_ERROR;
	int rc = symlink("/nonexistent-mesh-target", sub);
	int err = errno;
	if (rc == 0) {
		unlink(sub);
		return RC_ALLOW;
	}
	return classify(-1, err);
}

// op_symlink_persistent: symlink(target, parent/persist-sym). HIGH-8
// (mesh Review-1): seq5's "actor creates a fresh alias to the same
// sealed target" property requires (a) a caller-specified target (not
// a hardcoded /nonexistent path) and (b) the new alias persisting
// past the create syscall so a downstream step can probe through it.
// op_symlink_in hardcodes "/nonexistent-mesh-target" and unlink()s
// the new symlink — leaving seq5 unable to witness the dynamic-alias
// seal-follow property. Deterministic alias name ("persist-sym")
// rather than uniq_suffix so the harness can address the new alias
// without capturing stdout.
static int op_symlink_persistent(const char *parent, const char *target)
{
	char sub[4096];
	if (snprintf(sub, sizeof(sub), "%s/persist-sym", parent)
	    >= (int)sizeof(sub))
		return RC_ERROR;
	// Best-effort unlink stale alias from a previous run; ignore
	// errors (the inode is unsealed unsealed-parent, so unlink is
	// always permitted by the LSM).
	(void)unlink(sub);
	int rc = symlink(target, sub);
	int err = errno;
	if (rc == 0)
		return RC_ALLOW;
	return classify(-1, err);
}

// op_link_dest_in: link(unsealed_src, p/dst-<unique>). Source is created
// fresh inside the stub (under /tmp; not sealed). Hooks: inode_link →
// parent NO_WRITE on destination dir. Source-side NO_WRITE check is
// also fired (R2-F11) but the source isn't sealed, so only the parent-
// dir seal can DENY.
static int op_link_dest_in(const char *p)
{
	char src[4096], dst[4096], suf[64];
	uniq_suffix(suf, sizeof(suf), "linkdest");
	if (snprintf(src, sizeof(src), "/tmp/mesh-linksrc-%s", suf) >= (int)sizeof(src))
		return RC_ERROR;
	if (snprintf(dst, sizeof(dst), "%s/%s", p, suf) >= (int)sizeof(dst))
		return RC_ERROR;
	int fd = open(src, O_WRONLY | O_CREAT | O_EXCL, 0644);
	if (fd < 0)
		return RC_ERROR;
	close(fd);
	int rc = link(src, dst);
	int err = errno;
	if (rc == 0) {
		unlink(dst);
		unlink(src);
		return RC_ALLOW;
	}
	unlink(src);
	return classify(-1, err);
}

// op_creat_in_parent: open(p/file-<unique>, O_WRONLY|O_CREAT|O_EXCL).
// Hooks: inode_create → parent NO_WRITE. Distinct from op_open_wronly
// (file-level NO_WRITE) by virtue of creating the inode rather than
// opening an existing one.
static int op_creat_in_parent(const char *p)
{
	char sub[4096], suf[64];
	uniq_suffix(suf, sizeof(suf), "creat");
	if (snprintf(sub, sizeof(sub), "%s/%s", p, suf) >= (int)sizeof(sub))
		return RC_ERROR;
	int fd = open(sub, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	int err = errno;
	if (fd >= 0) {
		close(fd);
		unlink(sub);
		return RC_ALLOW;
	}
	return classify(-1, err);
}

// op_open_through_symlink: open(symlink, O_WRONLY). The kernel resolves
// the symlink before the LSM file_open hook fires; LSM sees the target
// inode. Test parameter is the symlink path; the target is whatever
// path the harness pointed it at (e.g., a sealed file).
static int op_open_through_symlink(const char *p)
{
	int fd = open(p, O_WRONLY | O_CLOEXEC);
	int err = errno;
	if (fd >= 0) { close(fd); return RC_ALLOW; }
	return classify(-1, err);
}

// op_link_symlink_src: link(symlink_p, /tmp/dst-<unique>). POSIX link(2)
// does NOT follow symlinks (linkat with AT_SYMLINK_FOLLOW would); the
// source inode at the LSM hook is the SYMLINK'S OWN inode, not its
// resolved target. So a seal on the symlink target does NOT fire via
// inode_link's source-check (R2-F11). Predict: ALLOW for unsealed
// symlink → unsealed /tmp dst, regardless of what the symlink points to.
static int op_link_symlink_src(const char *p)
{
	char dst[4096], suf[64];
	uniq_suffix(suf, sizeof(suf), "linksym");
	if (snprintf(dst, sizeof(dst), "/tmp/mesh-linksymdst-%s", suf) >= (int)sizeof(dst))
		return RC_ERROR;
	unlink(dst);                          // best-effort cleanup.
	int rc = link(p, dst);                // link(2) does not follow symlinks.
	int err = errno;
	if (rc == 0) {
		unlink(dst);
		return RC_ALLOW;
	}
	return classify(-1, err);
}

static int op_chmod(const char *p)
{
	int rc = chmod(p, 0644);
	return classify(rc, errno);
}

static int op_chown(const char *p)
{
	// Pass concrete uid/gid (the caller's own) rather than (-1, -1):
	// chown(p, -1, -1) is a no-op that the kernel short-circuits BEFORE
	// inode_setattr fires, so the LSM hook never sees the call and the
	// seal can't deny it. Matches tests/sealprobe.c:do_chown convention.
	int rc = chown(p, getuid(), getgid());
	return classify(rc, errno);
}

static int op_setxattr(const char *p)
{
	int rc = setxattr(p, "user.mesh", "v", 1, 0);
	return classify(rc, errno);
}

// op_inotify_watch: inotify_init1 + inotify_add_watch(p). compartment-bpf
// has no LSM hook for inotify-watch registration — it reads metadata,
// doesn't modify the inode. Predict ALLOW for every caller against
// every path (sealed or not). ME-24 §3.24 information-disclosure
// boundary witness.
static int op_inotify_watch(const char *p)
{
	int fd = inotify_init1(IN_CLOEXEC);
	if (fd < 0)
		return classify(-1, errno);
	int wd = inotify_add_watch(fd, p, IN_ALL_EVENTS);
	int err = errno;
	if (wd >= 0) {
		inotify_rm_watch(fd, wd);
		close(fd);
		return RC_ALLOW;
	}
	close(fd);
	return classify(-1, err);
}

static int op_removexattr(const char *p)
{
	int rc = removexattr(p, "user.mesh");
	if (rc < 0 && errno == ENODATA) {
		// Attribute was never set on this fixture. The harness
		// tolerates this for the DENY-expected path (EACCES still
		// fires before the kernel checks for attribute presence)
		// but here we got past the LSM hook and into the FS layer.
		// ENODATA is a downstream "no such attr" — treat as ALLOW.
		return RC_ALLOW;
	}
	return classify(rc, errno);
}

// Wait helper: collect child status and collapse to RC_ALLOW/DENY/ERROR
// using the child's own exit code (the child already ran do_op or exec'd
// a stub that ran do_op, so its exit code is in our 0/1/2 vocabulary).
static int wait_child_rc(pid_t pid)
{
	int status;
	if (waitpid(pid, &status, 0) < 0)
		return RC_ERROR;
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return RC_ERROR;
}

// op_fork_no_exec — parent forks, child runs <sub_op> <target> [arg2]
// in-process via do_op(). E-4 sub-case 1: child inherits parent's
// exe_file; from the LSM hook's perspective the caller's exe inode is
// the parent's binary, so actor-group membership is preserved.
//
// argv: [prog, "fork-no-exec", sub_op, target, optional_arg2]
static int op_fork_no_exec(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "fork-no-exec needs <sub_op> <target> [arg2]\n");
		return RC_ERROR;
	}
	pid_t pid = fork();
	if (pid < 0)
		return RC_ERROR;
	if (pid == 0) {
		// Reshape argv: [prog, sub_op, target, opt_arg2].
		char *sub[5];
		sub[0] = argv[0];
		sub[1] = argv[2];
		sub[2] = argv[3];
		int sub_argc = 3;
		if (argc >= 5) {
			sub[3] = argv[4];
			sub_argc = 4;
		}
		sub[sub_argc] = NULL;
		_exit(do_op(sub_argc, sub));
	}
	return wait_child_rc(pid);
}

// op_fork_exec — parent forks, child execs <exec_path> with
// [exec_path, sub_op, target, optional_arg2]. After execve the child's
// exe inode is now <exec_path>'s inode (E-4 sub-cases 2 & 3).
//
// argv: [prog, "fork-exec", exec_path, sub_op, target, optional_arg2]
static int op_fork_exec(int argc, char **argv)
{
	if (argc < 5) {
		fprintf(stderr, "fork-exec needs <exec_path> <sub_op> <target> [arg2]\n");
		return RC_ERROR;
	}
	pid_t pid = fork();
	if (pid < 0)
		return RC_ERROR;
	if (pid == 0) {
		char *eargv[6];
		eargv[0] = argv[2];
		eargv[1] = argv[3];
		eargv[2] = argv[4];
		int eargc = 3;
		if (argc >= 6) {
			eargv[3] = argv[5];
			eargc = 4;
		}
		eargv[eargc] = NULL;
		execv(argv[2], eargv);
		_exit(RC_ERROR);
	}
	return wait_child_rc(pid);
}

// op_exec_via_bash — child execve's /bin/bash -c '<cmd>' where cmd is
// built from a sub_op + target template. Used by T-X5 (§3.5) interpreter
// chain: after execve, the child's exe inode is bash's inode (NOT in
// any actor group), so the LSM hook must DENY on the sealed target.
//
// Bash hides errno on syscall failure; classify by exit code:
//   bash rc == 0      → command succeeded → ALLOW
//   bash rc != 0      → command failed; we attribute to LSM denial.
//   Since the sole reason these commands fail in the mesh context is
//   compartment-bpf returning EACCES, this mapping is sound.
//
// argv: [prog, "exec-via-bash", sub_op, target]
static int op_exec_via_bash(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "exec-via-bash needs <sub_op> <target>\n");
		return RC_ERROR;
	}
	const char *sub_op = argv[2];
	const char *target = argv[3];
	// Target paths are mktemp-d-controlled; no single-quote risk.
	char cmd[4096];
	if (!strcmp(sub_op, "write"))
		snprintf(cmd, sizeof(cmd), "printf x > '%s'", target);
	else if (!strcmp(sub_op, "unlink"))
		snprintf(cmd, sizeof(cmd), "rm -f -- '%s'", target);
	else if (!strcmp(sub_op, "chmod"))
		// Use 0600 (not 0644) so GNU coreutils chmod doesn't detect
		// "same mode" and skip fchmodat(); we need the syscall to fire
		// so the LSM inode_setattr hook actually gets called. Files
		// created by ': > fpath' default to 0644 (umask 022); a 0600
		// target forces the chmod syscall.
		snprintf(cmd, sizeof(cmd), "chmod 600 '%s'", target);
	else {
		fprintf(stderr, "exec-via-bash: unsupported sub_op: %s\n", sub_op);
		return RC_ERROR;
	}

	pid_t pid = fork();
	if (pid < 0)
		return RC_ERROR;
	if (pid == 0) {
		execl("/bin/bash", "bash", "-c", cmd, (char *)NULL);
		_exit(RC_ERROR);
	}
	int status;
	if (waitpid(pid, &status, 0) < 0)
		return RC_ERROR;
	if (!WIFEXITED(status))
		return RC_ERROR;
	int rc = WEXITSTATUS(status);
	if (rc == 0)
		return RC_ALLOW;
	return RC_DENY;
}

// op_open_then_exec — open(target, O_WRONLY) → fd; dup2 to FD_PRESERVE;
// clear FD_CLOEXEC; execv(exec_path, [exec_path, "use-fd-write",
// "<FD_PRESERVE>"]). After execve the child's exe inode is exec_path's;
// the in-flight fd is preserved and the next write through it hits
// file_permission with the post-exec caller (proxy for ME-8 §3.7
// in-flight-reload semantics: file_permission fires on every write
// through an existing fd, with the *current* task's exe inode used as
// the caller — equivalent to swapping the profile underneath the fd).
//
// argv: [prog, "open-then-exec", target, exec_path]
#define FD_PRESERVE 100
static int op_open_then_exec(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "open-then-exec needs <target> <exec_path>\n");
		return RC_ERROR;
	}
	const char *target = argv[2];
	const char *exec_path = argv[3];
	int fd = open(target, O_WRONLY);   // no O_CLOEXEC: must survive execve.
	int err = errno;
	if (fd < 0) {
		// The initial open itself may be denied (no-write seal + caller
		// not in actor list). Surface as DENY so the harness can record.
		if (err == EACCES || err == EPERM)
			return RC_DENY;
		return RC_ERROR;
	}
	// Move fd to a known number so the post-exec stub can locate it.
	if (fd != FD_PRESERVE) {
		if (dup2(fd, FD_PRESERVE) < 0) {
			close(fd);
			return RC_ERROR;
		}
		close(fd);
	}
	// Belt-and-braces: clear FD_CLOEXEC.
	long flags = fcntl(FD_PRESERVE, F_GETFD, 0);
	if (flags >= 0)
		fcntl(FD_PRESERVE, F_SETFD, flags & ~FD_CLOEXEC);
	char fdbuf[16];
	snprintf(fdbuf, sizeof(fdbuf), "%d", FD_PRESERVE);
	char *eargv[] = { (char *)exec_path, "use-fd-write", fdbuf, NULL };
	execv(exec_path, eargv);
	return RC_ERROR;   // execv failed.
}

// op_use_fd_write — write one byte to the inherited fd identified by
// argv[2]. Paired with op_open_then_exec via execv.
//
// argv: [prog, "use-fd-write", <fdnum>]
static int op_use_fd_write(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "use-fd-write needs <fdnum>\n");
		return RC_ERROR;
	}
	int fd = atoi(argv[2]);
	if (fd <= 0)
		return RC_ERROR;
	ssize_t n = write(fd, "y", 1);
	int err = errno;
	if (n == 1)
		return RC_ALLOW;
	return classify(-1, err);
}

static int do_op(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: %s <op> <target> [arg2]\n",
			argv[0] ? argv[0] : "mesh_stub");
		return RC_ERROR;
	}
	const char *op = argv[1];
	const char *p  = argv[2];

	if (!strcmp(op, "open-ro"))      return op_open_ro(p);
	if (!strcmp(op, "open-wronly"))  return op_open_wronly(p);
	if (!strcmp(op, "open-rdwr"))    return op_open_rdwr(p);
	if (!strcmp(op, "write"))        return op_write(p);
	if (!strcmp(op, "truncate"))     return op_truncate(p);
	if (!strcmp(op, "ftruncate"))    return op_ftruncate(p);
	if (!strcmp(op, "mmap-write"))   return op_mmap_write(p);
	if (!strcmp(op, "open-trunc"))   return op_open_trunc(p);
	if (!strcmp(op, "open-append"))  return op_open_append(p);
	if (!strcmp(op, "mprotect"))     return op_mprotect(p);
	if (!strcmp(op, "use-fd-write-op")) return op_use_fd_write_op(p);
	if (!strcmp(op, "link-src"))     return op_link_src(p);
	// Dir-level ops (target = sealed PARENT DIR; the stub composes a
	// unique child path under it).
	if (!strcmp(op, "mkdir"))            return op_mkdir_in(p);
	if (!strcmp(op, "rmdir"))            return op_rmdir_in(p);
	if (!strcmp(op, "mknod"))            return op_mknod_in(p);
	if (!strcmp(op, "symlink"))          return op_symlink_in(p);
	if (!strcmp(op, "symlink-persistent")) {
		// HIGH-8: <parent> <target>. The new symlink resolves to
		// <target> and persists past this op so a downstream step
		// can probe through it. Used by seq5 dynamic-alias witness.
		if (argc < 4) {
			fprintf(stderr, "symlink-persistent needs <parent> <target>\n");
			return RC_ERROR;
		}
		return op_symlink_persistent(p, argv[3]);
	}
	if (!strcmp(op, "link-dest"))        return op_link_dest_in(p);
	if (!strcmp(op, "creat-in-parent"))  return op_creat_in_parent(p);
	// Symlink-resolution + link(2) source-side semantics (ME-18).
	if (!strcmp(op, "open-via-symlink")) return op_open_through_symlink(p);
	if (!strcmp(op, "link-symlink-src")) return op_link_symlink_src(p);
	if (!strcmp(op, "unlink"))       return op_unlink(p);
	if (!strcmp(op, "rename")) {
		if (argc < 4) {
			fprintf(stderr, "rename needs <src> <dst>\n");
			return RC_ERROR;
		}
		return op_rename(p, argv[3]);
	}
	if (!strcmp(op, "link-src-dst")) {
		if (argc < 4) {
			fprintf(stderr, "link-src-dst needs <src> <dst_parent>\n");
			return RC_ERROR;
		}
		return op_link_src_dst(p, argv[3]);
	}
	if (!strcmp(op, "chmod"))        return op_chmod(p);
	if (!strcmp(op, "chown"))        return op_chown(p);
	if (!strcmp(op, "setxattr"))     return op_setxattr(p);
	if (!strcmp(op, "removexattr"))  return op_removexattr(p);
	if (!strcmp(op, "inotify-watch")) return op_inotify_watch(p);

	fprintf(stderr, "unknown op: %s\n", op);
	return RC_ERROR;
}

int mesh_stub_main(int argc, char **argv)
{
	if (argc < 2)
		return do_op(argc, argv);
	const char *op = argv[1];
	if (!strcmp(op, "fork-no-exec"))    return op_fork_no_exec(argc, argv);
	if (!strcmp(op, "fork-exec"))       return op_fork_exec(argc, argv);
	if (!strcmp(op, "exec-via-bash"))   return op_exec_via_bash(argc, argv);
	if (!strcmp(op, "open-then-exec"))  return op_open_then_exec(argc, argv);
	if (!strcmp(op, "use-fd-write"))    return op_use_fd_write(argc, argv);
	return do_op(argc, argv);
}
