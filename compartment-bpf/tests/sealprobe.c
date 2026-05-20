// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
//
// sealprobe — single-purpose test instrument for compartment-bpf.
//
// One subcommand per filesystem operation. Each subcommand attempts the
// operation against an already-existing path (the caller stages the
// filesystem state) and exits with a stable, machine-readable code so
// shell harnesses can compare actual vs. expected without parsing prose.
//
// Exit codes:
//    0  EXPECTED_ALLOW    op succeeded, kernel allowed it
//    1  EXPECTED_DENY     op failed with EACCES (compartment-bpf denial)
//    2  USAGE_ERROR       bad arguments
//    3  UNEXPECTED_ERRNO  op failed with something other than EACCES
//    4  STAGE_ERROR       a setup step (open, etc.) failed before the test op
//    5  UNEXPECTED_OK     op succeeded but caller expected EACCES (bypass!)
//
// The harness invokes sealprobe like:  sealprobe op /path [arg2]
// then asserts the exit code matches the cell of the matrix.
//
// This file is plain C and compiles on host or VM without any bpf headers.
// _GNU_SOURCE is provided by the Makefile's CFLAGS.

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
// name_to_handle_at / open_by_handle_at live in <fcntl.h> on glibc but
// require _GNU_SOURCE which CFLAGS already supplies.
#include <linux/types.h>

enum {
	RC_ALLOW            = 0,
	RC_DENY             = 1,
	RC_USAGE            = 2,
	RC_UNEXPECTED_ERRNO = 3,
	RC_STAGE_ERROR      = 4,
};

static int classify(int syscall_rc, int err)
{
	if (syscall_rc == 0)
		return RC_ALLOW;
	if (err == EACCES || err == EPERM)
		return RC_DENY;
	return RC_UNEXPECTED_ERRNO;
}

static int do_open_ro(const char *p)
{
	int fd = open(p, O_RDONLY | O_CLOEXEC);
	int err = errno;
	if (fd >= 0) {
		close(fd);
		return RC_ALLOW;
	}
	return classify(-1, err);
}

static int do_open_wronly(const char *p)
{
	int fd = open(p, O_WRONLY | O_CLOEXEC);
	int err = errno;
	if (fd >= 0) {
		close(fd);
		return RC_ALLOW;
	}
	return classify(-1, err);
}

static int do_open_rdwr(const char *p)
{
	int fd = open(p, O_RDWR | O_CLOEXEC);
	int err = errno;
	if (fd >= 0) {
		close(fd);
		return RC_ALLOW;
	}
	return classify(-1, err);
}

static int do_open_trunc(const char *p)
{
	int fd = open(p, O_WRONLY | O_TRUNC | O_CLOEXEC);
	int err = errno;
	if (fd >= 0) {
		close(fd);
		return RC_ALLOW;
	}
	return classify(-1, err);
}

static int do_truncate(const char *p)
{
	int rc = truncate(p, 0);
	return classify(rc, errno);
}

static int do_truncate_same(const char *p)
{
	struct stat st;
	if (stat(p, &st) < 0)
		return RC_STAGE_ERROR;
	int rc = truncate(p, st.st_size);
	return classify(rc, errno);
}

static int do_ftruncate(const char *p)
{
	int fd = open(p, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		// open(O_RDONLY) was denied or path missing — for the
		// no-write-only seal case open(O_RDONLY) is allowed; if
		// it wasn't, this is a stage error or a different denial.
		return errno == EACCES ? RC_DENY : RC_STAGE_ERROR;
	}
	int rc = ftruncate(fd, 0);
	int err = errno;
	close(fd);
	return classify(rc, err);
}

static int do_unlink(const char *p)
{
	int rc = unlink(p);
	return classify(rc, errno);
}

static int do_rename(const char *src, const char *dst)
{
	int rc = rename(src, dst);
	return classify(rc, errno);
}

static int do_chmod(const char *p)
{
	int rc = chmod(p, 0644);
	return classify(rc, errno);
}

static int do_chown(const char *p)
{
	int rc = chown(p, getuid(), getgid());
	return classify(rc, errno);
}

static int do_setxattr(const char *p)
{
	int rc = setxattr(p, "user.sealprobe", "x", 1, 0);
	return classify(rc, errno);
}

static int do_removexattr(const char *p)
{
	int rc = removexattr(p, "user.sealprobe");
	return classify(rc, errno);
}

static int do_create_in(const char *dir)
{
	char path[4096];
	if (snprintf(path, sizeof(path), "%s/sealprobe-create.%d",
		     dir, (int)getpid()) >= (int)sizeof(path))
		return RC_STAGE_ERROR;
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	int err = errno;
	if (fd >= 0) {
		close(fd);
		unlink(path);
		return RC_ALLOW;
	}
	return classify(-1, err);
}

static int do_mkdir_in(const char *dir)
{
	char path[4096];
	if (snprintf(path, sizeof(path), "%s/sealprobe-mkdir.%d",
		     dir, (int)getpid()) >= (int)sizeof(path))
		return RC_STAGE_ERROR;
	int rc = mkdir(path, 0755);
	int err = errno;
	if (rc == 0) {
		rmdir(path);
		return RC_ALLOW;
	}
	return classify(rc, err);
}

static int do_symlink_in(const char *dir)
{
	char path[4096];
	if (snprintf(path, sizeof(path), "%s/sealprobe-symlink.%d",
		     dir, (int)getpid()) >= (int)sizeof(path))
		return RC_STAGE_ERROR;
	int rc = symlink("/tmp", path);
	int err = errno;
	if (rc == 0) {
		unlink(path);
		return RC_ALLOW;
	}
	return classify(rc, err);
}

static int do_hardlink_in(const char *src, const char *dir)
{
	char path[4096];
	if (snprintf(path, sizeof(path), "%s/sealprobe-link.%d",
		     dir, (int)getpid()) >= (int)sizeof(path))
		return RC_STAGE_ERROR;
	int rc = link(src, path);
	int err = errno;
	if (rc == 0) {
		unlink(path);
		return RC_ALLOW;
	}
	return classify(rc, err);
}

static int do_mmap_shared_write(const char *p)
{
	int fd = open(p, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		// If the open itself was denied that already counts as a
		// deny. The mmap-write seal is layered: write-open is the
		// first gate, mmap is the second. Either denial proves the
		// "shared writable mapping not allowed" property.
		return errno == EACCES ? RC_DENY : RC_STAGE_ERROR;
	}
	struct stat st;
	if (fstat(fd, &st) < 0) {
		close(fd);
		return RC_STAGE_ERROR;
	}
	// Empty file — mmap of zero pages is fine but we want to see whether
	// MAP_SHARED+PROT_WRITE is permitted. Force a 4 KiB length.
	size_t len = st.st_size > 0 ? (size_t)st.st_size : 4096;
	void *m = mmap(NULL, len, PROT_READ | PROT_WRITE,
		       MAP_SHARED, fd, 0);
	int err = errno;
	close(fd);
	if (m == MAP_FAILED)
		return classify(-1, err);
	munmap(m, len);
	return RC_ALLOW;
}

// Coverage probe for comp_mmap_file. The existing mmap-shared-write
// op opens O_RDWR first, which already trips comp_file_open for sealed
// paths — so on the matrix the deny credit goes to file_open, not
// mmap_file. This probe opens O_RDONLY (allowed) and THEN attempts
// mmap(PROT_WRITE | MAP_SHARED). In current 6.x kernels
// security_mmap_file() fires inside vm_mmap_pgoff BEFORE
// do_mmap()'s FMODE_WRITE check, so when the file is sealed NO_WRITE
// the LSM hook denies first and the EACCES we observe is attributable
// to comp_mmap_file rather than to the VFS write check.
//
// Returns RC_STAGE_ERROR if the O_RDONLY open itself fails — that
// would mean the file is not reachable for the baseline read path and
// the probe cannot make a clean claim about mmap.
static int do_mmap_after_ro_open(const char *p)
{
	int fd = open(p, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return RC_STAGE_ERROR;
	void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		       MAP_SHARED, fd, 0);
	int err = errno;
	close(fd);
	if (m == MAP_FAILED)
		return classify(-1, err);
	munmap(m, 4096);
	return RC_ALLOW;
}

static int do_mprotect_shared_to_rw(const char *p)
{
	int fd = open(p, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == EACCES ? RC_DENY : RC_STAGE_ERROR;
	void *m = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
	int err = errno;
	if (m == MAP_FAILED) {
		close(fd);
		return classify(-1, err);
	}
	int rc = mprotect(m, 4096, PROT_READ | PROT_WRITE);
	err = errno;
	munmap(m, 4096);
	close(fd);
	return classify(rc, err);
}

// Bypass-class probe: name_to_handle_at on PATH, then open_by_handle_at
// for O_WRONLY. The kernel routes file_handle resolution through the
// same VFS, so the BPF LSM hook still sees the (dev, ino) and should
// deny. A successful open is a bypass.
static int do_open_by_handle_wronly(const char *p)
{
	struct file_handle *fh;
	int mount_id;
	int rc;

	fh = calloc(1, sizeof(*fh) + MAX_HANDLE_SZ);
	if (!fh)
		return RC_STAGE_ERROR;
	fh->handle_bytes = MAX_HANDLE_SZ;

	rc = name_to_handle_at(AT_FDCWD, p, fh, &mount_id, 0);
	if (rc < 0) {
		int err = errno;
		free(fh);
		// EOPNOTSUPP / ENOSYS on filesystems without handle support
		// is a stage error, not a deny.
		if (err == EACCES)
			return RC_DENY;
		return RC_STAGE_ERROR;
	}

	// Need a mount fd. open_by_handle_at requires a real fs fd as
	// mount_fd, not O_PATH (kernel returns EBADF on at least 7.0).
	// Use the parent directory opened O_RDONLY|O_DIRECTORY.
	char *pcopy = strdup(p);
	if (!pcopy) { free(fh); return RC_STAGE_ERROR; }
	char *parent = dirname(pcopy);
	int mfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	int err_open = errno;
	free(pcopy);
	if (mfd < 0) {
		free(fh);
		return err_open == EACCES ? RC_DENY : RC_STAGE_ERROR;
	}

	int fd = open_by_handle_at(mfd, fh, O_WRONLY | O_CLOEXEC);
	int err = errno;
	close(mfd);
	free(fh);
	if (fd >= 0) {
		close(fd);
		return RC_ALLOW;
	}
	return classify(-1, err);
}

// Tight in-process benchmark loop. Avoids fork/exec overhead so the
// measured ops/sec actually reflects the LSM hook cost, not the cost
// of spawning sealprobe per iteration. Modes:
//   "ro"     open(O_RDONLY) + close — exercises file_open hook miss-path
//   "wronly" open(O_WRONLY) + close — exercises deny path on sealed paths
// Prints one line: "elapsed_us=N ops=N ops_sec=N denies=N"
static int do_bench_open(const char *mode, const char *p, long iters)
{
	int want_wo = !strcmp(mode, "wronly");
	int flags   = want_wo ? (O_WRONLY | O_CLOEXEC) : (O_RDONLY | O_CLOEXEC);
	long denies = 0;
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (long i = 0; i < iters; i++) {
		int fd = open(p, flags);
		if (fd < 0) {
			if (errno == EACCES || errno == EPERM)
				denies++;
		} else {
			close(fd);
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);
	long long ns = (long long)(t1.tv_sec - t0.tv_sec) * 1000000000LL
		     + (t1.tv_nsec - t0.tv_nsec);
	long long us = ns / 1000;
	double secs = (double)ns / 1e9;
	long ops_sec = secs > 0 ? (long)(iters / secs) : 0;
	printf("elapsed_us=%lld ops=%ld ops_sec=%ld denies=%ld\n",
	       us, iters, ops_sec, denies);
	return 0;
}

static int do_write_via_old_fd(const char *p)
{
	// Open BEFORE the caller arms the seal, then write AFTER. The
	// harness controls the timing; we just take an fd and try to
	// write to it on demand. This subcommand is meant to be invoked
	// twice: once with `pre` to dup the fd to a known number, then
	// with `post` to attempt the write through the saved fd.
	//
	// Simpler shape: open + write in one shot. Harness must call us
	// only AFTER the seal is live. Used to confirm the documented
	// limit "writes through fds opened before attach can succeed."
	int fd = open(p, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return classify(-1, errno);
	ssize_t n = write(fd, "x", 1);
	int err = errno;
	close(fd);
	return classify(n < 0 ? -1 : 0, err);
}

// V-3 D-V3.E: directory ops on caller-supplied explicit paths. Differ
// from create-in / mkdir-in / symlink-in / hardlink-in (which auto-name
// a path inside a given directory); V-3 needs deterministic per-cell
// paths so the runner can pre-stage cell preconditions. Each follows
// the existing rc convention via classify(): 0=ALLOW, 1=DENY on
// EACCES/EPERM, 3=UNEXPECTED_ERRNO otherwise.

static int do_mkdir_path(const char *p)
{
	int rc = mkdir(p, 0700);
	return classify(rc, errno);
}

static int do_mknod_fifo(const char *p)
{
	int rc = mknod(p, S_IFIFO | 0600, 0);
	return classify(rc, errno);
}

static int do_symlink_path(const char *target, const char *linkpath)
{
	int rc = symlink(target, linkpath);
	return classify(rc, errno);
}

static int do_link_path(const char *oldpath, const char *newpath)
{
	int rc = link(oldpath, newpath);
	return classify(rc, errno);
}

static int do_rmdir(const char *p)
{
	int rc = rmdir(p);
	return classify(rc, errno);
}

static void usage(void)
{
	fputs(
"sealprobe op args...\n"
"  open-ro PATH\n"
"  open-write PATH\n"
"  open-rdwr PATH\n"
"  open-trunc PATH\n"
"  truncate PATH\n"
"  truncate-same PATH\n"
"  ftruncate PATH\n"
"  unlink PATH\n"
"  rename SRC DST\n"
"  chmod PATH\n"
"  chown PATH\n"
"  setxattr PATH\n"
"  removexattr PATH\n"
"  create-in DIR\n"
"  mkdir-in DIR\n"
"  symlink-in DIR\n"
"  hardlink-in SRC DIR\n"
"  mkdir PATH\n"
"  mknod-fifo PATH\n"
"  symlink TARGET LINKPATH\n"
"  link OLDPATH NEWPATH\n"
"  rmdir PATH\n"
"  rename-into SRC DST  (alias of rename)\n"
"  mmap-shared-write PATH\n"
"  mmap-after-ro-open PATH\n"
"  mprotect-rw PATH\n"
"  open-by-handle-wronly PATH\n"
"  write-via-fd PATH\n"
"  bench-open MODE PATH ITERS  (MODE=ro|wronly)\n"
"\n"
"Exit: 0=ALLOW 1=DENY 2=USAGE 3=UNEXPECTED_ERRNO 4=STAGE_ERROR\n",
		stderr);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
		return RC_USAGE;
	}
	const char *op = argv[1];

#define NEEDARGS(n) do { if (argc < (n)) { usage(); return RC_USAGE; } } while (0)

	if (!strcmp(op, "open-ro"))            { NEEDARGS(3); return do_open_ro(argv[2]); }
	if (!strcmp(op, "open-write"))         { NEEDARGS(3); return do_open_wronly(argv[2]); }
	if (!strcmp(op, "open-rdwr"))          { NEEDARGS(3); return do_open_rdwr(argv[2]); }
	if (!strcmp(op, "open-trunc"))         { NEEDARGS(3); return do_open_trunc(argv[2]); }
	if (!strcmp(op, "truncate"))           { NEEDARGS(3); return do_truncate(argv[2]); }
	if (!strcmp(op, "truncate-same"))      { NEEDARGS(3); return do_truncate_same(argv[2]); }
	if (!strcmp(op, "ftruncate"))          { NEEDARGS(3); return do_ftruncate(argv[2]); }
	if (!strcmp(op, "unlink"))             { NEEDARGS(3); return do_unlink(argv[2]); }
	if (!strcmp(op, "rename"))             { NEEDARGS(4); return do_rename(argv[2], argv[3]); }
	if (!strcmp(op, "chmod"))              { NEEDARGS(3); return do_chmod(argv[2]); }
	if (!strcmp(op, "chown"))              { NEEDARGS(3); return do_chown(argv[2]); }
	if (!strcmp(op, "setxattr"))           { NEEDARGS(3); return do_setxattr(argv[2]); }
	if (!strcmp(op, "removexattr"))        { NEEDARGS(3); return do_removexattr(argv[2]); }
	if (!strcmp(op, "create-in"))          { NEEDARGS(3); return do_create_in(argv[2]); }
	if (!strcmp(op, "mkdir-in"))           { NEEDARGS(3); return do_mkdir_in(argv[2]); }
	if (!strcmp(op, "symlink-in"))         { NEEDARGS(3); return do_symlink_in(argv[2]); }
	if (!strcmp(op, "hardlink-in"))        { NEEDARGS(4); return do_hardlink_in(argv[2], argv[3]); }
	if (!strcmp(op, "mkdir"))              { NEEDARGS(3); return do_mkdir_path(argv[2]); }
	if (!strcmp(op, "mknod-fifo"))         { NEEDARGS(3); return do_mknod_fifo(argv[2]); }
	if (!strcmp(op, "symlink"))            { NEEDARGS(4); return do_symlink_path(argv[2], argv[3]); }
	if (!strcmp(op, "link"))               { NEEDARGS(4); return do_link_path(argv[2], argv[3]); }
	if (!strcmp(op, "rmdir"))              { NEEDARGS(3); return do_rmdir(argv[2]); }
	if (!strcmp(op, "rename-into"))        { NEEDARGS(4); return do_rename(argv[2], argv[3]); }
	if (!strcmp(op, "mmap-shared-write"))  { NEEDARGS(3); return do_mmap_shared_write(argv[2]); }
	if (!strcmp(op, "mmap-after-ro-open")) { NEEDARGS(3); return do_mmap_after_ro_open(argv[2]); }
	if (!strcmp(op, "mprotect-rw"))        { NEEDARGS(3); return do_mprotect_shared_to_rw(argv[2]); }
	if (!strcmp(op, "open-by-handle-wronly")) { NEEDARGS(3); return do_open_by_handle_wronly(argv[2]); }
	if (!strcmp(op, "write-via-fd"))       { NEEDARGS(3); return do_write_via_old_fd(argv[2]); }
	if (!strcmp(op, "bench-open"))         { NEEDARGS(5); return do_bench_open(argv[2], argv[3], atol(argv[4])); }

	usage();
	return RC_USAGE;
}
