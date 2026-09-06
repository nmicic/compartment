// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
//
// tests/bypass/helpers/ioctl32_setflags.c — 32-bit FS_IOC_SETFLAGS witness
// for tests/bypass/18-chattr-no-chmod.sh.
//
// Compiled with `gcc -m32`, this binary is an i386 process. On an x86-64
// kernel its ioctl(2) enters fs/ioctl.c COMPAT_SYSCALL_DEFINE3(ioctl), which
// calls security_file_ioctl_compat() and NEVER security_file_ioctl(). A
// deployment that hooks only lsm/file_ioctl therefore lets a 32-bit
// `chattr +i` walk straight past the no-chmod gate. lsm/file_ioctl_compat
// (v0.8) closes it; this helper is the regression witness.
//
// `long` is 4 bytes here, so _IOW('f', 2, long) encodes as 0x40046602 —
// FS_IOC32_SETFLAGS — which is exactly what a 32-bit chattr(1) would send.
//
// Exit codes: 0 = the ioctl succeeded (bypass), 1 = denied with EACCES/EPERM,
//             2 = other errno (printed), 77 = the fs has no SETFLAGS support.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifndef FS_IOC_SETFLAGS
#define FS_IOC_SETFLAGS _IOW('f', 2, long)
#endif
#ifndef FS_IMMUTABLE_FL
#define FS_IMMUTABLE_FL 0x00000010
#endif

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <path>\n", argv[0]);
		return 2;
	}
	int fd = open(argv[1], O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "open(%s): %s\n", argv[1], strerror(errno));
		return 2;
	}
	long flags = FS_IMMUTABLE_FL;
	int rc = ioctl(fd, FS_IOC_SETFLAGS, &flags);
	int saved = errno;
	if (rc == 0) {
		// Undo immediately: an immutable file breaks the test teardown.
		flags = 0;
		(void)ioctl(fd, FS_IOC_SETFLAGS, &flags);
		close(fd);
		return 0;
	}
	close(fd);
	if (saved == EACCES || saved == EPERM)
		return 1;
	if (saved == ENOTTY || saved == EOPNOTSUPP || saved == EINVAL)
		return 77;
	fprintf(stderr, "ioctl(FS_IOC_SETFLAGS): %s\n", strerror(saved));
	return 2;
}
