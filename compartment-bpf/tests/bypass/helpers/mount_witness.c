// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
//
// tests/bypass/helpers/mount_witness.c — raw mount(2)/move_mount(2) probes
// for tests/bypass/17-mount-inside-sealed-dir.sh. mount(8) cannot express
// either of these shapes:
//
//   bind-private <src> <dst>
//       mount(src, dst, NULL, MS_BIND|MS_PRIVATE, NULL). path_mount()
//       dispatches MS_BIND before the propagation bits, so this is a bind
//       mount, not a propagation change — the exact flag combination that
//       defeated the first cut of the sb_mount gate. `mount --bind -o private`
//       is a two-step operation in util-linux, so only a raw mount(2) call
//       reproduces the single-syscall form.
//
//   move-fs <src> <dst>
//       move_mount(AT_FDCWD, src, AT_FDCWD, dst, 0) on an ATTACHED mount —
//       the new-mount-API spelling of `mount --move`. This is the only
//       spelling that reaches security_move_mount(): `mount(2)` with MS_MOVE
//       runs do_move_mount_old(), which calls do_move_mount() directly and
//       never the hook (verified in fs/namespace.c on both 6.8 and 7.0), so a
//       `mount --move` shell probe cannot tell our deny apart from the EINVAL
//       a shared-propagation parent produces. Only a direct move_mount(2)
//       call is a deterministic witness.
//
//   opentree-move <src> <dst>
//       open_tree(AT_FDCWD, src, OPEN_TREE_CLONE|AT_RECURSIVE) followed by
//       move_mount(fd, "", AT_FDCWD, dst, MOVE_MOUNT_F_EMPTY_PATH). This is
//       the new mount API and reaches security_move_mount() WITHOUT passing
//       security_sb_mount() at all, so it is the only independent witness for
//       the comp_move_mount program (mount --move is gated by sb_mount first).
//
// Exit codes: 0 = the operation succeeded (a bypass, for a sealed target)
//             1 = denied with EACCES/EPERM (expected under a seal)
//             2 = usage / other errno (caller decides; printed to stderr)
//            77 = the syscall is unavailable on this kernel (skip)
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MS_BIND
#define MS_BIND 0x1000
#endif
#ifndef MS_PRIVATE
#define MS_PRIVATE (1 << 18)
#endif
#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif

static int classify(int rc)
{
	if (rc == 0)
		return 0;
	if (errno == EACCES || errno == EPERM)
		return 1;
	fprintf(stderr, "mount_witness: unexpected errno %d (%s)\n",
		errno, strerror(errno));
	return 2;
}

int main(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr,
			"usage: %s bind-private <src> <dst>\n"
			"       %s move-fs <src> <dst>\n"
			"       %s opentree-move <src> <dst>\n",
			argv[0], argv[0], argv[0]);
		return 2;
	}

	if (strcmp(argv[1], "bind-private") == 0)
		return classify(mount(argv[2], argv[3], NULL,
				      MS_BIND | MS_PRIVATE, NULL));

	if (strcmp(argv[1], "move-fs") == 0) {
#if defined(__NR_move_mount)
		int rc = (int)syscall(__NR_move_mount, AT_FDCWD, argv[2],
				      AT_FDCWD, argv[3], 0);
		if (rc < 0 && errno == ENOSYS)
			return 77;
		return classify(rc);
#else
		return 77;
#endif
	}

	if (strcmp(argv[1], "opentree-move") == 0) {
#if defined(__NR_open_tree) && defined(__NR_move_mount)
		int fd = (int)syscall(__NR_open_tree, AT_FDCWD, argv[2],
				      OPEN_TREE_CLONE | AT_RECURSIVE);
		if (fd < 0) {
			if (errno == ENOSYS)
				return 77;
			fprintf(stderr, "open_tree(%s): %s\n", argv[2],
				strerror(errno));
			return 77;
		}
		int rc = (int)syscall(__NR_move_mount, fd, "", AT_FDCWD,
				      argv[3], MOVE_MOUNT_F_EMPTY_PATH);
		int saved = errno;
		close(fd);
		errno = saved;
		if (rc < 0 && errno == ENOSYS)
			return 77;
		return classify(rc);
#else
		return 77;
#endif
	}

	fprintf(stderr, "mount_witness: unknown op '%s'\n", argv[1]);
	return 2;
}
