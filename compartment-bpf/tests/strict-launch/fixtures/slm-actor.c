// SPDX-License-Identifier: GPL-2.0
// Minimal "actor" test binary for strict-launch-marker witnesses.
//
// Usage: slm-actor SUBCMD ARGS...
//   write  PATH          : open(O_WRONLY|O_APPEND) PATH; write "ok"; return 0 / 11 / 12.
//   fork-write PATH      : fork; child does write; parent waits.
//   exec PATH PROG ARGS  : execve PROG with kept env (for the exec-chain test).
//   sh-then-write SHELL TARGET_ACTOR PATH : exec SHELL -c "$TARGET_ACTOR write $PATH"
//   set-mm-exe IFD       : prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, IFD) ; return errno
//   open-only PATH       : open(O_WRONLY|O_APPEND) only (no write).
//   ptrace-me            : ptrace(PTRACE_TRACEME,...) ; return 15 if denied (EPERM).
//
// Exit codes:
//   0  = succeeded
//   1  = arg error
//   11 = open failed (write/fork-write/open-only)
//   12 = write short
//   13 = prctl failed (set-mm-exe) — errno printed
//   14 = exec failed
//   15 = ptrace_traceme denied (EPERM from strict-launch LSM hook)
//   99 = other

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PR_SET_MM
#define PR_SET_MM 35
#endif
#ifndef PR_SET_MM_EXE_FILE
#define PR_SET_MM_EXE_FILE 13
#endif

static int do_write(const char *path) {
	int fd = open(path, O_WRONLY|O_APPEND);
	if (fd < 0) { fprintf(stderr,"open(%s): %s\n", path, strerror(errno)); return 11; }
	if (write(fd, "ok", 2) != 2) { close(fd); return 12; }
	close(fd);
	return 0;
}

int main(int argc, char **argv) {
	if (argc < 2) return 1;
	const char *cmd = argv[1];

	if (!strcmp(cmd, "write") && argc == 3) return do_write(argv[2]);

	if (!strcmp(cmd, "fork-write") && argc == 3) {
		pid_t p = fork();
		if (p < 0) return 99;
		if (p == 0) _exit(do_write(argv[2]));
		int st;
		if (waitpid(p, &st, 0) < 0) return 99;
		return WIFEXITED(st) ? WEXITSTATUS(st) : 99;
	}

	if (!strcmp(cmd, "open-only") && argc == 3) {
		int fd = open(argv[2], O_WRONLY|O_APPEND);
		if (fd < 0) { fprintf(stderr,"open(%s): %s\n", argv[2], strerror(errno)); return 11; }
		close(fd);
		return 0;
	}

	if (!strcmp(cmd, "exec") && argc >= 3) {
		execv(argv[2], argv + 2);
		fprintf(stderr,"execv(%s): %s\n", argv[2], strerror(errno));
		return 14;
	}

	if (!strcmp(cmd, "sh-then-write") && argc == 5) {
		char buf[1024];
		snprintf(buf, sizeof(buf), "%s write %s", argv[3], argv[4]);
		execl(argv[2], argv[2], "-c", buf, NULL);
		fprintf(stderr,"execl(%s): %s\n", argv[2], strerror(errno));
		return 14;
	}

	if (!strcmp(cmd, "sleep") && argc == 3) {
		sleep(atoi(argv[2]));
		return 0;
	}

	if (!strcmp(cmd, "set-mm-exe") && argc == 3) {
		int fd = atoi(argv[2]);
		if (prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0) < 0) {
			fprintf(stderr,"prctl(PR_SET_MM_EXE_FILE) errno=%d (%s)\n", errno, strerror(errno));
			return 13;
		}
		return 0;
	}

	if (!strcmp(cmd, "ptrace-me")) {
		/* Strict actors must not request tracing.
		 * The comp_ptrace_traceme LSM hook denies PTRACE_TRACEME for
		 * any task that carries a strict-launch actor_marker. */
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
			fprintf(stderr,"ptrace(PTRACE_TRACEME) errno=%d (%s)\n", errno, strerror(errno));
			return 15;
		}
		return 0;
	}

	fprintf(stderr,"unknown subcommand: %s\n", cmd);
	return 1;
}
