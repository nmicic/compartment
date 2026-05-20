// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
// tests/strict-launch/helpers/slm_traceme.c — SL-8c LSM-direct witness.
//
// Built statically (-static) and registered in the SL-8c policy as a
// strict-launch launcher. comp_bprm_check_security therefore sets
// actor_marker.state=1 on this process at exec time. The helper then
// calls ptrace(PTRACE_TRACEME) directly — there is NO seccomp wrapper
// in the path, so the syscall reaches comp_ptrace_traceme, the LSM hook
// returns -EPERM, and ptrace_traceme_denied_total + the audit ringbuf
// emit DENY_PTRACE_TRACEME.
//
// Exit codes:
//   15 — ptrace returned EPERM (LSM denied — expected witness)
//   14 — ptrace returned a different error
//    0 — ptrace SUCCEEDED (regression: hook did not fire)
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>

int main(void) {
	errno = 0;
	long r = ptrace(PTRACE_TRACEME, 0, 0, 0);
	if (r == 0) {
		fputs("SL-8c: PTRACE_TRACEME SUCCEEDED — comp_ptrace_traceme did not fire\n", stderr);
		return 0;
	}
	int e = errno;
	fprintf(stderr, "SL-8c: PTRACE_TRACEME errno=%d (%s)\n", e, strerror(e));
	return e == EPERM ? 15 : 14;
}
