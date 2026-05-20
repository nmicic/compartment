/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 * ptrace_attempter — calls ptrace(PTRACE_TRACEME, 0, 0, 0) and prints
 * the result. Under the wrapper's seccomp denylist, the call returns
 * EPERM (we never SIGSYS-kill in this build; EPERM is the deny shape).
 *
 * Exit codes:
 *   0  ptrace returned EPERM (expected when wrapped)
 *   1  ptrace returned 0 (unexpected — seccomp not installed)
 *   2  ptrace returned non-EPERM error (unexpected)
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

int main(void) {
    long r = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    int e = errno;
    if (r == 0) {
        printf("ptrace_attempter: ptrace(PTRACE_TRACEME)=0 (NOT BLOCKED)\n");
        return 1;
    }
    if (e == EPERM) {
        printf("ptrace_attempter: ptrace(PTRACE_TRACEME) -> EPERM (BLOCKED)\n");
        return 0;
    }
    printf("ptrace_attempter: ptrace(PTRACE_TRACEME)=%ld errno=%d (%s) (UNEXPECTED)\n",
           r, e, strerror(e));
    return 2;
}
