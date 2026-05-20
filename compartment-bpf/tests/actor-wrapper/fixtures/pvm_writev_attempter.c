/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 * pvm_writev_attempter — calls process_vm_writev against self. Under
 * the wrapper's seccomp denylist, this returns EPERM.
 *
 * Exit codes:
 *   0  call returned EPERM (BLOCKED, expected when wrapped)
 *   1  call returned >=0 (NOT BLOCKED — seccomp absent or rule missing)
 *   2  call returned non-EPERM error (unexpected)
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

int main(void) {
    char src[16] = "hello";
    char dst[16] = "____";
    struct iovec local = { .iov_base = src, .iov_len = 5 };
    struct iovec remote = { .iov_base = dst, .iov_len = 5 };
    long r = syscall(SYS_process_vm_writev, getpid(), &local, 1L, &remote,
                     1L, 0L);
    int e = errno;
    if (r >= 0) {
        printf("pvm_writev: rc=%ld (NOT BLOCKED)\n", r);
        return 1;
    }
    if (e == EPERM) {
        printf("pvm_writev: -> EPERM (BLOCKED)\n");
        return 0;
    }
    printf("pvm_writev: rc=%ld errno=%d (%s) (UNEXPECTED)\n", r, e, strerror(e));
    return 2;
}
