/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 * fd_probe — prints which of fds 0..15 are open inside the process.
 * Used to assert that the wrapper closes inherited fds >= 3.
 */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    int n_open_high = 0;
    for (int fd = 0; fd < 16; fd++) {
        int r = fcntl(fd, F_GETFD);
        if (r < 0) continue;
        printf("fd_probe: fd=%d OPEN flags=0x%x\n", fd, r);
        if (fd >= 3) n_open_high++;
    }
    if (n_open_high == 0) {
        printf("fd_probe: no fd>=3 open (CLEAN)\n");
        return 0;
    }
    printf("fd_probe: %d fd>=3 open (LEAKED)\n", n_open_high);
    return 1;
}
