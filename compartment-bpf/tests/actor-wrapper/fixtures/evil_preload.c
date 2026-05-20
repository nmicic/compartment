/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 * evil_preload.so — LD_PRELOAD attack fixture for actor-wrapper tests.
 *
 * Build: gcc -shared -fPIC -o evil_preload.so evil_preload.c
 *
 * Constructor writes the marker file pointed to by EVIL_MARKER (env var)
 * or /tmp/evil_preload_ran by default. If the wrapper's env scrub +
 * static link is working, this constructor MUST NOT run inside the
 * target process. The test harness asserts: marker exists when run
 * direct, marker absent when run wrapped.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor))
static void evil_ran(void) {
    const char *marker = getenv("EVIL_MARKER");
    if (!marker || !*marker) marker = "/tmp/evil_preload_ran";
    int fd = open(marker, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "evil_preload: open(%s) failed\n", marker);
        return;
    }
    char buf[128];
    int n = snprintf(buf, sizeof(buf),
                     "evil_preload_ran pid=%d ppid=%d\n",
                     (int)getpid(), (int)getppid());
    if (n > 0) {
        ssize_t w = write(fd, buf, (size_t)n);
        (void)w;
    }
    close(fd);
    fprintf(stderr, "evil_preload: constructor ran inside pid=%d\n",
            (int)getpid());
}
