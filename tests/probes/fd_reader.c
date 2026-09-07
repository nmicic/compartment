/*
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;

    char *end = NULL;
    long fd = strtol(argv[1], &end, 10);
    if (!end || *end != '\0' || fd < 0 || fd > INT_MAX)
        return 2;

    dprintf(STDOUT_FILENO, "FD_READER_START fd=%ld\n", fd);
    char buf[256];
    ssize_t n = read((int)fd, buf, sizeof(buf));
    if (n < 0) {
        dprintf(STDOUT_FILENO, "FD_READER_CLOSED errno=%d\n", errno);
        return 1;
    }
    if (write(STDOUT_FILENO, buf, (size_t)n) != n)
        return 1;
    return 0;
}
