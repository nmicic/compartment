/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 * env_probe — prints all envp entries (sorted by name) so the test
 * harness can assert which names survived the wrapper's scrub.
 * Static-linked deliberately: avoids /etc/ld.so.cache effects in tests.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>

extern char **environ;

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

int main(void) {
    /* Print /proc/self/exe so callers can assert the post-execve identity. */
    char exe[4096];
    ssize_t r = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (r > 0) {
        exe[r] = '\0';
        printf("EXE %s\n", exe);
    }
    int n = 0;
    while (environ[n]) n++;
    if (n == 0) {
        printf("env_probe: empty environment\n");
        return 0;
    }
    char **sorted = calloc(n, sizeof(*sorted));
    for (int i = 0; i < n; i++) sorted[i] = environ[i];
    qsort(sorted, n, sizeof(*sorted), cmp_str);
    for (int i = 0; i < n; i++) printf("ENV %s\n", sorted[i]);
    free(sorted);
    return 0;
}
