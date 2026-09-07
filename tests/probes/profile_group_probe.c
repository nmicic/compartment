/*
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 * SPDX-License-Identifier: Apache-2.0
 */
#include <sys/wait.h>

#include "compartment.h"

#define OWNER_UID 12345
#define PEER_UID  12346
#define SHARED_GID 12345

static int enter_as(const char *root, uid_t uid)
{
    if (chroot(root) != 0 || chdir("/") != 0 ||
        setgroups(0, NULL) != 0 || setgid(SHARED_GID) != 0 ||
        setuid(uid) != 0) {
        perror("profile_group_probe setup");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;

    pid_t peer = fork();
    if (peer < 0) {
        perror("fork");
        return 2;
    }
    if (peer == 0) {
        if (enter_as(argv[1], PEER_UID) != 0)
            _exit(2);
        int fd = open("/policy.conf", O_WRONLY | O_TRUNC);
        if (fd < 0)
            _exit(3);
        static const char replacement[] = "block getpid\n";
        ssize_t n = write(fd, replacement, sizeof(replacement) - 1);
        close(fd);
        _exit(n == (ssize_t)(sizeof(replacement) - 1) ? 0 : 4);
    }

    int status = 0;
    if (waitpid(peer, &status, 0) != peer || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        fprintf(stderr, "foreign primary-group writer failed\n");
        return 2;
    }
    puts("FOREIGN_PRIMARY_GROUP_WRITE_OK");

    if (enter_as(argv[1], OWNER_UID) != 0)
        return 2;
    int fd = open("/policy.conf", O_RDONLY);
    if (fd < 0) {
        perror("open policy");
        return 2;
    }
    int rc = profile_fd_trusted(fd, 0, S_IFREG, "profile", "/policy.conf");
    close(fd);
    if (rc == 0) {
        fputs("GROUP_WRITABLE_PROFILE_TRUSTED\n", stderr);
        return 1;
    }
    puts("GROUP_WRITABLE_PROFILE_REFUSED");
    return 0;
}
