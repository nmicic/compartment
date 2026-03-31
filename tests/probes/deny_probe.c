/*
 * Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
 * SPDX-License-Identifier: Apache-2.0
 *
 * deny_probe — synthetic test probe for compartment sandbox validation
 *
 * Subcommand-driven probe that exercises filesystem, syscall, network,
 * environment, FD, and child-process operations. Prints structured
 * single-line results for machine parsing.
 *
 * Output format:
 *   RESULT op=<op> <key>=<val>... rc=<n> errno=<n> name=<errname>
 *
 * Build:
 *   cc -o deny_probe deny_probe.c
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sched.h>
#include <linux/perf_event.h>

static const char *errname(int e)
{
    switch (e) {
    case 0:      return "OK";
    case EACCES: return "EACCES";
    case EPERM:  return "EPERM";
    case ENOENT: return "ENOENT";
    case ENOSYS: return "ENOSYS";
    case EEXIST: return "EEXIST";
    case EISDIR: return "EISDIR";
    case ENOTDIR:return "ENOTDIR";
    case ENOTEMPTY: return "ENOTEMPTY";
    case ECONNREFUSED: return "ECONNREFUSED";
    case ETIMEDOUT: return "ETIMEDOUT";
    case ENETUNREACH: return "ENETUNREACH";
    case EHOSTUNREACH: return "EHOSTUNREACH";
    default:     return "OTHER";
    }
}

static void result(const char *op, const char *detail, int rc)
{
    int e = (rc < 0) ? errno : 0;
    printf("RESULT op=%s %s rc=%d errno=%d name=%s\n",
           op, detail, rc, e, errname(e));
}

/* ── Filesystem operations ──────────────────────────────────────────── */

static int do_fs_read(const char *path)
{
    int fd = open(path, O_RDONLY);
    char detail[512];
    snprintf(detail, sizeof(detail), "path=%s", path);
    if (fd < 0) { result("fs_read", detail, -1); return 1; }
    char buf[1];
    ssize_t r = read(fd, buf, 1);
    close(fd);
    result("fs_read", detail, r >= 0 ? 0 : -1);
    return r >= 0 ? 0 : 1;
}

static int do_fs_write(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    char detail[512];
    snprintf(detail, sizeof(detail), "path=%s", path);
    if (fd < 0) { result("fs_write", detail, -1); return 1; }
    ssize_t r = write(fd, "test\n", 5);
    close(fd);
    result("fs_write", detail, r > 0 ? 0 : -1);
    return r > 0 ? 0 : 1;
}

static int do_fs_append(const char *path)
{
    int fd = open(path, O_WRONLY | O_APPEND);
    char detail[512];
    snprintf(detail, sizeof(detail), "path=%s", path);
    if (fd < 0) { result("fs_append", detail, -1); return 1; }
    ssize_t r = write(fd, "appended\n", 9);
    close(fd);
    result("fs_append", detail, r > 0 ? 0 : -1);
    return r > 0 ? 0 : 1;
}

static int do_fs_create(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    char detail[512];
    snprintf(detail, sizeof(detail), "path=%s", path);
    if (fd < 0) { result("fs_create", detail, -1); return 1; }
    close(fd);
    result("fs_create", detail, 0);
    return 0;
}

static int do_fs_truncate(const char *path)
{
    char detail[512];
    snprintf(detail, sizeof(detail), "path=%s", path);
    int r = truncate(path, 0);
    result("fs_truncate", detail, r);
    return r == 0 ? 0 : 1;
}

static int do_fs_unlink(const char *path)
{
    char detail[512];
    snprintf(detail, sizeof(detail), "path=%s", path);
    int r = unlink(path);
    result("fs_unlink", detail, r);
    return r == 0 ? 0 : 1;
}

static int do_fs_mkdir(const char *path)
{
    char detail[512];
    snprintf(detail, sizeof(detail), "path=%s", path);
    int r = mkdir(path, 0755);
    result("fs_mkdir", detail, r);
    return r == 0 ? 0 : 1;
}

static int do_fs_rmdir(const char *path)
{
    char detail[512];
    snprintf(detail, sizeof(detail), "path=%s", path);
    int r = rmdir(path);
    result("fs_rmdir", detail, r);
    return r == 0 ? 0 : 1;
}

static int do_fs_rename(const char *src, const char *dst)
{
    char detail[512];
    snprintf(detail, sizeof(detail), "src=%s dst=%s", src, dst);
    int r = rename(src, dst);
    result("fs_rename", detail, r);
    return r == 0 ? 0 : 1;
}

static int do_fs_symlink(const char *target, const char *linkpath)
{
    char detail[512];
    snprintf(detail, sizeof(detail), "target=%s linkpath=%s", target, linkpath);
    int r = symlink(target, linkpath);
    result("fs_symlink", detail, r);
    return r == 0 ? 0 : 1;
}

static int do_fs_chdir(const char *path)
{
    char detail[512];
    snprintf(detail, sizeof(detail), "path=%s", path);
    int r = chdir(path);
    result("fs_chdir", detail, r);
    return r == 0 ? 0 : 1;
}

static int do_fs_stat(const char *path)
{
    struct stat st;
    char detail[512];
    snprintf(detail, sizeof(detail), "path=%s", path);
    int r = stat(path, &st);
    result("fs_stat", detail, r);
    return r == 0 ? 0 : 1;
}

static int do_fs_exec(int argc, char **argv)
{
    if (argc < 1) { fprintf(stderr, "fs_exec: need path\n"); return 1; }
    char detail[512];
    snprintf(detail, sizeof(detail), "path=%s", argv[0]);

    pid_t pid = fork();
    if (pid < 0) { result("fs_exec", detail, -1); return 1; }
    if (pid == 0) {
        execv(argv[0], argv);
        _exit(errno == EACCES || errno == EPERM ? 126 : 127);
    }
    int status;
    waitpid(pid, &status, 0);
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    char detail2[512];
    snprintf(detail2, sizeof(detail2), "path=%s exit=%d", argv[0], rc);
    result("fs_exec", detail2, rc == 0 ? 0 : -1);
    return rc == 0 ? 0 : 1;
}

/* ── Environment operations ─────────────────────────────────────────── */

static int do_env_get(const char *var)
{
    const char *val = getenv(var);
    char detail[512];
    if (val)
        snprintf(detail, sizeof(detail), "var=%s value=%s", var, val);
    else
        snprintf(detail, sizeof(detail), "var=%s value=(null)", var);
    result("env_get", detail, val ? 0 : -1);
    return val ? 0 : 1;
}

static int do_env_dump(void)
{
    extern char **environ;
    int count = 0;
    for (char **e = environ; *e; e++) {
        printf("ENV %s\n", *e);
        count++;
    }
    char detail[64];
    snprintf(detail, sizeof(detail), "count=%d", count);
    result("env_dump", detail, 0);
    return 0;
}

/* ── FD inspection ──────────────────────────────────────────────────── */

static int do_fd_list(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (!d) { result("fd_list", "dir=/proc/self/fd", -1); return 1; }
    int count = 0;
    struct dirent *de;
    int dir_fd = dirfd(d);
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        int fd = atoi(de->d_name);
        if (fd == dir_fd) continue;
        char link[256], target[256];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(link, target, sizeof(target) - 1);
        if (n > 0) { target[n] = '\0'; } else { strcpy(target, "?"); }
        printf("FD %d -> %s\n", fd, target);
        count++;
    }
    closedir(d);
    char detail[64];
    snprintf(detail, sizeof(detail), "count=%d", count);
    result("fd_list", detail, 0);
    return 0;
}

static int do_fd_read(const char *fdstr)
{
    int fd = atoi(fdstr);
    char buf[1];
    char detail[64];
    snprintf(detail, sizeof(detail), "fd=%d", fd);
    ssize_t r = read(fd, buf, 1);
    result("fd_read", detail, r >= 0 ? 0 : -1);
    return r >= 0 ? 0 : 1;
}

/* ── Network operations ─────────────────────────────────────────────── */

static int do_net_tcp(const char *host, const char *port)
{
    char detail[256];
    snprintf(detail, sizeof(detail), "host=%s port=%s", host, port);

    struct addrinfo hints = { .ai_socktype = SOCK_STREAM };
    struct addrinfo *res;
    int err = getaddrinfo(host, port, &hints, &res);
    if (err != 0) {
        printf("RESULT op=net_tcp %s rc=-1 errno=0 name=DNS_FAIL\n", detail);
        return 1;
    }

    int sock = socket(res->ai_family, SOCK_STREAM, 0);
    if (sock < 0) { freeaddrinfo(res); result("net_tcp", detail, -1); return 1; }

    /* 5 second timeout */
    struct timeval tv = { .tv_sec = 5 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int r = connect(sock, res->ai_addr, res->ai_addrlen);
    int saved = errno;
    close(sock);
    freeaddrinfo(res);
    errno = saved;
    result("net_tcp", detail, r);
    return r == 0 ? 0 : 1;
}

/* ── Child-process operations ───────────────────────────────────────── */

static int do_spawn(const char *op, const char *shell, const char *cmd)
{
    char detail[512];
    snprintf(detail, sizeof(detail), "shell=%s cmd=%.200s", shell, cmd);

    pid_t pid = fork();
    if (pid < 0) { result(op, detail, -1); return 1; }
    if (pid == 0) {
        execl(shell, shell, "-c", cmd, (char *)NULL);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    char detail2[512];
    snprintf(detail2, sizeof(detail2), "shell=%s cmd=%.200s exit=%d", shell, cmd, rc);
    result(op, detail2, rc == 0 ? 0 : -1);
    return rc == 0 ? 0 : 1;
}

static int do_spawn_sh(const char *cmd) { return do_spawn("spawn_sh", "/bin/sh", cmd); }
static int do_spawn_abs_bash(const char *cmd) { return do_spawn("spawn_abs_bash", "/bin/bash", cmd); }

static int do_spawn_nested(const char *cmd)
{
    /* Spawn a shell that itself spawns another shell */
    char nested[1024];
    snprintf(nested, sizeof(nested), "/bin/sh -c '%s'", cmd);
    return do_spawn("spawn_nested", "/bin/sh", nested);
}

/* ── Syscall probes ─────────────────────────────────────────────────── */

static int do_sc_ptrace(void)
{
    int r = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    int saved = errno;
    /* If ptrace succeeded, detach */
    if (r == 0) ptrace(PTRACE_DETACH, 0, NULL, NULL);
    errno = saved;
    result("sc_ptrace_traceme", "", r);
    return r == 0 ? 0 : 1;
}

static int do_sc_unshare(void)
{
    int r = unshare(CLONE_NEWUSER);
    result("sc_unshare_user", "", r);
    return r == 0 ? 0 : 1;
}

static int do_sc_process_vm_readv(void)
{
    char buf[16];
    struct iovec local = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct iovec remote = { .iov_base = buf, .iov_len = sizeof(buf) };
    ssize_t r = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    result("sc_process_vm_readv", "", r >= 0 ? 0 : -1);
    return r >= 0 ? 0 : 1;
}

static int do_sc_process_vm_writev(void)
{
    char buf[16] = "test";
    struct iovec local = { .iov_base = buf, .iov_len = 4 };
    struct iovec remote = { .iov_base = buf, .iov_len = 4 };
    ssize_t r = process_vm_writev(getpid(), &local, 1, &remote, 1, 0);
    result("sc_process_vm_writev", "", r >= 0 ? 0 : -1);
    return r >= 0 ? 0 : 1;
}

static int do_sc_userfaultfd(void)
{
    long r = syscall(__NR_userfaultfd, 0);
    if (r >= 0) close((int)r);
    result("sc_userfaultfd", "", r >= 0 ? 0 : -1);
    return r >= 0 ? 0 : 1;
}

static int do_sc_perf_event_open(void)
{
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .size = sizeof(attr),
        .config = PERF_COUNT_SW_CPU_CLOCK,
    };
    int r = (int)syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    if (r >= 0) close(r);
    result("sc_perf_event_open", "", r >= 0 ? 0 : -1);
    return r >= 0 ? 0 : 1;
}

/* ── Usage ──────────────────────────────────────────────────────────── */

static void usage(void)
{
    fprintf(stderr,
        "deny_probe — sandbox validation probe\n\n"
        "Filesystem:\n"
        "  fs_read <path>              fs_write <path>\n"
        "  fs_append <path>            fs_create <path>\n"
        "  fs_truncate <path>          fs_unlink <path>\n"
        "  fs_mkdir <path>             fs_rmdir <path>\n"
        "  fs_rename <src> <dst>       fs_symlink <target> <linkpath>\n"
        "  fs_chdir <path>             fs_stat <path>\n"
        "  fs_exec <path> [args...]\n\n"
        "Environment:\n"
        "  env_get <VAR>               env_dump\n\n"
        "FD:\n"
        "  fd_list                     fd_read <fd>\n\n"
        "Network:\n"
        "  net_tcp <host> <port>\n\n"
        "Child process:\n"
        "  spawn_sh <cmd>              spawn_abs_bash <cmd>\n"
        "  spawn_nested <cmd>\n\n"
        "Syscall probes:\n"
        "  sc_ptrace_traceme           sc_unshare_user\n"
        "  sc_process_vm_readv         sc_process_vm_writev\n"
        "  sc_userfaultfd              sc_perf_event_open\n"
    );
}

int main(int argc, char *argv[])
{
    if (argc < 2) { usage(); return 1; }

    const char *cmd = argv[1];

    /* Filesystem */
    if (strcmp(cmd, "fs_read") == 0 && argc >= 3)      return do_fs_read(argv[2]);
    if (strcmp(cmd, "fs_write") == 0 && argc >= 3)     return do_fs_write(argv[2]);
    if (strcmp(cmd, "fs_append") == 0 && argc >= 3)    return do_fs_append(argv[2]);
    if (strcmp(cmd, "fs_create") == 0 && argc >= 3)    return do_fs_create(argv[2]);
    if (strcmp(cmd, "fs_truncate") == 0 && argc >= 3)  return do_fs_truncate(argv[2]);
    if (strcmp(cmd, "fs_unlink") == 0 && argc >= 3)    return do_fs_unlink(argv[2]);
    if (strcmp(cmd, "fs_mkdir") == 0 && argc >= 3)     return do_fs_mkdir(argv[2]);
    if (strcmp(cmd, "fs_rmdir") == 0 && argc >= 3)     return do_fs_rmdir(argv[2]);
    if (strcmp(cmd, "fs_rename") == 0 && argc >= 4)    return do_fs_rename(argv[2], argv[3]);
    if (strcmp(cmd, "fs_symlink") == 0 && argc >= 4)   return do_fs_symlink(argv[2], argv[3]);
    if (strcmp(cmd, "fs_chdir") == 0 && argc >= 3)     return do_fs_chdir(argv[2]);
    if (strcmp(cmd, "fs_stat") == 0 && argc >= 3)      return do_fs_stat(argv[2]);
    if (strcmp(cmd, "fs_exec") == 0 && argc >= 3)      return do_fs_exec(argc - 2, argv + 2);

    /* Environment */
    if (strcmp(cmd, "env_get") == 0 && argc >= 3)      return do_env_get(argv[2]);
    if (strcmp(cmd, "env_dump") == 0)                   return do_env_dump();

    /* FD */
    if (strcmp(cmd, "fd_list") == 0)                    return do_fd_list();
    if (strcmp(cmd, "fd_read") == 0 && argc >= 3)      return do_fd_read(argv[2]);

    /* Network */
    if (strcmp(cmd, "net_tcp") == 0 && argc >= 4)      return do_net_tcp(argv[2], argv[3]);

    /* Child process */
    if (strcmp(cmd, "spawn_sh") == 0 && argc >= 3)     return do_spawn_sh(argv[2]);
    if (strcmp(cmd, "spawn_abs_bash") == 0 && argc >= 3) return do_spawn_abs_bash(argv[2]);
    if (strcmp(cmd, "spawn_nested") == 0 && argc >= 3) return do_spawn_nested(argv[2]);

    /* Syscall probes */
    if (strcmp(cmd, "sc_ptrace_traceme") == 0)          return do_sc_ptrace();
    if (strcmp(cmd, "sc_unshare_user") == 0)            return do_sc_unshare();
    if (strcmp(cmd, "sc_process_vm_readv") == 0)        return do_sc_process_vm_readv();
    if (strcmp(cmd, "sc_process_vm_writev") == 0)       return do_sc_process_vm_writev();
    if (strcmp(cmd, "sc_userfaultfd") == 0)             return do_sc_userfaultfd();
    if (strcmp(cmd, "sc_perf_event_open") == 0)         return do_sc_perf_event_open();

    fprintf(stderr, "deny_probe: unknown command: %s\n", cmd);
    usage();
    return 1;
}
