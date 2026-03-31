/*
 * shell-guard — shell replacement with policy enforcement
 *
 * Replaces the login shell to enforce security policies:
 *   - UID/GID validation
 *   - PPID chain inspection (who launched this shell?)
 *   - CWD and executable path validation
 *   - Network socket auditing
 *   - Environment variable sanitization
 *   - Argument validation
 *   - seccomp syscall filtering
 *   - Comprehensive syslog logging
 *
 * Install by symlinking as /bin/bash (or whatever shell) and placing
 * the real shell at /bin/shells/bash. All shell invocations are logged
 * and optionally policy-checked before exec'ing the real shell.
 *
 * Compile with MONITORING defined (default) for log-only mode.
 * Undefine MONITORING for enforcement mode.
 *
 * Usage: Typically invoked as the user's login shell, not directly.
 * Configuration: config.yaml → config.py → config.h (compile-time)
 *
 * Requirements: libseccomp (enforcement mode only)
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <syslog.h>
#include <pwd.h>
#include <time.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <termios.h>
#ifndef MONITORING
#include <seccomp.h>
#endif
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <stdarg.h>
#include "config.h"

#define REAL_SHELL_DIR "/bin/shells"
#define MAX_LOG_MESSAGE_SIZE 4096
#define ALLOWED_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_. /"
#define MAX_ARG_STR_LENGTH 1024
#define MAX_CWD_LENGTH 1024
#define MAX_TTY_INFO_LENGTH 256
#define MAX_PPID_STR_LENGTH 256
#define MAX_ALLOWED_ARG_LENGTH 4096

/* Uncomment to enable monitoring mode (log-only, no enforcement) */
#define MONITORING

/* Maximum depth for PPID traversal to avoid infinite loops */
#define MAX_PPID_CHAIN 64

#define SYSLOG_IDENT "shell-guard"

/* Prototypes */
void log_execution(const char *shell_name, char *const argv[], pid_t pid,
                   pid_t ppid, const pid_t ppid_chain[], int ppid_chain_length);
void log_tty_info(pid_t pid, char *tty_info);
char *get_cwd(pid_t pid);
#ifndef MONITORING
bool is_uid_allowed(uid_t uid);
bool is_gid_allowed(gid_t gid);
bool check_rate_limit(uid_t uid);
bool is_ppid_chain_valid(const pid_t ppid_chain[], int ppid_chain_length);
bool is_cwd_allowed(const char *cwd);
bool is_executable_allowed(pid_t pid);
bool check_forbidden_env(void);
void sanitize_environment(void);
bool validate_arguments(char *const argv[], const pid_t ppid_chain[], int ppid_chain_length);
void apply_strict_seccomp(uid_t uid);
void deny_execution(const char *reason, const pid_t ppid_chain[], int ppid_chain_length);
#endif
void execute_real_shell(const char *shell_path, char *const argv[]);
bool has_allowed_socket(pid_t pid);
bool check_inode_in_net_file(unsigned long inode, const char *net_file,
                             int family, const char *protocol);
bool is_ip_in_allowed_range(const char *ip_str);
bool ip_in_cidr(const char *ip_str, const char *cidr);
int get_ppid_chain(pid_t pid, pid_t ppid_chain[], int max_length);

int main(int argc, char *argv[]) {
    (void)argc;

    char *shell_name = basename(argv[0]);

    pid_t pid = getpid();
    pid_t ppid_chain[MAX_PPID_CHAIN];
    int ppid_chain_length = get_ppid_chain(pid, ppid_chain, MAX_PPID_CHAIN);

    log_execution(shell_name, argv, pid, getppid(), ppid_chain, ppid_chain_length);

#ifndef MONITORING
    uid_t uid = getuid();
    gid_t gid = getgid();

    if (!is_uid_allowed(uid))
        deny_execution("UID not allowed", ppid_chain, ppid_chain_length);
    if (!is_gid_allowed(gid))
        deny_execution("GID not allowed", ppid_chain, ppid_chain_length);
    if (!check_rate_limit(uid))
        deny_execution("Rate limit exceeded", ppid_chain, ppid_chain_length);
    if (!is_ppid_chain_valid(ppid_chain, ppid_chain_length))
        deny_execution("Parent process chain validation failed", ppid_chain, ppid_chain_length);
    if (!check_forbidden_env())
        deny_execution("Forbidden environment variables detected", ppid_chain, ppid_chain_length);

    sanitize_environment();

    if (!validate_arguments(argv, ppid_chain, ppid_chain_length))
        deny_execution("Invalid command arguments", ppid_chain, ppid_chain_length);

    apply_strict_seccomp(uid);
#endif

    char real_shell_path[PATH_MAX];
    snprintf(real_shell_path, sizeof(real_shell_path), "%s/%s", REAL_SHELL_DIR, shell_name);
    execute_real_shell(real_shell_path, argv);

    perror("execv");
    exit(EXIT_FAILURE);
}

/* Get PPID chain up to PID 1 */
int get_ppid_chain(pid_t pid, pid_t ppid_chain[], int max_length) {
    int length = 0;
    pid_t current_pid = pid;

    while (current_pid != 1 && length < max_length) {
        char status_path[PATH_MAX];
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", current_pid);

        FILE *fp = fopen(status_path, "r");
        if (!fp) break;

        char line[256];
        pid_t ppid = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "PPid:", 5) == 0) {
                sscanf(line, "PPid:\t%d", &ppid);
                break;
            }
        }
        fclose(fp);

        if (ppid == 0 || ppid == current_pid) break;

        ppid_chain[length++] = ppid;
        current_pid = ppid;
    }
    return length;
}

/* Log shell execution to syslog */
void log_execution(const char *shell_name, char *const argv[], pid_t pid,
                   pid_t ppid, const pid_t ppid_chain[], int ppid_chain_length) {
    char log_message[MAX_LOG_MESSAGE_SIZE];
    char cwd[PATH_MAX] = {0};
    char tty_info[256] = {0};
    char ppid_exe_path[PATH_MAX] = "Unknown";

    /* Build argument string */
    size_t total_arg_len = 1;  /* at least 1 for NUL */
    for (int i = 0; argv[i] != NULL; i++)
        total_arg_len += strlen(argv[i]) + 1;
    if (total_arg_len > MAX_ARG_STR_LENGTH)
        total_arg_len = MAX_ARG_STR_LENGTH;

    char *arg_str = malloc(total_arg_len);
    if (arg_str == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    arg_str[0] = '\0';

    for (int i = 0; argv[i] != NULL && strlen(arg_str) < total_arg_len - 1; i++) {
        strncat(arg_str, argv[i], total_arg_len - strlen(arg_str) - 1);
        if (argv[i + 1] != NULL && strlen(arg_str) < total_arg_len - 1)
            strncat(arg_str, " ", total_arg_len - strlen(arg_str) - 1);
    }

    /* Build PPID chain string */
    size_t ppid_str_size = ppid_chain_length * 16;
    if (ppid_str_size > MAX_PPID_STR_LENGTH)
        ppid_str_size = MAX_PPID_STR_LENGTH;
    if (ppid_str_size == 0)
        ppid_str_size = 1;

    char *ppid_str = malloc(ppid_str_size);
    if (ppid_str == NULL) {
        perror("malloc");
        free(arg_str);
        exit(EXIT_FAILURE);
    }
    ppid_str[0] = '\0';

    for (int i = 0; i < ppid_chain_length && strlen(ppid_str) < ppid_str_size - 1; i++) {
        char pid_buf[16];
        snprintf(pid_buf, sizeof(pid_buf), "%d", ppid_chain[i]);
        strncat(ppid_str, pid_buf, ppid_str_size - strlen(ppid_str) - 1);
        if (i < ppid_chain_length - 1 && strlen(ppid_str) < ppid_str_size - 1)
            strncat(ppid_str, "->", ppid_str_size - strlen(ppid_str) - 1);
    }

    /* Get current working directory */
    char *cwd_ptr = get_cwd(pid);
    if (cwd_ptr) {
        strncpy(cwd, cwd_ptr, sizeof(cwd) - 1);
        cwd[sizeof(cwd) - 1] = '\0';
        free(cwd_ptr);
    } else {
        strcpy(cwd, "Unknown");
    }

    log_tty_info(pid, tty_info);

    /* Timestamp */
    time_t now = time(NULL);
    char time_str[64];
    if (strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now)) == 0)
        strcpy(time_str, "Unknown Time");

    /* Username */
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    const char *username = pw ? pw->pw_name : "unknown";

    /* Truncated copies */
    char truncated_cwd[MAX_CWD_LENGTH + 1];
    strncpy(truncated_cwd, cwd, MAX_CWD_LENGTH);
    truncated_cwd[MAX_CWD_LENGTH] = '\0';

    char truncated_tty_info[MAX_TTY_INFO_LENGTH + 1];
    strncpy(truncated_tty_info, tty_info, MAX_TTY_INFO_LENGTH);
    truncated_tty_info[MAX_TTY_INFO_LENGTH] = '\0';

    /* PPID executable path */
    char exe_path[PATH_MAX];
    char resolved_path[PATH_MAX];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", ppid);
    ssize_t len = readlink(exe_path, resolved_path, sizeof(resolved_path) - 1);
    if (len != -1) {
        resolved_path[len] = '\0';
        strncpy(ppid_exe_path, resolved_path, sizeof(ppid_exe_path) - 1);
        ppid_exe_path[sizeof(ppid_exe_path) - 1] = '\0';
    }

    int ret = snprintf(log_message, sizeof(log_message),
        "[%s] USER:%s UID:%d PID:%d PPID:%d PPID_EXE:\"%s\" PPID_CHAIN:%.256s "
        "CMD:\"%s\" ARGS:\"%.1024s\" CWD:\"%.1024s\" TTY:\"%.256s\"",
        time_str, username, uid, pid, ppid, ppid_exe_path, ppid_str,
        shell_name, arg_str, truncated_cwd, truncated_tty_info);

    if (ret < 0) {
        perror("snprintf");
    } else if (ret >= (int)sizeof(log_message)) {
        fprintf(stderr, "Warning: log message truncated\n");
    }

    openlog(SYSLOG_IDENT, LOG_PID | LOG_NDELAY, LOG_AUTH);
    syslog(LOG_INFO, "%s", log_message);
    closelog();

    free(arg_str);
    free(ppid_str);
}

char *get_cwd(pid_t pid) {
    char cwd_path[PATH_MAX];
    char *resolved_path = malloc(PATH_MAX);
    if (!resolved_path) return NULL;

    snprintf(cwd_path, sizeof(cwd_path), "/proc/%d/cwd", pid);
    ssize_t len = readlink(cwd_path, resolved_path, PATH_MAX - 1);
    if (len == -1) {
        free(resolved_path);
        return NULL;
    }
    resolved_path[len] = '\0';
    return resolved_path;
}

void log_tty_info(pid_t pid, char *tty_info) {
    char tty_path[PATH_MAX];
    char link_path[PATH_MAX];
    snprintf(tty_path, sizeof(tty_path), "/proc/%d/fd/0", pid);
    ssize_t len = readlink(tty_path, link_path, sizeof(link_path) - 1);
    if (len != -1) {
        link_path[len] = '\0';
        strncpy(tty_info, link_path, 255);
        tty_info[255] = '\0';
    } else {
        strcpy(tty_info, "No TTY");
    }
}

#ifndef MONITORING

void deny_execution(const char *reason, const pid_t ppid_chain[], int ppid_chain_length) {
    char log_message[MAX_LOG_MESSAGE_SIZE];
    char ppid_str[256] = {0};

    for (int i = 0; i < ppid_chain_length; i++) {
        char pid_buf[16];
        snprintf(pid_buf, sizeof(pid_buf), "%d", ppid_chain[i]);
        strncat(ppid_str, pid_buf, sizeof(ppid_str) - strlen(ppid_str) - 2);
        if (i < ppid_chain_length - 1)
            strncat(ppid_str, "->", sizeof(ppid_str) - strlen(ppid_str) - 1);
    }

    time_t now = time(NULL);
    char time_str[64];
    if (strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now)) == 0)
        strcpy(time_str, "Unknown Time");

    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    const char *username = pw ? pw->pw_name : "unknown";

    snprintf(log_message, sizeof(log_message),
        "[%s] DENIED USER:%s UID:%d REASON:%s PPID_CHAIN:%s",
        time_str, username, uid, reason, ppid_str);

    openlog(SYSLOG_IDENT, LOG_PID | LOG_NDELAY, LOG_AUTH);
    syslog(LOG_WARNING, "%s", log_message);
    closelog();

    fprintf(stderr, "Execution denied: %s\n", reason);
    exit(EXIT_FAILURE);
}

bool is_ppid_chain_valid(const pid_t ppid_chain[], int ppid_chain_length) {
    for (int i = 0; i < ppid_chain_length; i++) {
        pid_t ppid = ppid_chain[i];

        if (!is_executable_allowed(ppid))
            return false;

        char *cwd = get_cwd(ppid);
        if (cwd) {
            bool cwd_allowed = is_cwd_allowed(cwd);
            free(cwd);
            if (!cwd_allowed) return false;
        } else {
            return false;
        }

        if (!has_allowed_socket(ppid))
            return false;
    }
    return true;
}

bool is_cwd_allowed(const char *cwd) {
    for (int i = 0; allowed_cwds[i] != NULL; i++) {
        if (strncmp(cwd, allowed_cwds[i], strlen(allowed_cwds[i])) == 0)
            return true;
    }
    return false;
}

bool is_uid_allowed(uid_t uid) {
    for (int i = 0; allowed_uids[i] != (uid_t)-1; i++) {
        if (uid == allowed_uids[i])
            return true;
    }
    return false;
}

bool is_gid_allowed(gid_t gid) {
    for (int i = 0; allowed_gids[i] != (gid_t)-1; i++) {
        if (gid == allowed_gids[i])
            return true;
    }
    return false;
}

bool check_rate_limit(uid_t uid) {
    (void)uid;
    /* TODO: implement via shared memory or temp file */
    return true;
}

bool is_executable_allowed(pid_t pid) {
    char exe_path[PATH_MAX];
    char resolved_path[PATH_MAX];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    ssize_t len = readlink(exe_path, resolved_path, sizeof(resolved_path) - 1);
    if (len == -1) return false;
    resolved_path[len] = '\0';
    char *deleted = strstr(resolved_path, " (deleted)");
    if (deleted) *deleted = '\0';

    for (int i = 0; allowed_executables[i] != NULL; i++) {
        if (strcmp(resolved_path, allowed_executables[i]) == 0)
            return true;
    }
    return false;
}

bool check_forbidden_env(void) {
    for (int i = 0; forbidden_env_vars[i] != NULL; i++) {
        if (getenv(forbidden_env_vars[i]))
            return false;
    }
    return true;
}

void sanitize_environment(void) {
    extern char **environ;
    char *saved_values[64] = {0};
    char *saved_names[64] = {0};
    int count = 0;
    for (int i = 0; allowed_env_vars[i] != NULL && count < 64; i++) {
        char *v = getenv(allowed_env_vars[i]);
        if (v) {
            saved_names[count] = (char *)allowed_env_vars[i];
            saved_values[count] = strdup(v);
            count++;
        }
    }
    clearenv();
    for (int i = 0; i < count; i++) {
        if (saved_values[i]) {
            setenv(saved_names[i], saved_values[i], 1);
            free(saved_values[i]);
        }
    }
}

bool validate_arguments(char *const argv[], const pid_t ppid_chain[], int ppid_chain_length) {
    for (int i = 0; argv[i] != NULL; i++) {
        if (strlen(argv[i]) > MAX_ALLOWED_ARG_LENGTH)
            deny_execution("Argument too long", ppid_chain, ppid_chain_length);
    }

    for (int i = 1; argv[i] != NULL; i++) {
        for (char *c = argv[i]; *c != '\0'; c++) {
            if (strchr(ALLOWED_CHARS, *c) == NULL)
                return false;
        }
    }
    return true;
}

void apply_strict_seccomp(uid_t uid) {
    (void)uid;

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (!ctx) {
        perror("seccomp_init");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; seccomp_allowed_syscalls[i] != NULL; i++) {
        int syscall_num = seccomp_syscall_resolve_name(seccomp_allowed_syscalls[i]);
        if (syscall_num == __NR_SCMP_ERROR) {
            fprintf(stderr, "Unknown syscall: %s\n", seccomp_allowed_syscalls[i]);
            seccomp_release(ctx);
            exit(EXIT_FAILURE);
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_num, 0) != 0) {
            perror("seccomp_rule_add");
            seccomp_release(ctx);
            exit(EXIT_FAILURE);
        }
    }

    if (seccomp_load(ctx) != 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        exit(EXIT_FAILURE);
    }
    seccomp_release(ctx);
}

#endif /* MONITORING */

void execute_real_shell(const char *shell_path, char *const argv[]) {
    if (access(shell_path, X_OK) != 0) {
#ifndef MONITORING
        deny_execution("Real shell not found or not executable", NULL, 0);
#else
        openlog(SYSLOG_IDENT, LOG_PID | LOG_NDELAY, LOG_AUTH);
        syslog(LOG_ERR, "Real shell not found or not executable: %s", shell_path);
        closelog();
#endif
    }

    execv(shell_path, argv);
    perror("execv");
    exit(EXIT_FAILURE);
}

/* Check if the process has allowed network sockets */
bool has_allowed_socket(pid_t pid) {
    const char *net_files[] = {
        "/proc/net/tcp",  "/proc/net/tcp6",
        "/proc/net/udp",  "/proc/net/udp6",
        "/proc/net/raw",  "/proc/net/raw6",
        NULL
    };
    const char *protocols[] = {
        "tcp", "tcp6", "udp", "udp6", "raw", "raw6"
    };

    char fd_dir[256];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
    DIR *dir = opendir(fd_dir);
    if (!dir) return false;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char fd_path[512];
        snprintf(fd_path, sizeof(fd_path), "%s/%s", fd_dir, entry->d_name);

        char link_target[256];
        ssize_t len = readlink(fd_path, link_target, sizeof(link_target) - 1);
        if (len == -1) continue;
        link_target[len] = '\0';

        if (strncmp(link_target, "socket:[", 8) == 0) {
            unsigned long inode = 0;
            sscanf(link_target, "socket:[%lu]", &inode);
            if (inode == 0) continue;

            for (int i = 0; net_files[i] != NULL; i++) {
                int family = (strstr(net_files[i], "6") != NULL) ? AF_INET6 : AF_INET;
                if (check_inode_in_net_file(inode, net_files[i], family, protocols[i])) {
                    closedir(dir);
                    return true;
                }
            }
        }
    }
    closedir(dir);
    return true;
}

bool check_inode_in_net_file(unsigned long inode, const char *net_file,
                             int family, const char *protocol) {
    FILE *fp = fopen(net_file, "r");
    if (!fp) return false;

    char line[512];
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return false; }

    while (fgets(line, sizeof(line), fp)) {
        unsigned long entry_inode = 0;
        char local_addr_hex[64];
        unsigned int local_port = 0;

        if (family == AF_INET) {
            sscanf(line, " %*d: %8[0-9A-Fa-f]:%X %*s %*s %*s %*s %*s %*s %*s %lu",
                   local_addr_hex, &local_port, &entry_inode);
        } else if (family == AF_INET6) {
            sscanf(line, " %*d: %32[0-9A-Fa-f]:%X %*s %*s %*s %*s %*s %*s %*s %lu",
                   local_addr_hex, &local_port, &entry_inode);
        }

        if (entry_inode == inode) {
            char ip_str[INET6_ADDRSTRLEN] = {0};
            if (family == AF_INET) {
                unsigned int addr_int;
                sscanf(local_addr_hex, "%X", &addr_int);
                struct in_addr addr;
                addr.s_addr = addr_int;
                inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            } else if (family == AF_INET6) {
                unsigned int addr_parts[4];
                sscanf(local_addr_hex, "%8X%8X%8X%8X",
                       &addr_parts[0], &addr_parts[1],
                       &addr_parts[2], &addr_parts[3]);
                struct in6_addr addr6;
                for (int i = 0; i < 4; i++)
                    addr6.s6_addr32[i] = htonl(addr_parts[i]);
                inet_ntop(AF_INET6, &addr6, ip_str, sizeof(ip_str));
            }

            fclose(fp);

            if (is_ip_in_allowed_range(ip_str)) {
                openlog(SYSLOG_IDENT, LOG_PID | LOG_NDELAY, LOG_AUTH);
                syslog(LOG_INFO, "Allowed %s socket to %s", protocol, ip_str);
                closelog();
                return true;
            } else {
                openlog(SYSLOG_IDENT, LOG_PID | LOG_NDELAY, LOG_AUTH);
                syslog(LOG_WARNING, "Disallowed %s socket to %s", protocol, ip_str);
                closelog();
                return false;
            }
        }
    }

    fclose(fp);
    return false;
}

bool is_ip_in_allowed_range(const char *ip_str) {
    for (int i = 0; allowed_network_ranges[i] != NULL; i++) {
        if (ip_in_cidr(ip_str, allowed_network_ranges[i]))
            return true;
    }
    return false;
}

bool ip_in_cidr(const char *ip_str, const char *cidr) {
    char network[INET6_ADDRSTRLEN + 4];
    strncpy(network, cidr, sizeof(network));
    network[sizeof(network) - 1] = '\0';

    char *slash = strchr(network, '/');
    int prefix_length = 0;

    int family = strchr(network, ':') ? AF_INET6 : AF_INET;
    int max_prefix = (family == AF_INET6) ? 128 : 32;

    if (slash) {
        *slash = '\0';
        prefix_length = atoi(slash + 1);
    } else {
        prefix_length = max_prefix;
    }

    if (prefix_length < 0 || prefix_length > max_prefix) return false;
    unsigned char ip_bin[16] = {0};
    unsigned char network_bin[16] = {0};

    if (inet_pton(family, ip_str, ip_bin) != 1) return false;
    if (inet_pton(family, network, network_bin) != 1) return false;

    int full_bytes = prefix_length / 8;
    int remaining_bits = prefix_length % 8;

    if (memcmp(ip_bin, network_bin, full_bytes) != 0) return false;

    if (remaining_bits > 0) {
        unsigned char mask = ((1 << remaining_bits) - 1) << (8 - remaining_bits);
        if ((ip_bin[full_bytes] & mask) != (network_bin[full_bytes] & mask))
            return false;
    }

    return true;
}
