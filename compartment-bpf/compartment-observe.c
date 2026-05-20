// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
// compartment-bpf observe subcommand — AO-1 (CLI), AO-4 (path resolver),
// AO-5 (profile draft transform).
//
// Entry point: observe_main(argc, argv) — called from compartment-bpf.c
// when argv[1] == "observe".
//
// AO-6 (global compact mode) and AO-7 (deny-first bridge) are deferred.
// DEFERRED: AO-6 — global compact mode (--global all-task with aggressive aggregation).
// DEFERRED: AO-7 — deny-first bridge / handoff to compartment-bpf genprofile.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "compartment-observe.skel.h"
#include "compartment-abi.h"

#define PIN_ROOT         "/sys/fs/bpf/compartment"
#define AO_MAX_ACTORS    32
#define AO_MAX_OBSERVED  65536
#define AO_DIR_COLLAPSE  3      /* min files per parent dir to collapse */
enum { AO_PROFILE_ACTOR_NAME_MAX = sizeof(((struct seal_value *)0)->actor_name) };

/* Event type codes (must match compartment-observe.bpf.c) */
#define AO_EV_ACTOR_EXEC         1u
#define AO_EV_ACTOR_EXEC_HELPER  3u
#define AO_EV_FS_FIRST_SIGHTING  6u
#define AO_EV_FS_CREATE          7u
#define AO_EV_FS_UNLINK          8u
#define AO_EV_FS_RENAME          9u
#define AO_EV_FS_MKDIR           10u
#define AO_EV_FS_RMDIR           11u
#define AO_EV_FS_LINK            12u
#define AO_EV_FS_MKNOD           13u
#define AO_EV_FS_SYMLINK         14u

/* op_class */
#define AO_OP_OPEN_R     1u
#define AO_OP_OPEN_W     2u
#define AO_OP_OPEN_RW    3u
#define AO_OP_OPEN_TRUNC 4u
#define AO_OP_CREATE     5u
#define AO_OP_UNLINK     6u
#define AO_OP_RENAME     7u
#define AO_OP_MKDIR      8u
#define AO_OP_RMDIR      9u
#define AO_OP_LINK       10u
#define AO_OP_MKNOD      11u
#define AO_OP_SYMLINK    12u
#define AO_OP_RENAME_DST 13u

/* Counter slots */
#define C_EVENTS_SEEN_TOTAL              0
#define C_EVENTS_SAMPLED_TOTAL           1
#define C_EVENTS_RINGBUF_DROP_TOTAL      2
#define C_OBSERVED_FILES_TOTAL           3
#define C_OBSERVED_FILES_OVERFLOW_TOTAL  4
#define C_CURRENT_ACTOR_COPY_FORK_TOTAL  5
#define C_LINEAGE_COPY_FORK_TOTAL        6
#define C_LINEAGE_EXEC_HELPER_TOTAL      7
#define C_PATH_RESOLVE_FAIL_TOTAL        8
#define C_MAX                            9

/* Output format */
#define FMT_PROFILE 0
#define FMT_COMPACT 1
#define FMT_JSONL   2
#define FMT_AUDIT   3

/* ----- data structures (userspace mirrors of BPF structs) ----- */

struct ao_file_id {
	uint64_t dev;
	uint64_t ino;
};

struct ao_event {
	uint32_t type;
	uint32_t actor_slot;
	uint64_t dev;
	uint64_t ino;
	uint64_t parent_dev;
	uint64_t parent_ino;
	uint32_t op_class;
	uint32_t pid;
	uint32_t tgid;
	uint32_t ppid;
	uint64_t timestamp_ns;
	uint64_t cgroup_id;
	uint8_t  under_current_actor;
	uint8_t  under_actor_lineage;
	uint8_t  _pad[6];
};

struct ao_observed_key {
	uint32_t actor_slot;
	uint32_t op_class;
	uint64_t dev;
	uint64_t ino;
	uint64_t parent_dev;
	uint64_t parent_ino;
};

struct ao_observed_value {
	uint64_t count;
	uint64_t first_ns;
	uint64_t last_ns;
	uint32_t sample_pid;
	uint32_t sample_tgid;
	uint32_t flags_seen;
	uint8_t  under_current_actor;
	uint8_t  under_actor_lineage;
	uint8_t  _pad[2];
	uint32_t _lock; /* matches struct bpf_spin_lock in BPF-side observed_value (M-9) */
};

struct ao_launcher_key {
	uint32_t actor_slot;
	uint32_t _pad;
	uint64_t parent_dev;
	uint64_t parent_ino;
};

struct ao_launcher_value {
	uint64_t count;
	uint32_t sample_pid;
	uint32_t sample_ppid;
	uint64_t sample_cgroup_id;
};

/* ----- actor registration ----- */

struct actor_reg {
	char     name[64];
	char     path[PATH_MAX];
	uint64_t dev;
	uint64_t ino;
	uint32_t slot;
	int      inferred_from_cmd;
};

/* ----- observed file entry with resolved path hint ----- */

struct obs_entry {
	struct ao_observed_key   key;
	struct ao_observed_value val;
	char path_hint[PATH_MAX];    /* file path; empty if unresolved */
	char parent_hint[PATH_MAX];  /* parent directory path; empty if unresolved */
};

/* ----- CLI options ----- */

struct observe_opts {
	struct actor_reg actors[AO_MAX_ACTORS];
	int   nactors;
	int   pid_seed;              /* --pid PID */
	int   duration;              /* --duration N; -1 = SIGINT / child-exit */
	int   format;                /* FMT_* */
	int   verbose;
	int   include_stat;
	int   no_resolve_paths;
	int   no_dir_dest;           /* force pre-v0.5 warning (testing) */
	char  output[PATH_MAX];      /* "" = stdout */
	char  provenance_out[PATH_MAX];
	char **cmd_argv;
	int    cmd_argc;
};

/* ----- globals ----- */

static volatile sig_atomic_t g_stop;
static void on_sig(int x) { (void)x; g_stop = 1; }

static uint64_t g_path_resolve_fail;     /* total resolution failures (no path found) */
static uint64_t g_path_resolve_fallback; /* resolved via dev/ino fallback, not /proc/fd */

/* ----- live ringbuf callback context ----- */

struct live_ctx {
	const struct observe_opts *opts;
	const struct actor_reg    *actors;
	int                        nactors;
};

/* ===== helpers ===== */

static uint64_t to_kernel_dev(dev_t st_dev)
{
	unsigned int maj = major(st_dev);
	unsigned int min = minor(st_dev);
	return (uint64_t)((maj << 20) | (min & 0xfffffu));
}

static int path_to_file_id(const char *path, uint64_t *dev_out, uint64_t *ino_out)
{
	struct stat st;
	if (stat(path, &st) < 0) {
		fprintf(stderr, "observe: stat(%s): %s\n", path, strerror(errno));
		return -1;
	}
	*dev_out = to_kernel_dev(st.st_dev);
	*ino_out = (uint64_t)st.st_ino;
	return 0;
}

static const char *op_class_str(uint32_t op)
{
	switch (op) {
	case AO_OP_OPEN_R:     return "open_r";
	case AO_OP_OPEN_W:     return "open_w";
	case AO_OP_OPEN_RW:    return "open_rw";
	case AO_OP_OPEN_TRUNC: return "open_trunc";
	case AO_OP_CREATE:     return "create";
	case AO_OP_UNLINK:     return "unlink";
	case AO_OP_RENAME:     return "rename";
	case AO_OP_MKDIR:      return "mkdir";
	case AO_OP_RMDIR:      return "rmdir";
	case AO_OP_LINK:       return "link";
	case AO_OP_MKNOD:      return "mknod";
	case AO_OP_SYMLINK:    return "symlink";
	case AO_OP_RENAME_DST: return "rename_dst";
	default:               return "?";
	}
}

static const char *actor_name_for_slot(const struct actor_reg *actors, int n,
				       uint32_t slot)
{
	for (int i = 0; i < n; i++)
		if (actors[i].slot == slot)
			return actors[i].name;
	return "?";
}

static const char *iso_now(void)
{
	static char buf[32];
	time_t now = time(NULL);
	struct tm tm;
	gmtime_r(&now, &tm);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
	return buf;
}

static int actor_name_valid_profile(const char *name)
{
	size_t n;

	if (!name || !*name)
		return 0;
	n = strlen(name);
	if (n + 1 > AO_PROFILE_ACTOR_NAME_MAX)
		return 0;
	if (!(isalpha((unsigned char)name[0]) || name[0] == '_'))
		return 0;
	for (size_t i = 1; i < n; i++) {
		unsigned char c = (unsigned char)name[i];
		if (!(isalnum(c) || c == '_' || c == '-'))
			return 0;
	}
	return 1;
}

static int normalize_actor_name(const char *src, char *dst, size_t dstsz)
{
	size_t out = 0;
	int changed = 0;

	if (!dst || dstsz < 2)
		return -1;
	if (!src || !*src) {
		snprintf(dst, dstsz, "_actor");
		return 1;
	}

	if (!(isalpha((unsigned char)src[0]) || src[0] == '_')) {
		dst[out++] = '_';
		changed = 1;
	}

	for (size_t i = 0; src[i] != '\0' && out + 1 < dstsz; i++) {
		unsigned char c = (unsigned char)src[i];
		if (isalnum(c) || c == '_' || c == '-') {
			dst[out++] = (char)c;
		} else {
			dst[out++] = '_';
			changed = 1;
		}
	}
	if (strlen(src) + 1 > dstsz)
		changed = 1;
	dst[out] = '\0';
	if (!actor_name_valid_profile(dst)) {
		snprintf(dst, dstsz, "_actor");
		return 1;
	}
	return changed || strcmp(dst, src) != 0;
}

static int actor_name_in_use(const struct observe_opts *opts, const char *name)
{
	for (int i = 0; i < opts->nactors; i++) {
		if (strcmp(opts->actors[i].name, name) == 0)
			return 1;
	}
	return 0;
}

static int resolve_existing_path(const char *path, char *out, size_t outsz)
{
	char resolved[PATH_MAX];

	if (!path || !*path) {
		fprintf(stderr, "observe: empty path\n");
		return -1;
	}
	if (!realpath(path, resolved)) {
		fprintf(stderr, "observe: realpath(%s): %s\n",
			path, strerror(errno));
		return -1;
	}
	if (snprintf(out, outsz, "%s", resolved) >= (int)outsz) {
		fprintf(stderr, "observe: resolved path too long: %s\n", resolved);
		return -1;
	}
	return 0;
}

static int resolve_command_path(const char *cmd, char *out, size_t outsz)
{
	if (!cmd || !*cmd) {
		fprintf(stderr, "observe: empty command path\n");
		return -1;
	}
	if (strchr(cmd, '/'))
		return resolve_existing_path(cmd, out, outsz);

	const char *path_env = getenv("PATH");
	char *search = strdup(path_env && *path_env ? path_env
				       : "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
	if (!search) {
		fprintf(stderr, "observe: strdup(PATH): %s\n", strerror(errno));
		return -1;
	}

	int rc = -1;
	char *save = NULL;
	for (char *dir = strtok_r(search, ":", &save);
	     dir;
	     dir = strtok_r(NULL, ":", &save)) {
		char cand[PATH_MAX];
		const char *base = *dir ? dir : ".";
		if (snprintf(cand, sizeof(cand), "%s/%s", base, cmd) >=
		    (int)sizeof(cand))
			continue;
		if (access(cand, X_OK) != 0)
			continue;
		rc = resolve_existing_path(cand, out, outsz);
		if (rc == 0)
			break;
	}

	free(search);
	if (rc == 0)
		return 0;

	fprintf(stderr,
		"observe: cannot resolve command '%s' via PATH for actor inference\n",
		cmd);
	return -1;
}

static int validate_loader_compatible_actor_path(const char *name,
						 const char *path)
{
	struct stat st, pst;
	char parent[PATH_MAX];
	int fd, dfd;

	fd = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "observe: actor %s open(%s): %s\n",
			name, path, strerror(errno));
		return -1;
	}
	if (fstat(fd, &st) < 0) {
		fprintf(stderr, "observe: actor %s fstat(%s): %s\n",
			name, path, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);

	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr,
			"observe: actor %s path %s is not a regular file "
			"(loader-compatible output requires a regular executable)\n",
			name, path);
		return -1;
	}
	if (!(st.st_mode & 0111)) {
		fprintf(stderr,
			"observe: actor %s path %s is not executable "
			"(loader-compatible output requires an executable actor binary)\n",
			name, path);
		return -1;
	}
	if (st.st_size == 0) {
		fprintf(stderr,
			"observe: actor %s path %s is zero-byte "
			"(loader-compatible output refuses placeholder binaries)\n",
			name, path);
		return -1;
	}
	if (st.st_mode & (S_IWGRP | S_IWOTH)) {
		fprintf(stderr,
			"observe: actor %s path %s is group/world-writable "
			"(loader-compatible output refuses writable actor binaries)\n",
			name, path);
		return -1;
	}

	if (snprintf(parent, sizeof(parent), "%s", path) >= (int)sizeof(parent)) {
		fprintf(stderr,
			"observe: actor %s path too long for parent-dir validation: %s\n",
			name, path);
		return -1;
	}
	char *slash = strrchr(parent, '/');
	if (!slash) {
		fprintf(stderr, "observe: actor %s path is not absolute: %s\n",
			name, path);
		return -1;
	}
	if (slash == parent)
		parent[1] = '\0';
	else
		*slash = '\0';

	dfd = open(parent, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (dfd < 0) {
		fprintf(stderr, "observe: actor %s open parent(%s): %s\n",
			name, parent, strerror(errno));
		return -1;
	}
	if (fstat(dfd, &pst) < 0) {
		fprintf(stderr, "observe: actor %s fstat parent(%s): %s\n",
			name, parent, strerror(errno));
		close(dfd);
		return -1;
	}
	close(dfd);
	if (pst.st_mode & (S_IWGRP | S_IWOTH)) {
		fprintf(stderr,
			"observe: actor %s parent dir %s is group/world-writable "
			"(loader-compatible output refuses swappable actor binaries)\n",
			name, parent);
		return -1;
	}

	return 0;
}

/* ===== AO-4: path resolution ===== */

/* Sanitize a path returned by readlink(/proc/PID/fd/N) before it
 * flows into emit_profile() as a `seal %s ...` argument. The kernel does not
 * filter the contents of `/proc/PID/fd/<N>` readlinks; an actor can open a
 * file whose name embeds `\n`, `\r`, or `#`, and special pseudo-paths
 * (`pipe:[N]`, `socket:[N]`, `anon_inode:[xxx]`) or stale entries that
 * suffix ` (deleted)` are returned verbatim. Any of these, emitted unchecked
 * into the candidate profile, would either inject extra `seal` directives
 * or cause the loader to refuse the whole file.
 *
 * Rules (returns 0 on accept, -1 on reject — caller treats as unresolvable):
 *   - path must start with '/' (rejects pipe:/socket:/anon_inode:)
 *   - path must not contain '\n', '\r', '#', ' ' (0x20), or '\t' (0x09)
 *   - trailing " (deleted)" is stripped; if nothing remains, reject
 *
 * Space (0x20) and horizontal tab (0x09) are also
 * rejected because the profile parser tokenizes seal directives on
 * `strtok_r(..., " \t\r\n", ...)` (compartment-bpf.c parse path) and
 * `parse_flagspec` separator set `", \t\r\n"` — a filename containing
 * either would silently split the emitted `seal` directive into
 * unintended tokens (e.g. `/tmp/realfile\tfull` → seal /tmp/realfile
 * with flags `full`). Paths with whitespace in filenames are legal on
 * Linux but out-of-scope for the observe tool's candidate profile.
 */
static int sanitize_observed_path(char *path)
{
	if (!path || path[0] == '\0') return -1;
	size_t len = strlen(path);
	static const char deleted[] = " (deleted)";
	const size_t dlen = sizeof(deleted) - 1;
	if (len >= dlen && memcmp(path + len - dlen, deleted, dlen) == 0) {
		path[len - dlen] = '\0';
		len -= dlen;
	}
	if (path[0] != '/') return -1;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)path[i];
		if (c == '\n' || c == '\r' || c == '#') return -1;
		if (c == ' ' || c == '\t') {
			fprintf(stderr,
				"sanitize_observed_path: rejecting path with whitespace byte 0x%02x (would split seal directive)\n",
				c);
			return -1;
		}
	}
	return 0;
}

/* Scan /proc/<pid>/fd/ for any process with (dev, ino) open. */
static int resolve_by_procfd(uint64_t dev, uint64_t ino, char *buf, size_t bufsz)
{
	DIR *proc = opendir("/proc");
	if (!proc) return -1;
	int found = 0;
	struct dirent *de;
	while (!found && (de = readdir(proc)) != NULL) {
		if (!isdigit((unsigned char)de->d_name[0])) continue;
		char fddir[128];
		snprintf(fddir, sizeof(fddir), "/proc/%.20s/fd", de->d_name);
		DIR *fdd = opendir(fddir);
		if (!fdd) continue;
		struct dirent *fde;
		while ((fde = readdir(fdd)) != NULL) {
			if (!isdigit((unsigned char)fde->d_name[0])) continue;
			char fdpath[256];
			snprintf(fdpath, sizeof(fdpath), "/proc/%.20s/fd/%.20s",
				 de->d_name, fde->d_name);
			struct stat st;
			if (fstatat(AT_FDCWD, fdpath, &st, 0) != 0) continue;
			if (to_kernel_dev(st.st_dev) == dev && (uint64_t)st.st_ino == ino) {
				ssize_t r = readlink(fdpath, buf, (ssize_t)bufsz - 1);
				if (r > 0) {
					buf[r] = '\0';
					/* Reject unsafe readlink output
					 * (pipe:/socket:/anon_inode:, embedded \n,
					 * \r, '#', or " (deleted)" with nothing left). */
					if (sanitize_observed_path(buf) == 0) {
						found = 1; break;
					}
					buf[0] = '\0';
				}
			}
		}
		closedir(fdd);
	}
	closedir(proc);
	return found ? 0 : -1;
}

/* Map dev number to mount point via /proc/mounts.
 * M-15: /proc/mounts is read once per resolve_path call. The map is stale if
 * a filesystem is mounted or unmounted after the call. This is acceptable for
 * short observation sessions; a production implementation would refresh
 * periodically or watch for mount events via inotify on /proc/mounts. */
static int dev_to_mountpoint(uint64_t dev, char *mp, size_t mpsz)
{
	FILE *f = fopen("/proc/mounts", "r");
	if (!f) return -1;
	char line[512];
	int found = 0;
	while (!found && fgets(line, sizeof(line), f)) {
		char device[256], mountpoint[256], fstype[64], opts[256];
		int freq, passno;
		if (sscanf(line, "%255s %255s %63s %255s %d %d",
			   device, mountpoint, fstype, opts, &freq, &passno) < 2)
			continue;
		struct stat st;
		if (stat(mountpoint, &st) == 0 && to_kernel_dev(st.st_dev) == dev) {
			/* A5-P2-1: symmetric with the procfd branch — drop the
			 * mountpoint if it carries bytes that would split a seal
			 * directive (whitespace, '#', '\n', '\r') so the synthetic
			 * `<ino=N>` hint cannot tunnel a hostile mountpoint string
			 * into the candidate profile. */
			char tmp[PATH_MAX];
			snprintf(tmp, sizeof(tmp), "%s", mountpoint);
			if (sanitize_observed_path(tmp) != 0)
				continue;
			snprintf(mp, mpsz, "%s", tmp);
			found = 1;
		}
	}
	fclose(f);
	return found ? 0 : -1;
}

/* AO-4: resolve (dev, ino) → path hint + parent hint (best-effort).
 * Failures keep dev/ino record; increment g_path_resolve_fail. */
static void resolve_path(uint64_t dev, uint64_t ino,
			 char *buf, size_t bufsz,
			 char *parbuf, size_t parsz)
{
	buf[0] = '\0';
	if (parbuf) parbuf[0] = '\0';

	if (resolve_by_procfd(dev, ino, buf, bufsz) == 0) {
		/* Extract parent directory from resolved path */
		if (parbuf) {
			char tmp[PATH_MAX];
			snprintf(tmp, sizeof(tmp), "%s", buf);
			char *slash = strrchr(tmp, '/');
			if (slash && slash != tmp) { *slash = '\0'; snprintf(parbuf, parsz, "%s", tmp); }
			else if (slash == tmp) snprintf(parbuf, parsz, "/");
		}
		return;
	}

	/* Fallback: find mount point for this device.
	 * M-14: count as fallback (partial resolution), not total failure. */
	char mp[PATH_MAX] = "";
	if (dev_to_mountpoint(dev, mp, sizeof(mp)) == 0) {
		/* avoid double-slash when mountpoint is root "/" */
		if (mp[0] == '/' && mp[1] == '\0')
			snprintf(buf, bufsz, "/<ino=%"PRIu64">", ino);
		else
			snprintf(buf, bufsz, "%s/<ino=%"PRIu64">", mp, ino);
		g_path_resolve_fallback++;
	} else {
		snprintf(buf, bufsz, "<dev=0x%"PRIx64",ino=%"PRIu64">", dev, ino);
		g_path_resolve_fail++;
	}
}

static int is_create_like_op(uint32_t op_class)
{
	return op_class == AO_OP_CREATE ||
	       op_class == AO_OP_MKDIR ||
	       op_class == AO_OP_MKNOD ||
	       op_class == AO_OP_SYMLINK;
}

static int forces_dir_rule_op(uint32_t op_class)
{
	return is_create_like_op(op_class) ||
	       op_class == AO_OP_RENAME ||
	       op_class == AO_OP_RENAME_DST;
}

static int same_emitted_rule(const struct obs_entry *a,
			     const struct obs_entry *b)
{
	if (a->key.dev == b->key.dev && a->key.ino == b->key.ino)
		return 1;
	if (a->path_hint[0] && b->path_hint[0] &&
	    strcmp(a->path_hint, b->path_hint) == 0)
		return 1;
	return 0;
}

static int earlier_rule_for_group(const struct obs_entry *entries, int upto,
				  const struct obs_entry *needle)
{
	for (int i = 0; i < upto; i++) {
		const struct obs_entry *prev = &entries[i];
		if (prev->key.actor_slot != needle->key.actor_slot)
			continue;
		if (is_create_like_op(prev->key.op_class))
			continue;
		if (prev->key.parent_dev != needle->key.parent_dev ||
		    prev->key.parent_ino != needle->key.parent_ino)
			continue;
		if (same_emitted_rule(prev, needle))
			return 1;
	}
	return 0;
}

static int waitpid_retry(pid_t pid, int *status, int options)
{
	pid_t rc;

	do {
		rc = waitpid(pid, status, options);
	} while (rc < 0 && errno == EINTR);

	if (rc < 0)
		return -1;
	return (int)rc;
}

static int terminate_observe_child(pid_t pid)
{
	int status = 0;

	if (pid <= 0)
		return 0;
	int rc = waitpid_retry(pid, &status, WNOHANG);
	if (rc < 0) {
		if (errno == ECHILD)
			return 0;
		fprintf(stderr, "observe: waitpid(%d): %s\n",
			(int)pid, strerror(errno));
		return -1;
	}
	if (rc == pid)
		return 0;

	if (kill(pid, SIGTERM) < 0 && errno != ESRCH) {
		fprintf(stderr, "observe: SIGTERM %d: %s\n",
			(int)pid, strerror(errno));
		return -1;
	}

	for (int i = 0; i < 20; i++) {
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000L };
		nanosleep(&ts, NULL);
		rc = waitpid_retry(pid, &status, WNOHANG);
		if (rc < 0) {
			if (errno == ECHILD)
				return 0;
			fprintf(stderr, "observe: waitpid(%d): %s\n",
				(int)pid, strerror(errno));
			return -1;
		}
		if (rc == pid)
			return 0;
	}

	if (kill(pid, SIGKILL) < 0 && errno != ESRCH) {
		fprintf(stderr, "observe: SIGKILL %d: %s\n",
			(int)pid, strerror(errno));
		return -1;
	}

	rc = waitpid_retry(pid, &status, 0);
	if (rc < 0 && errno != ECHILD) {
		fprintf(stderr, "observe: waitpid(%d): %s\n",
			(int)pid, strerror(errno));
		return -1;
	}
	return 0;
}

/* ===== broad root check for directory collapse (SPEC §9.2) ===== */

static int is_broad_root(const char *path)
{
	/* M-16: extended with Ubuntu-common paths where per-file enumeration
	 * is preferred over a broad directory-destination seal. */
	static const char *broad[] = {
		"/", "/usr", "/etc", "/var", "/var/lib", "/run", "/tmp",
		"/opt", "/home", "/snap", "/lib", "/lib64", NULL
	};
	for (int i = 0; broad[i]; i++)
		if (strcmp(path, broad[i]) == 0) return 1;
	return 0;
}

/* ===== ABI version detection for dir-destination (AO-5 SPEC §9.1) ===== */

static int read_pinned_u32_map_cell(const char *path, uint32_t *out)
{
	__u32 zero = 0, val = 0;
	int fd = bpf_obj_get(path);
	int saved_errno;

	if (fd < 0)
		return -1;
	if (bpf_map_lookup_elem(fd, &zero, &val) < 0) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	close(fd);
	*out = val;
	return 0;
}

/* v0.6 exact probe: read PIN_ROOT/maps/abi_version_map[0] when present.
 * Legacy pinned runtimes from v0.4/v0.5 do not have that map, and the old
 * map shapes do not distinguish v0.4 from v0.5. In that legacy-ambiguous
 * case we fail safe to v0.4 behavior (per-file fallback only) rather than
 * guessing "v0.5" and emitting a profile the running loader may reject. */
static uint32_t detect_runtime_abi(int force_old)
{
	uint32_t abi = 0;
	int saved_errno;

	if (force_old) return 0x0004;
	if (read_pinned_u32_map_cell(PIN_ROOT "/maps/abi_version_map", &abi) == 0) {
		if (abi >= 0x0004 && abi <= COMPARTMENT_ABI_VERSION)
			return abi;
		fprintf(stderr,
			"observe: WARNING: unsupported runtime ABI 0x%04x from %s; "
			"using compile-time default 0x%04x.\n",
			abi, PIN_ROOT "/maps/abi_version_map",
			(unsigned)COMPARTMENT_ABI_VERSION);
		return COMPARTMENT_ABI_VERSION;
	}
	saved_errno = errno;

	/* Legacy pre-v0.6 runtime: exact v0.4 vs v0.5 discrimination is
	 * impossible from the remaining pinned surface. Use the safe minimum
	 * so observe emits only per-file fallback rules. */
	int fd = bpf_obj_get(PIN_ROOT "/maps/policy_state_map");
	if (fd >= 0) {
		close(fd);
		fprintf(stderr,
			"observe: WARNING: pinned runtime is legacy pre-v0.6 "
			"(no abi_version_map). Exact v0.4/v0.5 detection is "
			"impossible; using safe fallback 0x0004 and emitting "
			"per-file rules only.\n");
		return 0x0004;
	}

	/* No pinned runtime detected at all. Fall back to the build-time ABI. */
	errno = saved_errno;
	saved_errno = errno;
	if (saved_errno == 0)
		saved_errno = ENOENT;
	fprintf(stderr,
		"observe: WARNING: cannot determine runtime ABI from "
		"%s (%s); using compile-time default 0x%04x. The "
		"emitted profile may not match the kernel module "
		"actually loaded.\n",
		PIN_ROOT "/maps/abi_version_map", strerror(saved_errno),
		(unsigned)COMPARTMENT_ABI_VERSION);
	return COMPARTMENT_ABI_VERSION;
}

/* ===== live ringbuf event handler (compact / jsonl / audit) ===== */

static int handle_event(void *ctx, void *data, size_t sz)
{
	if (sz < sizeof(struct ao_event)) return 0;
	const struct ao_event *e = data;
	const struct live_ctx *lc = ctx;
	const struct observe_opts *opts = lc->opts;
	const char *aname = actor_name_for_slot(lc->actors, lc->nactors, e->actor_slot);

	if (opts->format == FMT_COMPACT) {
		time_t now = (time_t)(e->timestamp_ns / 1000000000ULL);
		struct tm tm;
		localtime_r(&now, &tm);
		char ts[16];
		strftime(ts, sizeof(ts), "%H:%M:%S", &tm);

		if (e->type == AO_EV_ACTOR_EXEC) {
			printf("%s actor=%s pid=%u ppid=%u exec\n",
			       ts, aname, e->pid, e->ppid);
		} else if (e->type == AO_EV_ACTOR_EXEC_HELPER) {
			printf("%s actor=%s lineage pid=%u helper "
			       "dev=0x%"PRIx64" ino=%"PRIu64"\n",
			       ts, aname, e->pid, e->dev, e->ino);
		} else {
			printf("%s actor=%s pid=%u op=%s "
			       "dev=0x%"PRIx64" ino=%"PRIu64,
			       ts, aname, e->pid,
			       op_class_str(e->op_class), e->dev, e->ino);
			if (opts->verbose)
				printf(" pdev=0x%"PRIx64" pino=%"PRIu64
				       " cgroup=%"PRIu64,
				       e->parent_dev, e->parent_ino, e->cgroup_id);
			printf("\n");
		}
		fflush(stdout);

	} else if (opts->format == FMT_JSONL) {
		const char *evtype =
			(e->type == AO_EV_ACTOR_EXEC)        ? "actor_exec" :
			(e->type == AO_EV_ACTOR_EXEC_HELPER)  ? "exec_helper" :
			(e->type == AO_EV_FS_CREATE)           ? "fs_create" :
			(e->type == AO_EV_FS_UNLINK)           ? "fs_unlink" :
			(e->type == AO_EV_FS_RENAME)           ? "fs_rename" :
			(e->type == AO_EV_FS_MKDIR)            ? "fs_mkdir" :
			(e->type == AO_EV_FS_RMDIR)            ? "fs_rmdir" :
			(e->type == AO_EV_FS_LINK)             ? "fs_link" :
			(e->type == AO_EV_FS_MKNOD)            ? "fs_mknod" :
			(e->type == AO_EV_FS_SYMLINK)          ? "fs_symlink" : "fs_open";
		printf("{\"type\":\"%s\",\"actor\":\"%s\","
		       "\"pid\":%u,\"ppid\":%u,"
		       "\"op\":\"%s\","
		       "\"dev\":\"0x%"PRIx64"\",\"ino\":%"PRIu64","
		       "\"ts_ns\":%"PRIu64"}\n",
		       evtype, aname, e->pid, e->ppid,
		       op_class_str(e->op_class), e->dev, e->ino,
		       e->timestamp_ns);
		fflush(stdout);

	} else if (opts->format == FMT_AUDIT) {
		printf("type=COMP_OBSERVE actor=%s pid=%u ppid=%u "
		       "op=%s dev=0x%"PRIx64" ino=%"PRIu64"\n",
		       aname, e->pid, e->ppid,
		       op_class_str(e->op_class), e->dev, e->ino);
		fflush(stdout);
	}
	return 0;
}

/* ===== AO-5: profile draft transform ===== */

/* dir_group: tracks files observed in one parent directory */
struct dir_group {
	uint64_t pdev;
	uint64_t pino;
	char     ppath[PATH_MAX];
	int      count;       /* open/unlink file count */
	int      has_creates; /* inode_create under this dir */
	int      force_dir_rule; /* op requires parent-dir coverage directly */
};

static void emit_profile(FILE *out,
			 const struct observe_opts *opts,
			 struct obs_entry *entries, int nentries,
			 const struct actor_reg *actors, int nactors,
			 int obs_fd, int launchers_fd,
			 uint64_t ringbuf_drops,
			 uint64_t obs_overflow)
{
	uint32_t abi = detect_runtime_abi(opts->no_dir_dest);
	int dir_dest = (abi >= 0x0005);
	int recursive_dir_dest = (abi >= 0x0006);
	const char *ts = iso_now();

	/* Build actor names list for header (M-18) */
	char actor_names[AO_MAX_ACTORS * 64 + 1];
	actor_names[0] = '\0';
	for (int ai = 0; ai < nactors; ai++) {
		if (ai > 0) strncat(actor_names, ",", sizeof(actor_names) - strlen(actor_names) - 1);
		strncat(actor_names, actors[ai].name, sizeof(actor_names) - strlen(actor_names) - 1);
	}

	/* Header */
	fprintf(out,
		"# generated by compartment-bpf observe\n"
		"#@compartment-bpf-profile-status: candidate\n"
		"# generated: %s\n"
		"# actors: %s\n"
		"# observed_at: %s\n"
		"# validation: candidate only; run deny-first before enforcing\n",
		ts, actor_names, ts);

	if (!dir_dest)
		fprintf(out,
			"# WARNING: running compartment-bpf does not expose exact directory-destination\n"
			"# semantics here. Emitting per-file rules as fallback.\n");

	if (ringbuf_drops > 0)
		fprintf(out,
			"# WARNING: %"PRIu64" ringbuf events dropped; "
			"observed_files map is authoritative.\n",
			ringbuf_drops);

	if (obs_overflow > 0)
		fprintf(out,
			"# WARNING: %"PRIu64" observed_files overflow(s); "
			"map full — some observations lost.\n",
			obs_overflow);

	if (g_path_resolve_fail > 0)
		fprintf(out,
			"# WARNING: %"PRIu64" path resolution failure(s) "
			"(no path found); dev/ino records preserved.\n",
			g_path_resolve_fail);
	if (g_path_resolve_fallback > 0)
		fprintf(out,
			"# NOTE: %"PRIu64" path(s) resolved via mountpoint fallback "
			"(dev/ino synthetic path, not /proc/fd).\n",
			g_path_resolve_fallback);

	/* One block per registered actor */
	for (int ai = 0; ai < nactors; ai++) {
		const struct actor_reg *a = &actors[ai];
		fprintf(out, "\n# target: %s\n", a->name);
		fprintf(out, "actor %s = %s\n", a->name, a->path);
		fprintf(out, "seal %s full\n", a->path);

		/* Launcher summary (SPEC §5.2) */
		fprintf(out, "\n# observed launchers:\n");
		{
			struct ao_launcher_key lk, lnxt;
			struct ao_launcher_value lv;
			int lr = bpf_map_get_next_key(launchers_fd, NULL, &lnxt);
			int found_any = 0;
			while (lr == 0) {
				lk = lnxt;
				if (lk.actor_slot == a->slot &&
				    bpf_map_lookup_elem(launchers_fd, &lk, &lv) == 0) {
					char ppath[PATH_MAX] = "", ppar[PATH_MAX] = "";
					if (!opts->no_resolve_paths)
						resolve_path(lk.parent_dev, lk.parent_ino,
							     ppath, sizeof(ppath),
							     ppar, sizeof(ppar));
					if (ppath[0])
						fprintf(out,
							"# parent %s count=%"PRIu64"\n",
							ppath, lv.count);
					else
						fprintf(out,
							"# parent dev=0x%"PRIx64
							" ino=%"PRIu64
							" count=%"PRIu64"\n",
							lk.parent_dev, lk.parent_ino,
							lv.count);
					found_any = 1;
				}
				lr = bpf_map_get_next_key(launchers_fd, &lk, &lnxt);
			}
			if (!found_any) fprintf(out, "# (none observed)\n");
		}

		/* Build directory groups for this actor.
		 * M-13: heap-allocate dir array to avoid ~2MB stack (512 * PATH_MAX). */
		int max_dirs = 512;
		struct dir_group *dirs = malloc((size_t)max_dirs * sizeof(*dirs));
		if (!dirs) {
			fprintf(stderr, "observe: out of memory for dir groups\n");
			continue;
		}
		int ndirs = 0;

		for (int ei = 0; ei < nentries; ei++) {
			struct obs_entry *e = &entries[ei];
			if (e->key.actor_slot != a->slot) continue;

			/* M-17: skip lineage-only observations from DD rule candidates.
			 * Lineage helper opens should not be promoted to directory-
			 * destination seals for the primary actor. */
			if (e->val.under_actor_lineage && !e->val.under_current_actor)
				continue;

			/* Create-like ops are keyed by parent dir (SPEC LIMITATION 2). */
			if (is_create_like_op(e->key.op_class)) {
				int found_d = 0;
				for (int di = 0; di < ndirs; di++) {
					if (dirs[di].pdev == e->key.dev &&
					    dirs[di].pino == e->key.ino) {
						dirs[di].has_creates = 1;
						dirs[di].force_dir_rule = 1;
						found_d = 1; break;
					}
				}
				if (!found_d && ndirs < 512) {
					dirs[ndirs].pdev = e->key.dev;
					dirs[ndirs].pino = e->key.ino;
					snprintf(dirs[ndirs].ppath,
						 sizeof(dirs[ndirs].ppath),
						 "%s", e->path_hint);
					dirs[ndirs].count       = 0;
					dirs[ndirs].has_creates = 1;
					dirs[ndirs].force_dir_rule = 1;
					ndirs++;
				}
				continue;
			}

			/* open/unlink: group by parent dir */
			uint64_t pdev = e->key.parent_dev;
			uint64_t pino = e->key.parent_ino;
			if (pdev == 0 && pino == 0) continue;

			int found_d = 0;
			for (int di = 0; di < ndirs; di++) {
				if (dirs[di].pdev == pdev && dirs[di].pino == pino) {
					dirs[di].count++;
					if (forces_dir_rule_op(e->key.op_class))
						dirs[di].force_dir_rule = 1;
					/* Update ppath if we now have a better one */
					if (!dirs[di].ppath[0] && e->parent_hint[0])
						snprintf(dirs[di].ppath,
							 sizeof(dirs[di].ppath),
							 "%s", e->parent_hint);
					found_d = 1; break;
				}
			}
			if (!found_d && ndirs < 512) {
				dirs[ndirs].pdev        = pdev;
				dirs[ndirs].pino        = pino;
				snprintf(dirs[ndirs].ppath,
					 sizeof(dirs[ndirs].ppath),
					 "%s", e->parent_hint);
				dirs[ndirs].count       = 1;
				dirs[ndirs].has_creates = 0;
				dirs[ndirs].force_dir_rule =
					forces_dir_rule_op(e->key.op_class);
				ndirs++;
			}
		}

		/* Emit seal rules */
		fprintf(out, "\n");

		for (int di = 0; di < ndirs; di++) {
			const char *ppath = dirs[di].ppath;
			int collapse =
				((dirs[di].count >= AO_DIR_COLLAPSE) ||
				 (dir_dest && dirs[di].force_dir_rule)) &&
				(ppath[0] == '/') &&
				!is_broad_root(ppath);

			if (collapse) {
				if (dir_dest) {
					if (recursive_dir_dest) {
						fprintf(out,
							"# recursive subtree directory rule.\n");
					} else {
						fprintf(out,
							"# directory destination rule; "
							"one-level child protection, not recursive.\n");
					}
					fprintf(out,
						"seal %s no-write no-unlink "
						"no-rename no-chmod actor=%s\n",
						ppath, a->name);
				} else {
					fprintf(out,
						"# enumerated fallback "
						"(dir-destination not supported):\n");
					for (int ei = 0; ei < nentries; ei++) {
						struct obs_entry *e = &entries[ei];
						if (e->key.actor_slot != a->slot) continue;
						if (is_create_like_op(e->key.op_class)) continue;
						if (e->key.parent_dev != dirs[di].pdev ||
						    e->key.parent_ino != dirs[di].pino) continue;
						if (!e->path_hint[0]) continue;
						if (earlier_rule_for_group(entries, ei, e))
							continue;
						fprintf(out,
							"seal %s no-write no-unlink "
							"no-rename actor=%s\n",
							e->path_hint, a->name);
					}
				}
				if (dirs[di].has_creates && !recursive_dir_dest)
					fprintf(out,
						"# WARNING: actor created new files under %s.\n"
						"# Directory-destination seals cover "
						"immediate child files only.\n"
						"# Full subtree write protection requires "
						"sealing observed subdirs\n"
						"# or a future recursive-subtree primitive.\n",
						ppath);
				if (dirs[di].has_creates && !dir_dest)
					fprintf(out,
						"# WARNING: actor created entries under %s, but the running enforcement ABI lacks directory-destination support.\n"
						"# Create-like activity cannot be represented precisely as per-file rules before child allocation.\n",
						ppath);
			} else if (dirs[di].count > 0) {
				/* Under threshold — emit per-file */
				for (int ei = 0; ei < nentries; ei++) {
					struct obs_entry *e = &entries[ei];
					if (e->key.actor_slot != a->slot) continue;
					if (is_create_like_op(e->key.op_class)) continue;
					if (e->key.parent_dev != dirs[di].pdev ||
					    e->key.parent_ino != dirs[di].pino) continue;
					if (!e->path_hint[0]) continue;
					if (earlier_rule_for_group(entries, ei, e))
						continue;
					fprintf(out,
						"seal %s no-write no-unlink "
						"no-rename actor=%s\n",
						e->path_hint, a->name);
				}
				if (dirs[di].has_creates)
					fprintf(out,
						"# WARNING: actor created entries under %s.\n"
						"# Per-file fallback cannot name child paths before allocation; enable directory-destination-capable enforcement for precise create coverage.\n",
						ppath[0] ? ppath : "<unresolved-parent>");
			} else if (dirs[di].has_creates) {
				fprintf(out,
					"# WARNING: actor created entries under %s but no stable child path could be emitted.\n"
					"# Directory-destination support is required for precise create-only coverage.\n",
					ppath[0] ? ppath : "<unresolved-parent>");
			}
		}

		/* Dev/ino-only entries (unresolved parent) */
		for (int ei = 0; ei < nentries; ei++) {
			struct obs_entry *e = &entries[ei];
			if (e->key.actor_slot != a->slot) continue;
			if (is_create_like_op(e->key.op_class)) continue;
			if (e->key.parent_dev != 0 || e->key.parent_ino != 0) continue;
			fprintf(out,
				"# unresolved: op=%s dev=0x%"PRIx64" ino=%"PRIu64
				" count=%"PRIu64"\n",
				op_class_str(e->key.op_class),
				e->key.dev, e->key.ino, e->val.count);
		}
		free(dirs);  /* M-13: heap-allocated above */
	}
	(void)obs_fd;  /* reserved for future unresolved-entry enrichment */
}

/* ===== usage ===== */

static void observe_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s observe [OPTIONS] [-- COMMAND [ARGS...]]\n"
		"\n"
		"Selectors (at least one required unless COMMAND is given):\n"
		"  --actor NAME=PATH    Track actor by resolved inode. Repeatable.\n"
		"  --pid PID            Reserved; not yet supported.\n"
		"\n"
		"Options:\n"
		"  --duration SECONDS   Stop after N seconds (0 = run until SIGINT).\n"
		"  --format profile|compact|jsonl|audit  Output format (default: profile).\n"
		"  --verbose            Include parent chain, dev/ino, cgroup.\n"
		"  --include-stat       Reserved; not yet implemented.\n"
		"  --no-resolve-paths   Emit dev/ino only; skip path resolution.\n"
		"  --no-dir-dest        Force per-file fallback rules (for testing/compat).\n"
		"  -o PATH              Output file (- for explicit stdout; default: stdout).\n"
		"  --provenance-out PATH  Write provenance JSON here.\n"
		"\n",
		prog);
}

/* ===== observe_main ===== */

int observe_main(int argc, char **argv)
{
	struct observe_opts opts = {
		.nactors          = 0,
		.pid_seed         = -1,
		.duration         = -1,
		.format           = FMT_PROFILE,
		.verbose          = 0,
		.include_stat     = 0,
		.no_resolve_paths = 0,
		.no_dir_dest      = 0,
		.output           = "",
		.provenance_out   = "",
		.cmd_argv         = NULL,
		.cmd_argc         = 0,
	};

	/* Parse from argv[2] (argv[0]="compartment-bpf", argv[1]="observe") */
	int i = 2;
	while (i < argc) {
		const char *a = argv[i];
#define NEXTARG() \
	(i + 1 < argc ? argv[++i] : \
	 (fprintf(stderr, "observe: missing argument to %s\n", a), exit(2), (char *)""))

		if (!strcmp(a, "--actor")) {
			const char *arg = NEXTARG();
			const char *eq = strchr(arg, '=');
			char raw_name[64];
			if (!eq) {
				fprintf(stderr,
					"observe: --actor expects NAME=PATH, got: %s\n", arg);
				return 2;
			}
			if (opts.nactors >= AO_MAX_ACTORS) {
				fprintf(stderr, "observe: too many actors (max %d)\n",
					AO_MAX_ACTORS);
				return 2;
			}
			size_t nlen = (size_t)(eq - arg);
			if (nlen == 0 || nlen >= sizeof(raw_name)) {
				fprintf(stderr,
					"observe: actor NAME must be 1..%zu bytes and loader-compatible\n",
					sizeof(raw_name) - 1);
				return 2;
			}
			memcpy(raw_name, arg, nlen);
			raw_name[nlen] = '\0';
			if (!actor_name_valid_profile(raw_name)) {
				fprintf(stderr,
					"observe: actor name '%s' must match loader grammar "
					"[A-Za-z_][A-Za-z0-9_-]* and fit in %d bytes including NUL\n",
					raw_name, AO_PROFILE_ACTOR_NAME_MAX);
				return 2;
			}
			if (actor_name_in_use(&opts, raw_name)) {
				fprintf(stderr,
					"observe: duplicate actor name '%s'\n",
					raw_name);
				return 2;
			}
			struct actor_reg *ar = &opts.actors[opts.nactors];
			snprintf(ar->name, sizeof(ar->name), "%s", raw_name);
			snprintf(ar->path, sizeof(ar->path), "%s", eq + 1);
			ar->slot = (uint32_t)opts.nactors;
			ar->inferred_from_cmd = 0;
			opts.nactors++;
		} else if (!strcmp(a, "--pid")) {
			opts.pid_seed = atoi(NEXTARG());
		} else if (!strcmp(a, "--duration")) {
			opts.duration = atoi(NEXTARG());
		} else if (!strcmp(a, "--format")) {
			const char *fmt = NEXTARG();
			if      (!strcmp(fmt, "profile")) opts.format = FMT_PROFILE;
			else if (!strcmp(fmt, "compact")) opts.format = FMT_COMPACT;
			else if (!strcmp(fmt, "jsonl"))   opts.format = FMT_JSONL;
			else if (!strcmp(fmt, "audit"))   opts.format = FMT_AUDIT;
			else {
				fprintf(stderr,
					"observe: unknown format '%s' "
					"(profile|compact|jsonl|audit)\n", fmt);
				return 2;
			}
		} else if (!strcmp(a, "--verbose")) {
			opts.verbose = 1;
		} else if (!strcmp(a, "--include-stat")) {
			opts.include_stat = 1;
		} else if (!strcmp(a, "--no-resolve-paths")) {
			opts.no_resolve_paths = 1;
		} else if (!strcmp(a, "--no-dir-dest")) {
			opts.no_dir_dest = 1;
		} else if (!strcmp(a, "-o")) {
			const char *p = NEXTARG();
			if (strcmp(p, "-") == 0)
				opts.output[0] = '\0';
			else
				snprintf(opts.output, sizeof(opts.output), "%s", p);
		} else if (!strcmp(a, "--provenance-out")) {
			snprintf(opts.provenance_out, sizeof(opts.provenance_out),
				 "%s", NEXTARG());
		} else if (!strcmp(a, "--")) {
			i++;
			opts.cmd_argc = argc - i;
			opts.cmd_argv = argv + i;
			break;
		} else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			observe_usage(argv[0]);
			return 0;
		} else {
			fprintf(stderr, "observe: unknown option: %s\n", a);
			observe_usage(argv[0]);
			return 2;
		}
		i++;
#undef NEXTARG
	}

	if (opts.pid_seed >= 0) {
		fprintf(stderr,
			"observe: --pid is not implemented in the current task-storage design; "
			"existing tasks cannot be seeded safely yet. Use --actor NAME=PATH "
			"or -- COMMAND.\n");
		return 2;
	}
	if (opts.include_stat) {
		fprintf(stderr,
			"observe: --include-stat is not implemented yet; metadata-only "
			"coverage is currently unsupported.\n");
		return 2;
	}

	/* Validate: need at least one selector */
	if (opts.nactors == 0 && opts.pid_seed < 0 && opts.cmd_argc == 0) {
		fprintf(stderr,
			"observe: at least one of --actor or -- COMMAND required.\n");
		observe_usage(argv[0]);
		return 2;
	}

	/* Infer actor from COMMAND argv[0] if no --actor given */
	if (opts.nactors == 0 && opts.cmd_argc > 0) {
		struct actor_reg *ar = &opts.actors[0];
		const char *cmd0 = opts.cmd_argv[0];
		char resolved_cmd[PATH_MAX];
		char normalized[AO_PROFILE_ACTOR_NAME_MAX];
		if (resolve_command_path(cmd0, resolved_cmd, sizeof(resolved_cmd)) < 0)
			return 1;
		const char *base = strrchr(resolved_cmd, '/');
		int norm = normalize_actor_name(base ? base + 1 : resolved_cmd,
						normalized, sizeof(normalized));
		if (norm < 0) {
			fprintf(stderr,
				"observe: cannot derive a loader-compatible actor name from %s\n",
				cmd0);
			return 1;
		}
		if (norm > 0) {
			fprintf(stderr,
				"observe: normalized inferred actor name '%s' -> '%s' "
				"to match loader grammar.\n",
				base ? base + 1 : resolved_cmd, normalized);
		}
		snprintf(ar->name, sizeof(ar->name), "%s", normalized);
		snprintf(ar->path, sizeof(ar->path), "%s", resolved_cmd);
		ar->slot = 0;
		ar->inferred_from_cmd = 1;
		opts.nactors = 1;
	}

	/* Resolve actor inodes */
	for (int ai = 0; ai < opts.nactors; ai++) {
		char resolved[PATH_MAX];
		if (resolve_existing_path(opts.actors[ai].path,
					  resolved, sizeof(resolved)) < 0)
			return 1;
		snprintf(opts.actors[ai].path, sizeof(opts.actors[ai].path),
			 "%s", resolved);
		if (validate_loader_compatible_actor_path(opts.actors[ai].name,
							  opts.actors[ai].path) < 0)
			return 1;
		if (path_to_file_id(opts.actors[ai].path,
				    &opts.actors[ai].dev,
				    &opts.actors[ai].ino) < 0)
			return 1;
	}

	/* Open + load BPF skeleton */
	struct compartment_observe_bpf *skel = compartment_observe_bpf__open();
	if (!skel) {
		fprintf(stderr, "observe: BPF open failed: %s\n", strerror(errno));
		return 1;
	}
	if (compartment_observe_bpf__load(skel)) {
		fprintf(stderr, "observe: BPF verifier rejected observe program: %s\n",
			strerror(errno));
		compartment_observe_bpf__destroy(skel);
		return 1;
	}

	/* Populate actor_targets BEFORE attach — no exec missed */
	int tgt_fd = bpf_map__fd(skel->maps.actor_targets);
	for (int ai = 0; ai < opts.nactors; ai++) {
		struct ao_file_id fid = {
			.dev = opts.actors[ai].dev,
			.ino = opts.actors[ai].ino,
		};
		uint32_t slot = opts.actors[ai].slot;
		if (bpf_map_update_elem(tgt_fd, &fid, &slot, BPF_ANY)) {
			fprintf(stderr, "observe: actor_targets update (%s): %s\n",
				opts.actors[ai].path, strerror(errno));
			compartment_observe_bpf__destroy(skel);
			return 1;
		}
		if (opts.verbose)
			fprintf(stderr,
				"observe: actor %s=%s dev=0x%"PRIx64
				" ino=%"PRIu64" slot=%u\n",
				opts.actors[ai].name, opts.actors[ai].path,
				opts.actors[ai].dev, opts.actors[ai].ino, slot);
	}

	/* M-12: freeze actor_targets after population; consistent with
	 * launcher_to_actor freeze pattern in enforcement loader. */
	if (bpf_map_freeze(tgt_fd) < 0) {
		fprintf(stderr, "observe: actor_targets freeze: %s\n", strerror(errno));
		compartment_observe_bpf__destroy(skel);
		return 1;
	}

	if (compartment_observe_bpf__attach(skel)) {
		fprintf(stderr, "observe: BPF attach failed: %s\n", strerror(errno));
		compartment_observe_bpf__destroy(skel);
		return 1;
	}

	signal(SIGINT,  on_sig);
	signal(SIGTERM, on_sig);
	signal(SIGCHLD, SIG_DFL);

	/* Fork+exec command if given */
	pid_t cmd_pid = -1;
	if (opts.cmd_argc > 0) {
		cmd_pid = fork();
		if (cmd_pid < 0) {
			fprintf(stderr, "observe: fork: %s\n", strerror(errno));
			compartment_observe_bpf__destroy(skel);
			return 1;
		}
		if (cmd_pid == 0) {
			execvp(opts.cmd_argv[0], opts.cmd_argv);
			fprintf(stderr, "observe: exec %s: %s\n",
				opts.cmd_argv[0], strerror(errno));
			_exit(127);
		}
	}

	int obs_fd      = bpf_map__fd(skel->maps.observed_files);
	int cntrs_fd    = bpf_map__fd(skel->maps.event_counters);
	int launchers_fd = bpf_map__fd(skel->maps.observed_launchers);

	/* Set up ringbuf for live formats */
	struct live_ctx lc = { .opts = &opts, .actors = opts.actors, .nactors = opts.nactors };
	struct ring_buffer *rb = NULL;
	if (opts.format != FMT_PROFILE) {
		rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
				      handle_event, &lc, NULL);
		if (!rb) {
			fprintf(stderr, "observe: ring_buffer__new: %s\n", strerror(errno));
			if (cmd_pid > 0) { kill(cmd_pid, SIGTERM); waitpid(cmd_pid, NULL, 0); }
			compartment_observe_bpf__destroy(skel);
			return 1;
		}
	}

	/* Poll loop */
	int duration = opts.duration;
	time_t end_time = (duration > 0) ? (time(NULL) + duration) : 0;
	int cmd_done = 0;
	int rc = 0;

	while (!g_stop && !cmd_done) {
		if (rb) {
			int r = ring_buffer__poll(rb, 200);
			if (r == -EINTR)
				continue;
			if (r < 0) {
				fprintf(stderr, "observe: ring_buffer__poll: %s\n",
					strerror(-r));
				rc = 1;
				break;
			}
		} else {
			struct timespec ts = { .tv_sec = 0, .tv_nsec = 200000000L };
			nanosleep(&ts, NULL);
		}
		if (cmd_pid > 0) {
			int wstatus;
			pid_t wp = waitpid(cmd_pid, &wstatus, WNOHANG);
			if (wp == cmd_pid) { cmd_done = 1; (void)wstatus; }
		}
		if (end_time > 0 && time(NULL) >= end_time) break;
	}

	/* Final ringbuf flush */
	if (rb) {
		int r = ring_buffer__poll(rb, 100);
		if (r < 0 && r != -EINTR) {
			fprintf(stderr, "observe: final ring_buffer__poll: %s\n",
				strerror(-r));
			rc = 1;
		}
		ring_buffer__free(rb);
	}

	if (cmd_pid > 0 && !cmd_done && terminate_observe_child(cmd_pid) < 0)
		rc = 1;

	/* Read drop/overflow counters */
	uint64_t ringbuf_drops = 0, obs_overflow = 0;
	{
		uint32_t k = C_EVENTS_RINGBUF_DROP_TOTAL;
		bpf_map_lookup_elem(cntrs_fd, &k, &ringbuf_drops);
	}
	{
		uint32_t k = C_OBSERVED_FILES_OVERFLOW_TOTAL;
		bpf_map_lookup_elem(cntrs_fd, &k, &obs_overflow);
	}
	if (opts.format == FMT_PROFILE) {
		/* AO-4: iterate observed_files and resolve paths */
		struct obs_entry *entries = calloc(AO_MAX_OBSERVED, sizeof(*entries));
		if (!entries) {
			fprintf(stderr, "observe: out of memory\n");
			compartment_observe_bpf__destroy(skel);
			return 1;
		}
		int nentries = 0;

		struct ao_observed_key kcur, knxt;
		struct ao_observed_value val;
		int mr = bpf_map_get_next_key(obs_fd, NULL, &knxt);
		while (mr == 0 && nentries < AO_MAX_OBSERVED) {
			kcur = knxt;
			if (bpf_map_lookup_elem(obs_fd, &kcur, &val) == 0) {
				entries[nentries].key = kcur;
				entries[nentries].val = val;
				if (!opts.no_resolve_paths) {
					/* Resolve file path */
					resolve_path(kcur.dev, kcur.ino,
						     entries[nentries].path_hint,
						     sizeof(entries[nentries].path_hint),
						     entries[nentries].parent_hint,
						     sizeof(entries[nentries].parent_hint));
					/* Resolve parent path if not extracted from file path */
					if (!entries[nentries].parent_hint[0] &&
					    (kcur.parent_dev || kcur.parent_ino)) {
						char ptmp[PATH_MAX], pprtmp[PATH_MAX];
						resolve_path(kcur.parent_dev, kcur.parent_ino,
							     ptmp, sizeof(ptmp),
							     pprtmp, sizeof(pprtmp));
						snprintf(entries[nentries].parent_hint,
							 sizeof(entries[nentries].parent_hint),
							 "%s", ptmp);
					}
				}
				nentries++;
			}
			mr = bpf_map_get_next_key(obs_fd, &kcur, &knxt);
		}

		/* Open output */
		FILE *outf = stdout;
		if (opts.output[0]) {
			outf = fopen(opts.output, "w");
			if (!outf) {
				fprintf(stderr, "observe: open(%s): %s\n",
					opts.output, strerror(errno));
				free(entries);
				compartment_observe_bpf__destroy(skel);
				return 1;
			}
		}

		emit_profile(outf, &opts, entries, nentries,
			     opts.actors, opts.nactors,
			     obs_fd, launchers_fd,
			     ringbuf_drops, obs_overflow);

		if (opts.output[0] && fclose(outf) < 0) {
			fprintf(stderr, "observe: fclose(%s): %s\n",
				opts.output, strerror(errno));
			rc = 1;
		}

		/* Provenance JSON */
		if (opts.provenance_out[0]) {
			FILE *pf = fopen(opts.provenance_out, "w");
			if (pf) {
				fprintf(pf,
					"{\"tool\":\"compartment-bpf observe\","
					"\"observed_at\":\"%s\","
					"\"nactors\":%d,"
					"\"observed_entries\":%d,"
					"\"ringbuf_drops\":%"PRIu64","
					"\"map_overflow\":%"PRIu64","
					"\"path_resolve_fail\":%"PRIu64","
					"\"path_resolve_fallback\":%"PRIu64","
					"\"abi_version\":\"0x%04x\","
					"\"status\":\"candidate\"}\n",
					iso_now(),
					opts.nactors, nentries,
					ringbuf_drops, obs_overflow,
					g_path_resolve_fail,
					g_path_resolve_fallback,
					detect_runtime_abi(opts.no_dir_dest));
				if (fclose(pf) < 0) {
					fprintf(stderr,
						"observe: fclose(%s): %s\n",
						opts.provenance_out, strerror(errno));
					rc = 1;
				}
			} else {
				fprintf(stderr, "observe: open(%s): %s\n",
					opts.provenance_out, strerror(errno));
				rc = 1;
			}
		}
		free(entries);
	}

	compartment_observe_bpf__destroy(skel);
	return rc;
}
