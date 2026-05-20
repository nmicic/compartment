// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
//
// fuzz_oracle — property-based random oracle for compartment-bpf.
//
// Reads a CSV (path,flags) describing the live seal map, then for N
// iterations picks a random (path, op), predicts allow/deny from the
// oracle, executes the op via direct syscalls, and asserts the
// prediction matches the kernel's verdict. Writes a JSON summary.
//
// Operations are deliberately non-destructive: open(O_RDONLY) / open
// (O_WRONLY) / truncate-to-current-size / chmod-to-current-mode /
// mmap-shared-write. The kernel hook still fires; the syscall result
// is the only signal we care about. unlink/rename are excluded because
// they change inode state and would invalidate the oracle on success.
//
// Usage:
//   fuzz_oracle --csv FILE --iters N [--seed N] [--output FILE]
//
// CSV format (no header):
//   /abs/path,FLAGS_HEX        # FLAGS_HEX is a non-zero u32

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define SEAL_NO_UNLINK (1U << 0)
#define SEAL_NO_RENAME (1U << 1)
#define SEAL_NO_WRITE  (1U << 2)
#define SEAL_NO_CHMOD  (1U << 3)

enum op_id {
	OP_OPEN_RO,
	OP_OPEN_WR,
	OP_TRUNCATE,
	OP_CHMOD,
	OP_MMAP_SW,
	N_OPS
};

static const char *op_name[] = {
	"open_ro", "open_wronly", "truncate", "chmod", "mmap_sw"
};

struct seal_entry {
	char     path[4096];
	uint32_t flags;
	mode_t   orig_mode;
	off_t    orig_size;
};

static int predict_deny(enum op_id op, uint32_t flags)
{
	switch (op) {
	case OP_OPEN_RO:  return 0;
	case OP_OPEN_WR:  return (flags & SEAL_NO_WRITE) != 0;
	case OP_TRUNCATE: return (flags & SEAL_NO_WRITE) != 0;
	case OP_CHMOD:    return (flags & SEAL_NO_CHMOD) != 0;
	case OP_MMAP_SW:  return (flags & SEAL_NO_WRITE) != 0;
	default:          return 0;
	}
}

// Returns 1 if denied (EACCES/EPERM), 0 if allowed, -1 on stage error
// (e.g. unrelated errno that breaks the test).
static int run_op(enum op_id op, struct seal_entry *e)
{
	switch (op) {
	case OP_OPEN_RO: {
		int fd = open(e->path, O_RDONLY | O_CLOEXEC);
		if (fd >= 0) { close(fd); return 0; }
		if (errno == EACCES || errno == EPERM) return 1;
		return -1;
	}
	case OP_OPEN_WR: {
		int fd = open(e->path, O_WRONLY | O_CLOEXEC);
		if (fd >= 0) { close(fd); return 0; }
		if (errno == EACCES || errno == EPERM) return 1;
		return -1;
	}
	case OP_TRUNCATE: {
		int rc = truncate(e->path, e->orig_size);
		if (rc == 0) return 0;
		if (errno == EACCES || errno == EPERM) return 1;
		return -1;
	}
	case OP_CHMOD: {
		int rc = chmod(e->path, e->orig_mode);
		if (rc == 0) return 0;
		if (errno == EACCES || errno == EPERM) return 1;
		return -1;
	}
	case OP_MMAP_SW: {
		int fd = open(e->path, O_RDWR | O_CLOEXEC);
		if (fd < 0) {
			if (errno == EACCES || errno == EPERM) return 1;
			return -1;
		}
		size_t len = e->orig_size > 0 ? (size_t)e->orig_size : 4096;
		void *m = mmap(NULL, len, PROT_READ | PROT_WRITE,
			       MAP_SHARED, fd, 0);
		int err = errno;
		close(fd);
		if (m == MAP_FAILED) {
			if (err == EACCES || err == EPERM) return 1;
			return -1;
		}
		munmap(m, len);
		return 0;
	}
	default: return -1;
	}
}

static int load_csv(const char *path, struct seal_entry **out, int *n_out)
{
	FILE *f = fopen(path, "r");
	if (!f) { perror("fopen csv"); return -1; }
	int cap = 64;
	int n = 0;
	struct seal_entry *arr = calloc(cap, sizeof(*arr));
	if (!arr) { fclose(f); return -1; }
	char line[8192];
	while (fgets(line, sizeof(line), f)) {
		char *nl = strchr(line, '\n');
		if (nl) *nl = 0;
		if (line[0] == '\0' || line[0] == '#') continue;
		char *comma = strchr(line, ',');
		if (!comma) continue;
		*comma = 0;
		uint32_t flags = (uint32_t)strtoul(comma + 1, NULL, 0);
		if (flags == 0) continue;
		if (n == cap) {
			cap *= 2;
			struct seal_entry *tmp = realloc(arr, cap * sizeof(*arr));
			if (!tmp) {
				free(arr);
				fclose(f);
				return -1;
			}
			arr = tmp;
		}
		size_t path_len = strlen(line);
		if (path_len >= sizeof(arr[n].path)) {
			fprintf(stderr, "fuzz_oracle: path too long in csv: %s\n",
				line);
			free(arr);
			fclose(f);
			return -1;
		}
		memcpy(arr[n].path, line, path_len + 1);
		arr[n].flags = flags;
		struct stat st;
		if (stat(arr[n].path, &st) < 0) {
			fprintf(stderr, "fuzz_oracle: stat %s: %s\n",
				arr[n].path, strerror(errno));
			free(arr);
			fclose(f);
			return -1;
		}
		arr[n].orig_mode = st.st_mode & 07777;
		arr[n].orig_size = st.st_size;
		n++;
	}
	fclose(f);
	*out = arr;
	*n_out = n;
	return 0;
}

static int parse_positive_int(const char *s, int *out)
{
	char *end = NULL;
	errno = 0;
	long v = strtol(s, &end, 0);
	if (errno || !end || *end || v <= 0 || v > INT_MAX)
		return -1;
	*out = (int)v;
	return 0;
}

int main(int argc, char **argv)
{
	const char *csv_path = NULL;
	const char *out_path = NULL;
	int iters = 10000;
	unsigned seed = (unsigned)(time(NULL) ^ getpid());
	int divergence_log_cap = 50;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--csv") && i + 1 < argc) {
			csv_path = argv[++i];
		} else if (!strcmp(argv[i], "--iters") && i + 1 < argc) {
			if (parse_positive_int(argv[++i], &iters) < 0) {
				fprintf(stderr, "fuzz_oracle: invalid --iters\n");
				return 2;
			}
		} else if (!strcmp(argv[i], "--seed") && i + 1 < argc) {
			seed = (unsigned)strtoul(argv[++i], NULL, 0);
		} else if (!strcmp(argv[i], "--output") && i + 1 < argc) {
			out_path = argv[++i];
		} else {
			fprintf(stderr, "fuzz_oracle: unknown arg %s\n", argv[i]);
			return 2;
		}
	}
	if (!csv_path) {
		fprintf(stderr, "fuzz_oracle: --csv required\n");
		return 2;
	}

	struct seal_entry *entries = NULL;
	int n_entries = 0;
	if (load_csv(csv_path, &entries, &n_entries) < 0) return 4;
	if (n_entries == 0) {
		fprintf(stderr, "fuzz_oracle: csv has no entries\n");
		return 2;
	}

	srand(seed);
	int divergences = 0;
	int stage_errors = 0;
	struct {
		int       iter;
		enum op_id op;
		int       expected_deny;
		int       actual_deny;
		int       index;
	} log[divergence_log_cap];
	int op_counts[N_OPS] = {0};
	int op_denies[N_OPS] = {0};

	for (int it = 0; it < iters; it++) {
		int idx = rand() % n_entries;
		int op_int = rand() % N_OPS;
		enum op_id op = (enum op_id)op_int;
		struct seal_entry *e = &entries[idx];
		int expected = predict_deny(op, e->flags);
		int actual = run_op(op, e);
		if (op_int >= 0 && op_int < N_OPS) {
			op_counts[op_int]++;
			if (actual == 1) op_denies[op_int]++;
		}
		if (actual < 0) {
			stage_errors++;
			continue;
		}
		if (actual != expected) {
			if (divergences < divergence_log_cap) {
				log[divergences].iter = it;
				log[divergences].op = op;
				log[divergences].expected_deny = expected;
				log[divergences].actual_deny = actual;
				log[divergences].index = idx;
			}
			divergences++;
		}
	}

	FILE *out = stdout;
	if (out_path) {
		out = fopen(out_path, "w");
		if (!out) { perror("fopen output"); return 4; }
	}

	fprintf(out, "{\n");
	fprintf(out, "  \"seed\":         %u,\n", seed);
	fprintf(out, "  \"iters\":        %d,\n", iters);
	fprintf(out, "  \"entries\":      %d,\n", n_entries);
	fprintf(out, "  \"divergences\":  %d,\n", divergences);
	fprintf(out, "  \"stage_errors\": %d,\n", stage_errors);
	fprintf(out, "  \"by_op\": {\n");
	for (int o = 0; o < N_OPS; o++) {
		fprintf(out, "    \"%s\": {\"runs\": %d, \"denies\": %d}%s\n",
			op_name[o], op_counts[o], op_denies[o],
			o + 1 < N_OPS ? "," : "");
	}
	fprintf(out, "  },\n");
	fprintf(out, "  \"divergence_log\": [");
	int n_log = divergences < divergence_log_cap ? divergences : divergence_log_cap;
	for (int i = 0; i < n_log; i++) {
		fprintf(out, "%s\n    {\"iter\": %d, \"op\": \"%s\", "
			"\"expected_deny\": %d, \"actual_deny\": %d, "
			"\"path\": \"%s\", \"flags\": \"0x%x\"}",
			i ? "," : "",
			log[i].iter, op_name[log[i].op],
			log[i].expected_deny, log[i].actual_deny,
			entries[log[i].index].path,
			entries[log[i].index].flags);
	}
	fprintf(out, "%s]\n", n_log ? "\n  " : "");
	fprintf(out, "}\n");

	if (out_path) fclose(out);
	free(entries);
	if (stage_errors > 0)
		return 4;
	return divergences > 0 ? 1 : 0;
}
