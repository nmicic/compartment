// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Nenad Mićić <nenad@micic.be>
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int usage(const char *argv0) {
	fprintf(stderr,
		"usage: %s mkdir <path> | rename <old> <new> | "
		"symlink <target> <linkpath> | link <old> <new>\n",
		argv0);
	return 2;
}

int main(int argc, char **argv) {
	if (argc < 3)
		return usage(argv[0]);

	if (strcmp(argv[1], "mkdir") == 0) {
		if (argc != 3)
			return usage(argv[0]);
		if (mkdir(argv[2], 0777) == 0)
			return 0;
		fprintf(stderr, "mkdir(%s): %s\n", argv[2], strerror(errno));
		return 1;
	}

	if (strcmp(argv[1], "rename") == 0) {
		if (argc != 4)
			return usage(argv[0]);
		if (rename(argv[2], argv[3]) == 0)
			return 0;
		fprintf(stderr, "rename(%s,%s): %s\n",
			argv[2], argv[3], strerror(errno));
		return 1;
	}

	if (strcmp(argv[1], "symlink") == 0) {
		if (argc != 4)
			return usage(argv[0]);
		if (symlink(argv[2], argv[3]) == 0)
			return 0;
		fprintf(stderr, "symlink(%s,%s): %s\n",
			argv[2], argv[3], strerror(errno));
		return 1;
	}

	if (strcmp(argv[1], "link") == 0) {
		if (argc != 4)
			return usage(argv[0]);
		if (link(argv[2], argv[3]) == 0)
			return 0;
		fprintf(stderr, "link(%s,%s): %s\n",
			argv[2], argv[3], strerror(errno));
		return 1;
	}

	return usage(argv[0]);
}
