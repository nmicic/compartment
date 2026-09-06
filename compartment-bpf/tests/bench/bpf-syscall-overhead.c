// SPDX-License-Identifier: Apache-2.0
// tests/bench/bpf-syscall-overhead.c — how much does the self-protection hook
// cost the bpf(2) syscall?
//
// comp_bpf_map sits on security_bpf_map(), which bpf_map_new_fd() calls for
// every map fd the kernel hands out. That is a hot path for anything doing BPF
// (bpftool, cilium, systemd's own BPF users), so the cost of arming
// --self-protect has to be a number, not an assertion.
//
// The loop is BPF_MAP_GET_FD_BY_ID + close on ONE unrelated map created up
// front. That is deliberately the thinnest syscall that still reaches
// bpf_map_new_fd(): the hook runs on every iteration and exits on its first
// branch (the map is not in protected_map_ids), and there is almost no other
// kernel work to hide the hook's fixed entry cost behind. BPF_MAP_CREATE was
// tried first and rejected as a probe -- at ~4.5 us per call it is dominated
// by allocation, and the run-to-run spread on a 2-vCPU guest swamped the
// effect being measured.
//
// Usage: bpf-syscall-overhead [iterations]   (default 200000)
// Output, one line:
//   BPFBENCH iters=<n> total_ns=<n> ns_per_call=<f> errors=<n>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

static int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return (int)syscall(__NR_bpf, cmd, attr, size);
}

static long long now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
	long iters = argc > 1 ? strtol(argv[1], NULL, 10) : 200000;
	long errors = 0;
	union bpf_attr a;

	if (iters <= 0 || iters > 100000000) {
		fprintf(stderr, "iterations out of range\n");
		return 2;
	}

	/* One unrelated map, held open for the whole run: the loop measures
	 * handing out an fd for it, not creating it. */
	memset(&a, 0, sizeof(a));
	a.map_type = BPF_MAP_TYPE_ARRAY;
	a.key_size = 4;
	a.value_size = 8;
	a.max_entries = 1;
	int keep = bpf(BPF_MAP_CREATE, &a, sizeof(a));
	if (keep < 0) {
		fprintf(stderr, "BPF_MAP_CREATE: %s\n", strerror(errno));
		return 2;
	}
	memset(&a, 0, sizeof(a));
	a.info.bpf_fd = (unsigned int)keep;
	a.info.info_len = 0;
	struct bpf_map_info info;
	unsigned int ilen = sizeof(info);
	memset(&info, 0, sizeof(info));
	a.info.info = (unsigned long)&info;
	a.info.info_len = ilen;
	if (bpf(BPF_OBJ_GET_INFO_BY_FD, &a, sizeof(a)) < 0) {
		fprintf(stderr, "BPF_OBJ_GET_INFO_BY_FD: %s\n", strerror(errno));
		return 2;
	}
	unsigned int id = info.id;

	/* Warm the path so page faults and the first-call cost do not land in
	 * the measured window. */
	for (int i = 0; i < 1024; i++) {
		memset(&a, 0, sizeof(a));
		a.map_id = id;
		int fd = bpf(BPF_MAP_GET_FD_BY_ID, &a, sizeof(a));
		if (fd < 0) {
			fprintf(stderr, "BPF_MAP_GET_FD_BY_ID: %s\n", strerror(errno));
			return 2;
		}
		close(fd);
	}

	long long t0 = now_ns();
	for (long i = 0; i < iters; i++) {
		memset(&a, 0, sizeof(a));
		a.map_id = id;
		int fd = bpf(BPF_MAP_GET_FD_BY_ID, &a, sizeof(a));
		if (fd < 0) {
			errors++;
			continue;
		}
		close(fd);
	}
	long long t1 = now_ns();
	close(keep);

	printf("BPFBENCH iters=%ld total_ns=%lld ns_per_call=%.1f errors=%ld\n",
	       iters, t1 - t0, (double)(t1 - t0) / (double)iters, errors);
	return 0;
}
