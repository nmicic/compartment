// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Nenad Mićić
//
// open-concurrency — isolate compartment's file_open LSM-hook cost under true
// thread concurrency, with NO shell fork/exec noise.
//
// The shell-based stress harness suggested a "concurrency cliff": a parallel
// open-storm timed out >100s with a daemon attached, vs ~58ms without. But the
// shell loop forks a process per worker AND a process per `open` builtin, so a
// daemon attached to the bprm/exec LSM hook serializes on *exec*, not file_open.
// This program does the opposite: N pthreads, each doing M open()+close() on the
// SAME pre-existing file in a tight loop — pure file_open hot path, zero exec.
// If the cliff does NOT reproduce here, it was an exec/fork measurement artifact.
//
//   open-concurrency <nthreads> <iters_per_thread> <path> [W]
//     W (optional) => open O_WRONLY (write path; DENY if the file is no-write
//     sealed); default O_RDONLY (read/ALLOW path).
//
// Prints: threads, total ops, wall ms, ops/sec, ns/op. Self-contained, no deps.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// Sane upper bounds. nthreads is also bounded by the fixed th[]/g_errs[256]
// arrays below; iters is capped so the nthreads*iters total cannot overflow a
// (signed) long even at MAX_THREADS, and a fat-finger arg can't run forever.
#define MAX_THREADS 256L
#define MAX_ITERS   1000000000L   // 1e9 per thread is already absurd for a microbench

// Parse a strictly-positive integer arg: reject empty, non-numeric, trailing
// junk, negative, and out-of-[1,limit] values. Returns the value, or -1 on any
// error (caller fails closed). Replaces atoi/atol which silently overflow/clamp.
static long parse_pos(const char *s, long limit, const char *what) {
	if (s == NULL || *s == '\0') {
		fprintf(stderr, "open-concurrency: empty %s\n", what);
		return -1;
	}
	errno = 0;
	char *end = NULL;
	long v = strtol(s, &end, 10);
	if (end == s || *end != '\0') {
		fprintf(stderr, "open-concurrency: %s '%s' is not a whole number\n", what, s);
		return -1;
	}
	if (errno == ERANGE || v == LONG_MAX || v == LONG_MIN) {
		fprintf(stderr, "open-concurrency: %s '%s' out of range\n", what, s);
		return -1;
	}
	if (v < 1 || v > limit) {
		fprintf(stderr, "open-concurrency: %s %ld out of bounds [1,%ld]\n", what, v, limit);
		return -1;
	}
	return v;
}

static long g_iters;
static const char *g_path;
static int g_oflag;
static volatile int g_start;        // spin-gate so all threads launch together
static long g_errs[256];

static void *worker(void *arg) {
	long idx = (long)arg;
	long errs = 0;
	while (!__atomic_load_n(&g_start, __ATOMIC_ACQUIRE)) { /* spin */ }
	for (long i = 0; i < g_iters; i++) {
		int fd = open(g_path, g_oflag);
		if (fd < 0) { errs++; continue; }
		close(fd);
	}
	if (idx < 256) g_errs[idx] = errs;
	return NULL;
}

static double now_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

int main(int argc, char **argv) {
	if (argc < 4) {
		fprintf(stderr, "usage: %s <nthreads> <iters_per_thread> <path> [W]\n", argv[0]);
		return 2;
	}
	long nthreads_l = parse_pos(argv[1], MAX_THREADS, "nthreads");
	g_iters = parse_pos(argv[2], MAX_ITERS, "iters_per_thread");
	if (nthreads_l < 0 || g_iters < 0)
		return 2;
	int nthreads = (int)nthreads_l;
	g_path = argv[3];
	g_oflag = (argc > 4 && argv[4][0] == 'W') ? O_WRONLY : O_RDONLY;

	// Reject any nthreads*iters product that would overflow the `long total`
	// we report (and feed into ns/op). Both factors are already bounded above,
	// so MAX_THREADS*MAX_ITERS fits in 64-bit long, but guard explicitly so the
	// bounds and this invariant can never silently drift apart.
	if (g_iters > LONG_MAX / nthreads_l) {
		fprintf(stderr, "open-concurrency: nthreads*iters overflows long\n");
		return 2;
	}

	pthread_t th[256];
	for (long t = 0; t < nthreads; t++) {
		if (pthread_create(&th[t], NULL, worker, (void *)t) != 0) {
			perror("pthread_create");
			return 1;
		}
	}
	// Let threads reach the spin-gate, then release them all at once.
	struct timespec settle = { 0, 50 * 1000 * 1000 };  // 50ms
	nanosleep(&settle, NULL);
	double t0 = now_ms();
	__atomic_store_n(&g_start, 1, __ATOMIC_RELEASE);
	for (int t = 0; t < nthreads; t++) pthread_join(th[t], NULL);
	double t1 = now_ms();

	double wall = t1 - t0;
	long total = (long)nthreads * g_iters;
	long errs = 0;
	for (int t = 0; t < nthreads && t < 256; t++) errs += g_errs[t];
	double ops_sec = wall > 0 ? total / (wall / 1000.0) : 0;
	double ns_op = total > 0 ? (wall * 1e6) / total : 0;

	printf("threads=%d iters=%ld total_ops=%ld errs=%ld wall_ms=%.1f ops_sec=%.0f ns_op=%.1f mode=%s\n",
	       nthreads, g_iters, total, errs, wall, ops_sec, ns_op,
	       g_oflag == O_WRONLY ? "W(deny-if-sealed)" : "R(allow)");
	return 0;
}
