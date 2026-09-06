// SPDX-License-Identifier: Apache-2.0
// bpf_map_fd_sweep.c — enumerate every BPF map on the box and try to obtain an
// fd for it, read-write and read-only, exactly the way an attacker looking for
// compartment's maps would (BPF_MAP_GET_NEXT_ID + BPF_MAP_GET_FD_BY_ID).
//
// Why a raw-syscall helper rather than bpftool: bpftool aborts its listing on
// the first non-ENOENT error, so it cannot count how many maps refused, and
// `bpftool map update name ...` is not supported on every shipped bpftool.
// This also documents the attack precisely: a read-only fd is enough, because
// a map spliced into a BPF program with bpf_map__reuse_fd() can be written
// from program context regardless of bpf_map_freeze().
//
// Output, one line: SWEEP total=<n> ok_rw=<n> ok_ro=<n> denied=<n> other=<n>
// Exit 0 always (the caller asserts on the numbers).
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

static int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static int get_fd(uint32_t id, int rdonly)
{
	union bpf_attr a;
	memset(&a, 0, sizeof(a));
	a.map_id = id;
	if (rdonly)
		a.open_flags = BPF_F_RDONLY;
	return bpf(BPF_MAP_GET_FD_BY_ID, &a, sizeof(a));
}

int main(void)
{
	uint32_t id = 0;
	int total = 0, ok_rw = 0, ok_ro = 0, denied = 0, other = 0;

	for (;;) {
		union bpf_attr n;
		memset(&n, 0, sizeof(n));
		n.start_id = id;
		if (bpf(BPF_MAP_GET_NEXT_ID, &n, sizeof(n)) < 0)
			break;
		id = n.next_id;
		total++;

		int fd = get_fd(id, 0);
		if (fd >= 0) {
			ok_rw++;
			close(fd);
		} else if (errno == EACCES || errno == EPERM) {
			denied++;
			/* A read-only fd must be refused too: it is a complete
			 * attack on its own. Count it as "other" if it slips
			 * through, so the caller can tell the two apart. */
			fd = get_fd(id, 1);
			if (fd >= 0) {
				ok_ro++;
				close(fd);
			}
			continue;
		} else if (errno == ENOENT) {
			total--;      /* raced a teardown */
			continue;
		} else {
			other++;
			continue;
		}
		fd = get_fd(id, 1);
		if (fd >= 0) {
			ok_ro++;
			close(fd);
		}
	}
	printf("SWEEP total=%d ok_rw=%d ok_ro=%d denied=%d other=%d\n",
	       total, ok_rw, ok_ro, denied, other);
	return 0;
}
