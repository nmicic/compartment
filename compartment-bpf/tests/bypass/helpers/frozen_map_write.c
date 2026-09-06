// SPDX-License-Identifier: Apache-2.0
// frozen_map_write.c — runner for the honest witness (26).
//
// usage: frozen_map_write <obj.o> <map_id>
//
// Obtains a READ-ONLY fd to <map_id> (BPF_MAP_GET_FD_BY_ID + BPF_F_RDONLY),
// splices it into the attacker object's `victim` map, loads, runs the program,
// and reports what the in-program bpf_map_update_elem() returned plus whether
// the value is readable back afterwards. Also drives the syscall-path write on
// the same fd as a control, which freeze DOES refuse.
//
// One machine-readable line on stdout:
//   FW fd=<ok|denied> prog=<loaded|failed> write=<rc> readback=<yes|no> syscall=<rc/errno>
// Exit 0 whenever the measurement completed; 2 when it could not be taken.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: %s <obj.o> <map_id>\n", argv[0]);
		return 2;
	}
	unsigned int id = (unsigned int)strtoul(argv[2], NULL, 0);

	libbpf_set_print(NULL);

	LIBBPF_OPTS(bpf_get_fd_by_id_opts, gopts, .open_flags = BPF_F_RDONLY);
	int vfd = bpf_map_get_fd_by_id_opts(id, &gopts);
	if (vfd < 0) {
		printf("FW fd=denied errno=%d prog=skipped write=- readback=- syscall=-\n",
		       errno);
		return 0;
	}

	struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
	if (!obj) {
		fprintf(stderr, "open_file %s: %s\n", argv[1], strerror(errno));
		return 2;
	}
	struct bpf_map *vm = bpf_object__find_map_by_name(obj, "victim");
	if (!vm) {
		fprintf(stderr, "no victim map in %s\n", argv[1]);
		return 2;
	}
	if (bpf_map__reuse_fd(vm, vfd)) {
		fprintf(stderr, "reuse_fd: %s\n", strerror(errno));
		return 2;
	}
	if (bpf_object__load(obj)) {
		printf("FW fd=ok prog=failed errno=%d write=- readback=- syscall=-\n",
		       errno);
		return 0;
	}

	struct bpf_program *p = bpf_object__find_program_by_name(obj, "do_write");
	if (!p) {
		fprintf(stderr, "no do_write program\n");
		return 2;
	}
	LIBBPF_OPTS(bpf_test_run_opts, ropts);
	if (bpf_prog_test_run_opts(bpf_program__fd(p), &ropts) < 0) {
		fprintf(stderr, "prog_test_run: %s\n", strerror(errno));
		return 2;
	}

	int rfd = bpf_map__fd(bpf_object__find_map_by_name(obj, "result"));
	unsigned int z = 0;
	long long wr = -1;
	bpf_map_lookup_elem(rfd, &z, &wr);

	unsigned long long k = 0xdeadbeefULL;
	unsigned int v = 0;
	int readback = (bpf_map_lookup_elem(vfd, &k, &v) == 0);

	/* Control: the same write through the syscall path, which
	 * bpf_map_freeze() is documented to refuse. */
	unsigned long long k2 = 0xfeedfaceULL;
	unsigned int v2 = 0x42424242;
	int sysrc = bpf_map_update_elem(vfd, &k2, &v2, BPF_ANY);
	int syserr = sysrc < 0 ? errno : 0;

	printf("FW fd=ok prog=loaded write=%lld readback=%s syscall=%d/%d\n",
	       wr, readback ? "yes" : "no", sysrc, syserr);
	return 0;
}
