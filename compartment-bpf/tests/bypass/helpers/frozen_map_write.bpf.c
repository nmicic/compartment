// SPDX-License-Identifier: GPL-2.0
// frozen_map_write.bpf.c — the attacker half of the honest witness (26).
//
// A one-function BPF program that writes a map it did not create. The runner
// splices a compartment map into `victim` with bpf_map__reuse_fd() before
// load, using an fd obtained from BPF_MAP_GET_FD_BY_ID with BPF_F_RDONLY.
// bpf_map_freeze() gates map_get_sys_perms() on the syscall path; this
// measures whether it gates the program path too. It does not.
//
// The map shape must match the target (compartment's sealed_devs:
// HASH __u64 -> __u32); libbpf checks key/value size on reuse_fd.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u32);
} victim SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __s64);
} result SEC(".maps");

SEC("syscall")
int do_write(void *ctx)
{
	__u64 key = 0xdeadbeefULL;
	__u32 val = 0x41414141;
	__s64 r = bpf_map_update_elem(&victim, &key, &val, BPF_ANY);
	__u32 z = 0;

	bpf_map_update_elem(&result, &z, &r, BPF_ANY);
	return 0;
}
