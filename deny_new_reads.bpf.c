// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

#define EACCES 13

// Array to hold blocked PIDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // PID
    __type(value, __u8);  // 1 if blocked
} blocked_pids SEC(".maps");

SEC("lsm.s/file_open") // sleepable hook variant
int BPF_PROG(deny_file_open, struct file *file, const struct cred *cred){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid & 0xFFFFFFFF;

    // Look up the PID in the blocked_pids map
    __u8 *blocked = bpf_map_lookup_elem(&blocked_pids, &pid);
    if (!blocked) {
        return 0;
    }


    // Block the access by overriding return value
    // bpf_override_return(ctx, -EACCES);
    return -EPERM; // deny open;
}

char LICENSE[] SEC("license") = "GPL";