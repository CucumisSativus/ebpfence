// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

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

// Structure to hold the data we want to send to userspace
struct data_t {
    u32 pid;              // Process ID
    u32 uid;              // User ID
    char comm[16];        // Process name (command)
    char filename[256];   // File path
    int flags;            // Open flags
};

// Create a perf buffer to send events to userspace
BPF_PERF_OUTPUT(events);

// Hook into the openat syscall entry point
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    
    // Get process information
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;  // Upper 32 bits is the PID
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // Get process name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Get the filename from syscall arguments
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
    
    // Get the flags
    data.flags = args->flags;
    
    // Send the event to userspace
    events.perf_submit(args, &data, sizeof(data));
    
    return 0;
}

// Also hook into openat2 for newer kernels
TRACEPOINT_PROBE(syscalls, sys_enter_openat2) {
    struct data_t data = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
    data.flags = 0;  // openat2 has a different structure for flags
    
    events.perf_submit(args, &data, sizeof(data));
    
    return 0;
}