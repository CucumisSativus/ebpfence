// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EACCES 13
#define EPERM 1

// Array to hold blocked PIDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // PID
    __type(value, __u8);  // 1 if blocked
} blocked_pids SEC(".maps");

SEC("lsm/file_open") // sleepable hook variant
int BPF_PROG(deny_file_open, struct file *file, const struct cred *cred){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    char comm[16];
    __u8 *blocked;

    // Look up the PID in the blocked_pids map
    blocked = bpf_map_lookup_elem(&blocked_pids, &pid);
    if (!blocked) {
        return 0;
    }

    // Log the blocked access to kernel trace buffer
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("BLOCKED: PID %d (%s) denied file permission", pid, comm);

    // Block the access
    return -EPERM;
}

// Structure to hold the data we want to send to userspace
struct event_t {
    __u32 pid;              // Process ID
    __u32 uid;              // User ID
    char comm[16];          // Process name (command)
    char filename[256];     // File path
    int flags;              // Open flags
};

// Create a ring buffer to send events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB ring buffer
} events SEC(".maps");

// Track per-PID file open count for disallowed files
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // PID
    __type(value, __u32); // Count of disallowed files opened
} pid_violation_count SEC(".maps");

// Hook into the openat syscall tracepoint
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Reserve space in ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Get process information
    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Get process name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Get the filename from syscall arguments (arg1 for openat)
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[1]);

    // Get the flags (arg2 for openat)
    e->flags = (int)ctx->args[2];

    // Submit the event to userspace
    bpf_ringbuf_submit(e, 0);

    return 0;
}

// Hook into openat2 for newer kernels
SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[1]);
    e->flags = 0;  // openat2 has a different structure for flags

    bpf_ringbuf_submit(e, 0);

    return 0;
}

