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

SEC("lsm.s/file_open") // sleepable hook variant (required for bpf_d_path)
int BPF_PROG(deny_file_open, struct file *file, const struct cred *cred) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 *blocked;

    // Look up the PID in the blocked_pids map — if blocked, deny immediately
    blocked = bpf_map_lookup_elem(&blocked_pids, &pid);
    if (blocked) {
        bpf_printk("BLOCKED: PID %d denied file permission", pid);
        return -EPERM;
    }

    // Emit an event for userspace processing
    struct event_t *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Zero the filename buffer to prevent leftover ring buffer data from leaking
    __builtin_memset(e->filename, 0, sizeof(e->filename));

    // Use bpf_d_path to read the resolved filename from kernel dentry cache
    int ret = bpf_d_path(&file->f_path, e->filename, sizeof(e->filename));
    if (ret < 0) {
        // If bpf_d_path fails, submit with empty filename
        e->filename[0] = '\0';
    }

    e->flags = BPF_CORE_READ(file, f_flags);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("lsm/socket_connect") // non-sleepable (no bpf_d_path needed)
int BPF_PROG(deny_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 *blocked;

    blocked = bpf_map_lookup_elem(&blocked_pids, &pid);
    if (blocked) {
        bpf_printk("BLOCKED: PID %d denied socket connect", pid);
        return -EPERM;
    }

    return 0;
}
