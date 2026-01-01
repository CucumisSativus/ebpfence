# eBPFence

eBPFence is an eBPF-based security monitoring and enforcement tool that tracks file access violations and dynamically blocks processes from opening files after they exceed a configured threshold.

## What It Does

eBPFence uses Linux Security Modules (LSM) and tracepoints to:

1. **Monitor file access** - Tracks all `openat` and `openat2` syscalls across the system
2. **Detect violations** - Identifies when processes attempt to open disallowed files (based on patterns you specify)
3. **Enforce restrictions** - Automatically blocks processes from opening ANY files after they exceed the violation threshold
4. **Log activity** - Records violations and blocking events to both userspace and kernel trace buffers

### How It Works

- **Tracepoints** (`sys_enter_openat`, `sys_enter_openat2`) capture file open attempts and send events to userspace
- **LSM Hook** (`file_open`) enforces blocking by returning `-EPERM` for processes in the blocked list
- **BPF Maps** maintain state about which PIDs are blocked
- **Ring Buffer** efficiently transfers events from kernel to userspace

When a process opens a disallowed file, eBPFence increments a violation counter. Once the threshold is reached, the process PID is added to a BPF hash map. The LSM hook checks this map on every file operation and denies access for blocked PIDs.

## Building

### Prerequisites

- Linux kernel 5.7+ with BTF support
- LSM BPF enabled in kernel (`bpf` in `/sys/kernel/security/lsm`)
- Go 1.21+
- clang
- libbpf headers

### Build Steps

1. Generate BPF bytecode:
```bash
go generate
```

2. Build the binary:
```bash
CGO_ENABLED=0 go build
```

Or combine both:
```bash
go generate && CGO_ENABLED=0 go build
```

The build process uses `bpf2go` to compile the C BPF code into Go-embedded bytecode.

## Usage

### Running eBPFence

Basic usage (requires root/CAP_BPF):
```bash
sudo ./ebpfence -disallowed "/path/to/file1,/path/to/file2" -threshold 2
```

Monitor a specific PID:
```bash
sudo ./ebpfence -disallowed "file1.txt,file2.txt" -threshold 2 -pid 12345
```

### Flags

- `-disallowed` - Comma-separated list of file patterns to monitor (supports wildcards)
- `-threshold` - Number of violations before blocking (default: 2)
- `-pid` - Optional: specific PID to monitor (default: 0 = all processes)

### Testing

Build and run the test program:
```bash
cd test
go build -o testprog
./testprog
```

The test program opens 4 files sequentially, allowing you to observe violation detection and blocking in action.

### Viewing Blocked Events

Check kernel trace logs for blocked file access attempts:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```


## Limitations

- Process names are limited to 16 characters (kernel `TASK_COMM_LEN` limitation)
- Blocking is process-level, not file-level (once blocked, ALL file access is denied)
- The LSM hook may fire frequently, monitor performance impact in production
- Requires kernel 5.7+ with BTF and LSM BPF support

## License

GPL-3.0
