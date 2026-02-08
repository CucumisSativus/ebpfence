# eBPFence

eBPFence is an eBPF-based security monitoring and enforcement tool that tracks file access violations and dynamically blocks processes from opening files after they exceed a configured threshold.

## What It Does

eBPFence uses a single sleepable LSM (Linux Security Module) hook to:

1. **Monitor file access** - Tracks all file open operations across the system via the `file_open` LSM hook
2. **Detect violations** - Identifies when processes attempt to open disallowed files (based on patterns you specify)
3. **Enforce restrictions** - Automatically blocks processes from opening ANY files after they exceed the violation threshold
4. **Log activity** - Records violations and blocking events to both userspace and kernel trace buffers

### How It Works

- **Sleepable LSM Hook** (`file_open`) handles both monitoring and enforcement in a single BPF program
- **`bpf_d_path`** resolves filenames from the kernel dentry cache (no expensive userspace memory reads)
- **BPF Maps** maintain state about which PIDs are blocked
- **Ring Buffer** efficiently transfers events from kernel to userspace

When a process opens a file, the LSM hook emits an event to userspace via the ring buffer. Userspace pattern-matches the filename and increments a violation counter if it matches a disallowed pattern. Once the threshold is reached, the process PID is added to a BPF hash map. On subsequent file operations, the LSM hook checks this map and denies access for blocked PIDs.

## Building

### Prerequisites

- Linux kernel 5.7+ with BTF support
- LSM BPF enabled in kernel (`bpf` in `/sys/kernel/security/lsm`)
- Go 1.21+
- clang
- libbpf headers

### Build Steps

Using the build script:
```bash
./build.sh
```

Or manually:
```bash
# Generate BPF bytecode
go generate ./daemon/

# Build the daemon and client binaries
CGO_ENABLED=0 go build -o ebpfence-daemon ./cmd/daemon/
CGO_ENABLED=0 go build -o ebpfence-client ./cmd/client/
```

The build process uses `bpf2go` to compile the C BPF code in `daemon/bpf/` into Go-embedded bytecode. This produces two binaries:
- **ebpfence-daemon** - The eBPF monitoring service that runs with root privileges
- **ebpfence-client** - A client for interacting with the running daemon

## Usage

### Running the Daemon

The daemon requires root/CAP_BPF privileges and a JSON config file:
```bash
# Create a config file
cat > config.json <<EOF
{
  "patterns": ["/etc/passwd", "/etc/shadow"],
  "threshold": 2
}
EOF

# Run the daemon
sudo ./ebpfence-daemon -config config.json
```

### Running the Client

```bash
./ebpfence-client
```

### Daemon Flags

- `-config` - Path to JSON configuration file (required)

### Configuration

The config file supports the following fields:
- **patterns** - Array of file path patterns to monitor (supports wildcards via `filepath.Match`)
- **threshold** - Number of violations before blocking (must be > 0)
- **target_pid** - Optional: specific PID to monitor (default: 0 = all processes)

### Testing

#### Unit Tests

Run standard unit tests (no privileges required):
```bash
go test -v ./...
```

#### Integration Tests

Integration tests load real eBPF programs and require:
- Root privileges
- Kernel 5.7+ with BTF support
- LSM BPF enabled

Run integration tests:
```bash
sudo go test -v -tags=integration ./...
```

The integration tests (in `daemon/integration_test.go`) will automatically skip if your system doesn't meet the requirements.

#### Test Program

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
