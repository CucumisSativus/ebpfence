# eBPFence

eBPFence is an eBPF-based security monitoring and enforcement tool that tracks file access violations and dynamically blocks processes after they exceed a configured threshold. The blocking strategy is configurable: block file opens, block socket connections, or both.

## What It Does

eBPFence uses LSM (Linux Security Module) hooks to:

1. **Monitor file access** - Tracks all file open operations across the system via the `file_open` LSM hook
2. **Detect violations** - Identifies when processes attempt to open disallowed files (based on patterns you specify)
3. **Enforce restrictions** - Once a process exceeds the violation threshold, applies the configured blocking strategy
4. **Log activity** - Records violations and blocking events to both userspace and kernel trace buffers

### Blocking Strategies

When a process exceeds the threshold, eBPFence can:

| Strategy | Effect |
|---|---|
| `block_files` | Process cannot open any further files (default) |
| `block_network` | Process cannot make any socket connections |
| `block_both` | Both file opens and socket connections are denied |

### How It Works

- **`lsm.s/file_open`** (sleepable) handles both monitoring and enforcement for file access. Uses `bpf_d_path` to resolve filenames from the kernel dentry cache.
- **`lsm/socket_connect`** (non-sleepable) enforces network blocking for socket connections.
- Both hooks check the same **`blocked_pids` BPF hash map** — a single shared map updated by userspace when a process is blocked.
- A **ring buffer** efficiently transfers file-open events from kernel to userspace for pattern matching and violation counting.
- Only the hooks relevant to the configured strategy are attached at startup.

When a process opens a file, the `file_open` hook emits an event to userspace. Userspace pattern-matches the filename and increments a per-PID violation counter. Once the threshold is reached, the PID is added to the `blocked_pids` BPF map. The active hooks then deny further file opens and/or socket connections for that PID.

## Development Environment (Nix)

If you have [Nix](https://nixos.org/download/) installed, you can get a fully reproducible development shell with all required tools without installing anything else manually.

### Prerequisites

- Nix with flakes support enabled. Add the following to `~/.config/nix/nix.conf` (or `/etc/nix/nix.conf`):
  ```
  experimental-features = nix-command flakes
  ```

### Enter the Dev Shell

```bash
nix develop
```

This drops you into a shell with Go, clang, LLVM, libbpf, linux headers, protobuf, and bpftools all available. The shell hook will print the versions of the key tools on entry.

### Build Inside the Dev Shell

Once inside `nix develop`, use the normal build commands:

```bash
go generate ./daemon/
CGO_ENABLED=0 go build -o ebpfence-daemon ./cmd/daemon/
CGO_ENABLED=0 go build -o ebpfence-client ./cmd/client/
```

Or with the build script:

```bash
./build.sh
```

---

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
  "threshold": 2,
  "strategy": "block_both"
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

| Field | Required | Description |
|---|---|---|
| `patterns` | yes | Array of file path patterns to monitor (supports wildcards via `filepath.Match`) |
| `threshold` | yes | Number of violations before blocking a process (must be > 0) |
| `strategy` | no | Blocking strategy: `block_files`, `block_network`, or `block_both` (default: `block_files`) |
| `target_pid` | no | Monitor only this PID (default: 0 = all processes) |

### Example Configurations

**Block file opens only (default):**
```json
{
  "patterns": ["/etc/passwd", "/etc/shadow"],
  "threshold": 2
}
```

**Block socket connections only:**
```json
{
  "patterns": ["/etc/passwd", "/etc/shadow"],
  "threshold": 2,
  "strategy": "block_network"
}
```

**Block both file opens and socket connections:**
```json
{
  "patterns": ["/etc/passwd", "/etc/shadow"],
  "threshold": 2,
  "strategy": "block_both"
}
```

**Monitor a specific process only:**
```json
{
  "patterns": ["secret*.txt", "/home/user/private/*"],
  "threshold": 1,
  "target_pid": 12345,
  "strategy": "block_both"
}
```

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

The test program opens 4 files sequentially and then attempts TCP connections to external hosts, allowing you to observe violation detection and blocking in action. The `test/config.json` uses `block_both` by default.

### Viewing Blocked Events

Check kernel trace logs for blocked file access and socket connection attempts:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```


## Limitations

- Process names are limited to 16 characters (kernel `TASK_COMM_LEN` limitation)
- Blocking is process-level, not file-specific (once blocked, ALL file access or ALL socket connections are denied)
- The `file_open` LSM hook fires on every file operation; monitor performance impact in high I/O environments
- `block_network` blocks all socket connections (including local Unix domain sockets), not just internet traffic
- Requires kernel 5.7+ with BTF and LSM BPF support

## License

GPL-3.0
