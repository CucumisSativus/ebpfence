# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

eBPFence is an eBPF-based security monitoring and enforcement tool that tracks file access violations and dynamically blocks processes from opening files after they exceed a configured threshold. It uses Linux Security Modules (LSM) and tracepoints to monitor and enforce file access restrictions.

## Build Commands

### Standard Build
```bash
# Generate eBPF bindings from C code
go generate ./daemon/

# Build both binaries
CGO_ENABLED=0 go build -o ebpfence-daemon ./cmd/daemon/
CGO_ENABLED=0 go build -o ebpfence-client ./cmd/client/

# Or use the build script
./build.sh
```

The `go generate` command runs `bpf2go` (defined in `daemon/generate.go`) which compiles the C eBPF code in `daemon/bpf/deny_new_reads.bpf.c` into Go-embedded bytecode (`daemon/bpf_bpfeb.go` and `daemon/bpf_bpfel.go`).

## Testing

### Unit Tests
Run standard unit tests without privileges:
```bash
go test -v ./...
go test -v -race -coverprofile=coverage.out ./...
```

### Integration Tests
Integration tests require root privileges and kernel 5.7+ with BTF and LSM BPF support:
```bash
sudo go test -v -tags=integration ./...
```

Integration tests are in `daemon/integration_test.go` with build tag `//go:build integration`. They will automatically skip if system requirements aren't met.

### Test Program
A test program exists in `test/` directory to manually trigger file open events:
```bash
cd test
go build -o testprog
./testprog
```

## Configuration

eBPFence requires a JSON configuration file. Create a config file with the following structure:

```json
{
  "patterns": ["/etc/passwd", "/etc/shadow", "/var/log/*.log"],
  "threshold": 2,
  "target_pid": 0
}
```

Configuration fields:
- **patterns** (required): Array of file path patterns to monitor. Supports wildcards via `filepath.Match` (e.g., `*.log`, `/path/to/*`)
- **threshold** (required): Number of disallowed file accesses before blocking a process (must be > 0)
- **target_pid** (optional): Specific PID to monitor (0 = monitor all processes, default: 0)

Example configurations:

**Monitor all processes:**
```json
{
  "patterns": ["/etc/passwd", "/etc/shadow"],
  "threshold": 2
}
```

**Monitor specific PID:**
```json
{
  "patterns": ["secret*.txt", "/home/user/private/*"],
  "threshold": 1,
  "target_pid": 12345
}
```

## Running the Tool

Requires root/CAP_BPF privileges:
```bash
# Create a config file first
cat > config.json <<EOF
{
  "patterns": ["/etc/passwd", "/etc/shadow"],
  "threshold": 2
}
EOF

# Run the daemon with config file
sudo ./ebpfence-daemon -config config.json

# Run the client
./ebpfence-client
```

View blocked events in kernel trace:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Architecture

### Project Structure

```
ebpfence/
├── cmd/
│   ├── daemon/main.go          # Daemon entry point (eBPF monitoring service)
│   └── client/main.go          # Client entry point (interacts with daemon)
├── daemon/                     # Core daemon package
│   ├── bpf/
│   │   ├── deny_new_reads.bpf.c  # eBPF C source code
│   │   └── vmlinux.h              # Kernel type definitions for eBPF
│   ├── generate.go             # go:generate directive for bpf2go
│   ├── config.go               # JSON configuration loading
│   ├── ebpf_interface.go       # Event struct + EBPFProvider interface
│   ├── ebpf_adapter.go         # Production eBPF implementation (RealEBPFProvider)
│   ├── ebpf_mock.go            # Mock provider for unit tests
│   ├── event_handler.go        # Core business logic
│   └── *_test.go               # Unit, integration, and example tests
├── test/                       # Manual test program
├── build.sh                    # Builds both binaries
└── ...
```

### Core Components

**1. eBPF Programs (`daemon/bpf/deny_new_reads.bpf.c`)**
- **Tracepoints**: `sys_enter_openat` and `sys_enter_openat2` capture file open attempts system-wide
- **LSM Hook**: `file_open` enforces blocking by returning `-EPERM` for blocked PIDs
- **BPF Maps**:
  - `blocked_pids` (hash map): tracks which PIDs are blocked
  - `events` (ring buffer): transfers events from kernel to userspace
- All events are sent to userspace for processing via ring buffer

**2. eBPF Provider Interface (`daemon/ebpf_interface.go`)**
- `EBPFProvider` interface abstracts eBPF operations for testability
- `RealEBPFProvider` (`daemon/ebpf_adapter.go`): production implementation using cilium/ebpf library
- `MockEBPFProvider` (`daemon/ebpf_mock.go`): test mock for unit tests
- Key operations: `ReadEvent()`, `BlockPID()`, `Close()`

**3. Event Handler (`daemon/event_handler.go`)**
- Core business logic for processing events and blocking decisions
- Maintains in-memory violation counts and blocked PID tracking
- Pattern matching for disallowed files (supports wildcards via `filepath.Match`)
- When threshold is reached, calls `provider.BlockPID()` which updates the kernel BPF map
- Decoupled from eBPF implementation via `EBPFProvider` interface

**4. Configuration (`daemon/config.go`)**
- JSON-based configuration file loading
- Validates required fields (patterns, threshold)
- Supports optional target PID specification

**5. Daemon Entry Point (`cmd/daemon/main.go`)**
- CLI argument parsing (config file path)
- Signal handling (SIGINT, SIGTERM)
- Wires together provider and handler components from the `daemon` package

**6. Client Entry Point (`cmd/client/main.go`)**
- Client for interacting with the running daemon
- Placeholder for future features (list blocked PIDs, unblock PIDs)

### Data Flow

1. User opens a file → kernel tracepoint captures event
2. Tracepoint sends event to ring buffer
3. `RealEBPFProvider.ReadEvent()` reads from ring buffer
4. `EventHandler.processEvent()` checks if file matches disallowed patterns
5. If match, increment violation count
6. If threshold reached, `provider.BlockPID()` updates `blocked_pids` BPF map
7. LSM hook checks `blocked_pids` on all subsequent file operations
8. If PID is blocked, LSM returns `-EPERM` to deny access

### Key Design Decisions

- **Interface-based architecture**: `EBPFProvider` interface enables testing without kernel access
- **Userspace violation tracking**: Violation counts and pattern matching done in Go for flexibility
- **BPF map blocking**: Only PIDs that exceed threshold are added to kernel map for enforcement
- **Process-level blocking**: Once blocked, a process cannot open ANY files (not file-specific)
- **Dual tracepoints**: Supports both `openat` and `openat2` syscalls (openat2 optional for older kernels)

## System Requirements

- Linux kernel 5.7+ with BTF (BPF Type Format) support
- LSM BPF must be enabled: `bpf` must be in `/sys/kernel/security/lsm`
- Root privileges or CAP_BPF capability
- clang, libbpf headers for building
- Go 1.21+

## Known Limitations

- Process names limited to 16 characters (kernel `TASK_COMM_LEN`)
- Blocking is process-level, not file-level (all file access denied once blocked)
- LSM hook fires on every file operation (monitor performance in production)
- Requires kernel 5.7+ with BTF and LSM BPF support
