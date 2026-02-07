#!/bin/bash
set -e

echo "Building ebpfence..."

# Generate protobuf Go code
echo "Generating protobuf code..."
go generate ./proto/

# Generate eBPF bindings from C code
echo "Generating eBPF bindings..."
go generate ./daemon/

# Build the daemon binary
echo "Building daemon binary..."
CGO_ENABLED=0 go build -o ebpfence-daemon ./cmd/daemon/

# Build the client binary
echo "Building client binary..."
CGO_ENABLED=0 go build -o ebpfence-client ./cmd/client/

echo "Build complete!"
echo "  Daemon: ./ebpfence-daemon"
echo "  Client: ./ebpfence-client"
echo ""
echo "Usage: sudo ./ebpfence-daemon -config config.json"
