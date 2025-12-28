#!/bin/bash
set -e

echo "Building ebpfence..."

# Generate eBPF bindings from C code
echo "Generating eBPF bindings..."
go generate

# Build the Go binary
echo "Building Go binary..."
go build -o ebpfence

echo "Build complete! Binary: ./ebpfence"
echo ""
echo "Usage: sudo ./ebpfence -pid <process_id>"
