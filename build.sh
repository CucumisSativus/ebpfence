#!/bin/bash
set -e

echo "Building ebpfence..."

# Build the daemon binary (also compiles BPF C + generates proto)
echo "Building daemon binary..."
cargo build --release -p ebpfence-daemon

# Build the client binary
echo "Building client binary..."
cargo build --release -p ebpfence-client

echo "Build complete!"
echo "  Daemon: ./target/release/ebpfence-daemon"
echo "  Client: ./target/release/ebpfence-client"
echo ""
echo "Usage: sudo ./target/release/ebpfence-daemon -c config.json"
