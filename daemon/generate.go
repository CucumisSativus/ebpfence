package daemon

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -target bpf" Bpf ./bpf/deny_new_reads.bpf.c -- -I./bpf
