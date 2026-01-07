package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -target bpf" Bpf ./bpf/deny_new_reads.bpf.c -- -I.

func main() {
	disallowedFiles := flag.String("disallowed", "", "Comma-separated list of disallowed file patterns (e.g., '/etc/passwd,/etc/shadow')")
	threshold := flag.Uint("threshold", 2, "Number of disallowed files before blocking (default: 2)")
	pid := flag.Uint("pid", 0, "PID to block (default: 0, which blocks all processes)")
	flag.Parse()

	if *disallowedFiles == "" {
		log.Fatalf("Please specify disallowed files with -disallowed flag")
	}

	// Parse disallowed file patterns
	patterns := strings.Split(*disallowedFiles, ",")
	for i := range patterns {
		patterns[i] = strings.TrimSpace(patterns[i])
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		cancel()
	}()

	// Create the eBPF provider
	provider, err := NewRealEBPFProvider()
	if err != nil {
		log.Fatalf("failed to create eBPF provider: %v", err)
	}
	defer provider.Close()

	// Create the event handler with configuration
	config := EventHandlerConfig{
		DisallowedPatterns: patterns,
		Threshold:          uint32(*threshold),
		TargetPID:          uint32(*pid),
	}
	handler := NewEventHandler(provider, config)

	// Run the event handler
	if err := handler.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("event handler error: %v", err)
	}

	fmt.Println("\nExiting...")
}
