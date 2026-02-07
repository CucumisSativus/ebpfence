package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ebpfence/daemon"
)

func main() {
	configFile := flag.String("config", "", "Path to JSON config file (required)")
	socketPath := flag.String("socket", "/var/run/ebpfence.sock", "Path to Unix socket for gRPC API")
	flag.Parse()

	if *configFile == "" {
		log.Fatalf("Please specify a config file with -config flag")
	}

	// Load configuration from JSON config file
	cfg, err := daemon.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config file: %v", err)
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
	provider, err := daemon.NewRealEBPFProvider()
	if err != nil {
		log.Fatalf("failed to create eBPF provider: %v", err)
	}
	defer provider.Close()

	// Create the event handler with configuration
	handlerConfig := daemon.EventHandlerConfig{
		DisallowedPatterns: cfg.Patterns,
		Threshold:          cfg.Threshold,
		TargetPID:          cfg.TargetPID,
	}
	handler := daemon.NewEventHandler(provider, handlerConfig)

	// Start gRPC server in a goroutine
	srv := daemon.NewServer(handler)
	go func() {
		if err := srv.Start(*socketPath); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()
	defer srv.Stop()

	// Run the event handler
	if err := handler.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("event handler error: %v", err)
	}

	fmt.Println("\nExiting...")
}
