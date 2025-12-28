package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -target bpf" Bpf ./bpf/deny_new_reads.bpf.c -- -I.

func main() {
	// Parse CLI flags
	pid := flag.Uint("pid", 0, "Process ID to block")
	flag.Parse()

	if *pid == 0 {
		log.Fatalf("Please specify a PID with -pid flag")
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

	// 1) Load BPF objects
	var objs BpfObjects
	if err := LoadBpfObjects(&objs, &ebpf.CollectionOptions{}); err != nil {
		log.Fatalf("load bpf objects: %v", err)
	}
	defer objs.Close()

	// 2) Attach kprobe to do_sys_openat2
	lnk, err := link.AttachLSM(link.LSMOptions{Program: objs.DenyFileOpen})
	if err != nil {
		log.Fatalf("attach kprobe: %v", err)
	}
	defer lnk.Close()

	// 3) Add the PID to the blocked_pids map
	pidKey := uint32(*pid)
	blockedValue := uint8(1)
	if err := objs.BlockedPids.Update(&pidKey, &blockedValue, ebpf.UpdateAny); err != nil {
		log.Fatalf("update blocked_pids map: %v", err)
	}

	fmt.Printf("Blocking file opens for PID %d (non-root only)\n", *pid)
	fmt.Println("Press Ctrl+C to stop")

	<-ctx.Done()
	fmt.Println("exiting")
}
