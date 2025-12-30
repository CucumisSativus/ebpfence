package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -target bpf" Bpf ./bpf/deny_new_reads.bpf.c -- -I.

// Event structure matching the BPF C struct
type Event struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [256]byte
	Flags    int32
}

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

	// Load BPF objects
	var objs BpfObjects
	if err := LoadBpfObjects(&objs, &ebpf.CollectionOptions{}); err != nil {
		log.Fatalf("load bpf objects: %v", err)
	}
	defer objs.Close()

	// Attach LSM hook for blocking
	lsmLink, err := link.AttachLSM(link.LSMOptions{Program: objs.DenyFileOpen})
	if err != nil {
		log.Fatalf("attach LSM hook: %v", err)
	}
	defer lsmLink.Close()

	// Attach tracepoint for openat
	tpLinkOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		log.Fatalf("attach openat tracepoint: %v", err)
	}
	defer tpLinkOpenat.Close()

	// Attach tracepoint for openat2
	tpLinkOpenat2, err := link.Tracepoint("syscalls", "sys_enter_openat2", objs.TraceOpenat2, nil)
	if err != nil {
		// openat2 might not be available on older kernels, so just log a warning
		log.Printf("Warning: could not attach openat2 tracepoint: %v", err)
	} else {
		defer tpLinkOpenat2.Close()
	}

	// Open the ring buffer
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ring buffer: %v", err)
	}
	defer rd.Close()

	fmt.Printf("Disallowed files: %v\n", patterns)
	fmt.Printf("Threshold: %d file(s)\n", *threshold)
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Track violations per PID
	violationCount := uint32(0)
	blocked := false
	parsedPid := uint32(*pid)
	// Start reading events
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("reading from ring buffer: %v", err)
				continue
			}

			// Parse the event
			var event Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing event: %v", err)
				continue
			}
			if event.Pid != parsedPid && parsedPid != 0 {
				continue
			}

			//log.Printf("Got an event %v", event)

			// Extract null-terminated strings
			comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
			filename := string(bytes.TrimRight(event.Filename[:], "\x00"))

			// Check if the file matches any disallowed pattern
			if matchesPattern(filename, patterns) {
				violationCount++
				fmt.Printf("[VIOLATION %d/%d] PID %d (%s) opened disallowed file: %s\n",
					violationCount, *threshold, event.Pid, comm, filename)

				// Check if we've reached the threshold
				if violationCount >= uint32(*threshold) && !blocked {
					blocked = true
					blockedValue := uint8(1)
					if err := objs.BlockedPids.Update(event.Pid, &blockedValue, ebpf.UpdateAny); err != nil {
						log.Printf("failed to block PID: %v", err)
					} else {
						fmt.Printf("\n*** PID %d is now BLOCKED from opening any further files! ***\n\n", event.Pid)
					}
				}
			} else {
				//fmt.Printf("[INFO] PID %d (%s) opened: %s\n", event.Pid, comm, filename)
			}
		}
	}()

	<-ctx.Done()
	fmt.Println("\nExiting...")
}

// matchesPattern checks if a filename matches any of the disallowed patterns
func matchesPattern(filename string, patterns []string) bool {
	for _, pattern := range patterns {
		// Support both exact match and wildcard match
		matched, _ := filepath.Match(pattern, filename)
		if matched || strings.Contains(filename, pattern) {
			return true
		}
	}
	return false
}
