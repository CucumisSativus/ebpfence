package main

import (
	"context"
	"fmt"
	"time"
)

// ExampleEventHandler demonstrates how to use the mock provider for testing
func ExampleEventHandler() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create mock events simulating a process accessing disallowed files
	events := []*Event{
		CreateMockEvent(1234, 1000, "myapp", "/etc/passwd"),
		CreateMockEvent(1234, 1000, "myapp", "/home/user/safe.txt"),
		CreateMockEvent(1234, 1000, "myapp", "/etc/shadow"),
	}

	// Create mock provider with predefined events
	provider := NewMockEBPFProvider(ctx, events)
	defer provider.Close()

	// Configure the handler
	config := EventHandlerConfig{
		DisallowedPatterns: []string{"/etc/*"},
		Threshold:          2,
		TargetPID:          0,
	}

	handler := NewEventHandler(provider, config)

	// Run handler in background
	done := make(chan error, 1)
	go func() {
		done <- handler.Run(ctx)
	}()

	// Let it process events
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	// Check results
	fmt.Printf("Total violations: %d\n", handler.GetViolationCount())
	fmt.Printf("PID 1234 violations: %d\n", handler.GetViolationCountForPID(1234))
	fmt.Printf("Any PIDs blocked: %v\n", handler.IsBlocked())
	fmt.Printf("PID 1234 blocked: %v\n", handler.IsPIDBlocked(1234))

	// Output:
	// Disallowed files: [/etc/*]
	// Threshold: 2 file(s)
	// Press Ctrl+C to stop
	//
	// [VIOLATION 1/2] PID 1234 (myapp) opened disallowed file: /etc/passwd
	// [VIOLATION 2/2] PID 1234 (myapp) opened disallowed file: /etc/shadow
	//
	// *** PID 1234 is now BLOCKED from opening any further files! ***
	//
	// Total violations: 2
	// PID 1234 violations: 2
	// Any PIDs blocked: true
	// PID 1234 blocked: true
}

// ExampleEventHandler_multipleProcesses demonstrates tracking multiple processes
func ExampleEventHandler_multipleProcesses() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create mock events from multiple processes
	events := []*Event{
		CreateMockEvent(1000, 1000, "proc1", "/etc/passwd"),
		CreateMockEvent(2000, 1000, "proc2", "/etc/shadow"),
		CreateMockEvent(1000, 1000, "proc1", "/etc/hosts"),
		CreateMockEvent(2000, 1000, "proc2", "/tmp/safe.txt"),
	}

	provider := NewMockEBPFProvider(ctx, events)
	defer provider.Close()

	config := EventHandlerConfig{
		DisallowedPatterns: []string{"/etc/*"},
		Threshold:          2,
		TargetPID:          0,
	}

	handler := NewEventHandler(provider, config)

	done := make(chan error, 1)
	go func() {
		done <- handler.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	// Check results for each PID
	fmt.Printf("Total violations: %d\n", handler.GetViolationCount())
	fmt.Printf("PID 1000 violations: %d, blocked: %v\n",
		handler.GetViolationCountForPID(1000), handler.IsPIDBlocked(1000))
	fmt.Printf("PID 2000 violations: %d, blocked: %v\n",
		handler.GetViolationCountForPID(2000), handler.IsPIDBlocked(2000))

	// Output:
	// Disallowed files: [/etc/*]
	// Threshold: 2 file(s)
	// Press Ctrl+C to stop
	//
	// [VIOLATION 1/2] PID 1000 (proc1) opened disallowed file: /etc/passwd
	// [VIOLATION 1/2] PID 2000 (proc2) opened disallowed file: /etc/shadow
	// [VIOLATION 2/2] PID 1000 (proc1) opened disallowed file: /etc/hosts
	//
	// *** PID 1000 is now BLOCKED from opening any further files! ***
	//
	// Total violations: 3
	// PID 1000 violations: 2, blocked: true
	// PID 2000 violations: 1, blocked: false
}
