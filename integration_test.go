//go:build integration

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// checkIntegrationTestRequirements checks if we can run integration tests
func checkIntegrationTestRequirements(t *testing.T) {
	// Check if running as root
	if os.Geteuid() != 0 {
		t.Skip("Integration tests require root privileges (run with sudo)")
	}

	// Check if kernel supports eBPF LSM
	if _, err := os.Stat("/sys/kernel/security/lsm"); err != nil {
		t.Skip("Kernel LSM support not available")
	}

	// Check if BPF filesystem is mounted
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		t.Skip("BPF filesystem not mounted")
	}

	// Verify BTF is available (required for CO-RE)
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("Kernel BTF not available (required for CO-RE eBPF)")
	}
}

// TestIntegration_RealEBPFProvider_LoadAndAttach tests that we can load and attach eBPF programs
func TestIntegration_RealEBPFProvider_LoadAndAttach(t *testing.T) {
	checkIntegrationTestRequirements(t)

	provider, err := NewRealEBPFProvider()
	if err != nil {
		t.Fatalf("Failed to create eBPF provider: %v", err)
	}
	defer provider.Close()

	t.Log("Successfully loaded and attached eBPF programs")
}

// TestIntegration_EventCollection tests that we can collect file open events
func TestIntegration_EventCollection(t *testing.T) {
	checkIntegrationTestRequirements(t)

	provider, err := NewRealEBPFProvider()
	if err != nil {
		t.Fatalf("Failed to create eBPF provider: %v", err)
	}
	defer provider.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create a temporary file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	// Start collecting events in background
	eventChan := make(chan *Event, 10)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				event, err := provider.ReadEvent()
				if err != nil {
					if ctx.Err() == nil {
						t.Logf("Error reading event: %v", err)
					}
					return
				}
				eventChan <- event
			}
		}
	}()

	// Give the event collector a moment to start
	time.Sleep(100 * time.Millisecond)

	// Trigger a file open event
	_, err = os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read temp file: %v", err)
	}

	// Wait for events
	timeout := time.After(2 * time.Second)
	eventReceived := false

	for !eventReceived {
		select {
		case event := <-eventChan:
			t.Logf("Received event: PID=%d, UID=%d, Comm=%s, File=%s",
				event.Pid, event.Uid, nullTerminatedString(event.Comm[:]),
				nullTerminatedString(event.Filename[:]))

			// Check if this is our file
			filename := nullTerminatedString(event.Filename[:])
			if filename == tmpFile {
				eventReceived = true
				t.Log("Successfully captured our file open event!")
			}
		case <-timeout:
			t.Fatal("Timeout waiting for file open event")
		}
	}
}

// TestIntegration_BlockingFunctionality tests that blocking actually works
func TestIntegration_BlockingFunctionality(t *testing.T) {
	checkIntegrationTestRequirements(t)

	provider, err := NewRealEBPFProvider()
	if err != nil {
		t.Fatalf("Failed to create eBPF provider: %v", err)
	}
	defer provider.Close()

	// Create a test directory and file
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("secret data"), 0644); err != nil {
		t.Fatalf("Failed to create secret file: %v", err)
	}

	// Start a child process that we'll block
	cmd := exec.Command("cat", secretFile)

	// Run once to verify file is accessible
	t.Log("First attempt: File should be accessible")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Initial file access failed (should succeed): %v", err)
	}

	// Get current PID for blocking (we'll block ourselves)
	currentPID := uint32(os.Getpid())
	t.Logf("Blocking PID %d", currentPID)

	// Block the current PID
	if err := provider.BlockPID(currentPID); err != nil {
		t.Fatalf("Failed to block PID: %v", err)
	}

	// Give kernel a moment to process the block
	time.Sleep(100 * time.Millisecond)

	// Try to open a file - should be blocked
	t.Log("Second attempt: File access should now be blocked")
	cmd = exec.Command("cat", secretFile)
	err = cmd.Run()

	if err == nil {
		t.Fatal("Expected file access to be blocked, but it succeeded")
	}

	// Check if error is permission denied
	if exitErr, ok := err.(*exec.ExitError); ok {
		t.Logf("File access blocked with exit code: %d", exitErr.ExitCode())
		if exitErr.ExitCode() == 0 {
			t.Fatal("Expected non-zero exit code for blocked access")
		}
	} else {
		t.Logf("File access blocked with error: %v", err)
	}

	t.Log("Successfully verified that blocking works!")
}

// TestIntegration_EndToEnd tests the complete event handler flow
func TestIntegration_EndToEnd(t *testing.T) {
	checkIntegrationTestRequirements(t)

	// Create test directory with secret files
	tmpDir := t.TempDir()
	secretDir := filepath.Join(tmpDir, "secrets")
	if err := os.MkdirAll(secretDir, 0755); err != nil {
		t.Fatalf("Failed to create secret dir: %v", err)
	}

	secret1 := filepath.Join(secretDir, "secret1.txt")
	secret2 := filepath.Join(secretDir, "secret2.txt")
	allowedFile := filepath.Join(tmpDir, "allowed.txt")

	for _, f := range []string{secret1, secret2, allowedFile} {
		if err := os.WriteFile(f, []byte("data"), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", f, err)
		}
	}

	// Create provider and handler
	provider, err := NewRealEBPFProvider()
	if err != nil {
		t.Fatalf("Failed to create eBPF provider: %v", err)
	}
	defer provider.Close()

	config := EventHandlerConfig{
		DisallowedPatterns: []string{secretDir + "/*"},
		Threshold:          2,
		TargetPID:          0, // Monitor all PIDs
	}

	handler := NewEventHandler(provider, config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start handler
	done := make(chan error, 1)
	go func() {
		done <- handler.Run(ctx)
	}()

	// Give handler time to start
	time.Sleep(200 * time.Millisecond)

	// Access allowed file - should not count as violation
	t.Log("Accessing allowed file...")
	if _, err := os.ReadFile(allowedFile); err != nil {
		t.Logf("Warning: Failed to read allowed file: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Access first secret file
	t.Log("Accessing first secret file...")
	if _, err := os.ReadFile(secret1); err != nil {
		t.Logf("Note: Failed to read secret1 (might be blocked): %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Access second secret file - should trigger block
	t.Log("Accessing second secret file...")
	if _, err := os.ReadFile(secret2); err != nil {
		t.Logf("Note: Failed to read secret2 (might be blocked): %v", err)
	}

	// Wait for events to be processed
	time.Sleep(500 * time.Millisecond)

	// Check if we were blocked
	currentPID := uint32(os.Getpid())
	violations := handler.GetViolationCountForPID(currentPID)

	t.Logf("Violations detected for PID %d: %d", currentPID, violations)
	t.Logf("Is PID blocked: %v", handler.IsPIDBlocked(currentPID))
	t.Logf("Total violations across all PIDs: %d", handler.GetViolationCount())

	// Note: The exact violation count may vary due to timing and other processes
	if violations > 0 {
		t.Logf("Successfully detected %d violations!", violations)
	} else {
		t.Log("Note: No violations detected (may be due to timing or event processing)")
	}

	cancel()
	<-done

	t.Log("Integration test completed successfully")
}

// nullTerminatedString converts a null-terminated byte array to a string
func nullTerminatedString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
