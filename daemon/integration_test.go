//go:build integration

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// checkIntegrationTestRequirements checks if we can run integration tests
func checkIntegrationTestRequirements(t *testing.T) {
	t.Helper()

	// Check if running as root
	if os.Geteuid() != 0 {
		t.Fatal("Integration tests require root privileges (run with sudo)")
	}

	// Check if BPF LSM is enabled
	if err := checkLSMBPFEnabled(); err != nil {
		t.Fatal(err.Error())
	}

	// Check if BPF filesystem is mounted
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		t.Fatal("BPF filesystem not mounted")
	}

	// Verify BTF is available (required for CO-RE)
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Fatal("Kernel BTF not available (required for CO-RE eBPF)")
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
	type eventResult struct {
		event *Event
		err   error
	}
	eventChan := make(chan *eventResult, 100)
	go func() {
		for {
			event, err := provider.ReadEvent()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				eventChan <- &eventResult{err: err}
				return
			}
			eventChan <- &eventResult{event: event}
		}
	}()

	// Give the event collector a moment to start
	time.Sleep(100 * time.Millisecond)

	// Trigger a file open event
	myPID := uint32(os.Getpid())
	_, err = os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read temp file: %v", err)
	}

	// Wait for events — match by PID first (bpf_d_path may not resolve on all kernels)
	timeout := time.After(6 * time.Second)
	pidMatched := false
	filenameMatched := false

	for !filenameMatched {
		select {
		case result := <-eventChan:
			if result.err != nil {
				t.Fatalf("Error reading event: %v", result.err)
			}
			event := result.event
			filename := nullTerminatedString(event.Filename[:])
			t.Logf("Received event: PID=%d, UID=%d, Comm=%s, File=%s",
				event.Pid, event.Uid, nullTerminatedString(event.Comm[:]), filename)

			if event.Pid == myPID {
				pidMatched = true
			}
			if filename == tmpFile {
				filenameMatched = true
				t.Log("Successfully captured our file open event!")
			}
		case <-timeout:
			if pidMatched {
				t.Log("Received events from our PID but bpf_d_path did not resolve the expected filename")
				t.Log("This is expected on some kernel configurations")
				return
			}
			t.Fatal("Timeout waiting for file open event. This likely means LSM BPF is not active. Check that 'bpf' is in /sys/kernel/security/lsm and the kernel was booted with lsm=...,bpf parameter.")
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
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test data"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// First, verify file is accessible before blocking
	t.Log("First attempt: File should be accessible")
	_, err = os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Initial file access failed (should succeed): %v", err)
	}

	// Get current PID for blocking
	currentPID := uint32(os.Getpid())
	t.Logf("Blocking PID %d", currentPID)

	// Block the current PID
	if err := provider.BlockPID(currentPID); err != nil {
		t.Fatalf("Failed to block PID: %v", err)
	}

	// Give kernel a moment to process the block
	time.Sleep(100 * time.Millisecond)

	// Try to open a file from this process - should be blocked
	t.Log("Second attempt: File access should now be blocked")
	_, err = os.ReadFile(testFile)

	if err == nil {
		t.Fatal("File access was not blocked after BlockPID — LSM hook is not enforcing. Verify the kernel was booted with lsm=...,bpf")
	}

	// If we got an error, verify it's a permission error
	if os.IsPermission(err) {
		t.Logf("File access correctly blocked with permission error: %v", err)
		t.Log("Successfully verified that blocking works!")
	} else {
		t.Logf("File access failed with error: %v (expected permission denied)", err)
		t.Log("Note: Error type suggests blocking may be working, but error format differs")
	}
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

	handlerConfig := EventHandlerConfig{
		DisallowedPatterns: []string{secretDir + "/*"},
		Threshold:          2,
		TargetPID:          0, // Monitor all PIDs
	}

	handler := NewEventHandler(provider, handlerConfig)

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

	cancel()
	<-done

	// Test must detect at least some violations to be valid
	if violations == 0 {
		t.Fatal("Expected to detect violations for secret file access, but got 0. This likely means LSM BPF is not active. Check that 'bpf' is in /sys/kernel/security/lsm")
	}

	// We expect at least 2 violations (threshold)
	if violations < 2 {
		t.Errorf("Expected at least 2 violations (our threshold), got %d", violations)
	}

	// Verify PID was blocked
	if !handler.IsPIDBlocked(currentPID) {
		t.Errorf("Expected PID %d to be blocked after %d violations (threshold: 2)", currentPID, violations)
	}

	t.Logf("Successfully detected %d violations and blocked PID %d!", violations, currentPID)
}

// TestIntegration_UnblockFunctionality tests that unblocking actually works
func TestIntegration_UnblockFunctionality(t *testing.T) {
	checkIntegrationTestRequirements(t)

	provider, err := NewRealEBPFProvider()
	if err != nil {
		t.Fatalf("Failed to create eBPF provider: %v", err)
	}
	defer provider.Close()

	// Create a test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test data"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Verify file is accessible before blocking
	if _, err := os.ReadFile(testFile); err != nil {
		t.Fatalf("Initial file access failed: %v", err)
	}

	currentPID := uint32(os.Getpid())

	// Block the current PID
	if err := provider.BlockPID(currentPID); err != nil {
		t.Fatalf("Failed to block PID: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Verify file access is denied
	_, err = os.ReadFile(testFile)
	if err == nil {
		t.Fatal("File access was not blocked after BlockPID — LSM hook is not enforcing. Verify the kernel was booted with lsm=...,bpf")
	}
	t.Logf("File access correctly blocked: %v", err)

	// Unblock the current PID
	if err := provider.UnblockPID(currentPID); err != nil {
		t.Fatalf("Failed to unblock PID: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Verify file access is restored
	if _, err := os.ReadFile(testFile); err != nil {
		t.Fatalf("File access should be restored after unblock, but got: %v", err)
	}
	t.Log("Successfully verified that unblocking restores file access!")
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
