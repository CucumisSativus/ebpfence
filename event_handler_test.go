package main

import (
	"context"
	"testing"
	"time"
)

func TestEventHandler_ViolationCounting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create mock events - 3 violations of disallowed files
	events := []*Event{
		CreateMockEvent(1234, 1000, "testproc", "/etc/passwd"),
		CreateMockEvent(1234, 1000, "testproc", "/tmp/allowed.txt"),
		CreateMockEvent(1234, 1000, "testproc", "/etc/shadow"),
		CreateMockEvent(1234, 1000, "testproc", "/var/log/allowed.log"),
		CreateMockEvent(1234, 1000, "testproc", "/etc/hosts"),
	}

	provider := NewMockEBPFProvider(ctx, events)
	defer provider.Close()

	config := EventHandlerConfig{
		DisallowedPatterns: []string{"/etc/*"},
		Threshold:          3,
		TargetPID:          0, // All PIDs
	}

	handler := NewEventHandler(provider, config)

	// Run handler in goroutine
	done := make(chan error, 1)
	go func() {
		done <- handler.Run(ctx)
	}()

	// Wait a bit for events to be processed
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// Check violation count
	if handler.GetViolationCount() != 3 {
		t.Errorf("expected 3 violations, got %d", handler.GetViolationCount())
	}

	// Check violation count for specific PID
	if handler.GetViolationCountForPID(1234) != 3 {
		t.Errorf("expected 3 violations for PID 1234, got %d", handler.GetViolationCountForPID(1234))
	}

	// Check that PID was blocked after reaching threshold
	if !handler.IsBlocked() {
		t.Error("expected handler to be in blocked state")
	}

	if !handler.IsPIDBlocked(1234) {
		t.Error("expected PID 1234 to be blocked in handler")
	}

	if !provider.IsBlocked(1234) {
		t.Error("expected PID 1234 to be blocked in provider")
	}
}

func TestEventHandler_ThresholdBlocking(t *testing.T) {
	tests := []struct {
		name              string
		threshold         uint32
		disallowedFiles   []string
		events            []*Event
		expectedViolations uint32
		shouldBlock       bool
	}{
		{
			name:      "block after 2 violations",
			threshold: 2,
			disallowedFiles: []string{"/secret/*"},
			events: []*Event{
				CreateMockEvent(5678, 1000, "app", "/secret/file1.txt"),
				CreateMockEvent(5678, 1000, "app", "/public/file.txt"),
				CreateMockEvent(5678, 1000, "app", "/secret/file2.txt"),
			},
			expectedViolations: 2,
			shouldBlock:       true,
		},
		{
			name:      "no block when threshold not reached",
			threshold: 5,
			disallowedFiles: []string{"/secret/*"},
			events: []*Event{
				CreateMockEvent(5678, 1000, "app", "/secret/file1.txt"),
				CreateMockEvent(5678, 1000, "app", "/secret/file2.txt"),
				CreateMockEvent(5678, 1000, "app", "/public/file.txt"),
			},
			expectedViolations: 2,
			shouldBlock:       false,
		},
		{
			name:      "exact match blocking",
			threshold: 1,
			disallowedFiles: []string{"/etc/passwd"},
			events: []*Event{
				CreateMockEvent(9999, 1000, "hacker", "/etc/passwd"),
			},
			expectedViolations: 1,
			shouldBlock:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			provider := NewMockEBPFProvider(ctx, tt.events)
			defer provider.Close()

			config := EventHandlerConfig{
				DisallowedPatterns: tt.disallowedFiles,
				Threshold:          tt.threshold,
				TargetPID:          0,
			}

			handler := NewEventHandler(provider, config)

			done := make(chan error, 1)
			go func() {
				done <- handler.Run(ctx)
			}()

			time.Sleep(100 * time.Millisecond)
			cancel()
			<-done

			if handler.GetViolationCount() != tt.expectedViolations {
				t.Errorf("expected %d violations, got %d", tt.expectedViolations, handler.GetViolationCount())
			}

			if handler.IsBlocked() != tt.shouldBlock {
				t.Errorf("expected blocked=%v, got %v", tt.shouldBlock, handler.IsBlocked())
			}
		})
	}
}

func TestEventHandler_MultipleProcesses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Events from multiple different PIDs
	events := []*Event{
		// PID 1000 - 2 violations (should be blocked)
		CreateMockEvent(1000, 1000, "proc1", "/etc/passwd"),
		CreateMockEvent(1000, 1000, "proc1", "/etc/shadow"),
		// PID 2000 - 1 violation (should not be blocked)
		CreateMockEvent(2000, 1000, "proc2", "/etc/hosts"),
		// PID 3000 - 3 violations (should be blocked)
		CreateMockEvent(3000, 1000, "proc3", "/etc/passwd"),
		CreateMockEvent(3000, 1000, "proc3", "/etc/shadow"),
		CreateMockEvent(3000, 1000, "proc3", "/etc/group"),
		// PID 1000 - 1 more violation (already blocked)
		CreateMockEvent(1000, 1000, "proc1", "/etc/gshadow"),
		// PID 4000 - 0 violations (accessing allowed files)
		CreateMockEvent(4000, 1000, "proc4", "/tmp/safe.txt"),
	}

	provider := NewMockEBPFProvider(ctx, events)
	defer provider.Close()

	config := EventHandlerConfig{
		DisallowedPatterns: []string{"/etc/*"},
		Threshold:          2,
		TargetPID:          0, // Monitor all PIDs
	}

	handler := NewEventHandler(provider, config)

	done := make(chan error, 1)
	go func() {
		done <- handler.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// Check total violations across all PIDs (includes violations after blocking)
	// PID 1000: 3 violations, PID 2000: 1 violation, PID 3000: 3 violations = 7 total
	if handler.GetViolationCount() != 7 {
		t.Errorf("expected 7 total violations, got %d", handler.GetViolationCount())
	}

	// Check per-PID violation counts
	if handler.GetViolationCountForPID(1000) != 3 {
		t.Errorf("expected 3 violations for PID 1000, got %d", handler.GetViolationCountForPID(1000))
	}
	if handler.GetViolationCountForPID(2000) != 1 {
		t.Errorf("expected 1 violation for PID 2000, got %d", handler.GetViolationCountForPID(2000))
	}
	if handler.GetViolationCountForPID(3000) != 3 {
		t.Errorf("expected 3 violations for PID 3000, got %d", handler.GetViolationCountForPID(3000))
	}
	if handler.GetViolationCountForPID(4000) != 0 {
		t.Errorf("expected 0 violations for PID 4000, got %d", handler.GetViolationCountForPID(4000))
	}

	// Check that the correct PIDs are blocked
	if !handler.IsPIDBlocked(1000) {
		t.Error("expected PID 1000 to be blocked")
	}
	if !handler.IsPIDBlocked(3000) {
		t.Error("expected PID 3000 to be blocked")
	}
	if handler.IsPIDBlocked(2000) {
		t.Error("PID 2000 should not be blocked (only 1 violation)")
	}
	if handler.IsPIDBlocked(4000) {
		t.Error("PID 4000 should not be blocked (no violations)")
	}

	// Verify blocked PIDs in provider
	if !provider.IsBlocked(1000) {
		t.Error("expected PID 1000 to be blocked in provider")
	}
	if !provider.IsBlocked(3000) {
		t.Error("expected PID 3000 to be blocked in provider")
	}
	if provider.IsBlocked(2000) {
		t.Error("PID 2000 should not be blocked in provider")
	}

	// Check GetBlockedPIDs returns correct list
	blockedPIDs := handler.GetBlockedPIDs()
	if len(blockedPIDs) != 2 {
		t.Errorf("expected 2 blocked PIDs, got %d", len(blockedPIDs))
	}

	// Check that both PIDs are in the list
	blockedMap := make(map[uint32]bool)
	for _, pid := range blockedPIDs {
		blockedMap[pid] = true
	}
	if !blockedMap[1000] || !blockedMap[3000] {
		t.Error("blocked PIDs list should contain 1000 and 3000")
	}
}

func TestEventHandler_PIDFiltering(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Events from different PIDs
	events := []*Event{
		CreateMockEvent(1000, 1000, "proc1", "/etc/passwd"),
		CreateMockEvent(2000, 1000, "proc2", "/etc/shadow"),
		CreateMockEvent(1000, 1000, "proc1", "/etc/hosts"),
	}

	provider := NewMockEBPFProvider(ctx, events)
	defer provider.Close()

	config := EventHandlerConfig{
		DisallowedPatterns: []string{"/etc/*"},
		Threshold:          2,
		TargetPID:          1000, // Only monitor PID 1000
	}

	handler := NewEventHandler(provider, config)

	done := make(chan error, 1)
	go func() {
		done <- handler.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// Should only count violations from PID 1000 (2 violations)
	if handler.GetViolationCount() != 2 {
		t.Errorf("expected 2 violations from PID 1000, got %d", handler.GetViolationCount())
	}

	// Check violation count for PID 1000 specifically
	if handler.GetViolationCountForPID(1000) != 2 {
		t.Errorf("expected 2 violations for PID 1000, got %d", handler.GetViolationCountForPID(1000))
	}

	// PID 2000 should have 0 violations (filtered out)
	if handler.GetViolationCountForPID(2000) != 0 {
		t.Errorf("expected 0 violations for PID 2000, got %d", handler.GetViolationCountForPID(2000))
	}

	// Should block PID 1000 after 2 violations
	if !handler.IsBlocked() {
		t.Error("expected handler to have blocked PIDs")
	}

	if !handler.IsPIDBlocked(1000) {
		t.Error("expected PID 1000 to be blocked in handler")
	}

	// Only PID 1000 should be blocked, not PID 2000
	if !provider.IsBlocked(1000) {
		t.Error("expected PID 1000 to be blocked in provider")
	}

	if provider.IsBlocked(2000) {
		t.Error("PID 2000 should not be blocked")
	}
}

func TestEventHandler_PatternMatching(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		filename string
		expected bool
	}{
		{
			name:     "wildcard match",
			patterns: []string{"/etc/*"},
			filename: "/etc/passwd",
			expected: true,
		},
		{
			name:     "exact match",
			patterns: []string{"/etc/passwd"},
			filename: "/etc/passwd",
			expected: true,
		},
		{
			name:     "substring match",
			patterns: []string{"secret"},
			filename: "/path/to/secret/file.txt",
			expected: true,
		},
		{
			name:     "no match",
			patterns: []string{"/etc/*"},
			filename: "/tmp/file.txt",
			expected: false,
		},
		{
			name:     "multiple patterns - first matches",
			patterns: []string{"/etc/*", "/var/*"},
			filename: "/etc/hosts",
			expected: true,
		},
		{
			name:     "multiple patterns - second matches",
			patterns: []string{"/etc/*", "/var/"},
			filename: "/var/log/syslog",
			expected: true,
		},
		{
			name:     "multiple patterns - none match",
			patterns: []string{"/etc/*", "/var/*"},
			filename: "/tmp/file.txt",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesPattern(tt.filename, tt.patterns)
			if result != tt.expected {
				t.Errorf("matchesPattern(%q, %v) = %v, want %v",
					tt.filename, tt.patterns, result, tt.expected)
			}
		})
	}
}

func TestEventHandler_NoViolations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Events that don't match disallowed patterns
	events := []*Event{
		CreateMockEvent(1234, 1000, "app", "/tmp/file1.txt"),
		CreateMockEvent(1234, 1000, "app", "/home/user/file2.txt"),
		CreateMockEvent(1234, 1000, "app", "/var/tmp/file3.txt"),
	}

	provider := NewMockEBPFProvider(ctx, events)
	defer provider.Close()

	config := EventHandlerConfig{
		DisallowedPatterns: []string{"/etc/*", "/secret/*"},
		Threshold:          2,
		TargetPID:          0,
	}

	handler := NewEventHandler(provider, config)

	done := make(chan error, 1)
	go func() {
		done <- handler.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if handler.GetViolationCount() != 0 {
		t.Errorf("expected 0 violations, got %d", handler.GetViolationCount())
	}

	if handler.IsBlocked() {
		t.Error("handler should not be in blocked state")
	}

	if provider.IsBlocked(1234) {
		t.Error("PID 1234 should not be blocked")
	}
}

func TestEventHandler_EmptyEventStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// No events
	provider := NewMockEBPFProvider(ctx, []*Event{})
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

	if handler.GetViolationCount() != 0 {
		t.Errorf("expected 0 violations, got %d", handler.GetViolationCount())
	}

	if handler.IsBlocked() {
		t.Error("handler should not be in blocked state")
	}
}
