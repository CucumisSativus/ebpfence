package daemon

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
)

// EventHandlerConfig holds configuration for the event handler
type EventHandlerConfig struct {
	DisallowedPatterns []string
	Threshold          uint32
	TargetPID          uint32        // 0 means all PIDs
	Strategy           BlockStrategy // what gets blocked when threshold is reached
}

// EventHandler manages the core logic of processing events and blocking PIDs
type EventHandler struct {
	mu              sync.RWMutex
	provider        EBPFProvider
	config          EventHandlerConfig
	violationCounts map[uint32]uint32 // PID -> violation count
	blockedPIDs     map[uint32]bool   // PID -> blocked status
}

// NewEventHandler creates a new event handler with the given provider and config
func NewEventHandler(provider EBPFProvider, config EventHandlerConfig) *EventHandler {
	return &EventHandler{
		provider:        provider,
		config:          config,
		violationCounts: make(map[uint32]uint32),
		blockedPIDs:     make(map[uint32]bool),
	}
}

// blockingDescription returns a human-readable description of the blocking strategy.
func blockingDescription(strategy BlockStrategy) string {
	switch strategy {
	case BlockNetwork:
		return "socket connections"
	case BlockBoth:
		return "file opens and socket connections"
	default:
		return "file opens"
	}
}

// Run starts processing events from the ring buffer
func (h *EventHandler) Run(ctx context.Context) error {
	if len(h.config.DisallowedPatterns) == 0 {
		return fmt.Errorf("no disallowed patterns configured")
	}
	if h.config.Threshold == 0 {
		return fmt.Errorf("threshold must be greater than 0")
	}

	fmt.Printf("Disallowed files: %v\n", h.config.DisallowedPatterns)
	fmt.Printf("Threshold: %d file(s)\n", h.config.Threshold)
	fmt.Printf("Blocking strategy: %s (blocks: %s)\n", h.config.Strategy, blockingDescription(h.config.Strategy))
	if h.config.TargetPID != 0 {
		fmt.Printf("Target PID: %d\n", h.config.TargetPID)
	}
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Close the provider when the context is cancelled to unblock ReadEvent
	go func() {
		<-ctx.Done()
		h.provider.Close()
	}()

	// Process events in a loop
	for {
		event, err := h.provider.ReadEvent()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("reading event: %v", err)
			continue
		}

		if err := h.processEvent(event); err != nil {
			log.Printf("processing event: %v", err)
		}
	}
}

// processEvent handles a single event
func (h *EventHandler) processEvent(event *Event) error {
	// Filter by PID if specified
	if h.config.TargetPID != 0 && event.Pid != h.config.TargetPID {
		return nil
	}

	// Extract null-terminated strings (truncate at first null byte)
	comm := nullTermStr(event.Comm[:])
	filename := nullTermStr(event.Filename[:])

	// Check if the file matches any disallowed pattern
	if !matchesPattern(filename, h.config.DisallowedPatterns) {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Process violation for this PID
	h.violationCounts[event.Pid]++
	pidViolations := h.violationCounts[event.Pid]

	fmt.Printf("[VIOLATION %d/%d] PID %d (%s) opened disallowed file: %s\n",
		pidViolations, h.config.Threshold, event.Pid, comm, filename)

	// Check if this PID has reached the threshold and is not already blocked
	if pidViolations >= h.config.Threshold && !h.blockedPIDs[event.Pid] {
		if err := h.provider.BlockPID(event.Pid); err != nil {
			return fmt.Errorf("failed to block PID: %w", err)
		}
		h.blockedPIDs[event.Pid] = true
		fmt.Printf("\n*** PID %d is now BLOCKED from %s! ***\n\n", event.Pid, blockingDescription(h.config.Strategy))
	}

	return nil
}

// GetViolationCount returns the total violation count across all PIDs
func (h *EventHandler) GetViolationCount() uint32 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var total uint32
	for _, count := range h.violationCounts {
		total += count
	}
	return total
}

// GetViolationCountForPID returns the violation count for a specific PID
func (h *EventHandler) GetViolationCountForPID(pid uint32) uint32 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.violationCounts[pid]
}

// IsBlocked returns whether any PID has been blocked
func (h *EventHandler) IsBlocked() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.blockedPIDs) > 0
}

// IsPIDBlocked returns whether a specific PID is blocked
func (h *EventHandler) IsPIDBlocked(pid uint32) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.blockedPIDs[pid]
}

// UnblockPID removes a PID from the blocked list and resets its violation count
func (h *EventHandler) UnblockPID(pid uint32) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.blockedPIDs[pid] {
		return fmt.Errorf("PID %d is not blocked", pid)
	}

	if err := h.provider.UnblockPID(pid); err != nil {
		return fmt.Errorf("failed to unblock PID in kernel: %w", err)
	}

	delete(h.blockedPIDs, pid)
	delete(h.violationCounts, pid)
	fmt.Printf("\n*** PID %d has been UNBLOCKED and can resume %s. ***\n\n", pid, blockingDescription(h.config.Strategy))
	return nil
}

// GetBlockedPIDs returns a slice of all blocked PIDs
func (h *EventHandler) GetBlockedPIDs() []uint32 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	pids := make([]uint32, 0, len(h.blockedPIDs))
	for pid := range h.blockedPIDs {
		pids = append(pids, pid)
	}
	return pids
}

// nullTermStr returns the string up to the first null byte.
func nullTermStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
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
