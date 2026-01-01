package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
)

// EventHandlerConfig holds configuration for the event handler
type EventHandlerConfig struct {
	DisallowedPatterns []string
	Threshold          uint32
	TargetPID          uint32 // 0 means all PIDs
}

// EventHandler manages the core logic of processing events and blocking PIDs
type EventHandler struct {
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

// Run starts processing events from the ring buffer
func (h *EventHandler) Run(ctx context.Context) error {
	fmt.Printf("Disallowed files: %v\n", h.config.DisallowedPatterns)
	fmt.Printf("Threshold: %d file(s)\n", h.config.Threshold)
	if h.config.TargetPID != 0 {
		fmt.Printf("Target PID: %d\n", h.config.TargetPID)
	}
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Process events in a loop
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			event, err := h.provider.ReadEvent()
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				log.Printf("reading event: %v", err)
				continue
			}

			if err := h.processEvent(event); err != nil {
				log.Printf("processing event: %v", err)
			}
		}
	}
}

// processEvent handles a single event
func (h *EventHandler) processEvent(event *Event) error {
	// Filter by PID if specified
	if h.config.TargetPID != 0 && event.Pid != h.config.TargetPID {
		return nil
	}

	// Extract null-terminated strings
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
	filename := string(bytes.TrimRight(event.Filename[:], "\x00"))

	// Check if the file matches any disallowed pattern
	if !matchesPattern(filename, h.config.DisallowedPatterns) {
		return nil
	}

	// Process violation for this PID
	h.violationCounts[event.Pid]++
	pidViolations := h.violationCounts[event.Pid]

	fmt.Printf("[VIOLATION %d/%d] PID %d (%s) opened disallowed file: %s\n",
		pidViolations, h.config.Threshold, event.Pid, comm, filename)

	// Check if this PID has reached the threshold and is not already blocked
	if pidViolations >= h.config.Threshold && !h.blockedPIDs[event.Pid] {
		h.blockedPIDs[event.Pid] = true
		if err := h.provider.BlockPID(event.Pid); err != nil {
			return fmt.Errorf("failed to block PID: %w", err)
		}
		fmt.Printf("\n*** PID %d is now BLOCKED from opening any further files! ***\n\n", event.Pid)
	}

	return nil
}

// GetViolationCount returns the total violation count across all PIDs
func (h *EventHandler) GetViolationCount() uint32 {
	var total uint32
	for _, count := range h.violationCounts {
		total += count
	}
	return total
}

// GetViolationCountForPID returns the violation count for a specific PID
func (h *EventHandler) GetViolationCountForPID(pid uint32) uint32 {
	return h.violationCounts[pid]
}

// IsBlocked returns whether any PID has been blocked
func (h *EventHandler) IsBlocked() bool {
	return len(h.blockedPIDs) > 0
}

// IsPIDBlocked returns whether a specific PID is blocked
func (h *EventHandler) IsPIDBlocked(pid uint32) bool {
	return h.blockedPIDs[pid]
}

// GetBlockedPIDs returns a slice of all blocked PIDs
func (h *EventHandler) GetBlockedPIDs() []uint32 {
	pids := make([]uint32, 0, len(h.blockedPIDs))
	for pid := range h.blockedPIDs {
		pids = append(pids, pid)
	}
	return pids
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
