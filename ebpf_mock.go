package main

import (
	"context"
	"fmt"
	"sync"
)

// MockEBPFProvider is a mock implementation of EBPFProvider for testing
type MockEBPFProvider struct {
	mu           sync.Mutex
	events       []*Event
	currentIndex int
	blockedPIDs  map[uint32]bool
	closed       bool
	ctx          context.Context
}

// NewMockEBPFProvider creates a new mock provider with predefined events
func NewMockEBPFProvider(ctx context.Context, events []*Event) *MockEBPFProvider {
	return &MockEBPFProvider{
		events:      events,
		blockedPIDs: make(map[uint32]bool),
		ctx:         ctx,
	}
}

// ReadEvent returns the next event from the predefined list
func (m *MockEBPFProvider) ReadEvent() (*Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, fmt.Errorf("provider is closed")
	}

	// Check if context is cancelled
	select {
	case <-m.ctx.Done():
		return nil, context.Canceled
	default:
	}

	if m.currentIndex >= len(m.events) {
		// No more events, wait for context cancellation
		<-m.ctx.Done()
		return nil, context.Canceled
	}

	event := m.events[m.currentIndex]
	m.currentIndex++
	return event, nil
}

// BlockPID adds a PID to the blocked list
func (m *MockEBPFProvider) BlockPID(pid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("provider is closed")
	}

	m.blockedPIDs[pid] = true
	return nil
}

// IsBlocked checks if a PID is blocked (for testing purposes)
func (m *MockEBPFProvider) IsBlocked(pid uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.blockedPIDs[pid]
}

// Close cleans up resources
func (m *MockEBPFProvider) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// CreateMockEvent is a helper function to create mock events for testing
func CreateMockEvent(pid uint32, uid uint32, comm string, filename string) *Event {
	event := &Event{
		Pid: pid,
		Uid: uid,
	}

	// Copy comm string to fixed-size array
	copy(event.Comm[:], comm)

	// Copy filename to fixed-size array
	copy(event.Filename[:], filename)

	return event
}
