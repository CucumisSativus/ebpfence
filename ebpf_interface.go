package main

// Event structure matching the BPF C struct
type Event struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [256]byte
	Flags    int32
}

// EBPFProvider defines the interface for eBPF operations
type EBPFProvider interface {
	// ReadEvent reads the next event from the ring buffer
	// Returns the event and any error encountered
	ReadEvent() (*Event, error)

	// BlockPID adds a PID to the blocked list
	BlockPID(pid uint32) error

	// Close cleans up resources
	Close() error
}
