package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// RealEBPFProvider is the production implementation of EBPFProvider
type RealEBPFProvider struct {
	objs          *BpfObjects
	reader        *ringbuf.Reader
	lsmLink       link.Link
	tpLinkOpenat  link.Link
	tpLinkOpenat2 link.Link
}

// NewRealEBPFProvider creates and initializes a new RealEBPFProvider
func NewRealEBPFProvider() (*RealEBPFProvider, error) {
	provider := &RealEBPFProvider{
		objs: &BpfObjects{},
	}

	// Load BPF objects
	if err := LoadBpfObjects(provider.objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	// Attach LSM hook for blocking
	lsmLink, err := link.AttachLSM(link.LSMOptions{Program: provider.objs.DenyFileOpen})
	if err != nil {
		provider.objs.Close()
		return nil, fmt.Errorf("attach LSM hook: %w", err)
	}
	provider.lsmLink = lsmLink

	// Attach tracepoint for openat
	tpLinkOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", provider.objs.TraceOpenat, nil)
	if err != nil {
		provider.Close()
		return nil, fmt.Errorf("attach openat tracepoint: %w", err)
	}
	provider.tpLinkOpenat = tpLinkOpenat

	// Attach tracepoint for openat2 (optional)
	tpLinkOpenat2, err := link.Tracepoint("syscalls", "sys_enter_openat2", provider.objs.TraceOpenat2, nil)
	if err != nil {
		// openat2 might not be available on older kernels, so just log a warning
		fmt.Printf("Warning: could not attach openat2 tracepoint: %v\n", err)
	} else {
		provider.tpLinkOpenat2 = tpLinkOpenat2
	}

	// Open the ring buffer
	reader, err := ringbuf.NewReader(provider.objs.Events)
	if err != nil {
		provider.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	provider.reader = reader

	return provider, nil
}

// ReadEvent reads the next event from the ring buffer
func (p *RealEBPFProvider) ReadEvent() (*Event, error) {
	record, err := p.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, fmt.Errorf("ring buffer closed: %w", err)
		}
		return nil, fmt.Errorf("reading from ring buffer: %w", err)
	}

	// Parse the event
	var event Event
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("parsing event: %w", err)
	}

	return &event, nil
}

// BlockPID adds a PID to the blocked list
func (p *RealEBPFProvider) BlockPID(pid uint32) error {
	blockedValue := uint8(1)
	if err := p.objs.BlockedPids.Update(pid, &blockedValue, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update blocked_pids map: %w", err)
	}
	return nil
}

// Close cleans up all resources
func (p *RealEBPFProvider) Close() error {
	var errs []error

	if p.reader != nil {
		if err := p.reader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close reader: %w", err))
		}
	}

	if p.tpLinkOpenat2 != nil {
		if err := p.tpLinkOpenat2.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close openat2 link: %w", err))
		}
	}

	if p.tpLinkOpenat != nil {
		if err := p.tpLinkOpenat.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close openat link: %w", err))
		}
	}

	if p.lsmLink != nil {
		if err := p.lsmLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close lsm link: %w", err))
		}
	}

	if p.objs != nil {
		if err := p.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close bpf objects: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing provider: %v", errs)
	}

	return nil
}
