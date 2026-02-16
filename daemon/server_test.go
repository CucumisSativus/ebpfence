package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	pb "ebpfence/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func startTestServer(t *testing.T, handler *EventHandler) (pb.EBPFenceClient, func()) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "test.sock")

	srv := NewServer(handler)
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(socketPath)
	}()

	// Wait briefly for the server to start listening.
	time.Sleep(50 * time.Millisecond)

	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("connecting to server: %v", err)
	}

	client := pb.NewEBPFenceClient(conn)
	cleanup := func() {
		conn.Close()
		srv.Stop()
	}
	return client, cleanup
}

func TestServer_ListBlockedPIDs_Empty(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	provider := NewMockEBPFProvider(ctx, []*Event{})
	defer provider.Close()

	handler := NewEventHandler(provider, EventHandlerConfig{
		DisallowedPatterns: []string{"/etc/*"},
		Threshold:          2,
	})

	client, cleanup := startTestServer(t, handler)
	defer cleanup()

	resp, err := client.ListBlockedPIDs(ctx, &pb.ListBlockedPIDsRequest{})
	if err != nil {
		t.Fatalf("ListBlockedPIDs: %v", err)
	}
	if len(resp.BlockedPids) != 0 {
		t.Errorf("expected 0 blocked PIDs, got %d", len(resp.BlockedPids))
	}
}

func TestServer_ListBlockedPIDs_WithBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := []*Event{
		CreateMockEvent(1000, 1000, "proc1", "/etc/passwd"),
		CreateMockEvent(1000, 1000, "proc1", "/etc/shadow"),
		CreateMockEvent(2000, 1000, "proc2", "/etc/passwd"),
	}

	provider := NewMockEBPFProvider(ctx, events)
	defer provider.Close()

	handler := NewEventHandler(provider, EventHandlerConfig{
		DisallowedPatterns: []string{"/etc/*"},
		Threshold:          2,
	})

	// Run handler to process events.
	done := make(chan error, 1)
	go func() {
		done <- handler.Run(ctx)
	}()
	time.Sleep(100 * time.Millisecond)

	client, cleanup := startTestServer(t, handler)
	defer cleanup()

	resp, err := client.ListBlockedPIDs(context.Background(), &pb.ListBlockedPIDsRequest{})
	if err != nil {
		t.Fatalf("ListBlockedPIDs: %v", err)
	}

	if len(resp.BlockedPids) != 1 {
		t.Fatalf("expected 1 blocked PID, got %d", len(resp.BlockedPids))
	}

	bp := resp.BlockedPids[0]
	if bp.Pid != 1000 {
		t.Errorf("expected blocked PID 1000, got %d", bp.Pid)
	}
	if bp.ViolationCount != 2 {
		t.Errorf("expected violation count 2, got %d", bp.ViolationCount)
	}

	cancel()
	<-done
}

func TestServer_ListBlockedPIDs_MultipleBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := []*Event{
		CreateMockEvent(1000, 1000, "proc1", "/etc/passwd"),
		CreateMockEvent(1000, 1000, "proc1", "/etc/shadow"),
		CreateMockEvent(2000, 1000, "proc2", "/etc/passwd"),
		CreateMockEvent(2000, 1000, "proc2", "/etc/shadow"),
		CreateMockEvent(2000, 1000, "proc2", "/etc/hosts"),
		CreateMockEvent(3000, 1000, "proc3", "/etc/passwd"),
	}

	provider := NewMockEBPFProvider(ctx, events)
	defer provider.Close()

	handler := NewEventHandler(provider, EventHandlerConfig{
		DisallowedPatterns: []string{"/etc/*"},
		Threshold:          2,
	})

	done := make(chan error, 1)
	go func() {
		done <- handler.Run(ctx)
	}()
	time.Sleep(100 * time.Millisecond)

	client, cleanup := startTestServer(t, handler)
	defer cleanup()

	resp, err := client.ListBlockedPIDs(context.Background(), &pb.ListBlockedPIDsRequest{})
	if err != nil {
		t.Fatalf("ListBlockedPIDs: %v", err)
	}

	if len(resp.BlockedPids) != 2 {
		t.Fatalf("expected 2 blocked PIDs, got %d", len(resp.BlockedPids))
	}

	// Build a map for easier assertion.
	blocked := make(map[uint32]uint32)
	for _, bp := range resp.BlockedPids {
		blocked[bp.Pid] = bp.ViolationCount
	}

	if blocked[1000] != 2 {
		t.Errorf("expected PID 1000 violation count 2, got %d", blocked[1000])
	}
	if blocked[2000] != 3 {
		t.Errorf("expected PID 2000 violation count 3, got %d", blocked[2000])
	}
	if _, ok := blocked[3000]; ok {
		t.Error("PID 3000 should not be blocked (only 1 violation)")
	}

	cancel()
	<-done
}

func TestServer_UnblockPID_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Events that will block PID 1000
	events := []*Event{
		CreateMockEvent(1000, 1000, "proc1", "/etc/passwd"),
		CreateMockEvent(1000, 1000, "proc1", "/etc/shadow"),
	}

	provider := NewMockEBPFProvider(ctx, events)
	defer provider.Close()

	handler := NewEventHandler(provider, EventHandlerConfig{
		DisallowedPatterns: []string{"/etc/*"},
		Threshold:          2,
	})

	// Process events to block PID 1000.
	done := make(chan error, 1)
	go func() {
		done <- handler.Run(ctx)
	}()
	time.Sleep(100 * time.Millisecond)

	client, cleanup := startTestServer(t, handler)
	defer cleanup()

	// Verify PID is blocked.
	listResp, err := client.ListBlockedPIDs(context.Background(), &pb.ListBlockedPIDsRequest{})
	if err != nil {
		t.Fatalf("ListBlockedPIDs: %v", err)
	}
	if len(listResp.BlockedPids) != 1 || listResp.BlockedPids[0].Pid != 1000 {
		t.Fatalf("expected PID 1000 to be blocked, got %v", listResp.BlockedPids)
	}

	// Unblock PID 1000 via RPC.
	_, err = client.UnblockPID(context.Background(), &pb.UnblockPIDRequest{Pid: 1000})
	if err != nil {
		t.Fatalf("UnblockPID: %v", err)
	}

	// Verify PID is no longer in the blocked list.
	listResp, err = client.ListBlockedPIDs(context.Background(), &pb.ListBlockedPIDsRequest{})
	if err != nil {
		t.Fatalf("ListBlockedPIDs after unblock: %v", err)
	}
	if len(listResp.BlockedPids) != 0 {
		t.Errorf("expected 0 blocked PIDs after unblock, got %d", len(listResp.BlockedPids))
	}

	cancel()
	<-done
}

func TestServer_UnblockPID_NotBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	provider := NewMockEBPFProvider(ctx, []*Event{})
	defer provider.Close()

	handler := NewEventHandler(provider, EventHandlerConfig{
		DisallowedPatterns: []string{"/etc/*"},
		Threshold:          2,
	})

	client, cleanup := startTestServer(t, handler)
	defer cleanup()

	_, err := client.UnblockPID(context.Background(), &pb.UnblockPIDRequest{Pid: 9999})
	if err == nil {
		t.Fatal("expected error when unblocking non-blocked PID")
	}
}

func TestServer_UnblockPID_InvalidPID(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	provider := NewMockEBPFProvider(ctx, []*Event{})
	defer provider.Close()

	handler := NewEventHandler(provider, EventHandlerConfig{
		DisallowedPatterns: []string{"/etc/*"},
		Threshold:          2,
	})

	client, cleanup := startTestServer(t, handler)
	defer cleanup()

	_, err := client.UnblockPID(context.Background(), &pb.UnblockPIDRequest{Pid: 0})
	if err == nil {
		t.Fatal("expected error when unblocking PID 0")
	}
}
