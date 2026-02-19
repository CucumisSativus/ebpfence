package daemon

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	pb "ebpfence/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server wraps a gRPC server that exposes the EventHandler state.
type Server struct {
	pb.UnimplementedEBPFenceServer
	handler    *EventHandler
	grpcServer *grpc.Server
	socketPath string
}

// NewServer creates a new gRPC server backed by the given EventHandler.
func NewServer(handler *EventHandler) *Server {
	return &Server{
		handler: handler,
	}
}

// ListBlockedPIDs implements the EBPFence.ListBlockedPIDs RPC.
func (s *Server) ListBlockedPIDs(_ context.Context, _ *pb.ListBlockedPIDsRequest) (*pb.ListBlockedPIDsResponse, error) {
	pids := s.handler.GetBlockedPIDs()
	resp := &pb.ListBlockedPIDsResponse{
		BlockedPids: make([]*pb.BlockedPID, 0, len(pids)),
	}
	for _, pid := range pids {
		resp.BlockedPids = append(resp.BlockedPids, &pb.BlockedPID{
			Pid:            pid,
			ViolationCount: s.handler.GetViolationCountForPID(pid),
		})
	}
	return resp, nil
}

// UnblockPID implements the EBPFence.UnblockPID RPC.
func (s *Server) UnblockPID(_ context.Context, req *pb.UnblockPIDRequest) (*pb.UnblockPIDResponse, error) {
	if req.Pid == 0 {
		return nil, status.Error(codes.InvalidArgument, "pid must be greater than 0")
	}
	if err := s.handler.UnblockPID(req.Pid); err != nil {
		return nil, status.Errorf(codes.NotFound, "failed to unblock PID %d: %v", req.Pid, err)
	}
	return &pb.UnblockPIDResponse{}, nil
}

// Start begins listening on the given Unix socket path.
// It blocks until the server is stopped, so call it in a goroutine.
func (s *Server) Start(socketPath string) error {
	s.socketPath = socketPath

	// Remove stale socket file from a previous run.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing stale socket: %w", err)
	}

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", socketPath, err)
	}

	s.grpcServer = grpc.NewServer()
	pb.RegisterEBPFenceServer(s.grpcServer, s)

	log.Printf("gRPC server listening on %s", socketPath)
	return s.grpcServer.Serve(lis)
}

// Stop gracefully stops the gRPC server and removes the socket file.
func (s *Server) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	if s.socketPath != "" {
		os.Remove(s.socketPath)
	}
}
