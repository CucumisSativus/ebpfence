package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	pb "ebpfence/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	socketPath := flag.String("socket", "/var/run/ebpfence.sock", "Path to daemon Unix socket")
	flag.Parse()

	conn, err := grpc.NewClient(
		"unix://"+*socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewEBPFenceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := flag.Args()
	if len(args) == 0 {
		listBlockedPIDs(ctx, client, *socketPath)
		return
	}

	switch args[0] {
	case "list":
		listBlockedPIDs(ctx, client, *socketPath)
	case "unblock":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: ebpfence-client unblock <pid>")
			os.Exit(1)
		}
		pid, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil || pid == 0 {
			fmt.Fprintf(os.Stderr, "Error: invalid PID %q\n", args[1])
			os.Exit(1)
		}
		unblockPID(ctx, client, *socketPath, uint32(pid))
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\nUsage: ebpfence-client [list | unblock <pid>]\n", args[0])
		os.Exit(1)
	}
}

func listBlockedPIDs(ctx context.Context, client pb.EBPFenceClient, socketPath string) {
	resp, err := client.ListBlockedPIDs(ctx, &pb.ListBlockedPIDsRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not reach daemon at %s: %v\n", socketPath, err)
		os.Exit(1)
	}

	if len(resp.BlockedPids) == 0 {
		fmt.Println("No blocked PIDs.")
		return
	}

	fmt.Printf("%-10s %s\n", "PID", "VIOLATIONS")
	for _, bp := range resp.BlockedPids {
		fmt.Printf("%-10d %d\n", bp.Pid, bp.ViolationCount)
	}
}

func unblockPID(ctx context.Context, client pb.EBPFenceClient, socketPath string, pid uint32) {
	_, err := client.UnblockPID(ctx, &pb.UnblockPIDRequest{Pid: pid})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not unblock PID %d: %v\n", pid, err)
		os.Exit(1)
	}
	fmt.Printf("PID %d has been unblocked.\n", pid)
}
