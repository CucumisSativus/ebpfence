package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
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

	resp, err := client.ListBlockedPIDs(ctx, &pb.ListBlockedPIDsRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not reach daemon at %s: %v\n", *socketPath, err)
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
