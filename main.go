package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -target bpf" Bpf ./deny_new_reads.bpf.c -- -I.

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		cancel()
	}()

	// 1) Load
	var objs BpfObjects
	if err := LoadBpfObjects(&objs, &ebpf.CollectionOptions{}); err != nil {
		log.Fatalf("load bpf objects: %v", err)
	}
	defer objs.Close()

	// 2) Attach (LSM example)
	lnk, err := link.AttachLSM(link.LSMOptions{
		Program: objs.BlockNewReads, // name comes from SEC() function
	})
	if err != nil {
		log.Fatalf("attach lsm: %v", err)
	}
	defer lnk.Close()

	// 3) Configure policy
	tgid := uint32(1234) // example; you’d pass via CLI
	if err := setMode(objs.ModeMap, tgid, 1 /*learn*/); err != nil {
		log.Fatalf("set learn: %v", err)
	}
	fmt.Println("learning… press Enter to enforce")
	fmt.Scanln()

	if err := setMode(objs.ModeMap, tgid, 2 /*enforce*/); err != nil {
		log.Fatalf("set enforce: %v", err)
	}
	fmt.Println("enforcing… Ctrl+C to stop")

	// 4) Optional: event loop (ringbuf/perf) would run here

	<-ctx.Done()
	fmt.Println("exiting")
}

func setMode(m *ebpf.Map, tgid uint32, mode uint8) error {
	if m == nil {
		return errors.New("mode map is nil")
	}
	return m.Update(&tgid, &mode, ebpf.UpdateAny)
}
