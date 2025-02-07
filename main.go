package main

import (
	"context"
	"encoding/json"
	"fmt"
	"gosnoop/internal/ebpf/dns"
	"gosnoop/internal/ebpf/exec"
	"gosnoop/internal/ebpf/file"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("failed removing memlock, do you have root priveledges? err: ", err)
	}

	ctx, ctxCancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}
	events := make(chan interface{})

	exec := exec.Exec{IncludeEnvp: false}
	err := exec.ReceiveEvents(ctx, &wg, events)
	if err != nil {
		log.Fatal("failed receiving exec events: ", err)
	}
	defer exec.Close()

	file := file.File{}
	err = file.ReceiveEvents(ctx, &wg, events)
	if err != nil {
		log.Fatal("failed receiving exec events: ", err)
	}
	defer file.Close()

	dns := dns.Dns{}
	err = dns.ReceiveEvents(ctx, &wg, events)
	if err != nil {
		log.Fatal("failed receiving exec events: ", err)
	}
	defer dns.Close()
	go func() {
		<-stopper
		ctxCancel()
		wg.Wait()
		close(events)
	}()

	for e := range events {
		j, err := json.Marshal(e)
		if err != nil {
			log.Printf("failed to marshal event, err: %s", err)
		}
		fmt.Println(string(j))
	}
}
