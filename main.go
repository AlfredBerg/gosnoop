package main

import (
	"encoding/json"
	"fmt"
	"gosnoop/internal/ebpf/dns"
	"gosnoop/internal/ebpf/exec"
	"gosnoop/internal/ebpf/file"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("failed emoving memlock, do you have root priveledges? err: ", err)
	}

	events := make(chan interface{})

	exec := exec.Exec{IncludeEnvp: false}
	err := exec.ReceiveEvents(events)
	if err != nil {
		log.Fatal("failed receiving exec events: ", err)
	}
	defer exec.Close()

	file := file.File{}
	err = file.ReceiveEvents(events)
	if err != nil {
		log.Fatal("failed receiving exec events: ", err)
	}
	defer file.Close()

	dns := dns.Dns{}
	err = dns.ReceiveEvents(events)
	if err != nil {
		log.Fatal("failed receiving exec events: ", err)
	}
	defer dns.Close()

	go func() {
		<-stopper
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
