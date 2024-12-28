package main

import (
	"fmt"
	"gosnoop/internal/ebpf/exec"
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

	e := exec.Exec{}
	eventChan, err := e.ReceiveEvents()
	if err != nil {
		log.Fatal("failed receiving exec events: ", err)
	}

	go func() {
		<-stopper
	}()

	for e := range eventChan {
		fmt.Println(e.String())
	}
}
