package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {

	//Print exec (not finished)
	if false {

		fn := "sys_execve"

		// Remove resource limits for kernels <5.11.
		if err := rlimit.RemoveMemlock(); err != nil {
			log.Fatal("Removing memlock:", err)
		}
		// Load the compiled eBPF ELF and load it into the kernel.
		var objs execObjects
		if err := loadExecObjects(&objs, nil); err != nil {
			log.Fatal("Loading eBPF objects:", err)
		}
		defer objs.Close()

		kp, err := link.Kprobe(fn, objs.CountPackets, nil)
		if err != nil {
			log.Fatalf("opening kprobe: %s", err)
		}
		defer kp.Close()

		time.Sleep(time.Hour)
	}
}
