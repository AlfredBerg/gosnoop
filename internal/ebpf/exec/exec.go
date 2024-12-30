package exec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type ExecEvent struct {
	comm string
	pid  int //TODO: This is the pid of the spawned process, would be usefull with the parent pid
	path string
	argv []string
}

func (r ExecEvent) String() string {
	return fmt.Sprintf("Exec event from comm %s, pid %d: %s %s", r.comm, r.pid, r.path, strings.Join(r.argv, " "))
}

func convertExecEvent(e execEvent) ExecEvent {
	o := ExecEvent{}
	o.comm, _, _ = strings.Cut(string(e.Comm[:]), "\x00")
	o.pid = int(e.Pid)

	o.path, _, _ = strings.Cut(string(e.Path[:]), "\x00")
	var argv []string
	for _, a := range e.Argv {
		arg, _, _ := strings.Cut(string(a[:]), "\x00")
		argv = append(argv, arg)
	}
	o.argv = argv
	return o
}

type Exec struct {
	events chan ExecEvent
	tp     link.Link
	rb     *ringbuf.Reader
}

func (r *Exec) Close() {
	if err := r.tp.Close(); err != nil {
		log.Fatalf("failed closing tracepoint: %s", err)
	}

	if err := r.rb.Close(); err != nil {
		log.Fatalf("failed closing ringbuf reader: %s", err)
	}

	close(r.events)
}

func (r *Exec) ReceiveEvents() (<-chan ExecEvent, error) {
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs execObjects
	if err := loadExecObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	r.tp = tp
	if err != nil {
		log.Fatalf("attatching tracepoint: %s", err)
	}

	r.rb, err = ringbuf.NewReader(objs.RingBuffer)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}

	r.events = make(chan ExecEvent)

	go func() {
		var event execEvent
		for {
			record, err := r.rb.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("rungbufer closed, exiting..")
					return
				}
				log.Printf("error reading from reader: %s", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("error parsing ringbuf event: %s", err)
				continue
			}
			r.events <- convertExecEvent(event)
		}
	}()
	return r.events, nil
}
