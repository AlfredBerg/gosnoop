package file

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

type FileEvent struct {
	comm string
	pid  int //TODO: This is the pid of the spawned process, would be usefull with the parent pid

	syscall string

	path string
}

func (r FileEvent) String() string {
	return fmt.Sprintf("File event from comm %s, pid %d, syscall %s: %s", r.comm, r.pid, r.syscall, r.path)
}

func convertExecEvent(e fileEvent) FileEvent {
	o := FileEvent{}
	o.comm, _, _ = strings.Cut(string(e.Comm[:]), "\x00")
	o.pid = int(e.Pid)

	o.path, _, _ = strings.Cut(string(e.Path[:]), "\x00")

	o.syscall, _, _ = strings.Cut(string(e.SysCall[:]), "\x00")

	return o
}

type File struct {
	events chan FileEvent
	tps    []link.Link
	rb     *ringbuf.Reader
}

func (r *File) Close() {
	for _, tp := range r.tps {
		if err := tp.Close(); err != nil {
			log.Fatalf("failed closing tracepoint: %s", err)
		}
	}

	if err := r.rb.Close(); err != nil {
		log.Fatalf("failed closing ringbuf reader: %s", err)
	}

	close(r.events)
}

func (r *File) ReceiveEvents() (<-chan FileEvent, error) {
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs fileObjects
	if err := loadFileObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_newstat", objs.TraceStat, nil)
	if err != nil {
		log.Fatalf("attatching tracepoint: %s", err)
	}
	r.tps = append(r.tps, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_newlstat", objs.TraceLstat, nil)
	if err != nil {
		log.Fatalf("attatching tracepoint: %s", err)
	}
	r.tps = append(r.tps, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_open", objs.TraceOpen, nil)
	if err != nil {
		log.Fatalf("attatching tracepoint: %s", err)
	}
	r.tps = append(r.tps, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		log.Fatalf("attatching tracepoint: %s", err)
	}
	r.tps = append(r.tps, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_openat2", objs.TraceOpenat2, nil)
	if err != nil {
		log.Fatalf("attatching tracepoint: %s", err)
	}
	r.tps = append(r.tps, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_creat", objs.TraceCreat, nil)
	if err != nil {
		log.Fatalf("attatching tracepoint: %s", err)
	}
	r.tps = append(r.tps, tp)

	r.rb, err = ringbuf.NewReader(objs.RingBuffer)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}

	r.events = make(chan FileEvent)

	go func() {
		var event fileEvent
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
