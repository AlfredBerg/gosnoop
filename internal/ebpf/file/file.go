package file

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"gosnoop/internal/event"
	"log"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type fileData struct {
	Syscall string `json:"syscall"`

	Path string `json:"path"`
}

type FileEvent struct {
	event.BaseEvent

	Data fileData `json:"data"`
}

func (r FileEvent) String() string {
	return fmt.Sprintf("File event from comm %s, pid %d, syscall %s: %s", r.BaseEvent.ProcessInfo.Comm, r.BaseEvent.ProcessInfo.PID, r.Data.Syscall, r.Data.Path)
}

func convertExecEvent(e fileEvent) FileEvent {
	d := fileData{}
	ev := FileEvent{}

	ev.BaseEvent.ProcessInfo.Comm, _, _ = strings.Cut(string(e.Comm[:]), "\x00")
	ev.BaseEvent.ProcessInfo.PID = int(e.Pid)

	d.Path, _, _ = strings.Cut(string(e.Path[:]), "\x00")

	d.Syscall, _, _ = strings.Cut(string(e.SysCall[:]), "\x00")

	ev.Type = "file"
	ev.Data = d
	return ev
}

type File struct {
	tps []link.Link
	rb  *ringbuf.Reader
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
}

func (r *File) ReceiveEvents(c chan<- interface{}) error {
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs fileObjects
	if err := loadFileObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_newstat", objs.TraceStat, nil)
	if err != nil {
		return fmt.Errorf("failed attatching tracepoint: %w", err)
	}
	r.tps = append(r.tps, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_newlstat", objs.TraceLstat, nil)
	if err != nil {
		return fmt.Errorf("failed attatching tracepoint: %w", err)
	}
	r.tps = append(r.tps, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_open", objs.TraceOpen, nil)
	if err != nil {
		return fmt.Errorf("failed attatching tracepoint: %w", err)
	}
	r.tps = append(r.tps, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		return fmt.Errorf("failed attatching tracepoint: %w", err)
	}
	r.tps = append(r.tps, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_openat2", objs.TraceOpenat2, nil)
	if err != nil {
		return fmt.Errorf("failed attatching tracepoint: %w", err)
	}
	r.tps = append(r.tps, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_creat", objs.TraceCreat, nil)
	if err != nil {
		return fmt.Errorf("failed attatching tracepoint: %w", err)
	}
	r.tps = append(r.tps, tp)

	r.rb, err = ringbuf.NewReader(objs.RingBuffer)
	if err != nil {
		return fmt.Errorf("failed opening ringbuf reader: %s", err)
	}

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

			c <- convertExecEvent(event)
		}
	}()
	return nil
}
