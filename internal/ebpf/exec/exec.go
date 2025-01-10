package exec

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

type execData struct {
	Path string   `json:"path"`
	Argv []string `json:"argv"`
	Envp []string `json:"envp"`
}

type ExecEvent struct {
	event.BaseEvent

	Data execData `json:"data"`
}

func (r ExecEvent) String() string {
	return fmt.Sprintf("Exec event from comm %s, pid %d: %s %s", r.ProcessInfo.Comm, r.ProcessInfo.PID, r.Data.Path, strings.Join(r.Data.Argv, " "))
}

func convertExecEvent(e execEvent) ExecEvent {
	d := execData{}
	ev := ExecEvent{}

	ev.BaseEvent.ProcessInfo.Comm, _, _ = strings.Cut(string(e.Comm[:]), "\x00")
	ev.BaseEvent.ProcessInfo.PID = int(e.Pid)

	d.Path, _, _ = strings.Cut(string(e.Path[:]), "\x00")
	var argv []string
	for _, a := range e.Argv {
		arg, _, _ := strings.Cut(string(a[:]), "\x00")
		if arg == "" {
			continue
		}
		argv = append(argv, arg)
	}
	d.Argv = argv

	var envp []string
	for _, a := range e.Envp {
		arg, _, _ := strings.Cut(string(a[:]), "\x00")
		if arg == "" {
			continue
		}
		envp = append(envp, arg)
	}
	d.Envp = envp

	ev.Type = "exec"
	ev.Data = d

	return ev
}

type Exec struct {
	IncludeEnvp bool
	tp          link.Link
	rb          *ringbuf.Reader
}

func (r *Exec) Close() {
	if err := r.tp.Close(); err != nil {
		log.Fatalf("failed closing tracepoint: %w", err)
	}

	if err := r.rb.Close(); err != nil {
		log.Fatalf("failed closing ringbuf reader: %w", err)
	}
}

func (r *Exec) ReceiveEvents(c chan<- interface{}) error {
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs execObjects
	if err := loadExecObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	r.tp = tp
	if err != nil {
		return fmt.Errorf("attatching tracepoint: %w", err)
	}

	r.rb, err = ringbuf.NewReader(objs.RingBuffer)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}

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
			execEvent := convertExecEvent(event)
			if !r.IncludeEnvp {
				execEvent.Data.Envp = []string{}
			}
			c <- execEvent
		}
	}()
	return nil
}
