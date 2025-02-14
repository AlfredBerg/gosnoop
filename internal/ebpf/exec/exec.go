package exec

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"gosnoop/internal/event"
	"log"
	"strings"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type execData struct {
	Path string   `json:"path"`
	Argv []string `json:"argv"`
	Envp []string `json:"envp,omitempty"`
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

	ev.ProcessInfo.Comm, _, _ = strings.Cut(string(e.ProcessInfo.Comm[:]), "\x00")
	ev.ProcessInfo.Cgroup, _, _ = strings.Cut(string(e.ProcessInfo.Cgroup[:]), "\x00")
	ev.ProcessInfo.PID = int(e.ProcessInfo.Pid)
	for i := 0; i < len(e.ProcessInfo.Spid); i++ {
		pid := int(e.ProcessInfo.Spid[i])
		if pid == 0 {
			break
		}
		comm, _, _ := strings.Cut(string(e.ProcessInfo.Scomm[i][:]), "\x00")
		ev.ProcessInfo.Parents = append(ev.ProcessInfo.Parents, event.Process{Comm: comm, PID: pid})
	}

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
		log.Fatalf("failed closing tracepoint: %s", err)
	}

	if err := r.rb.Close(); err != nil {
		log.Fatalf("failed closing ringbuf reader: %s", err)
	}
}

func (r *Exec) ReceiveEvents(ctx context.Context, wg *sync.WaitGroup, c chan<- interface{}) error {
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

	wg.Add(1)
	go func() {
		defer wg.Done()
		var event execEvent

		go func() {
			<-ctx.Done()
			r.rb.Close()
		}()

		for {
			select {
			case <-ctx.Done():
				return

			default:
				record, err := r.rb.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						log.Println("rungbuffer closed, exiting..")
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
		}
	}()
	return nil
}
