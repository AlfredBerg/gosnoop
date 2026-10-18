package exec

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"gosnoop/internal/event"

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

	objs execObjects
	tp   link.Link
	rb   *ringbuf.Reader
}

func (r *Exec) Name() string {
	return "exec"
}

// Close releases everything ReceiveEvents managed to set up. It is safe to call
// on a collector that never started, or that only started partially.
func (r *Exec) Close() error {
	var errs []error

	if r.rb != nil {
		if err := r.rb.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
			errs = append(errs, fmt.Errorf("closing ringbuf reader: %w", err))
		}
		r.rb = nil
	}
	if r.tp != nil {
		if err := r.tp.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing tracepoint: %w", err))
		}
		r.tp = nil
	}
	if err := r.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing eBPF objects: %w", err))
	}

	return errors.Join(errs...)
}

func (r *Exec) ReceiveEvents(ctx context.Context, wg *sync.WaitGroup, c chan<- event.Event) (err error) {
	// Anything already set up has to go back if we bail out half way, otherwise
	// a collector that main decided to skip would keep its probes attached.
	defer func() {
		if err != nil {
			r.Close()
		}
	}()

	// Load the compiled eBPF ELF and load it into the kernel.
	if err = loadExecObjects(&r.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	r.tp, err = link.Tracepoint("syscalls", "sys_enter_execve", r.objs.TraceExecve, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint syscalls/sys_enter_execve: %w", err)
	}

	r.rb, err = ringbuf.NewReader(r.objs.RingBuffer)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		var record execEvent

		go func() {
			<-ctx.Done()
			r.rb.Close()
		}()

		for {
			select {
			case <-ctx.Done():
				return

			default:
				raw, err := r.rb.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					log.Printf("exec: error reading from ringbuf: %s", err)
					continue
				}

				if err := binary.Read(bytes.NewBuffer(raw.RawSample), binary.NativeEndian, &record); err != nil {
					log.Printf("exec: error parsing ringbuf event: %s", err)
					continue
				}
				execEvent := convertExecEvent(record)
				if !r.IncludeEnvp {
					execEvent.Data.Envp = nil
				}

				select {
				case c <- execEvent:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return nil
}
