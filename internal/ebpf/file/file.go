package file

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"

	"gosnoop/internal/event"

	"github.com/cilium/ebpf"
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

func convertFileEvent(e fileEvent) FileEvent {
	d := fileData{}
	ev := FileEvent{}

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

	d.Syscall, _, _ = strings.Cut(string(e.SysCall[:]), "\x00")

	if (d.Syscall == "openat" || d.Syscall == "openat2") && !strings.HasPrefix(d.Path, "/") {
		var pSegments []string
		for _, p := range e.PathSegments {
			pSegment, _, _ := strings.Cut(string(p[:]), "\x00")
			if pSegment == "" {
				break
			}
			pSegments = append(pSegments, pSegment)
		}
		slices.Reverse(pSegments)

		if len(pSegments) > 1 {
			d.Path = "/" + strings.Join(pSegments[1:], "/") + d.Path
		}
	}

	ev.Type = "file"
	ev.Data = d
	return ev
}

// tracepoints maps the syscall tracepoints this collector traces to the program
// that handles them. A kernel that is missing one of these still gets the rest.
func (r *File) tracepoints() []struct {
	name string
	prog *ebpf.Program
} {
	return []struct {
		name string
		prog *ebpf.Program
	}{
		{"sys_enter_newstat", r.objs.TraceStat},
		{"sys_enter_newfstatat", r.objs.TraceFstatat},
		{"sys_enter_newlstat", r.objs.TraceLstat},
		{"sys_enter_open", r.objs.TraceOpen},
		{"sys_enter_openat", r.objs.TraceOpenat},
		{"sys_enter_openat2", r.objs.TraceOpenat2},
		{"sys_enter_creat", r.objs.TraceCreat},
	}
}

type File struct {
	objs fileObjects
	tps  []link.Link
	rb   *ringbuf.Reader
}

func (r *File) Name() string {
	return "file"
}

// Close releases everything ReceiveEvents managed to set up. It is safe to call
// on a collector that never started, or that only started partially.
func (r *File) Close() error {
	var errs []error

	if r.rb != nil {
		if err := r.rb.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
			errs = append(errs, fmt.Errorf("closing ringbuf reader: %w", err))
		}
		r.rb = nil
	}
	for _, tp := range r.tps {
		if err := tp.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing tracepoint: %w", err))
		}
	}
	r.tps = nil
	if err := r.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing eBPF objects: %w", err))
	}

	return errors.Join(errs...)
}

func (r *File) ReceiveEvents(ctx context.Context, wg *sync.WaitGroup, c chan<- event.Event) (err error) {
	defer func() {
		if err != nil {
			r.Close()
		}
	}()

	// Load the compiled eBPF ELF and load it into the kernel.
	if err = loadFileObjects(&r.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	// Not every kernel exposes every one of these syscalls — arm64, for
	// instance, has no sys_enter_open or sys_enter_newstat. Trace what is there
	// and only give up if nothing attached at all.
	var skipped []string
	for _, tp := range r.tracepoints() {
		l, attachErr := link.Tracepoint("syscalls", tp.name, tp.prog, nil)
		if attachErr != nil {
			skipped = append(skipped, tp.name)
			continue
		}
		r.tps = append(r.tps, l)
	}
	if len(skipped) > 0 {
		log.Printf("file: not tracing %s, this kernel does not expose those tracepoints", strings.Join(skipped, ", "))
	}
	if len(r.tps) == 0 {
		return errors.New("attaching tracepoints: none of the file syscall tracepoints could be attached")
	}

	r.rb, err = ringbuf.NewReader(r.objs.RingBuffer)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		var record fileEvent

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
					log.Printf("file: error reading from ringbuf: %s", err)
					continue
				}

				if err := binary.Read(bytes.NewBuffer(raw.RawSample), binary.NativeEndian, &record); err != nil {
					log.Printf("file: error parsing ringbuf event: %s", err)
					continue
				}

				select {
				case c <- convertFileEvent(record):
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return nil
}
