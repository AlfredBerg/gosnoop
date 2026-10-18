package dns

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
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type question struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type dnsData struct {
	Q []question `json:"q"`
}

type DnsEvent struct {
	event.BaseEvent
	Data dnsData `json:"data"`
}

func (r DnsEvent) String() string {
	names := make([]string, 0, len(r.Data.Q))
	for _, q := range r.Data.Q {
		names = append(names, fmt.Sprintf("%s %s", q.Type, q.Name))
	}
	return fmt.Sprintf("DNS event from comm %s, pid %d: %s", r.ProcessInfo.Comm, r.ProcessInfo.PID, strings.Join(names, ", "))
}

func convertDnsEvent(e dnsEvent) DnsEvent {
	ev := DnsEvent{}

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

	ev.Type = "dns"

	// pkt_len is set by the probe and is bounded by the size of pkt_data, but
	// clamp anyway rather than trust a kernel buffer with a slice expression.
	n := int(e.PktLen)
	if n > len(e.PktData) {
		n = len(e.PktData)
	}
	if n == 0 {
		return ev
	}

	pkt := gopacket.NewPacket(e.PktData[:n], layers.LayerTypeDNS, gopacket.Default).ApplicationLayer()
	if pkt == nil {
		return ev
	}
	dnsPkt, ok := pkt.(*layers.DNS)
	if !ok {
		return ev
	}

	var qs []question
	for _, q := range dnsPkt.Questions {
		qs = append(qs, question{string(q.Name), q.Type.String()})
	}
	ev.Data.Q = qs

	return ev
}

type Dns struct {
	objs      dnsObjects
	udpKprobe link.Link
	rb        *ringbuf.Reader
}

func (r *Dns) Name() string {
	return "dns"
}

// Close releases everything ReceiveEvents managed to set up. It is safe to call
// on a collector that never started, or that only started partially.
func (r *Dns) Close() error {
	var errs []error

	if r.rb != nil {
		if err := r.rb.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
			errs = append(errs, fmt.Errorf("closing ringbuf reader: %w", err))
		}
		r.rb = nil
	}
	if r.udpKprobe != nil {
		if err := r.udpKprobe.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing kprobe: %w", err))
		}
		r.udpKprobe = nil
	}
	if err := r.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing eBPF objects: %w", err))
	}

	return errors.Join(errs...)
}

func (r *Dns) ReceiveEvents(ctx context.Context, wg *sync.WaitGroup, c chan<- event.Event) (err error) {
	defer func() {
		if err != nil {
			r.Close()
		}
	}()

	// Load the compiled eBPF ELF and load it into the kernel.
	if err = loadDnsObjects(&r.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	r.udpKprobe, err = link.Kprobe("udp_sendmsg", r.objs.UdpSendmsgProbe, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe to udp_sendmsg: %w", err)
	}

	r.rb, err = ringbuf.NewReader(r.objs.RingBuffer)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		var record dnsEvent

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
					log.Printf("dns: error reading from ringbuf: %s", err)
					continue
				}

				if err := binary.Read(bytes.NewBuffer(raw.RawSample), binary.NativeEndian, &record); err != nil {
					log.Printf("dns: error parsing ringbuf event: %s", err)
					continue
				}

				select {
				case c <- convertDnsEvent(record):
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return nil
}
