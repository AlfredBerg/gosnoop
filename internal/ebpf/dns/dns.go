package dns

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
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type question struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type dnsdata struct {
	sport   uint16
	dport   uint16
	saddr   uint32
	daddr   uint32
	ifindex uint32

	dnsPkt *layers.DNS
	Q      []question `json:"q"`
}

type DnsEvent struct {
	event.BaseEvent
	Data dnsdata `json:"data"`
}

func convertdnsEvent(e dnsEvent) DnsEvent {
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

	d := dnsdata{}
	var len int = int(e.PktLen)

	gopkt := gopacket.NewPacket(e.PktData[:len], layers.LayerTypeDNS, gopacket.Default).ApplicationLayer()
	if gopkt != nil {
		dnsPkt, ok := gopkt.(*layers.DNS)
		if !ok {
			return ev
		}
		var qs []question

		for _, q := range dnsPkt.Questions {
			qs = append(qs, question{string(q.Name), q.Type.String()})
		}
		d.Q = qs

	}
	ev.Data = d

	return ev
}

type Dns struct {
	udpKprobe link.Link
	// tcpKprobe link.Link
	rb   *ringbuf.Reader
	objs dnsObjects
}

func (r *Dns) Close() {
	r.objs.Close()

	if err := r.udpKprobe.Close(); err != nil {
		log.Fatalf("failed closing tracepoint: %s", err)
	}

	// if err := r.tcpKprobe.Close(); err != nil {
	// 	log.Fatalf("failed closing tracepoint: %s", err)
	// }

	if err := r.rb.Close(); err != nil {
		log.Fatalf("failed closing ringbuf reader: %s", err)
	}
}

func (r *Dns) ReceiveEvents(c chan<- interface{}) error {
	// Load the compiled eBPF ELF and load it into the kernel.
	if err := loadDnsObjects(&r.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	var err error
	r.udpKprobe, err = link.Kprobe("udp_sendmsg", r.objs.UdpSendmsgProbe, nil)
	if err != nil {
		return fmt.Errorf("failed attatching kprobe: %w", err)
	}

	// r.tcpKprobe, err = link.Kprobe("tcp_sendmsg", r.objs.TcpSendmsgProbe, nil)
	// if err != nil {
	// 	return fmt.Errorf("failed attatching kprobe: %w", err)
	// }

	r.rb, err = ringbuf.NewReader(r.objs.RingBuffer)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}

	go func() {
		var event dnsEvent
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
			c <- convertdnsEvent(event)
		}
	}()
	return nil
}
