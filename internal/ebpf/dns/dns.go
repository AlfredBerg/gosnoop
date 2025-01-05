package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type dnsdata struct {
	comm string
	pid  int //TODO: This is the pid of the spawned process, would be usefull with the parent pid

	sport   uint16
	dport   uint16
	saddr   uint32
	daddr   uint32
	ifindex uint32

	dnsPkt *layers.DNS
}

func (r dnsdata) String() string {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("DNS event from comm %s, pid %d: ", r.comm, r.pid))
	if r.dnsPkt != nil {
		for _, q := range r.dnsPkt.Questions {
			sb.WriteString(fmt.Sprintf("%s %s", q.Name, q.Type))
		}
	} else {
		sb.WriteString("empty or nil dns request")
	}
	return sb.String()
}

func convertdnsEvent(e dnsEvent) dnsdata {
	o := dnsdata{}
	o.comm, _, _ = strings.Cut(string(e.Comm[:]), "\x00")
	o.pid = int(e.Pid)

	var len int = int(e.PktLen)

	dnsPacket := gopacket.NewPacket(e.PktData[:len], layers.LayerTypeDNS, gopacket.Default).ApplicationLayer()
	if dnsPacket != nil {
		o.dnsPkt = dnsPacket.(*layers.DNS)
	}

	return o
}

type Dns struct {
	events chan dnsdata
	ifXDP  link.Link
	rb     *ringbuf.Reader
	objs   dnsObjects
}

func (r *Dns) Close() {
	r.objs.Close()

	if err := r.ifXDP.Close(); err != nil {
		log.Fatalf("failed closing tracepoint: %s", err)
	}

	if err := r.rb.Close(); err != nil {
		log.Fatalf("failed closing ringbuf reader: %s", err)
	}
	close(r.events)
}

func (r *Dns) ReceiveEvents() (<-chan dnsdata, error) {
	// Load the compiled eBPF ELF and load it into the kernel.
	if err := loadDnsObjects(&r.objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}

	var err error
	r.ifXDP, err = link.Kprobe("udp_sendmsg", r.objs.UdpSendmsgProbe, nil)
	if err != nil {
		log.Fatalf("failed attatching kprobe: %s", err)
	}

	r.rb, err = ringbuf.NewReader(r.objs.RingBuffer)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}

	r.events = make(chan dnsdata)

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
			r.events <- convertdnsEvent(event)
		}
	}()
	return r.events, nil
}
