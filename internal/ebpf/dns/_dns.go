package dns

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type dnsdata struct {
	comm    string
	pid     int //TODO: This is the pid of the spawned process, would be usefull with the parent pid
	request string
	argv    []string
}

func (r dnsdata) String() string {
	return fmt.Sprintf("Dns event: %s", r.request)
}

func convertdnsEvent(e dnsEvent) dnsdata {
	o := dnsdata{}
	// o.comm, _, _ = strings.Cut(string(e.Comm[:]), "\x00")
	// o.pid = int(e.Pid)

	rawDNS, _, _ := bytes.Cut(e.Request[:], []byte("\x00"))
	o.request = base64.StdEncoding.EncodeToString(rawDNS)

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

	ifname := "enp42s0" // Change this to an interface on your machine. TODO: Get all interfaces
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach to the network interface.
	r.ifXDP, err = link.AttachXDP(link.XDPOptions{
		Program:   r.objs.DnsMonitor,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
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
