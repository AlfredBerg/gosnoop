// Package dnsanswer watches DNS answers arrive and feeds them to a dnscache.
// It emits no events of its own; the network collector uses the cache to label
// connections with the domain that was looked up.
package dnsanswer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	"gosnoop/internal/dnscache"
	"gosnoop/internal/event"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseAnswer returns the name that was asked for and the addresses it
// resolved to. ok is false for anything that is not a successful answer
// carrying addresses.
func parseAnswer(payload []byte) (name string, addrs []netip.Addr, ttl time.Duration, ok bool) {
	app := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default).ApplicationLayer()
	if app == nil {
		return "", nil, 0, false
	}
	msg, isDNS := app.(*layers.DNS)
	if !isDNS || !msg.QR || msg.ResponseCode != layers.DNSResponseCodeNoErr || len(msg.Questions) == 0 {
		return "", nil, 0, false
	}

	// The answer to a question for a name that is an alias lists the alias
	// first and the addresses under the name it points to, so the address
	// records are not matched against the question; the name asked for is what
	// the application knows the host as.
	var minTTL uint32
	for _, rr := range msg.Answers {
		var a netip.Addr
		switch rr.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			var good bool
			if a, good = netip.AddrFromSlice(rr.IP); !good {
				continue
			}
		default:
			continue
		}
		addrs = append(addrs, a.Unmap())
		if minTTL == 0 || rr.TTL < minTTL {
			minTTL = rr.TTL
		}
	}
	if len(addrs) == 0 {
		return "", nil, 0, false
	}
	return string(msg.Questions[0].Name), addrs, time.Duration(minTTL) * time.Second, true
}

type Answers struct {
	Cache *dnscache.Cache

	objs  dnsAnswerObjects
	links []link.Link
	rb    *ringbuf.Reader
}

func (r *Answers) Name() string {
	return "dns-answers"
}

// Close releases everything ReceiveEvents managed to set up. It is safe to call
// on a collector that never started, or that only started partially.
func (r *Answers) Close() error {
	var errs []error

	if r.rb != nil {
		if err := r.rb.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
			errs = append(errs, fmt.Errorf("closing ringbuf reader: %w", err))
		}
		r.rb = nil
	}
	for _, l := range r.links {
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing probe link: %w", err))
		}
	}
	r.links = nil
	if err := r.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing eBPF objects: %w", err))
	}

	return errors.Join(errs...)
}

func (r *Answers) ReceiveEvents(ctx context.Context, wg *sync.WaitGroup, _ chan<- event.Event) (err error) {
	defer func() {
		if err != nil {
			r.Close()
		}
	}()

	if err = loadDnsAnswerObjects(&r.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	// IPv4 and IPv6 are attached independently: a kernel without IPv6 has no
	// udpv6_recvmsg, and answers over IPv4 are still worth having. An entry
	// probe without its return probe would only fill the map, so they go in
	// pairs.
	type pair struct {
		symbol string
		enter  func() (link.Link, error)
		exit   func() (link.Link, error)
	}
	pairs := []pair{
		{"udp_recvmsg",
			func() (link.Link, error) { return link.Kprobe("udp_recvmsg", r.objs.UdpRecvmsgEnter, nil) },
			func() (link.Link, error) { return link.Kretprobe("udp_recvmsg", r.objs.UdpRecvmsgExit, nil) }},
		{"udpv6_recvmsg",
			func() (link.Link, error) { return link.Kprobe("udpv6_recvmsg", r.objs.Udpv6RecvmsgEnter, nil) },
			func() (link.Link, error) { return link.Kretprobe("udpv6_recvmsg", r.objs.Udpv6RecvmsgExit, nil) }},
	}
	var skipped []string
	for _, p := range pairs {
		enter, enterErr := p.enter()
		if enterErr != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %s", p.symbol, enterErr))
			continue
		}
		exit, exitErr := p.exit()
		if exitErr != nil {
			enter.Close()
			skipped = append(skipped, fmt.Sprintf("%s: %s", p.symbol, exitErr))
			continue
		}
		r.links = append(r.links, enter, exit)
	}
	if len(skipped) > 0 {
		log.Printf("dns-answers: not watching DNS answers received through %s", strings.Join(skipped, "; "))
	}
	if len(r.links) == 0 {
		return errors.New("attaching probes: neither udp_recvmsg nor udpv6_recvmsg could be probed")
	}

	r.rb, err = ringbuf.NewReader(r.objs.RingBuffer)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		var record dnsAnswerEvent

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
					log.Printf("dns-answers: error reading from ringbuf: %s", err)
					continue
				}

				if err := binary.Read(bytes.NewBuffer(raw.RawSample), binary.NativeEndian, &record); err != nil {
					log.Printf("dns-answers: error parsing ringbuf event: %s", err)
					continue
				}

				n := min(int(record.PktLen), len(record.PktData))
				if name, addrs, ttl, ok := parseAnswer(record.PktData[:n]); ok {
					r.Cache.Add(name, addrs, ttl)
				}
			}
		}
	}()
	return nil
}
