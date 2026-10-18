package network

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

	"gosnoop/internal/event"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	afInet  = 2
	afInet6 = 10

	ipprotoTCP = 6
	ipprotoUDP = 17

	dirOutbound = 1
	dirInbound  = 2
)

type endpoint struct {
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port"`
	// Scope classifies the address: loopback, private, link-local, multicast,
	// unspecified or public.
	Scope string `json:"scope,omitempty"`
}

type networkData struct {
	Protocol  string   `json:"protocol"`
	Direction string   `json:"direction"`
	Family    string   `json:"family"`
	Remote    endpoint `json:"remote"`
	Local     endpoint `json:"local"`
	// Connected is only set for UDP: true when the datagram went to the peer
	// the socket was connect()ed to, false when it named its own destination.
	Connected *bool `json:"connected,omitempty"`
	UID       int   `json:"uid"`
	// Netns is the inode of the socket's network namespace, as in
	// /proc/<pid>/ns/net.
	Netns uint32 `json:"netns"`
}

type NetworkEvent struct {
	event.BaseEvent

	Data networkData `json:"data"`
}

func (r NetworkEvent) String() string {
	return fmt.Sprintf("Network event from comm %s, pid %d: %s %s %s:%d",
		r.ProcessInfo.Comm, r.ProcessInfo.PID, r.Data.Protocol, r.Data.Direction, r.Data.Remote.IP, r.Data.Remote.Port)
}

func scope(a netip.Addr) string {
	switch {
	case a.IsLoopback():
		return "loopback"
	case a.IsUnspecified():
		return "unspecified"
	case a.IsPrivate():
		return "private"
	case a.IsMulticast():
		return "multicast"
	case a.IsLinkLocalUnicast():
		return "link-local"
	}
	return "public"
}

// addrFrom reads the address the probe stored in a 16 byte field: the first
// four bytes for IPv4, all sixteen for IPv6. An IPv4-mapped IPv6 address is
// returned as the IPv4 address it stands for.
func addrFrom(family uint8, raw [16]uint8) (netip.Addr, bool) {
	switch family {
	case afInet:
		return netip.AddrFrom4([4]byte(raw[:4])), true
	case afInet6:
		return netip.AddrFrom16(raw).Unmap(), true
	}
	return netip.Addr{}, false
}

func convertNetworkEvent(e networkEvent) (NetworkEvent, bool) {
	ev := NetworkEvent{}

	remote, ok := addrFrom(e.Family, e.Daddr)
	if !ok {
		return ev, false
	}
	local, _ := addrFrom(e.Family, e.Saddr)

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

	ev.Type = "network"

	d := networkData{
		UID:   int(e.Uid),
		Netns: e.Netns,
		Remote: endpoint{
			IP:    remote.String(),
			Port:  int(e.Dport),
			Scope: scope(remote),
		},
		Local: endpoint{Port: int(e.Sport)},
	}
	// A wildcard source address means the kernel had not picked one yet, which
	// is not worth reporting as "0.0.0.0".
	if local.IsValid() && !local.IsUnspecified() {
		d.Local.IP = local.String()
	}

	// Report the family on the wire: an AF_INET6 socket talking to an
	// IPv4-mapped address is an IPv4 connection.
	if remote.Is4() {
		d.Family = "ipv4"
	} else {
		d.Family = "ipv6"
	}

	switch e.Protocol {
	case ipprotoTCP:
		d.Protocol = "tcp"
	case ipprotoUDP:
		d.Protocol = "udp"
		connected := e.Connected != 0
		d.Connected = &connected
	default:
		return ev, false
	}

	switch e.Direction {
	case dirOutbound:
		d.Direction = "outbound"
	case dirInbound:
		d.Direction = "inbound"
	default:
		return ev, false
	}

	ev.Data = d
	return ev, true
}

type Network struct {
	objs  networkObjects
	links []link.Link
	rb    *ringbuf.Reader
}

func (r *Network) Name() string {
	return "network"
}

// Close releases everything ReceiveEvents managed to set up. It is safe to call
// on a collector that never started, or that only started partially.
func (r *Network) Close() error {
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

// attachment is one kernel hook feeding the collector.
type attachment struct {
	// what says what the hook gives you, for the warning when it is missing.
	what   string
	attach func() (link.Link, error)
}

func (r *Network) attachments() []attachment {
	kprobe := func(symbol string, prog *ebpf.Program) func() (link.Link, error) {
		return func() (link.Link, error) { return link.Kprobe(symbol, prog, nil) }
	}
	return []attachment{
		{"outgoing TCP connections (kprobe tcp_connect, else tracepoint sock:inet_sock_set_state)", func() (link.Link, error) {
			l, err := link.Kprobe("tcp_connect", r.objs.TcpConnectProbe, nil)
			if err == nil {
				return l, nil
			}
			// The tracepoint fires before the source port is chosen, so events
			// from it carry local port 0; better that than no outgoing TCP at all.
			log.Printf("network: cannot probe tcp_connect (%s), falling back to a tracepoint that cannot report the local port of outgoing TCP connections", err)
			return link.Tracepoint("sock", "inet_sock_set_state", r.objs.TraceInetSockSetState, nil)
		}},
		{"accepted TCP connections (kretprobe inet_csk_accept)", func() (link.Link, error) {
			return link.Kretprobe("inet_csk_accept", r.objs.InetCskAcceptRet, nil)
		}},
		{"IPv4 UDP (kprobe udp_sendmsg)", kprobe("udp_sendmsg", r.objs.UdpSendmsgProbe)},
		{"IPv6 UDP (kprobe udpv6_sendmsg)", kprobe("udpv6_sendmsg", r.objs.Udpv6SendmsgProbe)},
	}
}

func (r *Network) ReceiveEvents(ctx context.Context, wg *sync.WaitGroup, c chan<- event.Event) (err error) {
	defer func() {
		if err != nil {
			r.Close()
		}
	}()

	// Load the compiled eBPF ELF and load it into the kernel.
	if err = loadNetworkObjects(&r.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	// A kernel without IPv6, say, has no udpv6_sendmsg. Trace what is there and
	// only give up if nothing attached at all.
	var skipped []string
	for _, a := range r.attachments() {
		l, attachErr := a.attach()
		if attachErr != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %s", a.what, attachErr))
			continue
		}
		r.links = append(r.links, l)
	}
	if len(skipped) > 0 {
		log.Printf("network: not tracing %s", strings.Join(skipped, "; "))
	}
	if len(r.links) == 0 {
		return errors.New("attaching probes: none of the network hooks could be attached")
	}

	r.rb, err = ringbuf.NewReader(r.objs.RingBuffer)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		var record networkEvent

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
					log.Printf("network: error reading from ringbuf: %s", err)
					continue
				}

				if err := binary.Read(bytes.NewBuffer(raw.RawSample), binary.NativeEndian, &record); err != nil {
					log.Printf("network: error parsing ringbuf event: %s", err)
					continue
				}

				ev, ok := convertNetworkEvent(record)
				if !ok {
					log.Printf("network: dropping an event with an unrecognised family, protocol or direction")
					continue
				}

				select {
				case c <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return nil
}
