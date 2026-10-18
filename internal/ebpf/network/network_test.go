package network

import (
	"net/netip"
	"testing"
)

func sample(family, protocol, direction uint8, saddr, daddr []byte, sport, dport uint16) networkEvent {
	e := networkEvent{
		Family:    family,
		Protocol:  protocol,
		Direction: direction,
		Sport:     sport,
		Dport:     dport,
		Uid:       1000,
		Netns:     4026531840,
	}
	copy(e.Saddr[:], saddr)
	copy(e.Daddr[:], daddr)
	copy(e.ProcessInfo.Comm[:], "curl")
	e.ProcessInfo.Pid = 4242
	e.ProcessInfo.Spid[0] = 100
	copy(e.ProcessInfo.Scomm[0][:], "bash")
	return e
}

func TestConvertTCPv4Outbound(t *testing.T) {
	ev, ok := convertNetworkEvent(sample(afInet, ipprotoTCP, dirOutbound,
		[]byte{192, 168, 1, 5}, []byte{93, 184, 216, 34}, 51234, 443))
	if !ok {
		t.Fatal("event was rejected")
	}
	d := ev.Data
	if ev.Type != "network" || ev.ProcessInfo.Comm != "curl" || ev.ProcessInfo.PID != 4242 {
		t.Errorf("bad process context: %+v", ev.BaseEvent)
	}
	if len(ev.ProcessInfo.Parents) != 1 || ev.ProcessInfo.Parents[0].Comm != "bash" {
		t.Errorf("bad parents: %+v", ev.ProcessInfo.Parents)
	}
	if d.Protocol != "tcp" || d.Direction != "outbound" || d.Family != "ipv4" {
		t.Errorf("bad classification: %+v", d)
	}
	if d.Remote.IP != "93.184.216.34" || d.Remote.Port != 443 || d.Remote.Scope != "public" {
		t.Errorf("bad remote: %+v", d.Remote)
	}
	if d.Local.IP != "192.168.1.5" || d.Local.Port != 51234 {
		t.Errorf("bad local: %+v", d.Local)
	}
	if d.Connected != nil {
		t.Errorf("connected is a UDP-only field, got %v", *d.Connected)
	}
	if d.UID != 1000 || d.Netns != 4026531840 {
		t.Errorf("bad identity: uid %d netns %d", d.UID, d.Netns)
	}
}

func TestConvertTCPv6Inbound(t *testing.T) {
	local := make([]byte, 16)
	local[15] = 1
	remote := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}
	ev, ok := convertNetworkEvent(sample(afInet6, ipprotoTCP, dirInbound, local, remote, 8080, 40000))
	if !ok {
		t.Fatal("event was rejected")
	}
	d := ev.Data
	if d.Family != "ipv6" || d.Direction != "inbound" || d.Remote.IP != "2001:db8::7" || d.Local.IP != "::1" || d.Local.Scope != "" {
		t.Errorf("bad event: %+v", d)
	}
}

func TestConvertUDP(t *testing.T) {
	e := sample(afInet, ipprotoUDP, dirOutbound, nil, []byte{10, 0, 0, 53}, 33333, 53)
	e.Connected = 1
	ev, ok := convertNetworkEvent(e)
	if !ok {
		t.Fatal("event was rejected")
	}
	d := ev.Data
	if d.Protocol != "udp" || d.Connected == nil || !*d.Connected {
		t.Errorf("bad udp event: %+v", d)
	}
	if d.Remote.Scope != "private" {
		t.Errorf("want private scope, got %q", d.Remote.Scope)
	}
	if d.Local.IP != "" {
		t.Errorf("an unbound source address should be omitted, got %q", d.Local.IP)
	}

	e.Connected = 0
	ev, _ = convertNetworkEvent(e)
	if ev.Data.Connected == nil || *ev.Data.Connected {
		t.Error("an unconnected send must report connected=false, not omit it")
	}
}

func TestConvertMappedAddressIsIPv4(t *testing.T) {
	mapped := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1}
	ev, ok := convertNetworkEvent(sample(afInet6, ipprotoTCP, dirOutbound, mapped, mapped, 1, 2))
	if !ok {
		t.Fatal("event was rejected")
	}
	if ev.Data.Family != "ipv4" || ev.Data.Remote.IP != "127.0.0.1" || ev.Data.Remote.Scope != "loopback" {
		t.Errorf("mapped address not normalised: %+v", ev.Data)
	}
}

func TestConvertRejectsGarbage(t *testing.T) {
	for name, e := range map[string]networkEvent{
		"family":    sample(99, ipprotoTCP, dirOutbound, nil, nil, 1, 2),
		"protocol":  sample(afInet, 99, dirOutbound, nil, []byte{1, 2, 3, 4}, 1, 2),
		"direction": sample(afInet, ipprotoTCP, 99, nil, []byte{1, 2, 3, 4}, 1, 2),
	} {
		if _, ok := convertNetworkEvent(e); ok {
			t.Errorf("%s: garbage event was accepted", name)
		}
	}
}

func TestScope(t *testing.T) {
	for ip, want := range map[string]string{
		"127.0.0.1":   "loopback",
		"::1":         "loopback",
		"10.1.2.3":    "private",
		"172.16.0.1":  "private",
		"192.168.0.1": "private",
		"fd00::1":     "private",
		"169.254.1.1": "link-local",
		"fe80::1":     "link-local",
		"224.0.0.251": "multicast",
		"ff02::fb":    "multicast",
		"0.0.0.0":     "unspecified",
		"8.8.8.8":     "public",
		"2606:4700::": "public",
	} {
		a := mustAddr(t, ip)
		if got := scope(a); got != want {
			t.Errorf("scope(%s) = %s, want %s", ip, got, want)
		}
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
