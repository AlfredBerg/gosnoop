package dnsanswer

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func serialize(t *testing.T, d *layers.DNS) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := d.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseAnswerFollowsCNAMEChain(t *testing.T) {
	payload := serialize(t, &layers.DNS{
		QR:        true,
		Questions: []layers.DNSQuestion{{Name: []byte("www.example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
		Answers: []layers.DNSResourceRecord{
			{Name: []byte("www.example.com"), Type: layers.DNSTypeCNAME, Class: layers.DNSClassIN, TTL: 300, CNAME: []byte("edge.cdn.net")},
			{Name: []byte("edge.cdn.net"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: net.ParseIP("192.0.2.7")},
			{Name: []byte("edge.cdn.net"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN, TTL: 90, IP: net.ParseIP("2001:db8::7")},
		},
	})

	name, addrs, ttl, ok := parseAnswer(payload)
	if !ok {
		t.Fatal("answer not recognised")
	}
	if name != "www.example.com" {
		t.Errorf("name = %q, want the name that was asked for", name)
	}
	want := []netip.Addr{netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("2001:db8::7")}
	if len(addrs) != len(want) || addrs[0] != want[0] || addrs[1] != want[1] {
		t.Errorf("addrs = %v, want %v", addrs, want)
	}
	if ttl != 60*time.Second {
		t.Errorf("ttl = %s, want the smallest, 1m0s", ttl)
	}
}

func TestParseAnswerIgnoresWhatIsNotAnAnswer(t *testing.T) {
	q := []layers.DNSQuestion{{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}
	a := []layers.DNSResourceRecord{{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: net.ParseIP("192.0.2.1")}}

	for name, payload := range map[string][]byte{
		"query":        serialize(t, &layers.DNS{Questions: q, Answers: a}),
		"nxdomain":     serialize(t, &layers.DNS{QR: true, ResponseCode: layers.DNSResponseCodeNXDomain, Questions: q}),
		"no addresses": serialize(t, &layers.DNS{QR: true, Questions: q}),
		"no question":  serialize(t, &layers.DNS{QR: true, Answers: a}),
		"garbage":      {1, 2, 3},
	} {
		if _, _, _, ok := parseAnswer(payload); ok {
			t.Errorf("%s was taken for an answer with addresses", name)
		}
	}
}
