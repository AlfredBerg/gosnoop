package dnscache

import (
	"net/netip"
	"testing"
	"time"
)

func TestLookupAndNormalisation(t *testing.T) {
	c := New()
	c.Add("WWW.Example.COM.", []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("2606:2800::1")}, time.Minute)

	for _, ip := range []string{"93.184.216.34", "2606:2800::1", "::ffff:93.184.216.34"} {
		if got, ok := c.Lookup(netip.MustParseAddr(ip)); !ok || got != "www.example.com" {
			t.Errorf("Lookup(%s) = %q, %v; want www.example.com", ip, got, ok)
		}
	}
	if _, ok := c.Lookup(netip.MustParseAddr("1.1.1.1")); ok {
		t.Error("an address that was never resolved has a name")
	}
}

func TestLatestAnswerWins(t *testing.T) {
	c := New()
	ip := netip.MustParseAddr("10.0.0.1")
	c.Add("a.example", []netip.Addr{ip}, time.Minute)
	c.Add("b.example", []netip.Addr{ip}, time.Minute)
	if got, _ := c.Lookup(ip); got != "b.example" {
		t.Errorf("got %q, want b.example", got)
	}
}

func TestRetention(t *testing.T) {
	now := time.Now()
	c := New()
	c.now = func() time.Time { return now }

	short, long := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	c.Add("short.example", []netip.Addr{short}, time.Second)
	c.Add("long.example", []netip.Addr{long}, 24*time.Hour)

	now = now.Add(minRetention - time.Second)
	if _, ok := c.Lookup(short); !ok {
		t.Error("a short TTL should still be kept for the minimum retention")
	}
	now = now.Add(2 * time.Second)
	if _, ok := c.Lookup(short); ok {
		t.Error("an entry outlived the minimum retention")
	}
	if _, ok := c.Lookup(long); !ok {
		t.Error("a long TTL entry expired too early")
	}
	now = now.Add(maxRetention)
	if _, ok := c.Lookup(long); ok {
		t.Error("an entry outlived the maximum retention")
	}
}

func TestBounded(t *testing.T) {
	c := New()
	for i := 0; i < maxEntries+100; i++ {
		c.Add("x.example", []netip.Addr{netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})}, time.Minute)
	}
	if len(c.m) > maxEntries {
		t.Errorf("cache grew to %d entries, limit is %d", len(c.m), maxEntries)
	}
}
