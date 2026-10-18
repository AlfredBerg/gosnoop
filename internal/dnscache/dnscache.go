// Package dnscache remembers which domain an IP address was last looked up as,
// so that connections to that address can be labelled with it.
package dnscache

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	// Applications keep using an address long after its TTL ran out (connection
	// pools, resolver caches, Java's, for one), so honouring a 30 second TTL to
	// the letter would leave most reconnects unlabelled.
	minRetention = 5 * time.Minute
	// Addresses get reassigned to other names. An hour is as far as an old
	// answer is trusted.
	maxRetention = time.Hour

	maxEntries = 1 << 16
)

type entry struct {
	name    string
	expires time.Time
}

// Cache maps IP addresses to the name most recently resolved to them. It is
// safe for concurrent use.
type Cache struct {
	mu  sync.Mutex
	m   map[netip.Addr]entry
	now func() time.Time
}

func New() *Cache {
	return &Cache{m: make(map[netip.Addr]entry), now: time.Now}
}

// Add records that name resolved to addrs, for roughly ttl. The latest answer
// wins: a shared address (a CDN edge) is labelled with the name that was asked
// for most recently.
func (c *Cache) Add(name string, addrs []netip.Addr, ttl time.Duration) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" || len(addrs) == 0 {
		return
	}
	ttl = max(minRetention, min(ttl, maxRetention))

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	for _, a := range addrs {
		a = a.Unmap()
		if _, known := c.m[a]; !known && len(c.m) >= maxEntries {
			c.evict(now)
		}
		c.m[a] = entry{name: name, expires: now.Add(ttl)}
	}
}

// evict makes room: expired entries go first, and if everything is still
// valid an arbitrary tenth of the cache is dropped.
func (c *Cache) evict(now time.Time) {
	for a, e := range c.m {
		if now.After(e.expires) {
			delete(c.m, a)
		}
	}
	drop := len(c.m) - maxEntries + maxEntries/10
	for a := range c.m {
		if drop <= 0 {
			break
		}
		delete(c.m, a)
		drop--
	}
}

// Lookup returns the name addr was last resolved from.
func (c *Cache) Lookup(addr netip.Addr) (string, bool) {
	addr = addr.Unmap()

	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.m[addr]
	if !ok {
		return "", false
	}
	if c.now().After(e.expires) {
		delete(c.m, addr)
		return "", false
	}
	return e.name, true
}
