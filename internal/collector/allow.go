package collector

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Exporter allowlist: when set, datagrams from other source addresses are
// dropped before decoding, so a stray or hostile sender can't add exporters,
// fill the disk or skew reports.

// maxRejectedSources bounds the table of rejected senders kept for display.
const maxRejectedSources = 64

type rejectedSource struct {
	datagrams uint64
	last      time.Time
}

type rejections struct {
	mu      sync.Mutex
	sources map[netip.Addr]*rejectedSource
}

// RejectedSource is a sender whose datagrams were dropped by the allowlist.
type RejectedSource struct {
	Addr      string `json:"addr"`
	Datagrams uint64 `json:"datagrams"`
	LastSeen  int64  `json:"lastSeen"` // unix ms
}

// SetAllowedSources restricts which source addresses may send flows. An
// empty list accepts every source.
func (c *Collector) SetAllowedSources(ps []netip.Prefix) {
	if len(ps) == 0 {
		c.allow.Store(nil)
		return
	}
	cp := append([]netip.Prefix(nil), ps...)
	c.allow.Store(&cp)
}

func (c *Collector) allowed(src netip.Addr) bool {
	ps := c.allow.Load()
	if ps == nil {
		return true
	}
	for _, p := range *ps {
		if p.Contains(src) {
			return true
		}
	}
	return false
}

func (c *Collector) reject(src netip.Addr, now time.Time) {
	c.Rejected.Add(1)
	r := &c.rejected
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sources == nil {
		r.sources = map[netip.Addr]*rejectedSource{}
	}
	s := r.sources[src]
	if s == nil {
		if len(r.sources) >= maxRejectedSources {
			// Forget the sender heard from least recently.
			var oldest netip.Addr
			var t time.Time
			for a, v := range r.sources {
				if t.IsZero() || v.last.Before(t) {
					oldest, t = a, v.last
				}
			}
			delete(r.sources, oldest)
		}
		s = &rejectedSource{}
		r.sources[src] = s
		c.log.Warn("dropping flows from a source not in the exporter allowlist", "addr", src)
	}
	s.datagrams++
	s.last = now
}

// RejectedSources lists recently rejected senders, most recent first.
func (c *Collector) RejectedSources() []RejectedSource {
	r := &c.rejected
	r.mu.Lock()
	out := make([]RejectedSource, 0, len(r.sources))
	for a, s := range r.sources {
		out = append(out, RejectedSource{Addr: a.String(), Datagrams: s.datagrams, LastSeen: s.last.UnixMilli()})
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen > out[j].LastSeen })
	return out
}

// ForgetRejected clears the rejected-sender table (e.g. after allowing one).
func (c *Collector) ForgetRejected(addr string) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return
	}
	c.rejected.mu.Lock()
	delete(c.rejected.sources, a)
	c.rejected.mu.Unlock()
}
