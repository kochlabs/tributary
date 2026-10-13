package decode

import (
	"net/netip"
	"sync"
	"time"
)

// Sampling state follows RFC 7011 §8.4: over UDP, template-derived state has a
// lifetime and is withdrawn if the exporter stops refreshing it. Exporters
// re-send sampling options on the same schedule as templates, so the lifetime
// is counted in template refreshes rather than wall-clock time, which works
// equally for quiet and busy devices.
const (
	// refreshGap merges template packets sent close together into one
	// refresh (exporters often spread a refresh over several datagrams).
	refreshGap = time.Minute
	// withdrawAfter template refreshes with no sampling announcement means
	// sampling was turned off. Three allows options and templates to arrive in
	// either order within a cycle and still requires two silent cycles.
	withdrawAfter = 3
)

// SamplingSource says where an exporter's current sampling rate came from.
type SamplingSource string

const (
	SamplingNone       SamplingSource = "none"       // nothing announced: unsampled
	SamplingAnnounced  SamplingSource = "announced"  // received from the exporter
	SamplingRemembered SamplingSource = "remembered" // persisted from a previous run, awaiting confirmation
)

type samplingKey struct {
	exporter netip.Addr
	domain   uint32
	sampler  uint32
}

type exporterSampling struct {
	rate       uint32 // last known rate, any domain/sampler
	systemWide bool   // announced without a sampler ID: applies to all records
	source     SamplingSource
	refreshes  int // template refreshes since the last announcement
	lastTmpl   time.Time
}

// samplingCache remembers sampling rates announced through options data,
// keyed by exporter, observation domain and sampler ID (0 = system-wide).
type samplingCache struct {
	mu  sync.RWMutex
	m   map[samplingKey]uint32
	exp map[netip.Addr]*exporterSampling
}

func newSamplingCache() *samplingCache {
	return &samplingCache{m: map[samplingKey]uint32{}, exp: map[netip.Addr]*exporterSampling{}}
}

func (c *samplingCache) state(e netip.Addr) *exporterSampling {
	s := c.exp[e]
	if s == nil {
		s = &exporterSampling{source: SamplingNone}
		c.exp[e] = s
	}
	return s
}

// set records an announcement and reports whether the known rate changed
// (or was only remembered until now) so it can be persisted.
func (c *samplingCache) set(k samplingKey, rate uint32) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[k] = rate
	s := c.state(k.exporter)
	sys := k.sampler == 0
	changed := s.rate != rate || s.systemWide != sys || s.source != SamplingAnnounced
	s.rate, s.systemWide, s.source, s.refreshes = rate, sys, SamplingAnnounced, 0
	return changed
}

// seed installs a persisted rate, used until the exporter confirms or the
// lifetime expires.
func (c *samplingCache) seed(e netip.Addr, rate uint32, systemWide bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state(e)
	s.rate, s.systemWide, s.source, s.refreshes = rate, systemWide, SamplingRemembered, 0
}

// templateSeen counts template refreshes and withdraws sampling state that
// hasn't been re-announced. It reports whether a rate was withdrawn.
func (c *samplingCache) templateSeen(e netip.Addr, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state(e)
	if now.Sub(s.lastTmpl) < refreshGap {
		return false
	}
	s.lastTmpl = now
	if s.source == SamplingNone {
		return false
	}
	s.refreshes++
	if s.refreshes < withdrawAfter {
		return false
	}
	for k := range c.m {
		if k.exporter == e {
			delete(c.m, k)
		}
	}
	s.rate, s.systemWide, s.source, s.refreshes = 0, false, SamplingNone, 0
	return true
}

// lookup returns the sampling rate for a record (0 = unsampled). hasSampler
// reports whether the record carried a sampler ID: exporters that tag sampled
// records (e.g. UniFi/ipt_NETFLOW) send untagged records when sampling is off.
func (c *samplingCache) lookup(exporter netip.Addr, domain, sampler uint32, hasSampler bool) uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if hasSampler {
		if r, ok := c.m[samplingKey{exporter, domain, sampler}]; ok {
			return r
		}
	}
	if r, ok := c.m[samplingKey{exporter, domain, 0}]; ok {
		return r
	}
	if s := c.exp[exporter]; s != nil && (hasSampler || s.systemWide) {
		return s.rate
	}
	return 0
}

func (c *samplingCache) info(e netip.Addr) (uint32, SamplingSource) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if s := c.exp[e]; s != nil {
		return s.rate, s.source
	}
	return 0, SamplingNone
}
