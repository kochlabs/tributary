package enrich

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Resolver performs reverse DNS lookups with caching, bounded concurrency
// and a per-request wait budget. Lookups that miss the budget keep running in
// the background and fill the cache for the next request.
type Resolver struct {
	Enabled atomic.Bool

	r   *net.Resolver
	sem chan struct{}

	mu       sync.Mutex
	cache    map[netip.Addr]rdnsEntry
	inflight map[netip.Addr]chan struct{}
}

type rdnsEntry struct {
	name string
	exp  time.Time
}

const (
	rdnsPositiveTTL = 6 * time.Hour
	rdnsNegativeTTL = 30 * time.Minute
	rdnsTimeout     = 3 * time.Second
	rdnsCacheMax    = 200_000
)

func NewResolver() *Resolver {
	r := &Resolver{r: net.DefaultResolver, sem: make(chan struct{}, 32), cache: map[netip.Addr]rdnsEntry{}, inflight: map[netip.Addr]chan struct{}{}}
	r.Enabled.Store(true)
	return r
}

// Names returns hostnames for the given addresses, waiting at most `wait`
// for uncached ones. Addresses without a name are omitted.
func (r *Resolver) Names(ctx context.Context, addrs []netip.Addr, wait time.Duration) map[netip.Addr]string {
	out := map[netip.Addr]string{}
	if !r.Enabled.Load() {
		return out
	}
	now := time.Now()
	var pending []chan struct{}
	var pendingAddrs []netip.Addr
	r.mu.Lock()
	for _, a := range addrs {
		if !a.IsValid() || a.IsUnspecified() {
			continue
		}
		if e, ok := r.cache[a]; ok && now.Before(e.exp) {
			if e.name != "" {
				out[a] = e.name
			}
			continue
		}
		ch, ok := r.inflight[a]
		if !ok {
			ch = make(chan struct{})
			r.inflight[a] = ch
			go r.lookup(a, ch)
		}
		pending = append(pending, ch)
		pendingAddrs = append(pendingAddrs, a)
	}
	r.mu.Unlock()
	if len(pending) == 0 {
		return out
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for _, ch := range pending {
		select {
		case <-ch:
		case <-timer.C:
			goto done
		case <-ctx.Done():
			goto done
		}
	}
done:
	r.mu.Lock()
	for _, a := range pendingAddrs {
		if e, ok := r.cache[a]; ok && e.name != "" {
			out[a] = e.name
		}
	}
	r.mu.Unlock()
	return out
}

func (r *Resolver) lookup(a netip.Addr, done chan struct{}) {
	r.sem <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), rdnsTimeout)
	names, err := r.r.LookupAddr(ctx, a.String())
	cancel()
	<-r.sem
	e := rdnsEntry{exp: time.Now().Add(rdnsNegativeTTL)}
	if err == nil && len(names) > 0 && GenericPTR(a, names[0]) {
		// ISP placeholder names carry no information; cache as "no name".
		e.exp = time.Now().Add(rdnsPositiveTTL)
	} else if err == nil && len(names) > 0 {
		e = rdnsEntry{name: strings.TrimSuffix(names[0], "."), exp: time.Now().Add(rdnsPositiveTTL)}
	}
	r.mu.Lock()
	if len(r.cache) >= rdnsCacheMax {
		// Crude eviction: drop about half; map iteration order is random.
		n := 0
		for k := range r.cache {
			delete(r.cache, k)
			if n++; n >= rdnsCacheMax/2 {
				break
			}
		}
	}
	r.cache[a] = e
	delete(r.inflight, a)
	r.mu.Unlock()
	close(done)
}

func (r *Resolver) CacheSize() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cache)
}

// GenericPTR reports whether a hostname is an ISP placeholder that just spells
// out the address (e.g. "syn-2603-7083-…res6.spectrum.com",
// "cpe-203-0-113-7.example.net", "7.113.0.203.in-addr.example").
func GenericPTR(a netip.Addr, name string) bool {
	n := strings.ToLower(name)
	a = a.Unmap()
	var parts []string
	if a.Is4() {
		b := a.As4()
		for _, x := range b {
			parts = append(parts, strconv.Itoa(int(x)))
		}
		fwd, rev := parts, []string{parts[3], parts[2], parts[1], parts[0]}
		for _, sep := range []string{"-", ".", "_"} {
			if strings.Contains(n, strings.Join(fwd, sep)) || strings.Contains(n, strings.Join(rev, sep)) {
				return true
			}
		}
		return false
	}
	// IPv6: two or more consecutive leading hextets spelled out.
	full := strings.Split(strings.ToLower(netip.AddrFrom16(a.As16()).StringExpanded()), ":")
	for i := range full {
		full[i] = strings.TrimLeft(full[i], "0")
	}
	for _, sep := range []string{"-", "."} {
		if strings.Contains(n, full[0]+sep+full[1]+sep+full[2]) {
			return true
		}
	}
	return false
}

// AddrsMatching lists cached addresses whose name matches.
func (r *Resolver) AddrsMatching(match func(name string) bool) []netip.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	var out []netip.Addr
	for a, e := range r.cache {
		if e.name != "" && now.Before(e.exp) && match(e.name) {
			out = append(out, a)
		}
	}
	return out
}
