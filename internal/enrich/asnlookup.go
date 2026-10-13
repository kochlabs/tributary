package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ASNLookup fills gaps in the local ASN database by asking RIPEstat (which
// covers every routed prefix) for public addresses the database doesn't know.
// Results are cached per /24 (IPv4) or /48 (IPv6); lookups run in the
// background so ingest never waits on the network.
type ASNLookup struct {
	Enabled atomic.Bool
	client  *http.Client
	sem     chan struct{}

	mu      sync.RWMutex
	cache   map[netip.Prefix]asnEntry
	pending map[netip.Prefix]bool
	names   map[uint32]string
}

type asnEntry struct {
	asn uint32
	exp time.Time
}

const (
	asnLookupTTL      = 7 * 24 * time.Hour
	asnLookupNegative = 6 * time.Hour
	asnLookupMax      = 100_000
)

func NewASNLookup() *ASNLookup {
	l := &ASNLookup{
		client:  &http.Client{Timeout: 8 * time.Second},
		sem:     make(chan struct{}, 4),
		cache:   map[netip.Prefix]asnEntry{},
		pending: map[netip.Prefix]bool{},
		names:   map[uint32]string{},
	}
	l.Enabled.Store(true)
	return l
}

func cacheKey(a netip.Addr) netip.Prefix {
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, _ := a.Prefix(bits)
	return p
}

// Get returns the cached AS number for a, scheduling a lookup on a miss.
func (l *ASNLookup) Get(a netip.Addr) uint32 {
	if !l.Enabled.Load() {
		return 0
	}
	k := cacheKey(a)
	l.mu.RLock()
	e, ok := l.cache[k]
	pend := l.pending[k]
	l.mu.RUnlock()
	if ok && time.Now().Before(e.exp) {
		return e.asn
	}
	if !pend {
		l.mu.Lock()
		if !l.pending[k] && len(l.pending) < 1000 {
			l.pending[k] = true
			go l.fetch(k, a)
		}
		l.mu.Unlock()
	}
	return 0
}

// Name returns the holder name learned for an AS number, if any.
func (l *ASNLookup) Name(asn uint32) string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.names[asn]
}

type prefixOverview struct {
	Data struct {
		ASNs []struct {
			ASN    uint32 `json:"asn"`
			Holder string `json:"holder"`
		} `json:"asns"`
	} `json:"data"`
}

func (l *ASNLookup) fetch(k netip.Prefix, a netip.Addr) {
	l.sem <- struct{}{}
	defer func() { <-l.sem }()
	e := asnEntry{exp: time.Now().Add(asnLookupNegative)}
	var name string
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	url := fmt.Sprintf("https://stat.ripe.net/data/prefix-overview/data.json?resource=%s&sourceapp=nfa", a)
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil); err == nil {
		if resp, err := l.client.Do(req); err == nil {
			var po prefixOverview
			if resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&po) == nil && len(po.Data.ASNs) > 0 {
				e = asnEntry{asn: po.Data.ASNs[0].ASN, exp: time.Now().Add(asnLookupTTL)}
				name = holderName(po.Data.ASNs[0].Holder)
			}
			resp.Body.Close()
		}
	}
	l.mu.Lock()
	if len(l.cache) >= asnLookupMax {
		clear(l.cache)
	}
	l.cache[k] = e
	delete(l.pending, k)
	if e.asn != 0 && name != "" {
		l.names[e.asn] = name
	}
	l.mu.Unlock()
}

// holderName turns RIPEstat's "DSS-EDGE - Disney Worldwide Services, Inc."
// into the organisation part.
func holderName(h string) string {
	if _, org, ok := strings.Cut(h, " - "); ok && org != "" {
		return strings.TrimSpace(org)
	}
	return strings.TrimSpace(h)
}

type asnCacheFile struct {
	Prefixes map[string]uint32 `json:"prefixes"`
	Names    map[uint32]string `json:"names"`
}

// Load restores positive lookups saved by Save. Missing files are not an error.
func (l *ASNLookup) Load(path string) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var f asnCacheFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	exp := time.Now().Add(asnLookupTTL)
	for p, asn := range f.Prefixes {
		if pfx, err := netip.ParsePrefix(p); err == nil {
			l.cache[pfx] = asnEntry{asn: asn, exp: exp}
		}
	}
	for asn, n := range f.Names {
		l.names[asn] = n
	}
	return nil
}

// Save writes positive lookups atomically so labels survive restarts.
func (l *ASNLookup) Save(path string) error {
	f := asnCacheFile{Prefixes: map[string]uint32{}, Names: map[uint32]string{}}
	l.mu.RLock()
	for p, e := range l.cache {
		if e.asn != 0 {
			f.Prefixes[p.String()] = e.asn
		}
	}
	for asn, n := range l.names {
		f.Names[asn] = n
	}
	l.mu.RUnlock()
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Persist loads the cache from path, then saves it every interval and when
// ctx ends.
func (l *ASNLookup) Persist(ctx context.Context, path string, interval time.Duration) {
	_ = l.Load(path)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = l.Save(path)
			return
		case <-t.C:
			_ = l.Save(path)
		}
	}
}
