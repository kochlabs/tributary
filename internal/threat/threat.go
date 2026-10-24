package threat

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kochlabs/tributary/internal/config"
)

// maxFeedBytes caps a download (the largest common lists are a few MB).
const maxFeedBytes = 64 << 20

// notMatched are ranges never matched even if a feed lists them: they are
// not reachable on the internet (feeds such as FireHOL Level 1 include them
// as bogons), so a match would always be a false alarm.
var notMatched = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT (and Tailscale)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
}

// Matchable reports whether a can be matched: a globally routable unicast
// address, not private.
func Matchable(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range notMatched {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// addrRange is an inclusive address range.
type addrRange struct{ lo, hi netip.Addr }

// list is one feed's ranges, sorted and merged.
type list struct {
	id     string // the feed's ID, stored in flows
	name   string
	ranges []addrRange
}

// Matcher finds the first feed (in table order) listing an address.
type Matcher struct {
	lists    []list
	prefixes int
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As16()
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	for i := bits; i < 128; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a := netip.AddrFrom16(b)
	if p.Addr().Is4() {
		return a.Unmap()
	}
	return a
}

func newList(id, name string, prefixes []netip.Prefix) list {
	rs := make([]addrRange, 0, len(prefixes))
	for _, p := range prefixes {
		rs = append(rs, addrRange{p.Addr(), lastAddr(p)})
	}
	slices.SortFunc(rs, func(a, b addrRange) int { return a.lo.Compare(b.lo) })
	merged := rs[:0]
	for _, r := range rs {
		if n := len(merged); n > 0 && merged[n-1].lo.BitLen() == r.lo.BitLen() &&
			(r.lo.Compare(merged[n-1].hi) <= 0 || merged[n-1].hi.Next() == r.lo) {
			if r.hi.Compare(merged[n-1].hi) > 0 {
				merged[n-1].hi = r.hi
			}
			continue
		}
		merged = append(merged, r)
	}
	return list{id: id, name: name, ranges: merged}
}

func (l list) contains(a netip.Addr) bool {
	// The last range starting at or before a.
	i, _ := slices.BinarySearchFunc(l.ranges, a, func(r addrRange, t netip.Addr) int {
		if c := r.lo.Compare(t); c != 0 {
			return c
		}
		return -1 // equal starts sort before t, so i lands after them
	})
	return i > 0 && l.ranges[i-1].lo.BitLen() == a.BitLen() && a.Compare(l.ranges[i-1].hi) <= 0
}

// Match returns the ID of the first feed listing a, or "". Flows store the
// ID, so renaming a feed relabels its past matches. Addresses that aren't
// Matchable never match.
func (m *Matcher) Match(a netip.Addr) string {
	if m == nil || len(m.lists) == 0 {
		return ""
	}
	a = a.Unmap()
	if !Matchable(a) {
		return ""
	}
	for _, l := range m.lists {
		if l.contains(a) {
			return l.id
		}
	}
	return ""
}

// Feeds lists the names of every feed listing a, for lookups.
func (m *Matcher) Feeds(a netip.Addr) []string {
	var out []string
	if m == nil || !Matchable(a.Unmap()) {
		return nil
	}
	for _, l := range m.lists {
		if l.contains(a.Unmap()) {
			out = append(out, l.name)
		}
	}
	return out
}

// ---- manager ----

// Manager keeps the feeds' lists downloaded and the matcher current.
type Manager struct {
	Cfg    *config.DB
	Log    *slog.Logger
	Dir    string // cached lists, one file per feed
	Client func() *http.Client
	Agent  string // User-Agent for downloads

	cur  atomic.Pointer[Matcher]
	kick chan int64
}

func (m *Manager) init() {
	if m.kick == nil {
		m.kick = make(chan int64, 32)
	}
}

// Match returns the ID of the first feed listing a, or "".
func (m *Manager) Match(a netip.Addr) string { return m.cur.Load().Match(a) }

// Feeds lists every feed listing a.
func (m *Manager) Feeds(a netip.Addr) []string { return m.cur.Load().Feeds(a) }

// Prefixes is how many (merged) ranges are being matched.
func (m *Manager) Prefixes() int {
	if c := m.cur.Load(); c != nil {
		return c.prefixes
	}
	return 0
}

func (m *Manager) cacheFile(id int64) string {
	return filepath.Join(m.Dir, strconv.FormatInt(id, 10)+".txt")
}

// Reload rebuilds the matcher from the cached lists of the enabled feeds,
// e.g. after feeds were enabled, disabled, reordered or deleted.
func (m *Manager) Reload() error {
	feeds, err := m.Cfg.ThreatFeeds()
	if err != nil {
		return err
	}
	mt := &Matcher{}
	for _, f := range feeds {
		if !f.Enabled {
			continue
		}
		fh, err := os.Open(m.cacheFile(f.ID))
		if err != nil {
			continue // not downloaded yet
		}
		ps, _, err := Parse(fh, Format{Kind: "text"})
		fh.Close()
		if err != nil {
			continue
		}
		l := newList(strconv.FormatInt(f.ID, 10), f.Name, ps)
		mt.lists = append(mt.lists, l)
		mt.prefixes += len(l.ranges)
	}
	m.cur.Store(mt)
	return nil
}

// Forget removes a deleted feed's cached list.
func (m *Manager) Forget(id int64) {
	_ = os.Remove(m.cacheFile(id))
}

// UpdateSoon asks for a feed to be downloaded now (0 = every enabled feed).
func (m *Manager) UpdateSoon(id int64) {
	m.init()
	select {
	case m.kick <- id:
	default:
	}
}

// Run downloads feeds when they are due until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.init()
	if err := os.MkdirAll(m.Dir, 0o750); err != nil {
		m.Log.Warn("threat feeds: cannot create the cache directory", "err", err)
	}
	if err := m.Reload(); err != nil {
		m.Log.Warn("threat feeds: loading", "err", err)
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	m.updateDue(ctx, 0, false)
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-m.kick:
			m.updateDue(ctx, id, true)
		case <-t.C:
			m.updateDue(ctx, 0, false)
		}
	}
}

// updateDue downloads the enabled feeds that are due (or feed id, or all
// when forced with id 0).
func (m *Manager) updateDue(ctx context.Context, id int64, force bool) {
	feeds, err := m.Cfg.ThreatFeeds()
	if err != nil {
		return
	}
	changed := false
	for _, f := range feeds {
		if !f.Enabled || (id != 0 && f.ID != id) {
			continue
		}
		due := time.Since(time.UnixMilli(f.LastAttempt)) >= time.Duration(f.IntervalHours)*time.Hour
		if _, err := os.Stat(m.cacheFile(f.ID)); err != nil {
			due = due || time.Since(time.UnixMilli(f.LastAttempt)) >= 10*time.Minute // never downloaded: retry sooner
		}
		if !force && !due {
			continue
		}
		ps, _, err := m.Fetch(ctx, f)
		if err == nil {
			err = m.store(f.ID, ps)
		}
		_ = m.Cfg.SaveThreatFeedResult(f.ID, time.Now(), len(ps), err)
		if err != nil {
			m.Log.Warn("threat feed update failed", "feed", f.Name, "err", err)
			continue
		}
		m.Log.Info("threat feed updated", "feed", f.Name, "entries", len(ps))
		changed = true
	}
	if changed {
		_ = m.Reload()
	}
}

// store writes a feed's parsed list to its cache file.
func (m *Manager) store(id int64, ps []netip.Prefix) error {
	var b bytes.Buffer
	for _, p := range ps {
		b.WriteString(p.String())
		b.WriteByte('\n')
	}
	tmp := m.cacheFile(id) + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, m.cacheFile(id))
}

// Fetch downloads (or reads) and parses a feed without storing it.
func (m *Manager) Fetch(ctx context.Context, f config.ThreatFeed) ([]netip.Prefix, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var body io.ReadCloser
	if strings.HasPrefix(f.URL, "/") {
		fh, err := os.Open(f.URL)
		if err != nil {
			return nil, 0, err
		}
		body = fh
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", m.Agent)
		resp, err := m.Client().Do(req)
		if err != nil {
			return nil, 0, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, 0, fmt.Errorf("download failed: %s", resp.Status)
		}
		body = resp.Body
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, maxFeedBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if len(data) > maxFeedBytes {
		return nil, 0, errors.New("the list is larger than 64 MB")
	}
	var r io.Reader = bytes.NewReader(data)
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, 0, err
		}
		r = bufio.NewReader(io.LimitReader(zr, maxFeedBytes))
	}
	return Parse(r, Format{Kind: f.Format, Field: f.Field, Column: f.Column, Delimiter: f.Delimiter})
}
