// Package enrich adds context to flows: country and ASN from MaxMind-format
// (mmdb) databases, and reverse DNS names at query time.
package enrich

import (
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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"

	"nfa/internal/flow"
)

// Database file names looked up in the GeoIP directory, in order of preference.
// MaxMind GeoLite2/GeoIP2 files dropped in by an administrator win over the
// automatically downloaded DB-IP Lite files.
var (
	countryFiles = []string{"GeoIP2-Country.mmdb", "GeoLite2-Country.mmdb", "dbip-country-lite.mmdb"}
	asnFiles     = []string{"GeoIP2-ISP.mmdb", "GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb"}
)

type dbs struct {
	country, asn         *maxminddb.Reader
	countryFile, asnFile string
	countryBuilt         time.Time
	asnBuilt             time.Time
}

type Geo struct {
	dir string
	log *slog.Logger
	cur atomic.Pointer[dbs]

	// Online fills ASNs missing from the local database (may be nil).
	Online *ASNLookup
	local  atomic.Pointer[[]netip.Prefix]

	namesMu   sync.RWMutex
	countries map[string]string // ISO code -> English name
	asNames   map[uint32]string

	updateMu   sync.Mutex
	lastUpdate atomic.Value // string: result of the last update attempt
}

func NewGeo(dir string, log *slog.Logger) *Geo {
	return &Geo{dir: dir, log: log, countries: map[string]string{}, asNames: map[uint32]string{}}
}

func firstExisting(dir string, names []string) string {
	for _, n := range names {
		p := filepath.Join(dir, n)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Load (re)opens whatever databases exist in the GeoIP directory.
func (g *Geo) Load() error {
	if err := os.MkdirAll(g.dir, 0o750); err != nil {
		return err
	}
	n := &dbs{}
	var errs []error
	if p := firstExisting(g.dir, countryFiles); p != "" {
		r, err := maxminddb.Open(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
		} else {
			n.country, n.countryFile, n.countryBuilt = r, filepath.Base(p), r.Metadata.BuildTime()
		}
	}
	if p := firstExisting(g.dir, asnFiles); p != "" {
		r, err := maxminddb.Open(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
		} else {
			n.asn, n.asnFile, n.asnBuilt = r, filepath.Base(p), r.Metadata.BuildTime()
		}
	}
	old := g.cur.Swap(n)
	if old != nil {
		// Readers may still be in use by in-flight lookups; let them finish.
		go func() {
			time.Sleep(10 * time.Second)
			if old.country != nil {
				old.country.Close()
			}
			if old.asn != nil {
				old.asn.Close()
			}
		}()
	}
	if n.country != nil || n.asn != nil {
		g.log.Info("geoip databases loaded", "country", n.countryFile, "asn", n.asnFile)
		go g.indexNames(n)
	}
	return errors.Join(errs...)
}

type countryRec struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
}

type asnRec struct {
	ASN uint32 `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

// indexNames walks the databases once so country and AS names are available
// for labels even for values only present in historical data.
func (g *Geo) indexNames(d *dbs) {
	start := time.Now()
	countries := map[string]string{}
	if d.country != nil {
		seen := map[uintptr]bool{}
		for res := range d.country.Networks() {
			if seen[res.Offset()] {
				continue
			}
			seen[res.Offset()] = true
			var c countryRec
			if res.Decode(&c) == nil && c.Country.ISOCode != "" {
				countries[c.Country.ISOCode] = c.Country.Names["en"]
			}
		}
	}
	asNames := map[uint32]string{}
	if d.asn != nil {
		seen := map[uintptr]bool{}
		for res := range d.asn.Networks() {
			if seen[res.Offset()] {
				continue
			}
			seen[res.Offset()] = true
			var a asnRec
			if res.Decode(&a) == nil && a.ASN != 0 {
				asNames[a.ASN] = a.Org
			}
		}
	}
	g.namesMu.Lock()
	g.countries, g.asNames = countries, asNames
	g.namesMu.Unlock()
	g.log.Info("geoip names indexed", "countries", len(countries), "asns", len(asNames), "took", time.Since(start).Round(time.Millisecond))
}

func skip(a netip.Addr) bool {
	return !a.IsValid() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified()
}

// SetLocalNetworks sets extra prefixes (e.g. the site's public IPv6 range)
// treated as internal: they are never geolocated or assigned an ASN.
func (g *Geo) SetLocalNetworks(ps []netip.Prefix) {
	g.local.Store(&ps)
}

// IsLocal reports whether a is private or inside a configured local network.
func (g *Geo) IsLocal(a netip.Addr) bool {
	if skip(a) {
		return true
	}
	if ps := g.local.Load(); ps != nil {
		a = a.Unmap()
		for _, p := range *ps {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}

// Info is the geo context of one address.
type Info struct {
	Country     string `json:"country,omitempty"`
	CountryName string `json:"countryName,omitempty"`
	ASN         uint32 `json:"asn,omitempty"`
	ASName      string `json:"asName,omitempty"`
}

func (g *Geo) Lookup(a netip.Addr) Info {
	var out Info
	d := g.cur.Load()
	if d == nil || g.IsLocal(a) {
		return out
	}
	if d.country != nil {
		var c countryRec
		if d.country.Lookup(a).Decode(&c) == nil {
			out.Country, out.CountryName = c.Country.ISOCode, c.Country.Names["en"]
		}
	}
	if d.asn != nil {
		var r asnRec
		if d.asn.Lookup(a).Decode(&r) == nil {
			out.ASN, out.ASName = r.ASN, r.Org
		}
	}
	if out.ASN == 0 && g.Online != nil {
		if out.ASN = g.Online.Get(a); out.ASN != 0 {
			out.ASName = g.ASName(out.ASN)
		}
	}
	return out
}

// countryCode is the hot-path lookup used during ingest.
func (g *Geo) countryCode(d *dbs, a netip.Addr) string {
	if d.country == nil || g.IsLocal(a) {
		return ""
	}
	var code string
	if d.country.Lookup(a).DecodePath(&code, "country", "iso_code") != nil {
		return ""
	}
	return code
}

func (g *Geo) asNumber(d *dbs, a netip.Addr) uint32 {
	if g.IsLocal(a) {
		return 0
	}
	var n uint32
	if d.asn != nil {
		_ = d.asn.Lookup(a).DecodePath(&n, "autonomous_system_number")
	}
	if n == 0 && g.Online != nil {
		n = g.Online.Get(a)
	}
	return n
}

// Enrich sets country codes and fills AS numbers the exporter didn't provide.
func (g *Geo) Enrich(r *flow.Record) {
	d := g.cur.Load()
	if d == nil {
		return
	}
	r.SrcCountry = g.countryCode(d, r.SrcAddr)
	r.DstCountry = g.countryCode(d, r.DstAddr)
	if r.SrcAS == 0 {
		r.SrcAS = g.asNumber(d, r.SrcAddr)
	}
	if r.DstAS == 0 {
		r.DstAS = g.asNumber(d, r.DstAddr)
	}
}

func (g *Geo) CountryName(code string) string {
	g.namesMu.RLock()
	defer g.namesMu.RUnlock()
	return g.countries[code]
}

func (g *Geo) ASName(asn uint32) string {
	g.namesMu.RLock()
	n := g.asNames[asn]
	g.namesMu.RUnlock()
	if n == "" && g.Online != nil {
		n = g.Online.Name(asn)
	}
	return n
}

type Status struct {
	Country      string `json:"country"`
	CountryBuilt int64  `json:"countryBuilt"`
	ASN          string `json:"asn"`
	ASNBuilt     int64  `json:"asnBuilt"`
	LastUpdate   string `json:"lastUpdate"`
	Attribution  string `json:"attribution,omitempty"`
}

func (g *Geo) Status() Status {
	s := Status{}
	if d := g.cur.Load(); d != nil {
		s.Country, s.ASN = d.countryFile, d.asnFile
		if d.country != nil {
			s.CountryBuilt = d.countryBuilt.UnixMilli()
		}
		if d.asn != nil {
			s.ASNBuilt = d.asnBuilt.UnixMilli()
		}
		if strings.HasPrefix(d.countryFile, "dbip") || strings.HasPrefix(d.asnFile, "dbip") {
			s.Attribution = "IP geolocation by DB-IP (https://db-ip.com), licensed CC BY 4.0"
		}
	}
	s.LastUpdate, _ = g.lastUpdate.Load().(string)
	return s
}

// Update downloads the current DB-IP Lite country and ASN databases.
func (g *Geo) Update(ctx context.Context) error {
	if !g.updateMu.TryLock() {
		return errors.New("an update is already running")
	}
	defer g.updateMu.Unlock()
	var errs []error
	for _, kind := range []string{"country", "asn"} {
		if err := g.download(ctx, kind); err != nil {
			errs = append(errs, err)
		}
	}
	err := errors.Join(errs...)
	if err == nil {
		err = g.Load()
	}
	msg := time.Now().Format(time.RFC3339) + ": "
	if err != nil {
		msg += "failed: " + err.Error()
		g.log.Warn("geoip update failed", "err", err)
	} else {
		msg += "ok"
	}
	g.lastUpdate.Store(msg)
	return err
}

func (g *Geo) download(ctx context.Context, kind string) error {
	now := time.Now().UTC()
	var lastErr error
	// The new month's file appears a little after the 1st; fall back a month.
	for _, t := range []time.Time{now, now.AddDate(0, -1, 0)} {
		url := fmt.Sprintf("https://download.db-ip.com/free/dbip-%s-lite-%s.mmdb.gz", kind, t.Format("2006-01"))
		if lastErr = g.fetch(ctx, url, filepath.Join(g.dir, "dbip-"+kind+"-lite.mmdb")); lastErr == nil {
			g.log.Info("geoip database downloaded", "url", url)
			return nil
		}
	}
	return lastErr
}

func (g *Geo) fetch(ctx context.Context, url, dest string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(g.dir, ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, io.LimitReader(zr, 1<<30)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Validate before replacing the working copy.
	r, err := maxminddb.Open(tmp.Name())
	if err != nil {
		return fmt.Errorf("downloaded database is invalid: %w", err)
	}
	r.Close()
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}

// AutoUpdate refreshes the downloaded databases when missing or older than
// 32 days, checking once a day while enabled() returns true.
func (g *Geo) AutoUpdate(ctx context.Context, enabled func() bool) {
	check := func() {
		if !enabled() {
			return
		}
		d := g.cur.Load()
		stale := d == nil || d.country == nil || d.asn == nil ||
			(d.countryFile == "dbip-country-lite.mmdb" && time.Since(d.countryBuilt) > 32*24*time.Hour)
		if stale {
			_ = g.Update(ctx)
		}
	}
	check()
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}
