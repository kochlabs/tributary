// Package enrich adds context to flows: country and ASN from MaxMind-format
// (mmdb) databases, and reverse DNS names at query time.
package enrich

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/kochlabs/tributary/internal/config"
	"github.com/kochlabs/tributary/internal/flow"
)

type dbs struct {
	country, asn         *maxminddb.Reader
	countryFile, asnFile string
	countryType, asnType string // metadata database_type
	countryBuilt         time.Time
	asnBuilt             time.Time
	countryMod, asnMod   time.Time // file modification times
	// Set when the selected source's database couldn't be loaded and the
	// previous one is kept in use until it can.
	countryKept, asnKept bool
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

	src         atomic.Pointer[config.Enrichment]
	updateMu    sync.Mutex
	lastUpdate  atomic.Value // string: result of the last update attempt
	lastAttempt atomic.Int64 // unix seconds of the last automatic download
}

func NewGeo(dir string, log *slog.Logger) *Geo {
	g := &Geo{dir: dir, log: log, countries: map[string]string{}, asNames: map[uint32]string{}}
	d := config.DefaultEnrichment()
	g.src.Store(&d)
	return g
}

func (g *Geo) source() config.Enrichment { return *g.src.Load() }

// SetSource selects where the databases come from. It reports whether the
// GeoIP part changed, in which case the caller should call Refresh.
func (g *Geo) SetSource(e config.Enrichment) bool {
	old := g.src.Swap(&e)
	return old.GeoSource != e.GeoSource || old.MaxMindAccountID != e.MaxMindAccountID || old.MaxMindLicenseKey != e.MaxMindLicenseKey ||
		old.MaxMindCountryEdition != e.MaxMindCountryEdition || old.MaxMindASNEdition != e.MaxMindASNEdition ||
		old.GeoCountryURL != e.GeoCountryURL || old.GeoASNURL != e.GeoASNURL || old.GeoCountryFile != e.GeoCountryFile || old.GeoASNFile != e.GeoASNFile
}

// paths returns the country and ASN database files for the current source;
// an empty path means that database isn't configured.
func (g *Geo) paths() (country, asn string) {
	e := g.source()
	switch e.GeoSource {
	case config.GeoMaxMind:
		return filepath.Join(g.dir, e.MaxMindCountryEdition+".mmdb"), filepath.Join(g.dir, e.MaxMindASNEdition+".mmdb")
	case config.GeoURLs:
		country = filepath.Join(g.dir, "custom-country.mmdb")
		if e.GeoASNURL != "" {
			asn = filepath.Join(g.dir, "custom-asn.mmdb")
		}
		return country, asn
	case config.GeoFiles:
		return e.GeoCountryFile, e.GeoASNFile
	}
	return filepath.Join(g.dir, "dbip-country-lite.mmdb"), filepath.Join(g.dir, "dbip-asn-lite.mmdb")
}

func openDB(p string) (*maxminddb.Reader, time.Time, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, time.Time{}, err
	}
	r, err := maxminddb.Open(p)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%s: %w", p, err)
	}
	return r, st.ModTime(), nil
}

// Load (re)opens the databases of the current source. Missing downloaded
// files are not an error (they are fetched later); missing local files are.
func (g *Geo) Load() error {
	if err := os.MkdirAll(g.dir, 0o750); err != nil {
		return err
	}
	external := g.source().GeoSource == config.GeoFiles
	n := &dbs{}
	var errs []error
	cp, ap := g.paths()
	name := func(p string) string {
		if external {
			return p
		}
		return filepath.Base(p)
	}
	if cp != "" {
		r, mod, err := openDB(cp)
		switch {
		case err == nil:
			n.country, n.countryFile, n.countryType, n.countryBuilt, n.countryMod = r, name(cp), r.Metadata.DatabaseType, r.Metadata.BuildTime(), mod
		case external || !errors.Is(err, os.ErrNotExist):
			errs = append(errs, err)
		}
	}
	if ap != "" {
		r, mod, err := openDB(ap)
		switch {
		case err == nil:
			n.asn, n.asnFile, n.asnType, n.asnBuilt, n.asnMod = r, name(ap), r.Metadata.DatabaseType, r.Metadata.BuildTime(), mod
		case external || !errors.Is(err, os.ErrNotExist):
			errs = append(errs, err)
		}
	}
	// Keep serving the previous databases rather than none while the new
	// source is downloading or broken.
	old := g.cur.Load()
	if old != nil && cp != "" && n.country == nil && old.country != nil {
		n.country, n.countryFile, n.countryType, n.countryBuilt, n.countryMod, n.countryKept = old.country, old.countryFile, old.countryType, old.countryBuilt, old.countryMod, true
	}
	if old != nil && ap != "" && n.asn == nil && old.asn != nil {
		n.asn, n.asnFile, n.asnType, n.asnBuilt, n.asnMod, n.asnKept = old.asn, old.asnFile, old.asnType, old.asnBuilt, old.asnMod, true
	}
	g.cur.Store(n)
	if old != nil {
		// Readers may still be in use by in-flight lookups; let them finish.
		go func() {
			time.Sleep(10 * time.Second)
			if old.country != nil && old.country != n.country {
				old.country.Close()
			}
			if old.asn != nil && old.asn != n.asn {
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

// Attribution is a credit a database's license requires wherever its data
// is shown.
type Attribution struct {
	Text    string `json:"text"`
	URL     string `json:"url"`
	License string `json:"license,omitempty"`
}

// attributionFor returns the credit required by a database, identified by
// its metadata type, or nil when its license needs none (e.g. commercial).
func attributionFor(dbType string) *Attribution {
	switch {
	case strings.HasPrefix(dbType, "DBIP") && strings.Contains(dbType, "Lite"):
		return &Attribution{Text: "IP Geolocation by DB-IP", URL: "https://db-ip.com", License: "CC BY 4.0"}
	case strings.HasPrefix(dbType, "GeoLite2"):
		return &Attribution{Text: "This product includes GeoLite2 data created by MaxMind", URL: "https://www.maxmind.com"}
	}
	return nil
}

type Status struct {
	Source       string        `json:"source"`
	Country      string        `json:"country"`
	CountryType  string        `json:"countryType"`
	CountryBuilt int64         `json:"countryBuilt"`
	CountryKept  bool          `json:"countryKept"` // previous source still in use
	ASN          string        `json:"asn"`
	ASNType      string        `json:"asnType"`
	ASNBuilt     int64         `json:"asnBuilt"`
	ASNKept      bool          `json:"asnKept"`
	LastUpdate   string        `json:"lastUpdate"`
	Attributions []Attribution `json:"attributions"`
}

func (g *Geo) Status() Status {
	s := Status{Source: g.source().GeoSource, Attributions: []Attribution{}}
	if d := g.cur.Load(); d != nil {
		s.Country, s.ASN, s.CountryType, s.ASNType = d.countryFile, d.asnFile, d.countryType, d.asnType
		s.CountryKept, s.ASNKept = d.countryKept, d.asnKept
		if d.country != nil {
			s.CountryBuilt = d.countryBuilt.UnixMilli()
		}
		if d.asn != nil {
			s.ASNBuilt = d.asnBuilt.UnixMilli()
		}
		seen := map[string]bool{}
		for _, t := range []string{d.countryType, d.asnType} {
			if a := attributionFor(t); a != nil && !seen[a.Text] {
				seen[a.Text] = true
				s.Attributions = append(s.Attributions, *a)
			}
		}
	}
	s.LastUpdate, _ = g.lastUpdate.Load().(string)
	return s
}

// Update downloads the databases of the current source now (or, for local
// files, reloads them).
func (g *Geo) Update(ctx context.Context) error {
	if !g.updateMu.TryLock() {
		return errors.New("an update is already running")
	}
	defer g.updateMu.Unlock()
	e := g.source()
	cp, ap := g.paths()
	var errs []error
	switch e.GeoSource {
	case config.GeoFiles:
	case config.GeoMaxMind:
		for _, x := range []struct{ edition, dest string }{{e.MaxMindCountryEdition, cp}, {e.MaxMindASNEdition, ap}} {
			u := "https://download.maxmind.com/geoip/databases/" + x.edition + "/download?suffix=tar.gz"
			if err := fetch(ctx, u, e.MaxMindAccountID, e.MaxMindLicenseKey, x.dest, ".mmdb", validMMDB); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", x.edition, err))
			}
		}
	case config.GeoURLs:
		for _, x := range []struct{ url, dest string }{{e.GeoCountryURL, cp}, {e.GeoASNURL, ap}} {
			if x.url == "" {
				continue
			}
			if err := fetch(ctx, x.url, "", "", x.dest, ".mmdb", validMMDB); err != nil {
				// The URL may hold a license key: report only its host.
				errs = append(errs, fmt.Errorf("download from %s failed: %w", hostOf(x.url), redact(err, x.url)))
			}
		}
	default:
		for _, kind := range []string{"country", "asn"} {
			if err := g.downloadDBIPLite(ctx, kind); err != nil {
				errs = append(errs, err)
			}
		}
	}
	err := errors.Join(errs...)
	if lerr := g.Load(); err == nil {
		err = lerr
	}
	msg := time.Now().Format(time.RFC3339) + ": "
	if err != nil {
		msg += "failed: " + err.Error()
		g.log.Warn("geoip update failed", "err", err)
	} else if e.GeoSource == config.GeoFiles {
		msg += "reloaded"
	} else {
		msg += "ok"
	}
	g.lastUpdate.Store(msg)
	return err
}

func (g *Geo) downloadDBIPLite(ctx context.Context, kind string) error {
	now := time.Now().UTC()
	var lastErr error
	// The new month's file appears a little after the 1st; fall back a month.
	for _, t := range []time.Time{now, now.AddDate(0, -1, 0)} {
		url := fmt.Sprintf("https://download.db-ip.com/free/dbip-%s-lite-%s.mmdb.gz", kind, t.Format("2006-01"))
		if lastErr = fetch(ctx, url, "", "", filepath.Join(g.dir, "dbip-"+kind+"-lite.mmdb"), ".mmdb", validMMDB); lastErr == nil {
			g.log.Info("geoip database downloaded", "url", url)
			return nil
		}
	}
	return lastErr
}

func validMMDB(path string) error {
	r, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("not a valid MaxMind-format database: %w", err)
	}
	return r.Close()
}

// stale reports whether downloaded databases are missing or due a refresh.
func (g *Geo) stale() bool {
	d := g.cur.Load()
	cp, ap := g.paths()
	if d == nil || (cp != "" && (d.country == nil || d.countryKept)) || (ap != "" && (d.asn == nil || d.asnKept)) {
		return true
	}
	if g.source().GeoSource == config.GeoDBIPLite {
		// Published monthly.
		return d.country != nil && time.Since(d.countryBuilt) > 32*24*time.Hour
	}
	// Commercial and GeoLite2 editions are refreshed weekly or more often.
	week := 7 * 24 * time.Hour
	return (d.country != nil && time.Since(d.countryMod) > week) || (d.asn != nil && time.Since(d.asnMod) > week)
}

// filesChanged reports whether externally managed files were replaced.
func (g *Geo) filesChanged() bool {
	d := g.cur.Load()
	cp, ap := g.paths()
	changed := func(p string, loaded time.Time) bool {
		if p == "" {
			return false
		}
		st, err := os.Stat(p)
		return err == nil && !st.ModTime().Equal(loaded)
	}
	return d == nil || d.countryKept || d.asnKept || changed(cp, d.countryMod) || changed(ap, d.asnMod)
}

// Refresh switches to a newly selected source. Account and URL sources are
// downloaded right away, since what they point at may have changed; DB-IP
// Lite only when missing or out of date; local files are just loaded.
func (g *Geo) Refresh(ctx context.Context) {
	src := g.source().GeoSource
	err := g.Load()
	if src == config.GeoMaxMind || src == config.GeoURLs || (src == config.GeoDBIPLite && g.stale()) {
		_ = g.Update(ctx)
		return
	}
	msg := time.Now().Format(time.RFC3339) + ": switched to " + src
	if err != nil {
		msg += "; failed: " + err.Error()
		g.log.Warn("geoip databases could not be loaded", "err", err)
	}
	g.lastUpdate.Store(msg)
}

// AutoUpdate keeps the databases current: downloaded ones are refreshed when
// missing or stale while enabled() returns true (retrying at most every 12
// hours), and externally managed files are reloaded when they change.
func (g *Geo) AutoUpdate(ctx context.Context, enabled func() bool) {
	check := func() {
		if g.source().GeoSource == config.GeoFiles {
			if g.filesChanged() {
				if err := g.Load(); err != nil {
					g.log.Warn("geoip databases could not be loaded", "err", err)
				}
			}
			return
		}
		if !enabled() || !g.stale() || time.Now().Unix()-g.lastAttempt.Load() < 12*3600 {
			return
		}
		g.lastAttempt.Store(time.Now().Unix())
		_ = g.Update(ctx)
	}
	check()
	t := time.NewTicker(time.Hour)
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
