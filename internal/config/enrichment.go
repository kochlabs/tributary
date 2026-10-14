package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// Where GeoIP databases come from.
const (
	GeoDBIPLite = "dbip-lite" // free DB-IP Lite, downloaded monthly
	GeoMaxMind  = "maxmind"   // MaxMind account (GeoLite2 or GeoIP2 editions)
	GeoURLs     = "urls"      // administrator-supplied download URLs
	GeoFiles    = "files"     // files on the appliance, updated externally
)

// Where the MAC vendor (OUI) table comes from.
const (
	OUIBuiltin = "builtin" // table compiled into the binary
	OUIIEEE    = "ieee"    // downloaded from the IEEE registration authority
	OUIURL     = "url"     // administrator-supplied download URL
	OUIFile    = "file"    // file on the appliance
)

var (
	maxmindCountryEditions = []string{"GeoLite2-Country", "GeoLite2-City", "GeoIP2-Country", "GeoIP2-City", "GeoIP2-Enterprise"}
	maxmindASNEditions     = []string{"GeoLite2-ASN", "GeoIP2-ISP"}
)

// Enrichment selects the sources of the GeoIP and MAC vendor databases.
// The MaxMind license key and download URLs (which often embed a key) are
// stored encrypted and never returned by the API.
type Enrichment struct {
	AutoUpdate bool `json:"autoUpdate"` // refresh downloaded databases on a schedule

	GeoSource             string `json:"geoSource"`
	MaxMindAccountID      string `json:"maxmindAccountId"`
	MaxMindLicenseKey     string `json:"maxmindLicenseKey,omitempty"`
	MaxMindCountryEdition string `json:"maxmindCountryEdition"`
	MaxMindASNEdition     string `json:"maxmindAsnEdition"`
	GeoCountryURL         string `json:"geoCountryUrl,omitempty"`
	GeoASNURL             string `json:"geoAsnUrl,omitempty"`
	GeoCountryFile        string `json:"geoCountryFile"`
	GeoASNFile            string `json:"geoAsnFile"`

	OUISource string `json:"ouiSource"`
	OUIURL    string `json:"ouiUrl"`
	OUIFile   string `json:"ouiFile"`
}

// EnrichmentView is what the API returns: secrets replaced by whether they
// are set, and URLs by their host so the administrator can recognise them.
type EnrichmentView struct {
	Enrichment
	HasLicenseKey  bool   `json:"hasLicenseKey"`
	GeoCountryHost string `json:"geoCountryHost"`
	GeoASNHost     string `json:"geoAsnHost"`
}

func DefaultEnrichment() Enrichment {
	return Enrichment{AutoUpdate: true, GeoSource: GeoDBIPLite, MaxMindCountryEdition: "GeoLite2-Country", MaxMindASNEdition: "GeoLite2-ASN", OUISource: OUIIEEE}
}

func oneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func checkURL(name, raw string, required bool) error {
	if raw == "" {
		if required {
			return fmt.Errorf("%s is required", name)
		}
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%s must be an http(s) URL", name)
	}
	return nil
}

func checkPath(name, p string, required bool) error {
	if p == "" {
		if required {
			return fmt.Errorf("%s is required", name)
		}
		return nil
	}
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("%s must be an absolute path", name)
	}
	return nil
}

// validate checks e; stored tells whether secrets already exist so an
// update can leave them empty to keep them.
func (e *Enrichment) validate(stored Enrichment) error {
	e.MaxMindAccountID = strings.TrimSpace(e.MaxMindAccountID)
	e.MaxMindLicenseKey = strings.TrimSpace(e.MaxMindLicenseKey)
	e.GeoCountryURL, e.GeoASNURL, e.OUIURL = strings.TrimSpace(e.GeoCountryURL), strings.TrimSpace(e.GeoASNURL), strings.TrimSpace(e.OUIURL)
	e.GeoCountryFile, e.GeoASNFile, e.OUIFile = strings.TrimSpace(e.GeoCountryFile), strings.TrimSpace(e.GeoASNFile), strings.TrimSpace(e.OUIFile)
	switch e.GeoSource {
	case GeoDBIPLite:
	case GeoMaxMind:
		if e.MaxMindAccountID == "" {
			return errors.New("MaxMind account ID is required")
		}
		if e.MaxMindLicenseKey == "" && stored.MaxMindLicenseKey == "" {
			return errors.New("MaxMind license key is required")
		}
		if !oneOf(e.MaxMindCountryEdition, maxmindCountryEditions...) {
			return fmt.Errorf("unknown MaxMind country edition %q", e.MaxMindCountryEdition)
		}
		if !oneOf(e.MaxMindASNEdition, maxmindASNEditions...) {
			return fmt.Errorf("unknown MaxMind ASN edition %q", e.MaxMindASNEdition)
		}
	case GeoURLs:
		if err := checkURL("country database URL", e.GeoCountryURL, stored.GeoCountryURL == ""); err != nil {
			return err
		}
		if err := checkURL("ASN database URL", e.GeoASNURL, false); err != nil {
			return err
		}
	case GeoFiles:
		if err := checkPath("country database file", e.GeoCountryFile, true); err != nil {
			return err
		}
		if err := checkPath("ASN database file", e.GeoASNFile, false); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown GeoIP source %q", e.GeoSource)
	}
	switch e.OUISource {
	case OUIBuiltin, OUIIEEE:
	case OUIURL:
		if err := checkURL("vendor database URL", e.OUIURL, true); err != nil {
			return err
		}
	case OUIFile:
		if err := checkPath("vendor database file", e.OUIFile, true); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown vendor database source %q", e.OUISource)
	}
	return nil
}

// loadEnrichment returns the stored record with secrets still encrypted.
func (c *DB) loadEnrichment() (Enrichment, bool) {
	e := DefaultEnrichment()
	var v string
	if err := c.db.QueryRow("SELECT value FROM settings WHERE key = 'enrichment'").Scan(&v); err != nil {
		return e, false
	}
	_ = json.Unmarshal([]byte(v), &e)
	return e, true
}

// Enrichment returns the database sources with secrets decrypted, for use
// by the appliance itself.
func (c *DB) Enrichment() Enrichment {
	e, ok := c.loadEnrichment()
	if !ok {
		// Before this record existed, auto-update lived in Settings.
		var v string
		if err := c.db.QueryRow("SELECT value FROM settings WHERE key = 'settings'").Scan(&v); err == nil {
			var legacy struct {
				GeoAutoUpdate *bool `json:"geoAutoUpdate"`
			}
			if json.Unmarshal([]byte(v), &legacy) == nil && legacy.GeoAutoUpdate != nil {
				e.AutoUpdate = *legacy.GeoAutoUpdate
			}
		}
	}
	for _, p := range []*string{&e.MaxMindLicenseKey, &e.GeoCountryURL, &e.GeoASNURL} {
		if *p != "" {
			plain, err := c.decrypt(*p)
			if err != nil {
				*p = ""
				continue
			}
			*p = plain
		}
	}
	return e
}

func urlHost(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return ""
}

// View redacts e for the API.
func (e Enrichment) View() EnrichmentView {
	v := EnrichmentView{Enrichment: e, HasLicenseKey: e.MaxMindLicenseKey != "", GeoCountryHost: urlHost(e.GeoCountryURL), GeoASNHost: urlHost(e.GeoASNURL)}
	v.MaxMindLicenseKey, v.GeoCountryURL, v.GeoASNURL = "", "", ""
	return v
}

// SaveEnrichment validates and stores e. Empty secret fields keep the stored
// values; set clearASNURL to remove a previously stored ASN URL. Secrets of
// sources that are no longer selected are deleted rather than kept around.
func (c *DB) SaveEnrichment(e Enrichment, clearASNURL bool) error {
	stored, _ := c.loadEnrichment()
	if clearASNURL {
		stored.GeoASNURL = ""
	}
	if err := e.validate(stored); err != nil {
		return err
	}
	for _, f := range []struct{ in, old *string }{
		{&e.MaxMindLicenseKey, &stored.MaxMindLicenseKey},
		{&e.GeoCountryURL, &stored.GeoCountryURL},
		{&e.GeoASNURL, &stored.GeoASNURL},
	} {
		if *f.in == "" {
			*f.in = *f.old // already encrypted
			continue
		}
		enc, err := c.encrypt(*f.in)
		if err != nil {
			return err
		}
		*f.in = enc
	}
	if e.GeoSource != GeoMaxMind {
		e.MaxMindAccountID, e.MaxMindLicenseKey = "", ""
	}
	if e.GeoSource != GeoURLs {
		e.GeoCountryURL, e.GeoASNURL = "", ""
	}
	b, _ := json.Marshal(e)
	_, err := c.db.Exec("INSERT INTO settings(key, value) VALUES('enrichment', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", string(b))
	return err
}
