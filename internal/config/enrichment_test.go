package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestEnrichmentSecrets(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if e := db.Enrichment(); e.GeoSource != GeoDBIPLite || e.OUISource != OUIIEEE || !e.AutoUpdate {
		t.Fatalf("defaults: %+v", e)
	}
	e := DefaultEnrichment()
	e.GeoSource = GeoMaxMind
	e.MaxMindAccountID = "12345"
	if err := db.SaveEnrichment(e, false); err == nil {
		t.Fatal("expected missing license key error")
	}
	e.MaxMindLicenseKey = "s3cret"
	if err := db.SaveEnrichment(e, false); err != nil {
		t.Fatal(err)
	}
	var raw string
	db.db.QueryRow("SELECT value FROM settings WHERE key = 'enrichment'").Scan(&raw)
	if strings.Contains(raw, "s3cret") {
		t.Fatal("license key stored in clear")
	}
	// Saving with an empty key keeps the stored one.
	e.MaxMindLicenseKey = ""
	e.MaxMindASNEdition = "GeoIP2-ISP"
	if err := db.SaveEnrichment(e, false); err != nil {
		t.Fatal(err)
	}
	got := db.Enrichment()
	if got.MaxMindLicenseKey != "s3cret" || got.MaxMindASNEdition != "GeoIP2-ISP" {
		t.Fatalf("got %+v", got)
	}
	if v := got.View(); v.MaxMindLicenseKey != "" || !v.HasLicenseKey {
		t.Fatalf("view leaks or loses key: %+v", v)
	}

	u := DefaultEnrichment()
	u.GeoSource = GeoURLs
	u.GeoCountryURL = "https://download.example.com/acct/KEY/country.mmdb.gz"
	u.GeoASNURL = "https://download.example.com/acct/KEY/asn.mmdb.gz"
	if err := db.SaveEnrichment(u, false); err != nil {
		t.Fatal(err)
	}
	if v := db.Enrichment().View(); v.GeoCountryURL != "" || v.GeoCountryHost != "download.example.com" {
		t.Fatalf("view: %+v", v)
	}
	u.GeoCountryURL, u.GeoASNURL = "", ""
	if err := db.SaveEnrichment(u, true); err != nil {
		t.Fatal(err)
	}
	if g := db.Enrichment(); g.GeoCountryURL == "" || g.GeoASNURL != "" {
		t.Fatalf("clear ASN URL: %+v", g)
	}

	// Switching away from a source forgets its secrets.
	if err := db.SaveEnrichment(DefaultEnrichment(), false); err != nil {
		t.Fatal(err)
	}
	if g := db.Enrichment(); g.GeoCountryURL != "" || g.MaxMindLicenseKey != "" || g.MaxMindAccountID != "" {
		t.Fatalf("secrets kept: %+v", g)
	}

	f := DefaultEnrichment()
	f.GeoSource = GeoFiles
	f.GeoCountryFile = "relative/GeoIP2-Country.mmdb"
	if err := db.SaveEnrichment(f, false); err == nil {
		t.Fatal("relative path accepted")
	}
	f.GeoCountryFile = "/var/lib/GeoIP/GeoIP2-Country.mmdb"
	f.OUISource = OUIURL
	f.OUIURL = "ftp://example.com/manuf"
	if err := db.SaveEnrichment(f, false); err == nil {
		t.Fatal("ftp URL accepted")
	}
}
