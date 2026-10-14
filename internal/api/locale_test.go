package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestPickLocale(t *testing.T) {
	avail := []string{"en-US", "de", "fr-CA", "pt-BR"}
	cases := []struct{ cookie, accept, want string }{
		{"", "", "en-US"},
		{"", "de-CH,de;q=0.9,en;q=0.8", "de"}, // same language
		{"", "fr-FR;q=0.5, pt-BR", "pt-BR"},   // q-values ordering
		{"", "fr-CA", "fr-CA"},                // exact
		{"", "ja,zh;q=0.8", "en-US"},          // nothing matches
		{"fr-CA", "de", "fr-CA"},              // cookie wins
		{"xx", "de", "de"},                    // unknown cookie ignored
		{"", "en-GB,en;q=0.9", "en-US"},       // language match
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		if c.cookie != "" {
			r.AddCookie(&http.Cookie{Name: langCookie, Value: c.cookie})
		}
		if c.accept != "" {
			r.Header.Set("Accept-Language", c.accept)
		}
		if got := pickLocale(r, avail); got != c.want {
			t.Errorf("cookie %q accept %q: got %q want %q", c.cookie, c.accept, got, c.want)
		}
	}
}

func TestUILocales(t *testing.T) {
	ui := fstest.MapFS{
		"de/index.html":        {},
		"en-US/index.html":     {},
		"en-US/main.js":        {},
		"3rdpartylicenses.txt": {},
		"empty/x.txt":          {},
	}
	if got := uiLocales(ui); len(got) != 2 || got[0] != "en-US" || got[1] != "de" {
		t.Fatalf("got %v", got)
	}
	if got := uiLocales(fstest.MapFS{"index.html": {}}); got != nil {
		t.Fatalf("non-localized build: %v", got)
	}
}
