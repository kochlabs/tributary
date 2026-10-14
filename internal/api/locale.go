package api

import (
	"io/fs"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// The web UI is built once per language (Angular i18n), each into a
// directory named after its locale (en-US, de, fr-CA, …). The server picks
// one per request: the user's choice (cookie), else the browser's
// Accept-Language, else the source language.

const (
	langCookie    = "nfa_lang"
	defaultLocale = "en-US"
)

// uiLocales lists the locales present in the UI build, the default first.
// A build without locale directories (index.html at the root) yields nil.
func uiLocales(ui fs.FS) []string {
	if ui == nil {
		return nil
	}
	if _, err := fs.Stat(ui, "index.html"); err == nil {
		return nil
	}
	entries, err := fs.ReadDir(ui, ".")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			if _, err := fs.Stat(ui, e.Name()+"/index.html"); err == nil {
				out = append(out, e.Name())
			}
		}
	}
	slices.SortFunc(out, func(a, b string) int {
		switch {
		case a == defaultLocale:
			return -1
		case b == defaultLocale:
			return 1
		}
		return strings.Compare(a, b)
	})
	return out
}

// pickLocale chooses the UI language for a request.
func pickLocale(r *http.Request, available []string) string {
	if len(available) == 0 {
		return ""
	}
	if c, err := r.Cookie(langCookie); err == nil {
		for _, l := range available {
			if strings.EqualFold(l, c.Value) {
				return l
			}
		}
	}
	for _, want := range acceptLanguages(r.Header.Get("Accept-Language")) {
		// Exact match first (de-CH), then the same language (de).
		for _, l := range available {
			if strings.EqualFold(l, want) {
				return l
			}
		}
		base, _, _ := strings.Cut(want, "-")
		for _, l := range available {
			lb, _, _ := strings.Cut(l, "-")
			if strings.EqualFold(lb, base) {
				return l
			}
		}
	}
	return available[0]
}

// acceptLanguages returns the tags of an Accept-Language header, most
// preferred first.
func acceptLanguages(h string) []string {
	type tag struct {
		name string
		q    float64
	}
	var tags []tag
	for _, part := range strings.Split(h, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if name == "" || name == "*" {
			continue
		}
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				q = f
			}
		}
		if q > 0 {
			tags = append(tags, tag{name, q})
		}
	}
	slices.SortStableFunc(tags, func(a, b tag) int {
		switch {
		case a.q > b.q:
			return -1
		case a.q < b.q:
			return 1
		}
		return 0
	})
	out := make([]string, len(tags))
	for i, t := range tags {
		out[i] = t.name
	}
	return out
}
