package threat

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kochlabs/tributary/internal/config"
)

func prefixes(t *testing.T, ps []netip.Prefix) string {
	t.Helper()
	var s []string
	for _, p := range ps {
		s = append(s, p.String())
	}
	return strings.Join(s, " ")
}

func TestParse(t *testing.T) {
	cases := []struct {
		name, in string
		f        Format
		want     string
		skipped  int
	}{
		{"spamhaus json lines", `{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"2001:678:254::/48","sblid":"SBL697648","rir":"ripencc"}
{"type":"metadata","timestamp":1792752242,"size":102980,"records":2}`, Format{Kind: "json", Field: "cidr"}, "1.10.16.0/20 2001:678:254::/48", 1},
		{"json array", `[{"ip":"5.6.7.8"},{"ip":"9.9.9.0/24"},"x"]`, Format{Kind: "json", Field: "ip"}, "5.6.7.8/32 9.9.9.0/24", 1},
		{"json strings", `["5.6.7.8", "2001:db8::1"]`, Format{Kind: "json"}, "5.6.7.8/32 2001:db8::1/128", 0},
		{"drop.txt", "; Spamhaus DROP List\n; Last-Modified: x\n1.10.16.0/20 ; SBL256894\n1.19.0.0/16 ; SBL434604\n", Format{Kind: "text"}, "1.10.16.0/20 1.19.0.0/16", 0},
		{"feodo", "####\n# DstIP\n50.16.16.211\n# END 1 entries", Format{}, "50.16.16.211/32", 0},
		{"netset", "#\n# firehol_level1\n#\n0.0.0.0/8\n1.10.16.7/20\n", Format{Kind: "text"}, "0.0.0.0/8 1.10.16.0/20", 0},
		{"tabs and junk", "101.206.210.3\tbad\nnot an address\n\n// note\n", Format{Kind: "text"}, "101.206.210.3/32", 1},
		{"csv", "first_seen,dst_ip,port\n2026-01-01,50.16.16.211,443\n2026-01-02,\"60.1.1.1\",80\n", Format{Kind: "csv", Column: 2, Delimiter: ","}, "50.16.16.211/32 60.1.1.1/32", 1},
		{"tsv", "a\t1.2.3.4\n", Format{Kind: "csv", Column: 2, Delimiter: `\t`}, "1.2.3.4/32", 0},
	}
	for _, c := range cases {
		ps, skipped, err := Parse(strings.NewReader(c.in), c.f)
		if err != nil || prefixes(t, ps) != c.want || skipped != c.skipped {
			t.Errorf("%s: %q skipped %d err %v; want %q skipped %d", c.name, prefixes(t, ps), skipped, err, c.want, c.skipped)
		}
	}
	if _, _, err := Parse(strings.NewReader("<html>nope</html>"), Format{Kind: "text"}); err == nil {
		t.Error("an HTML page parsed as a feed")
	}
	if _, _, err := Parse(strings.NewReader(`{"a":1}`), Format{Kind: "json", Field: "cidr"}); err == nil {
		t.Error("JSON without the field parsed")
	}
}

func TestMatcher(t *testing.T) {
	mk := func(s ...string) []netip.Prefix {
		var ps []netip.Prefix
		for _, x := range s {
			p, _ := parsePrefix(x)
			ps = append(ps, p)
		}
		return ps
	}
	m := &Matcher{lists: []list{
		newList("1", "first", mk("1.10.16.0/20", "1.10.20.0/22", "1.10.32.0/24", "1.10.33.0/24", "2a00:1::/32")),
		newList("2", "second", mk("1.10.16.5", "8.8.8.8", "10.0.0.0/8", "100.64.0.0/10", "224.0.0.0/3", "0.0.0.0/0")),
	}}
	// The /22 is inside the /20, which ends where 1.10.32.0/24 starts, and that
	// is adjacent to 1.10.33.0/24: one IPv4 range, plus the IPv6 one.
	if n := len(m.lists[0].ranges); n != 2 {
		t.Fatalf("first list has %d ranges", n)
	}
	for addr, want := range map[string]string{
		"1.10.16.0":        "1",
		"1.10.31.255":      "1",
		"1.10.32.200":      "1",
		"1.10.33.255":      "1",
		"1.10.16.5":        "1", // first feed wins
		"8.8.8.8":          "2",
		"9.9.9.9":          "2", // 0.0.0.0/0
		"2a00:1:ffff::1":   "1",
		"2a00:2::1":        "",
		"10.1.2.3":         "", // private
		"192.168.1.1":      "",
		"100.100.1.1":      "", // CGNAT / Tailscale
		"224.0.0.251":      "", // multicast
		"127.0.0.1":        "",
		"169.254.1.1":      "",
		"203.0.113.9":      "", // documentation
		"::ffff:1.10.16.9": "1",
	} {
		if got := m.Match(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %q, want %q", addr, got, want)
		}
	}
	if f := m.Feeds(netip.MustParseAddr("1.10.16.5")); strings.Join(f, ",") != "first,second" {
		t.Errorf("feeds: %v", f)
	}
	var none *Matcher
	if none.Match(netip.MustParseAddr("1.2.3.4")) != "" {
		t.Error("nil matcher matched")
	}
}

func TestManager(t *testing.T) {
	cfg, err := config.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	if feeds, _ := cfg.ThreatFeeds(); len(feeds) != len(config.DefaultThreatFeeds) {
		t.Fatalf("seeded %d feeds", len(feeds))
	}
	// Our own feeds only: a served gzip list and a file.
	for _, f := range mustFeeds(t, cfg) {
		cfg.DeleteThreatFeed(f.ID)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	io.WriteString(zw, "# test\n198.51.99.0/24\n45.1.1.1\n")
	zw.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "Tributary/test" {
			http.Error(w, "no agent", 400)
			return
		}
		w.Write(gz.Bytes())
	}))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "list.json")
	os.WriteFile(file, []byte(`[{"cidr":"45.1.1.0/24"},{"cidr":"46.0.0.1"}]`), 0o644)
	id1, err := cfg.SaveThreatFeed(config.ThreatFeed{Name: "served", URL: srv.URL + "/list.txt.gz", Enabled: true, Notify: true})
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := cfg.SaveThreatFeed(config.ThreatFeed{Name: "file", URL: file, Format: "json", Field: "cidr", Enabled: true})
	cfg.SaveThreatFeed(config.ThreatFeed{Name: "broken", URL: srv.URL + "/x", Format: "json", Field: "nope", Enabled: true})

	m := &Manager{Cfg: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Dir: t.TempDir(), Client: func() *http.Client { return srv.Client() }, Agent: "Tributary/test"}
	m.init()
	m.updateDue(context.Background(), 0, true)
	// Match returns the feed's ID; Feeds lists every feed by name.
	if got := m.Match(netip.MustParseAddr("45.1.1.1")); got != strconv.FormatInt(id1, 10) {
		t.Fatalf("45.1.1.1 matched %q", got)
	}
	if got := m.Match(netip.MustParseAddr("45.1.1.2")); got != strconv.FormatInt(id2, 10) {
		t.Fatalf("45.1.1.2 matched %q", got)
	}
	if got := m.Feeds(netip.MustParseAddr("45.1.1.1")); len(got) != 2 || got[0] != "served" || got[1] != "file" {
		t.Fatalf("feeds for 45.1.1.1: %v", got)
	}
	f1, _ := cfg.ThreatFeed(id1)
	if f1.Entries != 2 || f1.LastSuccess == 0 || f1.LastError != "" {
		t.Fatalf("status: %+v", f1)
	}
	feeds := mustFeeds(t, cfg)
	if broken := feeds[len(feeds)-1]; broken.LastError == "" || broken.LastSuccess != 0 {
		t.Fatalf("broken feed: %+v", broken)
	}
	// Disabling a feed takes its list out of matching.
	f2, _ := cfg.ThreatFeed(id2)
	f2.Enabled = false
	cfg.SaveThreatFeed(f2)
	m.Reload()
	if m.Match(netip.MustParseAddr("46.0.0.1")) != "" {
		t.Fatal("a disabled feed still matches")
	}
	// The cached list survives a restart without downloading.
	m2 := &Manager{Cfg: cfg, Log: m.Log, Dir: m.Dir, Client: m.Client}
	m2.Reload()
	if m2.Match(netip.MustParseAddr("45.1.1.1")) != strconv.FormatInt(id1, 10) {
		t.Fatal("cached list not loaded")
	}
	// Defaults come back on request, without duplicating.
	if n, _ := cfg.AddDefaultThreatFeeds(); n != len(config.DefaultThreatFeeds) {
		t.Fatalf("restored %d defaults", n)
	}
	if n, _ := cfg.AddDefaultThreatFeeds(); n != 0 {
		t.Fatalf("restored %d defaults twice", n)
	}
}

func mustFeeds(t *testing.T, cfg *config.DB) []config.ThreatFeed {
	t.Helper()
	f, err := cfg.ThreatFeeds()
	if err != nil {
		t.Fatal(err)
	}
	return f
}
