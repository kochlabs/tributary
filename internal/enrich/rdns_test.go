package enrich

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestGenericPTR(t *testing.T) {
	cases := []struct {
		ip, name string
		want     bool
	}{
		{"2603:7083:8640:9600:9485:a7e8:4bd1:2faf", "syn-2603-7083-8640-9600-9485-a7e8-4bd1-2faf.res6.spectrum.com", true},
		{"203.0.113.7", "cpe-203-0-113-7.example.net", true},
		{"203.0.113.7", "7.113.0.203.static.example.net", true},
		{"142.250.219.136", "tzrioa-aj-in-f8.1e100.net", false},
		{"192.168.80.210", "MacBookPro", false},
		{"2620:138:302d:4:8000::12", "edge.hulu.example", false},
	}
	for _, c := range cases {
		if got := GenericPTR(netip.MustParseAddr(c.ip), c.name); got != c.want {
			t.Errorf("%s %s: got %v", c.ip, c.name, got)
		}
	}
}

func TestASNCachePersist(t *testing.T) {
	path := t.TempDir() + "/asn.json"
	a := NewASNLookup()
	a.mu.Lock()
	a.cache[netip.MustParsePrefix("2620:138:302d::/48")] = asnEntry{asn: 23344, exp: time.Now().Add(time.Hour)}
	a.cache[netip.MustParsePrefix("203.0.113.0/24")] = asnEntry{asn: 0, exp: time.Now().Add(time.Hour)} // negative: not saved
	a.names[23344] = "Disney Worldwide Services, Inc."
	a.mu.Unlock()
	if err := a.Save(path); err != nil {
		t.Fatal(err)
	}
	b := NewASNLookup()
	if err := b.Load(path); err != nil {
		t.Fatal(err)
	}
	if got := b.Get(netip.MustParseAddr("2620:138:302d:4:8000::12")); got != 23344 {
		t.Fatalf("asn %d", got)
	}
	if b.Name(23344) != "Disney Worldwide Services, Inc." || len(b.cache) != 1 {
		t.Fatalf("names %v cache %d", b.names, len(b.cache))
	}
}

func TestVendor(t *testing.T) {
	tbl := newOUITable()
	registry := "Registry,Assignment,Organization Name,Organization Address\n" +
		"MA-L,24E50F,\"Google, Inc.\",Mountain View\n" +
		"MA-L,BC2411,Proxmox Server Solutions GmbH,Vienna\n" +
		"MA-L,942A6F,Ubiquiti Inc,New York\n" +
		"MA-L,001132,Synology Incorporated,Taipei\n" +
		"MA-L,001BC5,IEEE Registration Authority,Piscataway\n" +
		"MA-S,001BC5000,Converging Systems Inc.,Somewhere\n"
	if err := parseOUI(strings.NewReader(registry), tbl); err != nil {
		t.Fatal(err)
	}
	ouiCur.Store(tbl)
	defer ouiCur.Store(nil)
	cases := map[string]string{
		"24:e5:0f:d8:b3:87": "Google, Inc.",
		"bc:24:11:52:d1:06": "Proxmox Server Solutions GmbH",
		"94:2a:6f:f8:4d:6d": "Ubiquiti Inc",
		"00:11:32:7d:2b:3b": "Synology Incorporated",
		"4a:d6:09:a8:9e:8a": "Private (randomized) address",
		"00:1b:c5:00:00:01": "Converging Systems Inc.", // a /36 (MA-S) block inside an /24
	}
	for s, want := range cases {
		m, ok := ParseMAC(s)
		if !ok {
			t.Fatalf("parse %s", s)
		}
		if got := Vendor(m); got != want {
			t.Errorf("%s: got %q want %q", s, got, want)
		}
		if FormatMAC(m) != s {
			t.Errorf("format round trip: %s -> %s", s, FormatMAC(m))
		}
	}
}
