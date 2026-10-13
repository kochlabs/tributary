package enrich

import (
	"net/netip"
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
