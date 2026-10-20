package collector

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"nfa/internal/flow"
)

func TestExporterAllowlist(t *testing.T) {
	c := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Hooks{Sink: func([]flow.Record) {}})
	junk := []byte{0, 9, 0, 0} // not a valid datagram; only the accounting matters here
	var batch []flow.Record
	now := time.Now()

	c.handle(netip.MustParseAddr("203.0.113.9"), junk, now, &batch)
	if c.Packets.Load() != 1 || c.Rejected.Load() != 0 {
		t.Fatal("without an allowlist every source is accepted")
	}

	c.SetAllowedSources([]netip.Prefix{netip.MustParsePrefix("192.168.20.0/24"), netip.MustParsePrefix("fd7a:115c::/32")})
	c.handle(netip.MustParseAddr("192.168.20.1"), junk, now, &batch)
	c.handle(netip.MustParseAddr("fd7a:115c::5"), junk, now, &batch)
	c.handle(netip.MustParseAddr("198.51.100.7"), junk, now, &batch)
	c.handle(netip.MustParseAddr("198.51.100.7"), junk, now.Add(time.Second), &batch)
	if c.Packets.Load() != 3 || c.Rejected.Load() != 2 {
		t.Fatalf("packets %d rejected %d", c.Packets.Load(), c.Rejected.Load())
	}
	if _, ok := c.exporters.Load(netip.MustParseAddr("198.51.100.7")); ok {
		t.Fatal("a rejected source must not become an exporter")
	}
	rs := c.RejectedSources()
	if len(rs) != 1 || rs[0].Addr != "198.51.100.7" || rs[0].Datagrams != 2 {
		t.Fatalf("rejected sources: %+v", rs)
	}
	if st := c.Status(); !st.Allowlist || st.Rejected != 2 {
		t.Fatalf("status: %+v", st)
	}

	// The table is bounded.
	for i := 0; i < maxRejectedSources+10; i++ {
		c.handle(netip.AddrFrom4([4]byte{198, 18, 0, byte(i)}), junk, now.Add(time.Duration(i)*time.Second), &batch)
	}
	if n := len(c.RejectedSources()); n != maxRejectedSources {
		t.Fatalf("table size %d", n)
	}

	c.SetAllowedSources(nil)
	c.handle(netip.MustParseAddr("198.51.100.7"), junk, now, &batch)
	if c.Status().Allowlist || c.Rejected.Load() != 2+uint64(maxRejectedSources+10) {
		t.Fatal("clearing the allowlist accepts every source again")
	}
}
