package store

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/kochlabs/tributary/internal/query"
)

type fakeNames struct{}

func (fakeNames) HostAddrs(name string) []netip.Addr {
	switch strings.ToLower(name) {
	case "nas":
		return []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("2001:db8::10")}
	case "big":
		out := make([]netip.Addr, MaxNameAddrs+1)
		for i := range out {
			out[i] = netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		}
		return out
	}
	return nil
}

func (fakeNames) DeviceMACs(name string) []uint64 {
	if strings.EqualFold(name, "Living room TV") {
		return []uint64{0xaabbccddeeff}
	}
	return nil
}

func compile(t *testing.T, q string) (*Filter, []query.Warning, error) {
	t.Helper()
	n, err := query.Parse(q)
	if err != nil {
		t.Fatalf("%q: %v", q, err)
	}
	return CompileQuery(n, fakeNames{})
}

// condArgs pairs each condition with its arguments, sorted, so filters can
// be compared regardless of order.
func condArgs(f *Filter) []string {
	var out []string
	i := 0
	for _, c := range f.conds {
		n := strings.Count(c, "?")
		out = append(out, fmt.Sprintf("%s %v", c, f.args[i:i+n]))
		i += n
	}
	slices.Sort(out)
	return out
}

// Classic filters converted to queries select the same flows: the same
// conditions, with the same arguments.
func TestFiltersToQueryEquivalence(t *testing.T) {
	SetThreatFeeds(map[string]string{"1": "Spamhaus DROP (IPv4)"})
	defer SetThreatFeeds(nil)
	for _, m := range []map[string]string{
		{"host": "10.0.0.5"},
		{"host": "10.0.0.0/8,2001:db8::/32", "dst_port": "443,8000-8100"},
		{"src": "!192.168.1.0/24", "proto": "tcp,17", "country": "!US,CA"},
		{"exporter": "127.0.1.1", "iface": "3", "etype": "6", "direction": "upload"},
		{"app": "tcp/443", "src_as": "65001", "dst_country": "DE", "vlan": "10", "dscp": "46"},
		{"threat": "*", "device": "aa:bb:cc:dd:ee:ff"},
		{"threat": "Spamhaus DROP (IPv4)", "peer": "10.0.0.9", "nexthop": "10.0.0.1"},
		{"in_if": "1,2", "out_if": "!4", "as": "13335", "flow_type": "3", "src_country": "FR", "port": "53", "src_port": "1-1023"},
	} {
		legacy, err := ParseFilter(m)
		if err != nil {
			t.Fatalf("%v: %v", m, err)
		}
		q := FiltersToQuery(m)
		f, warns, err := compile(t, q)
		if err != nil || len(warns) > 0 {
			t.Fatalf("%q: %v %v", q, err, warns)
		}
		if a, b := condArgs(legacy), condArgs(f); !slices.Equal(a, b) {
			t.Errorf("%v → %q\nlegacy %v\nquery  %v", m, q, a, b)
		}
		if legacy.rollupOK != f.rollupOK {
			t.Errorf("%q: rollup %v, want %v", q, f.rollupOK, legacy.rollupOK)
		}
	}
}

func TestFiltersToQuery(t *testing.T) {
	got := FiltersToQuery(map[string]string{"threat": "Spamhaus DROP (IPv4)", "dst_port": "!22,23", "host": "2001:db8::1", "bogus": "x"})
	want := `dst_port:(22 OR 23) AND host:2001:db8::1 AND threat:"Spamhaus DROP (IPv4)"`
	want = strings.Replace(want, "dst_port", "NOT dst_port", 1)
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCompileQuery(t *testing.T) {
	for _, c := range []struct {
		q, sql string
		args   []any
	}{
		{"bytes:>100MB", "(bytes > ?)", []any{uint64(100e6)}},
		{"bytes:[1KiB TO *]", "(bytes >= ?)", []any{uint64(1024)}},
		{"duration:>=5m", "(" + durationExpr + " >= ?)", []any{uint64(300000)}},
		{"dst_port:[1 TO 1023]", "(dst_port BETWEEN ? AND ?)", []any{uint64(1), uint64(1023)}},
		{"port:<1024", "(src_port < ? OR dst_port < ?)", []any{uint64(1024), uint64(1024)}},
		{"as:AS13335", "((src_as = ? OR dst_as = ?))", []any{uint64(13335), uint64(13335)}},
		{"flags:syn", "((proto = 6 AND bitAnd(tcp_flags, ?) != 0))", []any{uint8(2)}},
		{"mac:aa:bb:cc:dd:ee:ff", "((src_mac = ? OR dst_mac = ?))", []any{uint64(0xaabbccddeeff), uint64(0xaabbccddeeff)}},
		{"vlan:*", "(vlan != 0)", nil},
		{"host:nas", "((src_addr IN (toIPv6(?), toIPv6(?)) OR dst_addr IN (toIPv6(?), toIPv6(?))))", []any{"192.168.1.10", "2001:db8::10", "192.168.1.10", "2001:db8::10"}},
		{`device:"living room tv"`, "((device_mac IN (?)))", []any{uint64(0xaabbccddeeff)}},
		{"src:10.0.0.10-10.0.0.20", "((src_addr BETWEEN toIPv6(?) AND toIPv6(?)))", []any{"::ffff:10.0.0.10", "::ffff:10.0.0.20"}},
		{"tcp.port:22", "(((src_port = ? OR dst_port = ?)) AND proto = 6)", []any{uint64(22), uint64(22)}},
		{"dst_port:!22", "NOT ((dst_port = ?))", []any{uint64(22)}},
	} {
		f, w, err := compile(t, c.q)
		if err != nil || len(w) > 0 {
			t.Errorf("%q: %v %v", c.q, err, w)
			continue
		}
		if len(f.conds) != 1 || f.conds[0] != c.sql || fmt.Sprint(f.args) != fmt.Sprint(c.args) {
			t.Errorf("%q:\n got %v %v\nwant %s %v", c.q, f.conds, f.args, c.sql, c.args)
		}
	}
	// Adjacent terms OR, AND binds tighter; NOT applies to its term.
	f, _, _ := compile(t, "dst_port:22 dst_port:23 AND NOT proto:udp")
	if want := "(((dst_port = ?)) OR (((dst_port = ?)) AND NOT ((proto = ?))))"; f.conds[0] != want {
		t.Errorf("got %s", f.conds[0])
	}
	// A top-level AND gives separate conditions; rollup only for rollup fields.
	f, _, _ = compile(t, "exporter:127.0.1.1 AND proto:tcp")
	if len(f.conds) != 2 || !f.rollupOK {
		t.Errorf("%v rollup %v", f.conds, f.rollupOK)
	}
	if f, _, _ = compile(t, "exporter:127.0.1.1 AND bytes:>1"); f.rollupOK {
		t.Error("bytes can't use the rollup")
	}
}

func TestCompileWarnings(t *testing.T) {
	f, w, err := compile(t, "host:nass OR dst_port:22")
	if err != nil || len(w) != 1 || w[0].Msg != "no host named nass" || w[0].Span != (query.Span{Pos: 5, Len: 4}) {
		t.Fatalf("%v %+v", err, w)
	}
	if f.conds[0] != "((0) OR ((dst_port = ?)))" {
		t.Errorf("an unknown name matches nothing: %s", f.conds[0])
	}
	if _, w, _ = compile(t, `threat:"No such feed"`); len(w) != 1 {
		t.Errorf("unknown feed: %+v", w)
	}
	if _, w, _ = compile(t, `device:"Kitchen"`); len(w) != 1 || w[0].Msg != "no device named Kitchen" {
		t.Errorf("unknown device: %+v", w)
	}
}

func TestCompileErrors(t *testing.T) {
	for _, c := range []struct{ q, msg, hint string }{
		{"dst_prot:443", "unknown field dst_prot", "did you mean dst_port?"},
		{"443", "a number alone isn't a host", "use port:443 or dst_port:443"},
		{"dst_port:https", "dst_port takes a number", ""},
		{"dst_port:70000", "dst_port is at most 65535", ""},
		{"bytes:>lots", "bytes takes a size such as 100MB", ""},
		{"src:10.0.0.0/33", "src: invalid address or prefix 10.0.0.0/33", ""},
		{"src:10.0.0.256", "src: invalid address or prefix 10.0.0.256", ""},
		{"country:>3", "country can't be compared with >", ""},
		{"proto:*", "proto:* isn't supported", ""},
		{"dst_port:[9 TO 1]", "the range is backwards", ""},
		{"flags:foo", "unknown TCP flag foo", "fin, syn, rst, psh, ack, urg, ece or cwr"},
		{"country:USA", "country: country must be a 2-letter ISO code, got \"USA\"", ""},
		{"host:big", "big matches 257 addresses", "use a prefix such as 10.0.0.0/24"},
	} {
		_, _, err := compile(t, c.q)
		var qe *query.Error
		if !errors.As(err, &qe) || qe.Msg != c.msg || qe.Hint != c.hint {
			t.Errorf("%q: got %v, want %q (%q)", c.q, err, c.msg, c.hint)
		}
	}
}
