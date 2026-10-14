package decode_test

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"nfa/internal/decode"
	"nfa/internal/flow"
	"nfa/internal/flowgen"
)

func sample(now time.Time) []flow.Record {
	return []flow.Record{
		{
			SrcAddr: netip.MustParseAddr("10.1.2.3"), DstAddr: netip.MustParseAddr("192.0.2.80"),
			NextHop: netip.MustParseAddr("10.0.0.1"),
			SrcPort: 51515, DstPort: 443, Proto: 6, TCPFlags: 0x1b, ToS: 0x28,
			InIf: 3, OutIf: 7, SrcAS: 64512, DstAS: 15169, SrcMask: 24, DstMask: 16, VLAN: 120,
			Bytes: 150000, Packets: 400, TimeStart: now.Add(-30 * time.Second), TimeEnd: now.Add(-time.Second),
		},
		{
			SrcAddr: netip.MustParseAddr("2001:db8::10"), DstAddr: netip.MustParseAddr("2001:db8:ffff::53"),
			SrcPort: 40000, DstPort: 53, Proto: 17,
			InIf: 4, OutIf: 9, SrcAS: 64512, DstAS: 13335, SrcMask: 64, DstMask: 48, VLAN: 200,
			Bytes: 9000, Packets: 200, TimeStart: now.Add(-10 * time.Second), TimeEnd: now.Add(-2 * time.Second),
		},
	}
}

func check(t *testing.T, got flow.Record, want flow.Record, sampling uint32, checkV6 bool) {
	t.Helper()
	if got.SrcAddr != want.SrcAddr || got.DstAddr != want.DstAddr {
		t.Errorf("addr: got %v->%v want %v->%v", got.SrcAddr, got.DstAddr, want.SrcAddr, want.DstAddr)
	}
	if got.SrcPort != want.SrcPort || got.DstPort != want.DstPort || got.Proto != want.Proto {
		t.Errorf("l4: got %d:%d/%d want %d:%d/%d", got.SrcPort, got.DstPort, got.Proto, want.SrcPort, want.DstPort, want.Proto)
	}
	if got.SamplingRate != sampling {
		t.Errorf("sampling: got %d want %d", got.SamplingRate, sampling)
	}
	if got.Bytes != want.Bytes || got.Packets != want.Packets {
		t.Errorf("counters: got %d/%d want %d/%d", got.Bytes, got.Packets, want.Bytes, want.Packets)
	}
	if got.InIf != want.InIf || got.OutIf != want.OutIf {
		t.Errorf("ifaces: got %d/%d want %d/%d", got.InIf, got.OutIf, want.InIf, want.OutIf)
	}
}

func TestV5(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	e := &flowgen.Exporter{Addr: netip.MustParseAddr("10.0.0.1"), Boot: now.Add(-time.Hour), Sampling: 10}
	recs := sample(now)[:1]
	d := decode.New()
	out, res, err := d.Decode(e.Addr, e.V5(now, recs), now, nil)
	if err != nil || res.Flows != 1 || len(out) != 1 {
		t.Fatalf("decode: %v %+v", err, res)
	}
	check(t, out[0], recs[0], 10, false)
	if out[0].SrcAS != 64512 || out[0].DstAS != 15169 || out[0].TCPFlags != 0x1b {
		t.Errorf("as/flags: %+v", out[0])
	}
	if d := out[0].TimeStart.Sub(recs[0].TimeStart); d > time.Millisecond || d < -time.Millisecond {
		t.Errorf("start time off by %v", d)
	}
}

func TestV9(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	e := &flowgen.Exporter{Addr: netip.MustParseAddr("10.0.0.2"), Boot: now.Add(-time.Hour), Sampling: 100, Domain: 7}
	recs := sample(now)
	d := decode.New()
	out, res, err := d.Decode(e.Addr, e.V9(now, recs), now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Templates != 3 || len(out) != 2 {
		t.Fatalf("got %d templates %d flows: %+v", res.Templates, len(out), res)
	}
	for i := range recs {
		check(t, out[i], recs[i], 100, true)
	}
	if out[0].VLAN != 120 || out[1].EType != flow.ETypeIPv6 {
		t.Errorf("vlan/etype: %+v", out)
	}
	// Second packet carries no templates and must use the cached ones.
	out, res, err = d.Decode(e.Addr, e.V9(now, recs), now, nil)
	if err != nil || len(out) != 2 || res.Templates != 0 {
		t.Fatalf("cached template decode: %v %+v", err, res)
	}
	// A different exporter has no templates yet.
	_, res, _ = d.Decode(netip.MustParseAddr("10.9.9.9"), e.V9(now, recs), now, nil)
	if res.MissingTmpl != 2 {
		t.Errorf("expected 2 missing templates, got %+v", res)
	}
}

func TestIPFIX(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	e := &flowgen.Exporter{Addr: netip.MustParseAddr("10.0.0.3"), Boot: now.Add(-time.Hour), Sampling: 4, Domain: 1}
	recs := sample(now)
	d := decode.New()
	out, res, err := d.Decode(e.Addr, e.IPFIX(now, recs), now, nil)
	if err != nil || len(out) != 2 {
		t.Fatalf("decode: %v %+v", err, res)
	}
	for i := range recs {
		check(t, out[i], recs[i], 4, true)
		if !out[i].TimeStart.Equal(recs[i].TimeStart) || !out[i].TimeEnd.Equal(recs[i].TimeEnd) {
			t.Errorf("times: got %v-%v want %v-%v", out[i].TimeStart, out[i].TimeEnd, recs[i].TimeStart, recs[i].TimeEnd)
		}
	}
}

func TestSFlow(t *testing.T) {
	now := time.Now()
	e := &flowgen.Exporter{Addr: netip.MustParseAddr("10.0.0.4"), Boot: now.Add(-time.Hour), Sampling: 512}
	recs := sample(now)
	recs[0].Packets, recs[0].Bytes = 1, 1400
	recs[1].Packets, recs[1].Bytes = 1, 200
	d := decode.New()
	out, res, err := d.Decode(netip.MustParseAddr("192.168.99.1"), e.SFlow(now, recs), now, nil)
	if err != nil || len(out) != 2 {
		t.Fatalf("decode: %v %+v", err, res)
	}
	if out[0].Exporter != e.Addr {
		t.Errorf("exporter should be sFlow agent address, got %v", out[0].Exporter)
	}
	for i := range recs {
		want := recs[i]
		want.Bytes *= 512
		want.Packets *= 512
		check(t, out[i], want, 512, true)
		if out[i].VLAN != recs[i].VLAN {
			t.Errorf("vlan: got %d want %d", out[i].VLAN, recs[i].VLAN)
		}
		// flowgen's synthetic Ethernet header: dst 00:1c:73:00:00:01, src 00:1c:73:00:00:02.
		if out[i].SrcMAC != 0x001c73000002 || out[i].DstMAC != 0x001c73000001 {
			t.Errorf("sflow macs: src %x dst %x", out[i].SrcMAC, out[i].DstMAC)
		}
	}
}

func TestGarbage(t *testing.T) {
	d := decode.New()
	a := netip.MustParseAddr("10.0.0.5")
	for _, p := range [][]byte{nil, {0, 9}, {0, 9, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}, {0, 10, 0, 3}, {0, 5, 0, 30}, {0, 0, 0, 5, 0, 0, 0, 1}} {
		_, _, _ = d.Decode(a, p, time.Now(), nil) // must not panic
	}
}

func FuzzDecode(f *testing.F) {
	now := time.Now()
	e := &flowgen.Exporter{Addr: netip.MustParseAddr("10.0.0.6"), Boot: now.Add(-time.Hour), Sampling: 2}
	recs := sample(now)
	f.Add(e.V5(now, recs[:1]))
	f.Add(e.V9(now, recs))
	f.Add(e.IPFIX(now, recs))
	f.Add(e.SFlow(now, recs))
	d := decode.New()
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = d.Decode(e.Addr, b, now, nil)
	})
}

func BenchmarkDecodeV9(b *testing.B) {
	now := time.Now()
	e := &flowgen.Exporter{Addr: netip.MustParseAddr("10.0.0.7"), Boot: now.Add(-time.Hour), Sampling: 1}
	recs := make([]flow.Record, 0, 24)
	for len(recs) < 24 {
		recs = append(recs, sample(now)...)
	}
	d := decode.New()
	_, _, _ = d.Decode(e.Addr, e.V9(now, recs), now, nil) // learn templates
	pkt := e.V9(now, recs)
	out := make([]flow.Record, 0, 64)
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _, _ = d.Decode(e.Addr, pkt, now, out[:0])
	}
	b.ReportMetric(float64(b.N*len(recs))/b.Elapsed().Seconds(), "flows/s")
}

// UniFi (ipt_NETFLOW) announces interface names as v9 options data:
// scope System/4, options ifIndex(10)/2, IF_NAME(82)/16, IF_DESC(83)/32.
func TestV9InterfaceNames(t *testing.T) {
	pkt := []byte{0, 9, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0}
	tmpl := []byte{0, 1, 0, 24, 1, 2, 0, 4, 0, 12, 0, 1, 0, 4, 0, 10, 0, 2, 0, 82, 0, 16, 0, 83, 0, 32}
	tmpl = append(tmpl, 0, 0) // pad to 4 bytes
	tmpl[3] = byte(len(tmpl))
	rec := make([]byte, 54)
	rec[5] = 17
	copy(rec[6:], "eth4")
	copy(rec[22:], "802.1Q VLAN Support")
	data := append([]byte{1, 2, 0, byte(4 + len(rec) + 2)}, rec...)
	data = append(data, 0, 0)
	pkt = append(append(pkt, tmpl...), data...)
	var got []string
	d := decode.New()
	d.OnInterface = func(_ netip.Addr, idx uint32, name, desc string) { got = append(got, fmt.Sprint(idx, name, "|", desc)) }
	if _, _, err := d.Decode(netip.MustParseAddr("192.168.20.1"), pkt, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "17eth4|802.1Q VLAN Support" {
		t.Fatalf("got %q", got)
	}
}

func TestSamplingSeedAndChange(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	e := &flowgen.Exporter{Addr: netip.MustParseAddr("10.0.0.8"), Boot: now.Add(-time.Hour), Sampling: 512}
	recs := sample(now)
	d := decode.New()
	var announced []uint32
	d.OnSampling = func(_ netip.Addr, r uint32, _ bool) { announced = append(announced, r) }
	first := e.V9(now, recs) // carries templates + options
	// A restarted collector sees data before options: seed must apply.
	d2 := decode.New()
	d2.SeedSampling(e.Addr, 512, false)
	_, _, _ = d2.Decode(e.Addr, first, now, nil)
	if out, _, _ := d.Decode(e.Addr, first, now, nil); out[0].SamplingRate != 512 {
		t.Fatalf("rate %d", out[0].SamplingRate)
	}
	_, _, _ = d.Decode(e.Addr, first, now, nil) // same rate again: no new announcement
	if len(announced) != 1 || announced[0] != 512 {
		t.Fatalf("announced %v", announced)
	}
}

// UniFi/ipt_NETFLOW tags sampled records with a sampler ID; once sampling is
// turned off, records carry no sampler field and must not inherit the old rate.
func TestStaleSamplerRateNotApplied(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	d := decode.New()
	exp := netip.MustParseAddr("192.168.20.1")
	d.SeedSampling(exp, 512, false)
	// v9 packet: template 300 = IPv4 src/dst, bytes, packets (no sampler ID), then one record.
	pkt := []byte{0, 9, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(pkt[8:], uint32(now.Unix()))
	pkt = append(pkt, 0, 0, 0, 24, 1, 44, 0, 4, 0, 8, 0, 4, 0, 12, 0, 4, 0, 1, 0, 4, 0, 2, 0, 4)
	pkt = append(pkt, 1, 44, 0, 20, 8, 8, 8, 8, 192, 168, 1, 2, 0, 0, 3, 232, 0, 0, 0, 2)
	out, _, err := d.Decode(exp, pkt, now, nil)
	if err != nil || len(out) != 1 {
		t.Fatalf("decode: %v %d", err, len(out))
	}
	if out[0].SamplingRate != 1 || out[0].Bytes != 1000 {
		t.Fatalf("unsampled record scaled: rate %d bytes %d", out[0].SamplingRate, out[0].Bytes)
	}
}

// RFC 7011 §8.4-style lifetime: a system-wide rate that stops being announced
// is withdrawn after repeated template refreshes, and the withdrawal reported.
func TestSamplingWithdrawnAfterSilentRefreshes(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	exp := netip.MustParseAddr("10.9.0.1")
	d := decode.New()
	var events []uint32
	d.OnSampling = func(_ netip.Addr, r uint32, _ bool) { events = append(events, r) }
	d.SeedSampling(exp, 100, true)
	if r, src := d.Sampling(exp); r != 100 || src != decode.SamplingRemembered {
		t.Fatalf("seed: %d %s", r, src)
	}
	// Templates only (no sampling options), refreshed every 5 minutes.
	tmpl := []byte{0, 9, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 12, 1, 44, 0, 1, 0, 8, 0, 4}
	for i := 0; i < 3; i++ {
		now := start.Add(time.Duration(i) * 5 * time.Minute)
		if _, _, err := d.Decode(exp, tmpl, now, nil); err != nil {
			t.Fatal(err)
		}
		r, _ := d.Sampling(exp)
		if i < 2 && r != 100 {
			t.Fatalf("withdrawn too early after %d refreshes", i+1)
		}
	}
	if r, src := d.Sampling(exp); r != 0 || src != decode.SamplingNone {
		t.Fatalf("not withdrawn: %d %s", r, src)
	}
	if len(events) != 1 || events[0] != 0 {
		t.Fatalf("events %v", events)
	}
	// A burst of template packets within a minute counts once.
	d.SeedSampling(exp, 100, true)
	for i := 0; i < 10; i++ {
		_, _, _ = d.Decode(exp, tmpl, start.Add(time.Hour+time.Duration(i)*time.Second), nil)
	}
	if r, _ := d.Sampling(exp); r != 100 {
		t.Fatalf("burst counted as multiple refreshes")
	}
}

// An exporter that keeps announcing its rate never has it withdrawn.
func TestSamplingKeptWhenReannounced(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	e := &flowgen.Exporter{Addr: netip.MustParseAddr("10.9.0.2"), Boot: now.Add(-time.Hour), Sampling: 64}
	recs := sample(now)
	d := decode.New()
	for i := 0; i < 10; i++ {
		t0 := now.Add(time.Duration(i) * 5 * time.Minute)
		for j := 0; j < 20; j++ { // templates + options ride on every 20th packet
			_, _, _ = d.Decode(e.Addr, e.V9(t0, recs), t0, nil)
		}
	}
	if r, src := d.Sampling(e.Addr); r != 64 || src != decode.SamplingAnnounced {
		t.Fatalf("got %d %s", r, src)
	}
}

// UniFi (ipt_NETFLOW) exports IN_SRC_MAC (56) and IN_DST_MAC (80).
func TestV9MACFields(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	exp := netip.MustParseAddr("192.168.20.1")
	pkt := []byte{0, 9, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(pkt[8:], uint32(now.Unix()))
	// template 300: src v4, dst v4, bytes, packets, IN_SRC_MAC/6, IN_DST_MAC/6
	pkt = append(pkt, 0, 0, 0, 32, 1, 44, 0, 6, 0, 8, 0, 4, 0, 12, 0, 4, 0, 1, 0, 4, 0, 2, 0, 4, 0, 56, 0, 6, 0, 80, 0, 6)
	rec := []byte{192, 168, 80, 45, 185, 40, 234, 113, 0, 0, 1, 0, 0, 0, 0, 1,
		0xbc, 0x24, 0x11, 0x52, 0xd1, 0x06, 0x94, 0x2a, 0x6f, 0xf8, 0x4d, 0x6d}
	pkt = append(append(pkt, 1, 44, 0, byte(4+len(rec))), rec...)
	out, _, err := decode.New().Decode(exp, pkt, now, nil)
	if err != nil || len(out) != 1 {
		t.Fatalf("decode: %v %d", err, len(out))
	}
	if out[0].SrcMAC != 0xbc241152d106 || out[0].DstMAC != 0x942a6ff84d6d {
		t.Fatalf("macs: %x %x", out[0].SrcMAC, out[0].DstMAC)
	}
}
