// Command flowgen simulates a small enterprise network exporting flows, for
// testing and demonstrating the appliance without real routers.
//
//	flowgen -target 127.0.0.1 -rate 2000          # live UDP export
//	flowgen -backfill 24h -backfill-rate 100        # insert history into ClickHouse
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"nfa/internal/enrich"
	"nfa/internal/flow"
	"nfa/internal/flowgen"
	"nfa/internal/store"
)

type device struct {
	name   string
	src    string // local source address the datagrams come from
	proto  string // v5 | v9 | ipfix | sflow
	port   int
	enc    *flowgen.Exporter
	weight float64
	ifWAN  uint32
	ifLAN  []uint32
}

type service struct {
	name     string
	proto    uint8
	port     uint16
	weight   float64
	external bool
	reqMean  float64 // log-mean bytes client->server
	respMean float64 // log-mean bytes server->client
	dscp     uint8
}

var services = []service{
	{"https", 6, 443, 40, true, 8.0, 12.0, 0},
	{"quic", 17, 443, 12, true, 8.5, 12.5, 0},
	{"http", 6, 80, 5, true, 7.5, 11.0, 0},
	{"dns", 17, 53, 14, true, 4.5, 5.5, 0},
	{"ntp", 17, 123, 2, true, 4.4, 4.4, 0},
	{"smtp", 6, 25, 1, true, 9.0, 7.0, 0},
	{"ssh", 6, 22, 2, false, 8.0, 10.0, 16},
	{"smb", 6, 445, 6, false, 9.0, 13.0, 0},
	{"rdp", 6, 3389, 2, false, 9.5, 11.5, 34},
	{"mysql", 6, 3306, 3, false, 8.0, 11.0, 0},
	{"postgres", 6, 5432, 3, false, 8.0, 11.5, 0},
	{"ldap", 6, 389, 2, false, 6.5, 7.5, 0},
	{"kerberos", 17, 88, 1, false, 6.0, 6.5, 0},
	{"syslog", 17, 514, 2, false, 7.5, 0, 0},
	{"snmp", 17, 161, 1, false, 5.0, 6.0, 0},
	{"sip", 17, 5060, 1, true, 6.5, 6.5, 46},
	{"rtp", 17, 16384, 2, true, 11.0, 11.0, 46},
	{"icmp", 1, 0, 1, true, 4.5, 4.5, 0},
	{"wireguard", 17, 51820, 1, true, 10.0, 10.0, 0},
}

type asn struct {
	as     uint32
	prefix netip.Prefix
	weight float64
}

var internet = []asn{
	{15169, netip.MustParsePrefix("142.250.0.0/15"), 30},
	{13335, netip.MustParsePrefix("104.16.0.0/13"), 15},
	{16509, netip.MustParsePrefix("52.0.0.0/11"), 18},
	{8075, netip.MustParsePrefix("13.104.0.0/14"), 14},
	{32934, netip.MustParsePrefix("157.240.0.0/16"), 8},
	{2906, netip.MustParsePrefix("198.38.96.0/19"), 6},
	{20940, netip.MustParsePrefix("23.32.0.0/11"), 6},
	{14618, netip.MustParsePrefix("3.80.0.0/12"), 5},
	{54113, netip.MustParsePrefix("151.101.0.0/16"), 4},
	{15169, netip.MustParsePrefix("2607:f8b0::/32"), 4},
	{13335, netip.MustParsePrefix("2606:4700::/32"), 3},
}

const ourAS = 64512

type model struct {
	r        *rand.Rand
	clients  []netip.Addr
	clients6 []netip.Addr
	macs     map[netip.Addr]uint64 // client address -> device MAC (v4 and v6 share one)
	servers  map[string][]netip.Addr
	zipf     *rand.Zipf
	extHosts [][]netip.Addr // per ASN, a fixed pool so top talkers are stable
}

func newModel(seed uint64) *model {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	m := &model{r: r, servers: map[string][]netip.Addr{}, macs: map[netip.Addr]uint64{}}
	for i := 0; i < 400; i++ {
		a := netip.AddrFrom4([4]byte{10, 10, byte(i / 250), byte(10 + i%250)})
		m.clients = append(m.clients, a)
		m.macs[a] = clientMAC(i)
	}
	for i := 0; i < 80; i++ {
		a := netip.MustParseAddr(fmt.Sprintf("2001:db8:10::%x", 0x100+i))
		m.clients6 = append(m.clients6, a)
		m.macs[a] = clientMAC(i) // dual-stack: the same devices as the first IPv4 clients
	}
	m.zipf = rand.NewZipf(r, 1.15, 4, uint64(len(m.clients)-1))
	srv := func(name string, ips ...string) {
		for _, ip := range ips {
			m.servers[name] = append(m.servers[name], netip.MustParseAddr(ip))
		}
	}
	srv("smb", "10.20.1.10", "10.20.1.11")
	srv("rdp", "10.20.2.20", "10.20.2.21", "10.20.2.22")
	srv("mysql", "10.20.3.30")
	srv("postgres", "10.20.3.31", "10.20.3.32")
	srv("ldap", "10.20.0.5", "10.20.0.6")
	srv("kerberos", "10.20.0.5", "10.20.0.6")
	srv("syslog", "10.20.9.50")
	srv("snmp", "10.20.9.51")
	srv("ssh", "10.20.4.40", "10.20.4.41", "10.20.4.42")
	for _, a := range internet {
		var pool []netip.Addr
		for i := 0; i < 25; i++ {
			b := a.prefix.Addr().AsSlice()
			for j := len(b) - 3; j < len(b); j++ {
				if (j*8) >= a.prefix.Bits() || j == len(b)-1 {
					b[j] = byte(r.IntN(254) + 1)
				}
			}
			ip, _ := netip.AddrFromSlice(b)
			pool = append(pool, ip)
		}
		m.extHosts = append(m.extHosts, pool)
	}
	return m
}

// Organisationally unique identifiers of common client and server vendors,
// so simulated devices get realistic vendor names. MACs are derived from the
// client index, so they are stable across runs.
var clientOUIs = []uint64{
	0x3C22FB, // Apple
	0xF4D488, // Apple
	0x001E4F, // Dell
	0x18DBF2, // Dell
	0x3417EB, // Dell
	0x9C7BEF, // Hewlett Packard
	0x54EE75, // Wistron InfoComm (Lenovo)
	0x8C1645, // LCFC (Lenovo)
	0x00155D, // Microsoft (Hyper-V)
	0x005056, // VMware
	0xB827EB, // Raspberry Pi Foundation
	0x001132, // Synology
	0x00248C, // ASUSTek
	0x7085C2, // ASRock
	0xD8BBC1, // Micro-Star (MSI)
	0x28CFE9, // Apple
}

func clientMAC(i int) uint64 {
	if i%9 == 4 {
		// Phones and laptops on Wi-Fi often use a private (randomized) MAC.
		return 0x0A0000000000 | uint64(0xC0FFEE00+i)<<4&0xFFFFFFFFFF
	}
	return clientOUIs[i%len(clientOUIs)]<<24 | uint64(0x100000+i*7919)&0xFFFFFF
}

func (m *model) pickWeighted(n int, w func(int) float64) int {
	total := 0.0
	for i := 0; i < n; i++ {
		total += w(i)
	}
	x := m.r.Float64() * total
	for i := 0; i < n; i++ {
		x -= w(i)
		if x <= 0 {
			return i
		}
	}
	return n - 1
}

func (m *model) logn(mean float64) uint64 {
	if mean == 0 {
		return 0
	}
	return uint64(math.Exp(mean + m.r.NormFloat64()*1.1))
}

// diurnal returns a traffic multiplier for business-hours shaped load.
func diurnal(t time.Time) float64 {
	h := float64(t.Hour()) + float64(t.Minute())/60
	v := 0.25 + 0.75*math.Max(0, math.Sin((h-6)/14*math.Pi))
	if wd := t.Weekday(); wd == time.Saturday || wd == time.Sunday {
		v *= 0.35
	}
	return v
}

// session generates the records for one conversation (one or two directions).
func (m *model) session(now time.Time, d *device) []flow.Record {
	svc := services[m.pickWeighted(len(services), func(i int) float64 { return services[i].weight })]
	v6 := svc.external && d.proto != "v5" && m.r.Float64() < 0.15 // v5 is IPv4-only
	var client, server netip.Addr
	var srcAS, dstAS uint32 = 0, 0
	if v6 {
		client = m.clients6[m.r.IntN(len(m.clients6))]
	} else {
		client = m.clients[m.zipf.Uint64()]
	}
	if svc.external {
		var idx int
		for {
			idx = m.pickWeighted(len(internet), func(i int) float64 { return internet[i].weight })
			if internet[idx].prefix.Addr().Is6() == v6 {
				break
			}
		}
		pool := m.extHosts[idx]
		server = pool[int(math.Min(float64(len(pool)-1), math.Abs(m.r.NormFloat64())*6))]
		dstAS = internet[idx].as
		srcAS = ourAS
	} else {
		ss := m.servers[svc.name]
		server = ss[m.r.IntN(len(ss))]
	}
	if svc.name == "smtp" && !v6 && m.r.Float64() < 0.5 {
		// Inbound mail to our MX
		client, server = server, netip.MustParseAddr("10.20.5.25")
		srcAS, dstAS = dstAS, ourAS
	}
	dur := time.Duration(m.r.ExpFloat64()*20*float64(time.Second)) + time.Second
	start := now.Add(-dur)
	sport := uint16(32768 + m.r.IntN(28000))
	lan := d.ifLAN[m.r.IntN(len(d.ifLAN))]
	inIf, outIf := lan, d.ifWAN
	if !svc.external {
		outIf = d.ifLAN[(m.r.IntN(len(d.ifLAN)))]
	}
	reqB := max(m.logn(svc.reqMean), 64)
	mk := func(src, dst netip.Addr, sp, dp uint16, b uint64, in, out uint32, sas, das uint32) flow.Record {
		pk := max(b/max(uint64(400+m.r.IntN(1000)), 1), 1)
		r := flow.Record{
			SrcAddr: src, DstAddr: dst, SrcPort: sp, DstPort: dp, Proto: svc.proto, Bytes: b, Packets: pk,
			InIf: in, OutIf: out, SrcAS: sas, DstAS: das, ToS: svc.dscp << 2, TimeStart: start, TimeEnd: now,
			SrcMask: 24, DstMask: 24,
		}
		if svc.proto == 6 {
			r.TCPFlags = 0x1b
		}
		if svc.proto == 1 {
			r.SrcPort, r.DstPort = 0, 0x0800
		}
		if v6 {
			r.SrcMask, r.DstMask = 64, 32
		}
		if lan := in; lan >= 10 {
			r.VLAN = uint16(lan * 10)
		}
		// Gateways like UniFi report the MAC of the local sender.
		r.SrcMAC = m.macs[src]
		return r
	}
	recs := []flow.Record{mk(client, server, sport, svc.port, reqB, inIf, outIf, srcAS, dstAS)}
	if svc.respMean > 0 {
		recs = append(recs, mk(server, client, svc.port, sport, max(m.logn(svc.respMean), 64), outIf, inIf, dstAS, srcAS))
	}
	// An occasional scanner hitting the edge from the internet.
	if d.proto == "ipfix" && m.r.Float64() < 0.02 {
		scanner := netip.AddrFrom4([4]byte{185, 220, 101, byte(m.r.IntN(8) + 1)})
		for i := 0; i < 5; i++ {
			recs = append(recs, flow.Record{SrcAddr: scanner, DstAddr: netip.AddrFrom4([4]byte{203, 0, 113, byte(m.r.IntN(30) + 1)}),
				SrcPort: uint16(40000 + m.r.IntN(20000)), DstPort: []uint16{22, 23, 3389, 445, 8080, 5900}[m.r.IntN(6)], Proto: 6,
				TCPFlags: 0x02, Bytes: 60, Packets: 1, InIf: d.ifWAN, OutIf: 0, SrcAS: 208294, TimeStart: now, TimeEnd: now})
		}
	}
	return recs
}

func devices(sampleV5 uint32) []*device {
	boot := time.Now().Add(-37 * 24 * time.Hour)
	mk := func(name, src, proto string, port int, sampling uint32, weight float64, wan uint32, lan ...uint32) *device {
		return &device{name: name, src: src, proto: proto, port: port, weight: weight, ifWAN: wan, ifLAN: lan,
			enc: &flowgen.Exporter{Addr: netip.MustParseAddr(src), Boot: boot, Sampling: sampling, Domain: 1}}
	}
	return []*device{
		mk("core-rtr-01", "127.0.1.1", "v9", 2055, 1, 0.45, 1, 2, 3, 4),
		mk("edge-fw-01", "127.0.1.2", "ipfix", 4739, 1, 0.30, 1, 2, 5),
		mk("dc-sw-01", "127.0.1.3", "sflow", 6343, 256, 0.15, 49, 10, 11, 12, 13),
		mk("branch-rtr-01", "127.0.1.4", "v5", 2055, sampleV5, 0.10, 1, 2),
	}
}

func main() {
	target := flag.String("target", "127.0.0.1", "collector address")
	rate := flag.Float64("rate", 1500, "approximate flows per second at peak (live mode)")
	duration := flag.Duration("duration", 0, "stop after this long (0 = forever)")
	backfill := flag.Duration("backfill", 0, "insert this much history directly into ClickHouse, then exit")
	bfRate := flag.Float64("backfill-rate", 60, "flows per second at peak for backfill")
	chAddr := flag.String("ch-addr", "127.0.0.1:9000", "ClickHouse address (backfill)")
	chUser := flag.String("ch-user", "netflow", "ClickHouse user (backfill)")
	chPassFile := flag.String("ch-password-file", "/etc/netflow/clickhouse.pw", "ClickHouse password file (backfill)")
	portOffset := flag.Int("port-offset", 0, "add this to the standard collector ports (live mode), e.g. to feed a demo instance")
	geoDir := flag.String("geoip-dir", "", "GeoIP database directory used to enrich backfilled flows (e.g. /var/lib/nfa/geoip)")
	flag.Parse()

	devs := devices(10)
	for _, d := range devs {
		d.port += *portOffset
	}
	m := newModel(uint64(time.Now().UnixNano()))
	if *backfill > 0 {
		pw, _ := os.ReadFile(*chPassFile)
		if err := runBackfill(m, devs, *backfill, *bfRate, *chAddr, *chUser, strings.TrimSpace(string(pw)), *geoDir); err != nil {
			log.Fatal(err)
		}
		return
	}
	runLive(m, devs, *target, *rate, *duration)
}

func pick(m *model, devs []*device) *device {
	return devs[m.pickWeighted(len(devs), func(i int) float64 { return devs[i].weight })]
}

func runLive(m *model, devs []*device, target string, rate float64, duration time.Duration) {
	conns := map[*device]*net.UDPConn{}
	for _, d := range devs {
		raddr := &net.UDPAddr{IP: net.ParseIP(target), Port: d.port}
		c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(d.src)}, raddr)
		if err != nil {
			log.Fatalf("%s: %v", d.name, err)
		}
		conns[d] = c
		log.Printf("exporter %-14s %-15s -> %s:%d (%s, 1:%d)", d.name, d.src, target, d.port, d.proto, d.enc.Sampling)
	}
	pending := map[*device][]flow.Record{}
	tick := 100 * time.Millisecond
	t := time.NewTicker(tick)
	end := time.Now().Add(duration)
	var sent, pkts uint64
	lastLog := time.Now()
	for now := range t.C {
		if duration > 0 && now.After(end) {
			break
		}
		n := rate * diurnal(now) * tick.Seconds() / 1.9 // ~1.9 records per session
		sessions := int(n)
		if m.r.Float64() < n-float64(sessions) {
			sessions++
		}
		for i := 0; i < sessions; i++ {
			d := pick(m, devs)
			recs := m.session(now, d)
			if d.proto == "sflow" {
				// sFlow samples packets: keep roughly 1 in Sampling packets.
				for _, r := range recs {
					if m.r.Float64() < math.Min(1, float64(r.Packets)/float64(d.enc.Sampling)) {
						r.Packets, r.Bytes = 1, max(r.Bytes/r.Packets, 64)
						pending[d] = append(pending[d], r)
					}
				}
				continue
			}
			pending[d] = append(pending[d], recs...)
		}
		for d, recs := range pending {
			for len(recs) > 0 {
				chunk := min(len(recs), map[string]int{"v5": 30, "v9": 24, "ipfix": 24, "sflow": 8}[d.proto])
				var pkt []byte
				switch d.proto {
				case "v5":
					pkt = d.enc.V5(now, recs[:chunk])
				case "v9":
					pkt = d.enc.V9(now, recs[:chunk])
				case "ipfix":
					pkt = d.enc.IPFIX(now, recs[:chunk])
				case "sflow":
					pkt = d.enc.SFlow(now, recs[:chunk])
				}
				if _, err := conns[d].Write(pkt); err == nil {
					pkts++
					sent += uint64(chunk)
				}
				recs = recs[chunk:]
			}
			pending[d] = recs[:0]
		}
		if now.Sub(lastLog) >= 10*time.Second {
			log.Printf("sent %d records in %d datagrams (%.0f rec/s)", sent, pkts, float64(sent)/now.Sub(lastLog).Seconds())
			sent, pkts, lastLog = 0, 0, now
		}
	}
}

// runBackfill writes synthetic history straight into ClickHouse, ending one
// minute ago so it doesn't overlap live traffic.
func runBackfill(m *model, devs []*device, span time.Duration, rate float64, addr, user, pw, geoDir string) error {
	ctx := context.Background()
	st, err := store.Open(ctx, store.Options{Addr: addr, User: user, Password: pw})
	if err != nil {
		return err
	}
	defer st.Close()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	w := st.NewWriter(logger)
	var geo *enrich.Geo
	if geoDir != "" {
		geo = enrich.NewGeo(geoDir, logger)
		if err := geo.Load(); err != nil {
			return err
		}
	}
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(wctx); close(done) }()

	end := time.Now().Add(-time.Minute).Truncate(time.Second)
	start := end.Add(-span)
	var total int
	var batch []flow.Record
	for ts := start; ts.Before(end); ts = ts.Add(time.Second) {
		n := rate * diurnal(ts) / 1.9
		sessions := int(n)
		if m.r.Float64() < n-float64(sessions) {
			sessions++
		}
		for i := 0; i < sessions; i++ {
			d := pick(m, devs)
			for _, r := range m.session(ts, d) {
				r.TimeReceived = ts
				r.Type = map[string]flow.Type{"v5": flow.TypeNetFlowV5, "v9": flow.TypeNetFlowV9, "ipfix": flow.TypeIPFIX, "sflow": flow.TypeSFlowV5}[d.proto]
				r.Exporter = d.enc.Addr
				// Records already describe real volumes; only label the sampling rate.
				r.SamplingRate = 1
				r.Normalize()
				if d.proto == "sflow" || d.proto == "v5" {
					r.SamplingRate = d.enc.Sampling
				}
				if geo != nil {
					geo.Enrich(&r)
				}
				// Attribute the flow to its local device, as the collector does.
				if mac := m.macs[r.SrcAddr]; mac != 0 {
					r.DeviceMAC = mac
				} else {
					r.DeviceMAC = m.macs[r.DstAddr]
				}
				batch = append(batch, r)
			}
		}
		if len(batch) >= 20000 {
			for w.QueueLen() > 4 {
				time.Sleep(50 * time.Millisecond)
			}
			w.Submit(batch)
			total += len(batch)
			batch = nil
		}
		if ts.Unix()%3600 == 0 {
			fmt.Fprintf(os.Stderr, "\rbackfill %s  %d records", ts.Format("2006-01-02 15:04"), total)
		}
	}
	w.Submit(batch)
	total += len(batch)
	cancel()
	<-done
	fmt.Fprintf(os.Stderr, "\nbackfilled %d records (%d written, %d dropped)\n", total, w.RowsWritten.Load(), w.Dropped.Load())
	return nil
}
