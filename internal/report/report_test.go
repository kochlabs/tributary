package report

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"testing"
	"time"
)

// fixture is a week of plausible data, including long and non-Latin names.
func fixture() *Summary {
	to := time.Date(2026, 10, 23, 14, 0, 0, 0, time.Local)
	from := to.Add(-7 * 24 * time.Hour)
	s := &Summary{Appliance: "Tributary", Version: "0.2.0", From: from, To: to, Generated: to,
		DownloadBytes: 65 << 30, UploadBytes: 3 << 30, DownloadBps: 6.02e6, UploadBps: 2.9e5, PeakDownloadBps: 3.04e8, PeakUploadBps: 2.06e7,
		LocalHosts: 169, RemoteHosts: 7992, Flows: 1162057, Packets: 61816877, ThreatFeedsEnabled: 5}
	names := []string{"Valve Corporation", "Google LLC", "Fastly, Inc.", "Fortinet Inc.", "Cloudflare, Inc.", "Apple Inc.", "Akamai International B.V.", "Other"}
	for t := from; t.Before(to); t = t.Add(time.Hour) {
		s.Times = append(s.Times, t)
	}
	for i, n := range names {
		v := make([]float64, len(s.Times))
		for j, t := range s.Times {
			day := 0.5 + 0.5*math.Sin(float64(t.Hour()-6)/24*2*math.Pi)
			v[j] = (8e6 / float64(i+1)) * (0.3 + day) * (1 + 0.2*math.Sin(float64(j)/5+float64(i)))
		}
		s.Traffic = append(s.Traffic, Series{Label: n, Values: v})
	}
	row := func(label, detail string, b uint64, pct float64) Row {
		return Row{Label: label, Detail: detail, Bytes: b, Flows: b / 50000, Rate: float64(b*8) / 604800, Pct: pct}
	}
	for i, n := range names {
		s.Services = append(s.Services, row(n, fmt.Sprintf("AS%d", 32590+i), uint64(34<<30)>>i, 50/float64(i+1)))
	}
	devs := []string{"Waldorf", "BedroomAppleTV", "Denniss-MBP", "Living-Room", "kl-sec-fleet-1", "mothership", "Proxmox 02:4c:09", "iPhone", "Ünïcødé-Gerät 東京", "A very long device name that will not fit in the column at all"}
	for i, n := range devs {
		s.Devices = append(s.Devices, row(n, fmt.Sprintf("4a:d6:09:a8:9e:%02x · Apple, Inc. · 192.168.80.%d", i, 100+i), uint64(43<<30)>>i, 63/float64(i+1)))
	}
	for i, n := range []string{"HTTPS (tcp/443)", "HTTPS (udp/443)", "IPsec-NAT-T (udp/4500)", "udp/7844", "udp/49359", "HTTP (tcp/80)"} {
		s.Apps = append(s.Apps, row(n, "", uint64(54<<30)>>(i*2), 80/float64(i+1)))
	}
	for i, n := range []string{"United States", "Canada", "United Kingdom", "Germany"} {
		s.Countries = append(s.Countries, row(n, "", uint64(60<<30)>>(i*3), 92/float64(i+1)))
	}
	s.ThreatFeeds = []Row{{Label: "Spamhaus DROP (IPv4)", Flows: 16, Bytes: 9000}, {Label: "FireHOL Level 1", Flows: 4, Bytes: 256}}
	s.ThreatHosts = []Row{{Label: "94.154.43.7", Detail: "NL · AS219502 Storm Industries LLC", Flows: 6, Bytes: 3452}, {Label: "45.138.12.16", Detail: "HK · AS218785 TC DATACENTER LIMITED", Flows: 4, Bytes: 1873}}
	s.ThreatTalkers = []Row{{Label: "proxy.kochlabs.io", Detail: "192.168.80.2", Flows: 14, Bytes: 8046}, {Label: "Fozzie", Detail: "192.168.80.51", Flows: 6, Bytes: 3452}}
	s.Exporters = []Exporter{{Name: "", Addr: "192.168.20.1", Bytes: 68 << 30, Flows: 1161728, LastSeen: to, Status: "active"}, {Name: "branch-rtr-01", Addr: "10.9.0.1", Bytes: 1 << 20, Flows: 30, LastSeen: to.Add(-3 * time.Hour), Status: "silent"}}
	return s
}

func TestRenderSummary(t *testing.T) {
	pdf, err := RenderSummary(fixture())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		t.Fatal("not a PDF")
	}
	if out := os.Getenv("REPORT_OUT"); out != "" {
		os.WriteFile(out, pdf, 0o644)
	}
	// Empty data still renders.
	if _, err := RenderSummary(&Summary{Appliance: "x", From: time.Now().Add(-time.Hour), To: time.Now(), Generated: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkRenderSummary(b *testing.B) {
	s := fixture()
	for b.Loop() {
		if _, err := RenderSummary(s); err != nil {
			b.Fatal(err)
		}
	}
}
