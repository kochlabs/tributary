package api

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/kochlabs/tributary/internal/config"
	"github.com/kochlabs/tributary/internal/enrich"
	"github.com/kochlabs/tributary/internal/report"
	"github.com/kochlabs/tributary/internal/store"
)

var templateTitles = map[string]string{"summary": "Network summary", "security": "Security digest"}

// buildReport gathers the data for def's sections over [from, to), with the
// web UI's labels. The queries are independent and run together.
func (s *Server) buildReport(ctx context.Context, def config.Report, from, to time.Time) (*report.Report, error) {
	title := def.Name
	if title == "" {
		title = templateTitles[def.Template]
	}
	out := &report.Report{Title: title, Appliance: s.Config.Settings().ApplianceName, Version: s.Version, From: from, To: to,
		Generated: time.Now(), Sections: def.Sections}
	text := config.AndQueries(store.FiltersToQuery(def.Filters), def.Query)
	filter, err := s.reportFilter(text)
	if err != nil {
		return nil, err
	}
	out.Scope = text
	q := store.Query{From: from, To: to, Metric: "bps", Filter: filter}
	want := func(sec string) bool { return slices.Contains(def.Sections, sec) }

	g, ctx := errgroup.WithContext(ctx)
	var mu sync.Mutex // guards out's shared fields
	if want("kpis") {
		g.Go(func() error {
			sum, err := s.Store.Summary(ctx, q)
			if err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			out.DownloadBytes, out.UploadBytes = sum.DownloadBytes, sum.UploadBytes
			out.DownloadBps, out.UploadBps = sum.DownloadBps, sum.UploadBps
			out.PeakDownloadBps, out.PeakUploadBps = sum.PeakDownBps, sum.PeakUpBps
			out.LocalHosts, out.RemoteHosts, out.Flows, out.Packets = sum.LocalHosts, sum.RemoteHosts, sum.Flows, sum.Packets
			out.ExporterCount = int(sum.Exporters)
			return nil
		})
	}
	if want("traffic") {
		g.Go(func() error {
			tq := q
			tq.GroupBy, tq.Limit = "remote_as", 8
			ts, err := s.Store.TimeSeries(ctx, tq)
			if err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			for _, t := range ts.Times {
				out.Times = append(out.Times, time.UnixMilli(t))
			}
			for _, sr := range ts.Series {
				out.Traffic = append(out.Traffic, report.Series{Label: s.label(tq.GroupBy, sr.Key), Values: sr.Values})
			}
			return nil
		})
	}

	top := func(q store.Query, dim string, limit int) ([]report.Row, error) {
		q.GroupBy, q.Limit = dim, limit
		res, err := s.Store.TopN(ctx, q)
		if err != nil {
			return nil, err
		}
		for i := range res.Rows {
			res.Rows[i].Label = s.label(dim, res.Rows[i].Key)
		}
		s.details(ctx, dim, res.Rows)
		rows := make([]report.Row, 0, len(res.Rows))
		for _, r := range res.Rows {
			rows = append(rows, report.Row{Label: r.Label, Detail: r.Detail, Bytes: r.Bytes, Flows: r.Flows, Rate: r.Rate, Pct: r.Pct})
		}
		return rows, nil
	}
	// Each writes its own field of out.
	topInto := func(q store.Query, dim string, limit int, dst *[]report.Row) {
		g.Go(func() error {
			rows, err := top(q, dim, limit)
			*dst = rows
			return err
		})
	}
	for _, t := range []struct {
		sec, dim string
		limit    int
		dst      *[]report.Row
	}{{"services", "remote_as", 8, &out.Services}, {"devices", "device", 10, &out.Devices}, {"apps", "app", 8, &out.Apps}, {"countries", "remote_country", 8, &out.Countries}} {
		if want(t.sec) {
			topInto(q, t.dim, t.limit, t.dst)
		}
	}

	if want("threats") {
		feeds, err := s.Config.ThreatFeeds()
		if err != nil {
			return nil, err
		}
		for _, f := range feeds {
			if f.Enabled {
				out.ThreatFeedsEnabled++
			}
		}
		if out.ThreatFeedsEnabled > 0 {
			fq := q
			fq.Metric = "fps" // ranked by flows: matches are usually small
			if fq.Filter, err = s.reportFilter(config.AndQueries(text, "threat:*")); err != nil {
				return nil, err
			}
			topInto(fq, "threat", 10, &out.ThreatFeeds)
			topInto(fq, "threat_host", 10, &out.ThreatHosts)
			topInto(fq, "local_host", 10, &out.ThreatTalkers)
		}
	}

	if want("exposure") {
		g.Go(func() error {
			list, err := s.Store.Exposure(ctx, q, 15)
			if err != nil {
				return err
			}
			var addrs []netip.Addr
			for _, e := range list {
				if a, err := netip.ParseAddr(e.Addr); err == nil {
					addrs = append(addrs, a)
				}
			}
			names := s.hostNames(ctx, addrs, 800*time.Millisecond)
			rows := make([]report.Row, 0, len(list))
			for _, e := range list {
				label, detail := e.Addr, ""
				if a, err := netip.ParseAddr(e.Addr); err == nil {
					if n := names[a]; n != "" {
						label, detail = n, e.Addr
					}
				}
				svc := s.label("app", fmt.Sprintf("%d/%d", e.Proto, e.Port))
				if a, err := netip.ParseAddr(e.Addr); err == nil {
					if doc := s.Inventory.Index().ServiceName(a, protoName(e.Proto), int(e.Port)); doc != "" {
						svc += " · " + doc // documented in the inventory
					}
				}
				rows = append(rows, report.Row{Label: label, Detail: detail, Service: svc,
					Sources: e.Sources, Flows: e.Flows, Bytes: e.Bytes})
			}
			out.Exposure = rows
			return nil
		})
	}

	if want("new_devices") {
		list, err := s.Config.Devices()
		if err != nil {
			return nil, err
		}
		for _, d := range list {
			first := time.UnixMilli(d.FirstSeen)
			if first.Before(from) || !first.Before(to) {
				continue
			}
			name, _ := s.deviceName(ctx, d.MAC, nil)
			detail := enrich.FormatMAC(d.MAC)
			if v := enrich.Vendor(d.MAC); v != "" {
				detail += " · " + v
			}
			if len(d.IPs) > 0 {
				detail += " · " + d.IPs[0].IP
			}
			out.NewDevices = append(out.NewDevices, report.Row{Label: name, Detail: detail, FirstSeen: first})
		}
		slices.SortFunc(out.NewDevices, func(a, b report.Row) int { return a.FirstSeen.Compare(b.FirstSeen) })
	}

	var traffic map[string]store.ExporterTraffic
	if want("exporters") {
		g.Go(func() (err error) {
			traffic, err = s.Store.ExporterTraffic(ctx, from, to)
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	if want("exporters") {
		live := map[string]int64{}
		for _, e := range s.Collector.Exporters() {
			live[e.Addr] = e.LastSeen
		}
		for _, e := range s.Config.Exporters() {
			t := traffic[e.Addr]
			last := max(live[e.Addr], t.LastSeen)
			status := "idle"
			switch {
			case last > 0 && time.Since(time.UnixMilli(last)) < 15*time.Minute:
				status = "active"
			case t.Bytes > 0 || t.Flows > 0:
				status = "silent"
			}
			row := report.Exporter{Name: e.Name, Addr: e.Addr, Bytes: t.Bytes, Flows: t.Flows, Status: status}
			if last > 0 {
				row.LastSeen = time.UnixMilli(last)
			}
			out.Exporters = append(out.Exporters, row)
		}
		slices.SortFunc(out.Exporters, func(a, b report.Exporter) int { return cmp.Compare(b.Bytes, a.Bytes) })
		if out.ExporterCount == 0 {
			out.ExporterCount = len(out.Exporters)
		}
	}
	return out, nil
}

func protoName(p uint8) string {
	return map[uint8]string{6: "tcp", 17: "udp", 132: "sctp"}[p]
}

// periodLabel names a run's period for subjects and file names.
func periodLabel(from, to time.Time) string {
	if to.Sub(from) <= 25*time.Hour && from.Hour() == 0 {
		return from.Format("2 Jan 2006")
	}
	return from.Format("2 Jan") + " – " + to.Add(-time.Second).Format("2 Jan 2006")
}

func reportFileName(name string, from time.Time) string {
	clean := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			clean = append(clean, r)
		case len(clean) > 0 && clean[len(clean)-1] != '-':
			clean = append(clean, '-')
		}
	}
	return string(clean) + "-" + from.Format("2006-01-02") + ".pdf"
}

// reportFilter compiles a report's query; names that match nothing match
// nothing, as on the pages.
func (s *Server) reportFilter(text string) (*store.Filter, error) {
	if text == "" {
		return nil, nil
	}
	f, _, _, err := s.compileQuery(text)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	return f, nil
}
