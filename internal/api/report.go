package api

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/kochlabs/tributary/internal/report"
	"github.com/kochlabs/tributary/internal/store"
)

// reportSummary renders the network summary for a range as PDF. The Reports
// page fetches it and shows it from a blob: URL in the browser's PDF viewer.
func (s *Server) reportSummary(w http.ResponseWriter, r *http.Request) {
	q, err := parseQuery(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := queryCtx(r)
	defer cancel()
	data, err := s.summaryReport(ctx, q.From, q.To)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	pdf, err := report.RenderSummary(data)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/pdf")
	h.Set("Content-Disposition", fmt.Sprintf(`inline; filename="tributary-summary-%s.pdf"`, q.To.Format("2006-01-02")))
	h.Set("Cache-Control", "no-store")
	w.Write(pdf)
}

// summaryReport gathers the network summary with the web UI's labels.
func (s *Server) summaryReport(ctx context.Context, from, to time.Time) (*report.Summary, error) {
	out := &report.Summary{Appliance: s.Config.Settings().ApplianceName, Version: s.Version, From: from, To: to, Generated: time.Now()}
	q := store.Query{From: from, To: to, Metric: "bps"}
	// The queries are independent: run them together (they take seconds
	// each over long ranges).
	g, ctx := errgroup.WithContext(ctx)
	var mu sync.Mutex // guards out
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
		return nil
	})
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
	topInto(q, "remote_as", 8, &out.Services)
	topInto(q, "device", 10, &out.Devices)
	topInto(q, "app", 8, &out.Apps)
	topInto(q, "remote_country", 8, &out.Countries)

	// Threat feed matches, ranked by flows.
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
		fq.Metric = "fps"
		if fq.Filter, err = store.ParseFilter(map[string]string{"threat": "*"}); err != nil {
			return nil, err
		}
		topInto(fq, "threat", 10, &out.ThreatFeeds)
		topInto(fq, "threat_host", 10, &out.ThreatHosts)
		topInto(fq, "local_host", 10, &out.ThreatTalkers)
	}

	// Exporters: those named or seen, with traffic in the range.
	var traffic map[string]store.ExporterTraffic
	g.Go(func() (err error) {
		traffic, err = s.Store.ExporterTraffic(ctx, from, to)
		return err
	})
	if err := g.Wait(); err != nil {
		return nil, err
	}
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
	return out, nil
}
