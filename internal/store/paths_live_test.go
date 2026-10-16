package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// Runs only against a live ClickHouse: NFA_TEST_CH_PW=... go test -run TestPathsLive
func TestPathsLive(t *testing.T) {
	pw := os.Getenv("NFA_TEST_CH_PW")
	if pw == "" {
		t.Skip("set NFA_TEST_CH_PW to run against a live ClickHouse")
	}
	ctx := context.Background()
	st, err := Open(ctx, Options{Addr: "127.0.0.1:9000", User: "netflow", Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, c := range []struct {
		dims []string
		span time.Duration
	}{{[]string{"device", "app", "remote_as"}, time.Hour}, {[]string{"proto", "exporter"}, 24 * time.Hour}, {[]string{"in_if", "out_if"}, 24 * time.Hour}} {
		now := time.Now()
		q := Query{From: now.Add(-c.span), To: now, Metric: "bps"}
		start := time.Now()
		res, err := st.Paths(ctx, q, c.dims, 5)
		if err != nil {
			t.Fatal(c.dims, err)
		}
		var col0, last uint64
		for _, n := range res.Nodes {
			if n.Column == 0 {
				col0 += n.Bytes
			}
			if n.Column == len(c.dims)-1 {
				last += n.Bytes
			}
		}
		var links uint64
		for _, l := range res.Links {
			if res.Nodes[l.Source].Column == 0 {
				links += l.Bytes
			}
		}
		t.Logf("%v %s: %d nodes, %d links, %s, col0=%d last=%d links0=%d took %s", c.dims, c.span, len(res.Nodes), len(res.Links), res.Source, col0, last, links, time.Since(start).Round(time.Millisecond))
		if col0 != last || col0 != links {
			t.Errorf("volume not conserved: %d %d %d", col0, last, links)
		}
		for _, n := range res.Nodes[:min(8, len(res.Nodes))] {
			t.Logf("  col %d %-30q %.1f Mbps", n.Column, n.Key, n.Rate/1e6)
		}
	}
	if _, err := st.Paths(ctx, Query{From: time.Now().Add(-time.Hour), To: time.Now()}, []string{"host", "app"}, 5); err == nil {
		t.Error("arrayJoin dimension accepted")
	}
}
