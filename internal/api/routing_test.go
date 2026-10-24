package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/kochlabs/tributary/internal/config"
	"github.com/kochlabs/tributary/internal/notify"
)

func TestRouteNotices(t *testing.T) {
	cfg, err := config.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &Server{Config: cfg, Log: log, Notify: &notify.Dispatcher{Cfg: cfg, Log: log, Client: func() *http.Client { return http.DefaultClient }}}
	ch, _ := cfg.SaveChannel(config.Channel{Name: "hook", Type: "webhook", URL: "https://example.com/hook", Enabled: true})
	sent := func() []string { // queued events, oldest first
		due, _ := cfg.DueDeliveries(time.Now().Add(time.Hour), 100)
		var out []string
		for _, d := range due {
			var ev notify.Event
			json.Unmarshal([]byte(d.Payload), &ev)
			out = append(out, ev.Type+" "+ev.Title)
		}
		return out
	}
	now := time.Now()
	disk := Notice{ID: "disk:/:warning", Kind: "disk-low", Level: "warning", Message: "low"}
	list := []Notice{disk, {ID: "updates:3:0", Kind: "updates", Level: "info"}, {ID: "threat:x", Kind: "threat-traffic", Level: "warning"}}

	s.routeNotices(list, now) // no channels chosen yet
	if got := sent(); len(got) != 0 {
		t.Fatalf("sent without channels: %v", got)
	}
	cfg.SaveNoticeRouting(config.NoticeRouting{Level: "warning", Channels: []int64{ch.ID}})
	s.routeNotices(list, now)
	s.routeNotices(list, now.Add(time.Minute)) // unchanged: nothing new
	if got := sent(); len(got) != 1 || got[0] != "notice.raised Disk space is low" {
		t.Fatalf("raised: %v", got)
	}
	// Escalating sends again, without a cleared for the warning.
	danger := Notice{ID: "disk:/:danger", Kind: "disk-low", Level: "danger", Message: "very low"}
	s.routeNotices([]Notice{danger}, now.Add(2*time.Minute))
	s.routeNotices([]Notice{danger}, now.Add(10*time.Minute))
	if got := sent(); len(got) != 2 {
		t.Fatalf("escalated: %v", got)
	}
	// Gone briefly: nothing; gone for longer: cleared.
	s.routeNotices(nil, now.Add(12*time.Minute))
	if got := sent(); len(got) != 2 {
		t.Fatalf("cleared too soon: %v", got)
	}
	s.routeNotices(nil, now.Add(20*time.Minute))
	if got := sent(); len(got) != 3 || got[2] != "notice.cleared Resolved: Disk space is low" {
		t.Fatalf("cleared: %v", got)
	}
}
