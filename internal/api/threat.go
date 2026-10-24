package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/kochlabs/tributary/internal/config"
	"github.com/kochlabs/tributary/internal/store"
)

// Threat feeds (Security → Threat Feeds): lists of known-bad addresses that
// flows are matched against at ingest. Flows store the feed's ID; names are
// looked up when shown, so a renamed feed relabels its past matches.

// threatFeedName is the current name of a feed ID stored in flows. Values
// stored before flows held IDs are names already; deleted feeds are marked.
func (s *Server) threatFeedName(id string) string {
	if id == "" {
		return ""
	}
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return id // stored by name, before IDs
	}
	if f, err := s.Config.ThreatFeed(n); err == nil {
		return f.Name
	}
	return fmt.Sprintf("Deleted feed (#%d)", n)
}

// SyncThreatFeedNames tells the store which names the threat filter
// resolves, after feeds change.
func (s *Server) SyncThreatFeedNames() map[string]string {
	feeds, err := s.Config.ThreatFeeds()
	if err != nil {
		return nil
	}
	names := make(map[string]string, len(feeds))
	for _, f := range feeds {
		names[strconv.FormatInt(f.ID, 10)] = f.Name
	}
	store.SetThreatFeeds(names)
	return names
}

func (s *Server) threatFeeds(w http.ResponseWriter, r *http.Request) {
	feeds, err := s.Config.ThreatFeeds()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	have := map[string]bool{}
	for _, f := range feeds {
		have[f.URL], have[f.Name] = true, true
	}
	missing := 0
	for _, d := range config.DefaultThreatFeeds {
		if !have[d.URL] && !have[d.Name] {
			missing++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"feeds": feeds, "ranges": s.Threats.Prefixes(), "defaultsMissing": missing})
}

// threatStatus is the summary for the Detections page: what is matched and
// how often each feed was seen in the last day.
func (s *Server) threatStatus(w http.ResponseWriter, r *http.Request) {
	feeds, err := s.Config.ThreatFeeds()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	type feed struct {
		Name        string `json:"name"`
		Notify      bool   `json:"notify"`
		Entries     int    `json:"entries"`
		LastSuccess int64  `json:"lastSuccess"`
		LastError   string `json:"lastError"`
	}
	out := []feed{}
	for _, f := range feeds {
		if f.Enabled {
			out = append(out, feed{f.Name, f.Notify, f.Entries, f.LastSuccess, f.LastError})
		}
	}
	hits, err := s.Store.ThreatHits(r.Context(), time.Now().Add(-24*time.Hour))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	for i := range hits {
		hits[i].Feed = s.threatFeedName(hits[i].Feed)
	}
	writeJSON(w, http.StatusOK, map[string]any{"feeds": out, "ranges": s.Threats.Prefixes(), "hits": hits})
}

func (s *Server) threatFeedSave(w http.ResponseWriter, r *http.Request) {
	var f config.ThreatFeed
	if err := readJSON(r, &f); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	f.ID = 0
	var old config.ThreatFeed
	if p := r.PathValue("id"); p != "" {
		f.ID, _ = strconv.ParseInt(p, 10, 64)
		var err error
		if old, err = s.Config.ThreatFeed(f.ID); err != nil {
			writeErr(w, http.StatusNotFound, "no such feed")
			return
		}
	}
	id, err := s.Config.SaveThreatFeed(f)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, config.ErrNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	saved, _ := s.Config.ThreatFeed(id)
	action := "threat.feed.update"
	if old.ID == 0 {
		action = "threat.feed.create"
	}
	s.Config.Audit(userFrom(r).Username, action, saved.String()+onOff(saved.Enabled))
	// A different source or format makes the cached list stale.
	if old.ID != 0 && (old.URL != saved.URL || old.Format != saved.Format || old.Field != saved.Field || old.Column != saved.Column || old.Delimiter != saved.Delimiter) {
		s.Threats.Forget(id)
	}
	if err := s.Threats.Reload(); err != nil {
		s.Log.Warn("threat feeds: reload", "err", err)
	}
	s.SyncThreatFeedNames()
	if saved.Enabled && (old.ID == 0 || saved.LastSuccess == 0 || !old.Enabled) {
		s.Threats.UpdateSoon(id)
	}
	writeJSON(w, http.StatusOK, saved)
}

func onOff(enabled bool) string {
	if enabled {
		return ", enabled"
	}
	return ", disabled"
}

func (s *Server) threatFeedDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	f, err := s.Config.ThreatFeed(id)
	if err == nil {
		err = s.Config.DeleteThreatFeed(id)
	}
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such feed")
		return
	}
	s.Threats.Forget(id)
	_ = s.Threats.Reload()
	s.SyncThreatFeedNames()
	s.Config.Audit(userFrom(r).Username, "threat.feed.delete", f.String())
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// threatFeedTest downloads and parses a feed as entered, without saving it.
func (s *Server) threatFeedTest(w http.ResponseWriter, r *http.Request) {
	var f config.ThreatFeed
	if err := readJSON(r, &f); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := config.ValidateThreatFeed(&f); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	ps, skipped, err := s.Threats.Fetch(ctx, f)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	sample := []string{}
	for _, p := range ps[:min(5, len(ps))] {
		sample = append(sample, p.String())
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "entries": len(ps), "skipped": skipped, "sample": sample})
}

// threatFeedMove moves a feed up or down: the first feed listing an address
// is the one a flow records.
func (s *Server) threatFeedMove(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		Up bool `json:"up"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	f, err := s.Config.ThreatFeed(id)
	if err == nil {
		err = s.Config.MoveThreatFeed(id, req.Up)
	}
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such feed")
		return
	}
	_ = s.Threats.Reload()
	dir := "down"
	if req.Up {
		dir = "up"
	}
	s.Config.Audit(userFrom(r).Username, "threat.feed.move", f.Name+" "+dir)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) threatFeedUpdate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id != 0 {
		if _, err := s.Config.ThreatFeed(id); err != nil {
			writeErr(w, http.StatusNotFound, "no such feed")
			return
		}
	}
	s.Threats.UpdateSoon(id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) threatFeedDefaults(w http.ResponseWriter, r *http.Request) {
	n, err := s.Config.AddDefaultThreatFeeds()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n > 0 {
		s.SyncThreatFeedNames()
		s.Config.Audit(userFrom(r).Username, "threat.feed.defaults", fmt.Sprintf("added %d default feeds", n))
		s.Threats.UpdateSoon(0)
	}
	writeJSON(w, http.StatusOK, map[string]int{"added": n})
}
