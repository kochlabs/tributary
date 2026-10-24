package api

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kochlabs/tributary/internal/config"
	"github.com/kochlabs/tributary/internal/notify"
)

// What goes to notification channels besides reports: appliance notices at
// or above a level (Configuration → Notifications) and threat feed matches,
// per feed (Security → Threat Feeds).

// noticeTitles names notices in messages, by kind.
var noticeTitles = map[string]string{
	"db-down":            "The flow database is down",
	"drops":              "Flows are being dropped",
	"disk-low":           "Disk space is low",
	"listen-failed":      "A collector port could not be opened",
	"exporters-silent":   "Exporters stopped sending flows",
	"exporters-rejected": "Exporters are being rejected",
	"updates":            "Operating system updates are available",
	"reboot-required":    "A restart is required",
	"cert-expired":       "The certificate has expired",
	"cert-expiring":      "The certificate expires soon",
	"initial-password":   "The initial password is still in use",
	"time-unsynced":      "The clock is not synchronized",
	"datasource-failed":  "A data source is failing",
	"backup-failed":      "A backup failed",
	"backup-overdue":     "A backup is overdue",
	"report-failed":      "A report failed",
	"channel-failing":    "A notification channel is failing",
}

func noticeTitle(n Notice) string {
	if t := noticeTitles[n.Kind]; t != "" {
		return t
	}
	return "Notice"
}

// noticeClearAfter is how long a sent notice must be gone before it counts
// as cleared, so a check that fails once doesn't send cleared and raised.
const noticeClearAfter = 5 * time.Minute

// routeNotices sends notices that appeared (notice.raised) and went away
// (notice.cleared) to the channels chosen for notices. Threat traffic goes
// per feed instead (routeThreats). A notice that changes but stays (more
// updates, disk space warning to danger) is sent again; it clears when no
// notice of its kind is left.
func (s *Server) routeNotices(list []Notice, now time.Time) {
	rt := s.Config.NoticeRouting()
	if len(rt.Channels) == 0 {
		return
	}
	sent := s.Config.SentNotices()
	byID := map[string]int{}
	for i, n := range sent {
		byID[n.ID] = i
	}
	kinds := map[string]bool{}
	appliance := s.Config.Settings().ApplianceName
	for _, n := range list {
		if n.Kind == "threat-traffic" || levelOrder[n.Level] > levelOrder[rt.Level] {
			continue
		}
		kinds[n.Kind] = true
		if i, ok := byID[n.ID]; ok {
			sent[i].LastSeen = now.UnixMilli()
			continue
		}
		link := ""
		if n.Action != nil {
			link = s.publicLink(n.Action.Route)
		}
		s.Notify.Publish(notify.Event{Type: "notice.raised", Level: n.Level, Appliance: appliance, Title: noticeTitle(n), Message: n.Message,
			URL: link, Data: map[string]any{"noticeId": n.ID, "kind": n.Kind, "params": n.Params}}, rt.Channels)
		sent = append(sent, config.SentNotice{ID: n.ID, Kind: n.Kind, Title: noticeTitle(n), LastSeen: now.UnixMilli()})
	}
	sent = slices.DeleteFunc(sent, func(n config.SentNotice) bool {
		if now.UnixMilli()-n.LastSeen < noticeClearAfter.Milliseconds() {
			return false
		}
		if !kinds[n.Kind] {
			s.Notify.Publish(notify.Event{Type: "notice.cleared", Level: "info", Appliance: appliance, Title: "Resolved: " + n.Title,
				Data: map[string]any{"noticeId": n.ID, "kind": n.Kind}}, rt.Channels)
		}
		return true
	})
	_ = s.Config.SaveSentNotices(sent)
}

// threatAlertEvery is how often one host's matches on one feed are sent
// while they continue.
const threatAlertEvery = 24 * time.Hour

// RunThreatAlerts sends traffic with threat feed addresses to the feeds'
// channels every minute until ctx ends: once per host and feed a day.
func (s *Server) RunThreatAlerts(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.routeThreats(ctx, now)
		}
	}
}

func (s *Server) routeThreats(ctx context.Context, now time.Time) {
	if s.Threats == nil || s.Threats.Prefixes() == 0 {
		return
	}
	feeds, err := s.Config.ThreatFeeds()
	if err != nil {
		return
	}
	byID := map[string]config.ThreatFeed{}
	for _, f := range feeds {
		if f.Enabled && len(f.Channels) > 0 {
			byID[strconv.FormatInt(f.ID, 10)] = f
		}
	}
	if len(byID) == 0 {
		return
	}
	// Flows arrive late (exporters' active timeout): look back far enough
	// that each is seen; sending is once a day per host and feed anyway.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	matches, err := s.Store.ThreatMatches(ctx, now.Add(-10*time.Minute), 200)
	if err != nil {
		return
	}
	var addrs []netip.Addr
	for _, m := range matches {
		if a, err := netip.ParseAddr(m.Host); err == nil {
			addrs = append(addrs, a)
		}
	}
	names := s.hostNames(ctx, addrs, 2*time.Second)
	appliance := s.Config.Settings().ApplianceName
	for _, m := range matches {
		f, ok := byID[m.Feed]
		if !ok {
			continue
		}
		if due, err := s.Config.ThreatAlertDue(f.ID, m.Host, now, threatAlertEvery); err != nil || !due {
			continue
		}
		host, name := m.Host, ""
		if a, err := netip.ParseAddr(m.Host); err == nil && names[a] != "" {
			name = names[a]
			host = name + " (" + m.Host + ")"
		}
		remotes := strings.Join(m.Remotes, ", ")
		if m.Count > uint64(len(m.Remotes)) {
			remotes += fmt.Sprintf(" and %d more", m.Count-uint64(len(m.Remotes)))
		}
		s.Notify.Publish(notify.Event{Type: "threat.detected", Level: "warning", Appliance: appliance,
			Title:   fmt.Sprintf("%s: traffic with %s", host, f.Name),
			Message: fmt.Sprintf("%s · %d flows, %s", remotes, m.Flows, humanBytes(m.Bytes)),
			URL:     s.publicLink("/security/detections"),
			Data: map[string]any{"feedId": f.ID, "feed": f.Name, "host": m.Host, "hostName": name,
				"remotes": m.Remotes, "remoteCount": m.Count, "flows": m.Flows, "bytes": m.Bytes, "first": m.First, "last": m.Last}}, f.Channels)
	}
	_ = s.Config.PruneThreatAlerts(now.Add(-2 * threatAlertEvery))
}

// existingChannels drops channels deleted since an editor loaded them.
func (s *Server) existingChannels(ids []int64) []int64 {
	return slices.DeleteFunc(ids, func(id int64) bool {
		_, err := s.Config.Channel(id)
		return err != nil
	})
}

func (s *Server) noticeRoutingSave(w http.ResponseWriter, r *http.Request) {
	var rt config.NoticeRouting
	if err := readJSON(r, &rt); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rt.Channels = s.existingChannels(rt.Channels)
	if err := s.Config.SaveNoticeRouting(rt); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "notify.notices.update", fmt.Sprintf("%s and up to %d channel(s)", rt.Level, len(rt.Channels)))
	writeJSON(w, http.StatusOK, s.Config.NoticeRouting())
}
