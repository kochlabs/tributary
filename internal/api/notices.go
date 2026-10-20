package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Notice is an appliance-wide condition shown as a banner above the header
// (updates available, disk space low, database down, …).
type Notice struct {
	// ID is stable while the condition is unchanged and changes when it does
	// (e.g. more updates), so a dismissed notice reappears when it matters.
	ID    string `json:"id"`
	Level string `json:"level"` // info | warning | danger
	// Kind and Params let the UI phrase the notice in the user's language;
	// Message is the English text, used when the UI has no translation.
	Kind        string            `json:"kind"`
	Params      map[string]string `json:"params,omitempty"`
	Message     string            `json:"message"`
	Action      *NoticeAction     `json:"action,omitempty"`
	Dismissible bool              `json:"dismissible"`
	adminOnly   bool
}

type NoticeAction struct {
	Label string `json:"label"`
	Route string `json:"route"`
	admin bool   // only administrators can use the target page
}

const noticeInterval = time.Minute

// RunNotices re-evaluates notices every minute until ctx ends. Checks run in
// the background so polling browsers never trigger them directly.
func (s *Server) RunNotices(ctx context.Context) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			list := s.checkNotices(ctx)
			s.notices.Store(&list)
			t.Reset(noticeInterval)
		}
	}
}

func (s *Server) noticesList(w http.ResponseWriter, r *http.Request) {
	p := s.notices.Load()
	if p == nil {
		// Not checked yet: an empty list would read as "all clear".
		writeErr(w, http.StatusServiceUnavailable, "notices are not available yet")
		return
	}
	out := []Notice{}
	admin := userFrom(r).Role == "admin"
	for _, n := range *p {
		if n.adminOnly && !admin {
			continue
		}
		if n.Action != nil && n.Action.admin && !admin {
			n.Action = nil
		}
		out = append(out, n)
	}
	writeJSON(w, http.StatusOK, out)
}

var levelOrder = map[string]int{"danger": 0, "warning": 1, "info": 2}

func (s *Server) checkNotices(ctx context.Context) []Notice {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out []Notice
	add := func(n Notice) {
		n.Dismissible = n.Level != "danger"
		out = append(out, n)
	}
	now := time.Now()
	settled := now.Sub(s.started) > 10*time.Minute // let exporters and NTP catch up after a restart

	// Database and disks.
	db, err := s.Store.Stats(ctx)
	if err != nil {
		add(Notice{ID: "db-down", Kind: "db-down", Level: "danger", Message: "The flow database is unavailable: flows are not being stored and reports may fail.",
			Action: &NoticeAction{Label: "System health", Route: "/system"}})
	}
	var paths []string
	if db != nil {
		for _, d := range db.Disks {
			paths = append(paths, d.Path)
		}
	}
	if s.DataDir != "" {
		paths = append(paths, s.DataDir)
	}
	for _, d := range diskUsage(paths) {
		free := float64(d.free) / float64(d.total)
		level := ""
		switch {
		case free < 0.05:
			level = "danger"
		case free < 0.15:
			level = "warning"
		default:
			continue
		}
		add(Notice{ID: "disk:" + d.path + ":" + level, Kind: "disk-low", Level: level,
			Params: map[string]string{"free": humanBytes(d.free), "total": humanBytes(d.total), "percent": fmt.Sprintf("%.0f", free*100), "path": d.path},
			Message: fmt.Sprintf("Disk space is low: %s free of %s (%.0f%%) on %s. Flow storage stops when the disk is full; shorten retention or add space.",
				humanBytes(d.free), humanBytes(d.total), free*100, d.path),
			Action: &NoticeAction{Label: "Retention settings", Route: "/admin/settings", admin: true}})
	}

	// Collector and writer.
	cs := s.Collector.Status()
	for _, proto := range slices.Sorted(mapKeys(cs.ListenErrors)) {
		add(Notice{ID: "listen:" + proto, Kind: "listen-failed", Level: "danger", Params: map[string]string{"protocol": proto, "error": cs.ListenErrors[proto]}, Message: fmt.Sprintf("Not receiving %s: %s", proto, cs.ListenErrors[proto]),
			Action: &NoticeAction{Label: "Collector ports", Route: "/admin/settings", admin: true}})
	}
	dropped := s.Writer.Dropped.Load()
	if prev := s.prevDropped.Swap(dropped); s.noticeRuns.Add(1) > 1 && dropped > prev {
		add(Notice{ID: "drops:" + now.Format("2006010215"), Kind: "drops", Level: "warning", Params: map[string]string{"count": fmt.Sprint(dropped - prev)},
			Message: fmt.Sprintf("%d flow records were dropped in the last minute because the database could not keep up.", dropped-prev),
			Action:  &NoticeAction{Label: "System health", Route: "/system"}})
	}

	// Flows dropped by the exporter allowlist (in the last minute).
	rejected := s.Collector.Rejected.Load()
	if prev := s.prevRejected.Swap(rejected); s.noticeRuns.Load() > 1 && rejected > prev {
		var addrs []string
		for _, r := range s.Collector.RejectedSources() {
			if now.UnixMilli()-r.LastSeen < 2*60*1000 {
				addrs = append(addrs, r.Addr)
			}
		}
		if len(addrs) > 0 {
			slices.Sort(addrs)
			if len(addrs) > 5 {
				addrs = append(addrs[:5], "…")
			}
			names := strings.Join(addrs, ", ")
			add(Notice{ID: "rejected:" + names, Kind: "exporters-rejected", Level: "warning", adminOnly: true,
				Params:  map[string]string{"count": fmt.Sprint(len(addrs)), "addrs": names},
				Message: "Flows from sources not in the exporter allowlist are being dropped: " + names + ".",
				Action:  &NoticeAction{Label: "System health", Route: "/system", admin: true}})
		}
	}

	// Exporters that stopped sending.
	if settled {
		if n := s.silentExporters(ctx, now); n != nil {
			add(*n)
		}
	}

	// Administration.
	if st, err := s.System.UpdateStatus(); err == nil && st.Installed {
		if k := len(st.Upgradable); k > 0 {
			sec := 0
			for _, p := range st.Upgradable {
				if p.Security {
					sec++
				}
			}
			msg, level := fmt.Sprintf("%d operating system update%s available.", k, plural(k)), "info"
			if sec > 0 {
				msg, level = fmt.Sprintf("%d operating system update%s available, including %d security update%s.", k, plural(k), sec, plural(sec)), "warning"
			}
			add(Notice{ID: fmt.Sprintf("updates:%d:%d", k, sec), Kind: "updates", Params: map[string]string{"count": fmt.Sprint(k), "security": fmt.Sprint(sec)}, Level: level, Message: msg, adminOnly: true,
				Action: &NoticeAction{Label: "View updates", Route: "/admin/updates", admin: true}})
		}
		if st.RebootRequired {
			add(Notice{ID: "reboot:" + st.Kernel, Kind: "reboot-required", Level: "warning", Message: "A restart is required to finish installing updates.", adminOnly: true,
				Action: &NoticeAction{Label: "Restart", Route: "/admin/updates", admin: true}})
		}
	}
	if cst, err := s.Certs.Status(); err == nil {
		c := cst.Certificate
		switch {
		case c.DaysLeft < 0:
			add(Notice{ID: fmt.Sprintf("cert:%d:expired", c.NotAfter), Kind: "cert-expired", Level: "danger", adminOnly: true,
				Message: "The appliance's TLS certificate has expired; browsers will refuse to connect.",
				Action:  &NoticeAction{Label: "Certificates", Route: "/admin/certificates", admin: true}})
		case c.DaysLeft <= 30:
			add(Notice{ID: fmt.Sprintf("cert:%d", c.NotAfter), Kind: "cert-expiring", Params: map[string]string{"days": fmt.Sprint(c.DaysLeft)}, Level: "warning", adminOnly: true,
				Message: fmt.Sprintf("The appliance's TLS certificate expires in %d day%s.", c.DaysLeft, plural(c.DaysLeft)),
				Action:  &NoticeAction{Label: "Certificates", Route: "/admin/certificates", admin: true}})
		}
	}
	if n := s.initialPasswordNotice(); n != nil {
		add(*n)
	}
	if settled {
		if ts, err := s.System.TimeStatus(ctx); err == nil && ts.NTPEnabled && !ts.Synchronized {
			add(Notice{ID: "time-unsynced", Kind: "time-unsynced", Level: "warning", adminOnly: true,
				Message: "The clock is not synchronized with a time server; flow timestamps may drift.",
				Action:  &NoticeAction{Label: "Time settings", Route: "/admin/time", admin: true}})
		}
	}
	for _, f := range []struct{ what, db, status string }{{"GeoIP", "geoip", s.Geo.Status().LastUpdate}, {"MAC vendor", "vendors", s.vendorStatus()}} {
		if when, msg, ok := strings.Cut(f.status, ": failed: "); ok {
			add(Notice{ID: "datasource:" + f.what + ":" + when, Kind: "datasource-failed", Params: map[string]string{"database": f.db, "error": firstLine(msg)}, Level: "info", adminOnly: true,
				Message: fmt.Sprintf("The %s database could not be updated: %s", f.what, firstLine(msg)),
				Action:  &NoticeAction{Label: "Data sources", Route: "/admin/data-sources", admin: true}})
		}
	}

	slices.SortStableFunc(out, func(a, b Notice) int { return levelOrder[a.Level] - levelOrder[b.Level] })
	return out
}

func (s *Server) vendorStatus() string {
	if s.Vendors == nil {
		return ""
	}
	return s.Vendors.Status().LastUpdate
}

// silentExporters reports exporters that sent flows within the past week but
// none in the last 15 minutes.
func (s *Server) silentExporters(ctx context.Context, now time.Time) *Notice {
	live := map[string]int64{}
	for _, e := range s.Collector.Exporters() {
		live[e.Addr] = e.LastSeen
	}
	traffic, err := s.Store.ExporterTraffic(ctx, now.Add(-7*24*time.Hour), now)
	if err != nil {
		return nil
	}
	var silent []string
	for _, e := range s.Config.Exporters() {
		t, ok := traffic[e.Addr]
		if !ok || t.Bytes == 0 && t.Flows == 0 {
			continue // nothing in the past week: decommissioned or never active
		}
		if last := max(live[e.Addr], t.LastSeen); now.UnixMilli()-last > 15*60*1000 {
			name := e.Addr
			if e.Name != "" {
				name = e.Name + " (" + e.Addr + ")"
			}
			silent = append(silent, name)
		}
	}
	if len(silent) == 0 {
		return nil
	}
	slices.Sort(silent)
	params := map[string]string{"count": fmt.Sprint(len(silent)), "names": strings.Join(silent, ", ")}
	msg := silent[0] + " has stopped sending flows."
	if len(silent) > 1 {
		msg = fmt.Sprintf("%d exporters have stopped sending flows: %s.", len(silent), strings.Join(silent, ", "))
	}
	return &Notice{ID: "silent:" + strings.Join(silent, ","), Kind: "exporters-silent", Params: params, Level: "warning", Message: msg,
		Action: &NoticeAction{Label: "Exporters", Route: "/exporters"}}
}

// initialPasswordNotice warns while the bootstrap admin password is still in
// use. Once it has been changed, the file holding it is deleted.
func (s *Server) initialPasswordNotice() *Notice {
	if s.DataDir == "" {
		return nil
	}
	path := filepath.Join(s.DataDir, "initial-admin-password")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if s.Config.PasswordMatches("admin", strings.TrimSpace(string(b))) {
		return &Notice{ID: "initial-password", Kind: "initial-password", Level: "warning", adminOnly: true,
			Message: "The admin account still uses its generated initial password. Change it, or create your own administrator and remove this one.",
			Action:  &NoticeAction{Label: "Users", Route: "/admin/users", admin: true}}
	}
	if err := os.Remove(path); err == nil {
		s.Log.Info("removed the initial admin password file: the password has been changed", "path", path)
	}
	return nil
}

type diskInfo struct {
	path        string
	free, total uint64
}

// diskUsage returns free and total space for the filesystems holding paths,
// once per filesystem.
func diskUsage(paths []string) []diskInfo {
	seen := map[[2]int32]bool{}
	var out []diskInfo
	for _, p := range paths {
		var st syscall.Statfs_t
		if err := syscall.Statfs(p, &st); err != nil || st.Blocks == 0 {
			continue
		}
		id := [2]int32{st.Fsid.X__val[0], st.Fsid.X__val[1]}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, diskInfo{path: p, free: st.Bavail * uint64(st.Bsize), total: st.Blocks * uint64(st.Bsize)})
	}
	return out
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}
