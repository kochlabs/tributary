package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/kochlabs/tributary/internal/config"
)

func TestReportsAPI(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Open(filepath.Join(dir, "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Config: cfg, DataDir: dir}
	app := httptest.NewServer(s.Handler())
	defer app.Close()
	cfg.CreateUser(config.User{Username: "viewer", Role: "viewer"}, "Viewer-pass-1")
	cfg.CreateUser(config.User{Username: "admin", Role: "admin"}, "Admin-pass-12")
	v := newClient(t, app.URL)
	v.post("/api/auth/login", map[string]string{"username": "viewer", "password": "Viewer-pass-1"})
	a := newClient(t, app.URL)
	a.post("/api/auth/login", map[string]string{"username": "admin", "password": "Admin-pass-12"})

	def := map[string]any{"name": "Weekly", "template": "security", "period": "last_week", "schedule": "weekly", "hour": 7, "weekday": 1,
		"filters": map[string]string{"exporter": "192.168.20.1"}, "recipients": "noc@example.com"}
	if code, _, _ := v.do("POST", "/api/reports", def); code != http.StatusForbidden {
		t.Fatalf("viewer created a report: %d", code)
	}
	code, out, raw := a.do("POST", "/api/reports", def)
	if code != 200 || out["nextRun"].(float64) == 0 || out["createdBy"] != "admin" {
		t.Fatalf("create: %d %s", code, raw)
	}
	id := int64(out["id"].(float64))
	// Filters are saved as a query, in canonical form.
	if out["query"] != "exporter:192.168.20.1" || out["filters"] != nil {
		t.Fatalf("filters not converted: %s", raw)
	}
	q := map[string]any{"name": "Q", "template": "summary", "period": "last_7d", "query": "dst_port:(80 443) and not country:us"}
	code, out, raw = a.do("POST", "/api/reports", q)
	if code != 200 || out["query"] != "dst_port:(80 OR 443) AND NOT country:us" {
		t.Fatalf("query: %d %s", code, raw)
	}
	a.do("DELETE", "/api/reports/"+itoa64(int64(out["id"].(float64))), nil)
	q["name"], q["query"] = "Q2", "dst_prot:443"
	if code, out, raw := a.do("POST", "/api/reports", q); code != 400 || out["hint"] != "did you mean dst_port?" {
		t.Fatalf("bad query: %d %s", code, raw)
	}
	bad := map[string]any{"name": "Bad", "template": "summary", "period": "last_7d", "filters": map[string]string{"nonsense": "1"}}
	if code, _, _ := a.do("POST", "/api/reports", bad); code != http.StatusBadRequest {
		t.Fatalf("unknown filter accepted: %d", code)
	}
	if code, out, raw := v.do("GET", "/api/reports", nil); code != 200 || len(out["reports"].([]any)) != 1 {
		t.Fatalf("viewer list: %d %s", code, raw)
	}

	// Kept runs download for any user; file names can't leave the reports directory.
	os.MkdirAll(filepath.Join(dir, "reports"), 0o750)
	os.WriteFile(filepath.Join(dir, "reports", "1-x.pdf"), []byte("%PDF-1.3 test"), 0o640)
	os.WriteFile(filepath.Join(dir, "secret.pdf"), []byte("secret"), 0o640)
	run, _, err := cfg.AddReportRun(config.ReportRun{ReportID: id, StartedAt: time.Now().UnixMilli(), Status: "ok", File: "1-x.pdf", Size: 13}, 12)
	if err != nil {
		t.Fatal(err)
	}
	evil, _, _ := cfg.AddReportRun(config.ReportRun{ReportID: id, StartedAt: time.Now().UnixMilli(), Status: "ok", File: "../secret.pdf", Size: 6}, 12)
	if code := v.get("/api/reports/runs/" + itoa64(run.ID) + "/pdf"); code != 200 {
		t.Fatalf("download: %d", code)
	}
	if code := v.get("/api/reports/runs/" + itoa64(evil.ID) + "/pdf"); code != http.StatusNotFound {
		t.Fatalf("path traversal: %d", code)
	}

	// Deleting removes the kept files.
	if code, _, _ := a.do("DELETE", "/api/reports/"+itoa64(id), nil); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "reports", "1-x.pdf")); !os.IsNotExist(err) {
		t.Fatal("run file left behind")
	}
	if _, err := os.Stat(filepath.Join(dir, "secret.pdf")); err != nil {
		t.Fatal("deleted a file outside the reports directory")
	}
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

func TestThreatFeedName(t *testing.T) {
	cfg, err := config.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	s := &Server{Config: cfg}
	id, _ := cfg.SaveThreatFeed(config.ThreatFeed{Name: "Lab list", URL: "https://example.com/l.txt"})
	key := strconv.FormatInt(id, 10)
	if got := s.threatFeedName(key); got != "Lab list" {
		t.Fatalf("name: %q", got)
	}
	// Renaming relabels matches already stored by ID.
	f, _ := cfg.ThreatFeed(id)
	f.Name = "Renamed list"
	cfg.SaveThreatFeed(f)
	if got := s.threatFeedName(key); got != "Renamed list" {
		t.Fatalf("after rename: %q", got)
	}
	// The filter resolves the new name to the stored ID.
	names := s.SyncThreatFeedNames()
	if names[key] != "Renamed list" {
		t.Fatalf("synced: %v", names)
	}
	cfg.DeleteThreatFeed(id)
	if got := s.threatFeedName(key); got != "Deleted feed (#"+key+")" {
		t.Fatalf("deleted: %q", got)
	}
	if s.threatFeedName("Old name") != "Old name" || s.threatFeedName("") != "" {
		t.Fatal("names stored before IDs, or none")
	}
	if _, err := cfg.SaveThreatFeed(config.ThreatFeed{Name: "123", URL: "https://example.com/x.txt"}); err == nil {
		t.Fatal("an all-digit name was accepted")
	}
}
