package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nfa/internal/config"
)

func (c *client) do(method, path string, body any) (int, map[string]any, string) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, c.base+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "nfa")
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	json.Unmarshal(raw, &out)
	return resp.StatusCode, out, string(raw)
}

func TestBackupScheduleAPI(t *testing.T) {
	cfg, err := config.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Config: cfg}
	app := httptest.NewServer(s.Handler())
	defer app.Close()
	cfg.CreateUser(config.User{Username: "admin", Role: "admin"}, "Local-pass-1")
	c := newClient(t, app.URL)
	if code, _ := c.post("/api/auth/login", map[string]string{"username": "admin", "password": "Local-pass-1"}); code != 200 {
		t.Fatal("login")
	}
	sch := map[string]any{"enabled": true, "frequency": "daily", "time": "02:30", "encryption": "passphrase", "passphrase": "correct horse battery",
		"keepLocal": 3, "keepRemote": 7, "destination": map[string]any{"type": "s3", "bucket": "b", "accessKey": "AK", "secretKey": "S3-SECRET-VALUE"}}
	code, out, raw := c.do("PUT", "/api/backup-schedule", sch)
	if code != 200 {
		t.Fatalf("save: %d %s", code, raw)
	}
	if strings.Contains(raw, "correct horse") || strings.Contains(raw, "S3-SECRET-VALUE") {
		t.Fatalf("secret returned: %s", raw)
	}
	got := out["schedule"].(map[string]any)
	if got["hasPassphrase"] != true || got["destination"].(map[string]any)["hasSecretKey"] != true || out["next"] == nil || !strings.HasPrefix(out["sshPublicKey"].(string), "ssh-ed25519 ") {
		t.Fatalf("status: %s", raw)
	}
	// Saving again without secrets keeps them.
	delete(sch, "passphrase")
	sch["destination"].(map[string]any)["secretKey"] = ""
	if code, _, raw := c.do("PUT", "/api/backup-schedule", sch); code != 200 {
		t.Fatalf("resave: %s", raw)
	}
	if full, _ := cfg.BackupScheduleSecrets(); full.Passphrase != "correct horse battery" || full.Destination.SecretKey != "S3-SECRET-VALUE" {
		t.Fatalf("secrets lost: %+v", full)
	}
	// The destination test validates only the destination (the form's
	// passphrase may be empty) and reports problems as a result.
	if code, out, raw := c.do("POST", "/api/backup-schedule/test", map[string]any{"encryption": "passphrase", "destination": map[string]any{"type": "sftp", "host": "", "username": "u"}}); code != 200 || out["ok"] != false || !strings.Contains(raw, "host name") {
		t.Fatalf("test validation: %d %s", code, raw)
	}
	// Invalid settings are refused.
	bad := map[string]any{"enabled": true, "time": "25:00", "encryption": "passphrase", "destination": map[string]any{}}
	if code, _, _ := c.do("PUT", "/api/backup-schedule", bad); code != 400 {
		t.Fatalf("bad time accepted: %d", code)
	}
	bad = map[string]any{"enabled": true, "time": "01:00", "encryption": "publickey", "publicKeys": "age1nope", "destination": map[string]any{}}
	if code, _, _ := c.do("PUT", "/api/backup-schedule", bad); code != 400 {
		t.Fatalf("bad public key accepted: %d", code)
	}
	// SFTP needs a confirmed host key before it can be enabled.
	bad = map[string]any{"enabled": true, "time": "01:00", "encryption": "passphrase", "destination": map[string]any{"type": "sftp", "host": "h", "username": "u"}}
	if code, _, raw := c.do("PUT", "/api/backup-schedule", bad); code != 400 || !strings.Contains(raw, "host key") {
		t.Fatalf("sftp without host key: %d %s", code, raw)
	}
	// A viewer can't see or change the schedule.
	cfg.CreateUser(config.User{Username: "viewer", Role: "viewer"}, "Viewer-pass-1")
	v := newClient(t, app.URL)
	v.post("/api/auth/login", map[string]string{"username": "viewer", "password": "Viewer-pass-1"})
	if v.get("/api/backup-schedule") != 403 {
		t.Fatal("viewer can read the schedule")
	}

	// Notices: a failed run, then overdue.
	now := time.Now()
	cfg.SaveBackupRun(config.BackupRun{Started: now.UnixMilli(), Finished: now.UnixMilli(), Error: "connecting: refused"})
	if n := s.backupNotice(now); n == nil || n.Kind != "backup-failed" || n.Params["error"] != "connecting: refused" {
		t.Fatalf("failed notice: %+v", n)
	}
	cfg.SaveBackupRun(config.BackupRun{OK: true, Finished: now.UnixMilli(), LastSuccess: now.UnixMilli()})
	if n := s.backupNotice(now); n != nil {
		t.Fatalf("notice after success: %+v", n)
	}
	if n := s.backupNotice(now.Add(31 * time.Hour)); n == nil || n.Kind != "backup-overdue" {
		t.Fatalf("overdue notice: %+v", n)
	}
}
