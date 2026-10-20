package backup

import (
	"bytes"
	"filippo.io/age"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestContainerRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := newEntryWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("0123456789"), chunkSize/4) // spans several chunks
	for _, e := range []struct{ name, data string }{{"manifest.json", `{"format":1}`}, {"empty", ""}, {"big", string(big)}} {
		if _, err := w.add(e.name, strings.NewReader(e.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.close(); err != nil {
		t.Fatal(err)
	}
	r, err := newEntryReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	// Skip an entry without reading it.
	if n, _, err := r.next(); err != nil || n != "manifest.json" {
		t.Fatal(n, err)
	}
	if n, d, _ := r.next(); n != "empty" {
		t.Fatal(n)
	} else if b, _ := io.ReadAll(d); len(b) != 0 {
		t.Fatal("empty entry has data")
	}
	n, d, err := r.next()
	if err != nil || n != "big" {
		t.Fatal(n, err)
	}
	if b, _ := io.ReadAll(d); !bytes.Equal(b, big) {
		t.Fatalf("big entry: %d bytes", len(b))
	}
	if _, _, err := r.next(); err != io.EOF {
		t.Fatal("expected EOF", err)
	}
	if _, err := newEntryReader(strings.NewReader("garbage")); err != errNotBackup {
		t.Fatal("garbage accepted")
	}
}

// Config-only backup → upload → inspect → restore → apply at start-up.
func TestBackupRestoreConfig(t *testing.T) {
	src := t.TempDir()
	files := map[string]string{"config.db": "DB-v1", "secret.key": "KEY-1", "tls.crt": "CRT", "tls.key": "TLSKEY"}
	for f, c := range files {
		os.WriteFile(filepath.Join(src, f), []byte(c), 0o600)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := &Manager{Dir: src, Version: "test", Log: log, Snapshot: func(p string) error {
		b, _ := os.ReadFile(filepath.Join(src, "config.db"))
		return os.WriteFile(p, b, 0o600)
	}}
	if err := m.StartBackup("short", false); err == nil {
		t.Fatal("short passphrase accepted")
	}
	if err := m.StartBackup("correct horse battery", false); err != nil {
		t.Fatal(err)
	}
	waitJob(t, m)
	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatal(list, err)
	}
	raw, _ := os.ReadFile(filepath.Join(src, "backups", list[0].Name))
	if bytes.Contains(raw, []byte("KEY-1")) || bytes.Contains(raw, []byte("TLSKEY")) {
		t.Fatal("backup is not encrypted")
	}

	// Restore onto a different appliance.
	dst := t.TempDir()
	os.WriteFile(filepath.Join(dst, "config.db"), []byte("DB-other"), 0o600)
	os.WriteFile(filepath.Join(dst, "config.db-wal"), []byte("wal"), 0o600)
	os.WriteFile(filepath.Join(dst, "secret.key"), []byte("KEY-other"), 0o600)
	r := &Manager{Dir: dst, Version: "test", Log: log}
	f, _ := os.Open(filepath.Join(src, "backups", list[0].Name))
	if _, err := r.Upload(f, 1<<30); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := r.Inspect("wrong passphrase!!"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	man, err := r.Inspect("correct horse battery")
	if err != nil || man.Version != "test" || len(man.Files) != 4 {
		t.Fatal(man, err)
	}
	restarted := make(chan bool, 1)
	if err := r.StartRestore("correct horse battery", false, func() { restarted <- true }); err != nil {
		t.Fatal(err)
	}
	waitJob(t, r)
	select {
	case <-restarted:
	case <-time.After(5 * time.Second):
		t.Fatal("no restart after restore")
	}
	// Nothing changes until the next start applies the staged files.
	if b, _ := os.ReadFile(filepath.Join(dst, "config.db")); string(b) != "DB-other" {
		t.Fatal("config replaced before restart")
	}
	applied, err := ApplyStaged(dst, log)
	if err != nil || !applied {
		t.Fatal(applied, err)
	}
	for f, c := range files {
		if b, _ := os.ReadFile(filepath.Join(dst, f)); string(b) != c {
			t.Errorf("%s = %q, want %q", f, b, c)
		}
	}
	if _, err := os.Stat(filepath.Join(dst, "config.db-wal")); err == nil {
		t.Error("stale WAL left next to the restored database")
	}
	kept, _ := filepath.Glob(filepath.Join(dst, "restore", "replaced-*", "secret.key"))
	if len(kept) != 1 {
		t.Error("replaced files not kept")
	}
	if applied, _ := ApplyStaged(dst, log); applied {
		t.Error("applied twice")
	}
}

func waitJob(t *testing.T, m *Manager) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if j := m.Job(); j != nil && j.State != "running" {
			if j.State != "done" {
				t.Fatalf("job %s: %s", j.Kind, j.Error)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("job did not finish")
}

func TestPublicKeyBackupAndPruning(t *testing.T) {
	src := t.TempDir()
	for f, c := range map[string]string{"config.db": "DB-v1", "secret.key": "KEY-1"} {
		os.WriteFile(filepath.Join(src, f), []byte(c), 0o600)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := &Manager{Dir: src, Version: "test", Log: log, Snapshot: func(p string) error {
		b, _ := os.ReadFile(filepath.Join(src, "config.db"))
		return os.WriteFile(p, b, 0o600)
	}}
	id, _ := age.GenerateX25519Identity()
	if _, err := Recipients("", "age1notakey"); err == nil {
		t.Fatal("invalid public key accepted")
	}
	rcpts, err := Recipients("", "# backup key\n"+id.Recipient().String()+"\n")
	if err != nil {
		t.Fatal(err)
	}
	// A manual backup (never pruned) and three scheduled ones.
	if err := m.StartBackup("correct horse battery", false); err != nil {
		t.Fatal(err)
	}
	waitJob(t, m)
	var names []string
	for range 3 {
		time.Sleep(1100 * time.Millisecond) // names have one-second resolution
		name, err := m.RunScheduled(rcpts, false)
		if err != nil {
			t.Fatal(err)
		}
		if !IsOwn(name) {
			t.Fatalf("%s not recognised as this appliance's", name)
		}
		names = append(names, name)
	}
	if IsOwn("tributary-otherhost-20260101-000000.tbk") || IsOwn(strings.Replace(names[0], ".tbk", "x.tbk", 1)) {
		t.Fatal("foreign name treated as own")
	}
	gone, err := m.PruneScheduled(2)
	if err != nil || len(gone) != 1 || gone[0] != names[0] {
		t.Fatalf("pruned %v, %v", gone, err)
	}
	list, _ := m.List()
	if len(list) != 3 {
		t.Fatalf("left %d backups", len(list))
	}

	// Restore with the private key (as a key file would hold it), not a passphrase.
	r := &Manager{Dir: t.TempDir(), Version: "test", Log: log}
	f, _ := os.Open(filepath.Join(src, "backups", names[2]))
	r.Upload(f, 1<<30)
	f.Close()
	if _, err := r.Inspect("correct horse battery"); err == nil {
		t.Fatal("passphrase opened a public-key backup")
	}
	other, _ := age.GenerateX25519Identity()
	if _, err := r.Inspect(other.String()); err == nil {
		t.Fatal("wrong key opened the backup")
	}
	man, err := r.Inspect("# created: today\n# public key: " + id.Recipient().String() + "\n" + id.String() + "\n")
	if err != nil || !man.Scheduled {
		t.Fatalf("inspect with key: %v %+v", err, man)
	}
	// The same key file pasted into a single-line field.
	man, err = r.Inspect("# created: today# public key: " + id.Recipient().String() + id.String())
	if err != nil || !man.Scheduled {
		t.Fatalf("inspect with key: %v %+v", err, man)
	}
}
