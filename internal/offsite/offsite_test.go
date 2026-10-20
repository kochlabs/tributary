package offsite

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"nfa/internal/backup"
	"nfa/internal/config"
)

func TestSchedule(t *testing.T) {
	loc := time.FixedZone("test", 3600)
	sch := config.BackupSchedule{Enabled: true, Frequency: "daily", Time: "02:30"}
	at := func(s string) time.Time { v, _ := time.ParseInLocation("2006-01-02 15:04", s, loc); return v }
	if n := Next(sch, at("2026-10-20 01:00")); !n.Equal(at("2026-10-20 02:30")) {
		t.Fatal("next daily", n)
	}
	if n := Next(sch, at("2026-10-20 02:30")); !n.Equal(at("2026-10-21 02:30")) {
		t.Fatal("next daily at slot", n)
	}
	// Saving the schedule doesn't trigger a run for a slot already past...
	sch.Updated = at("2026-10-20 09:00").UnixMilli()
	if Due(sch, config.BackupRun{}, at("2026-10-20 09:01")) {
		t.Fatal("due right after saving")
	}
	// ...but the next slot does, once.
	if !Due(sch, config.BackupRun{}, at("2026-10-21 02:31")) {
		t.Fatal("not due at the next slot")
	}
	if Due(sch, config.BackupRun{Started: at("2026-10-21 02:31").UnixMilli()}, at("2026-10-21 08:00")) {
		t.Fatal("due again after running")
	}
	// A slot missed while the appliance was off runs when it's back.
	if !Due(sch, config.BackupRun{Started: at("2026-10-21 02:31").UnixMilli()}, at("2026-10-23 10:00")) {
		t.Fatal("missed slot not caught up")
	}
	weekly := config.BackupSchedule{Enabled: true, Frequency: "weekly", Weekday: 0, Time: "23:15"} // Sundays
	if n := Next(weekly, at("2026-10-20 12:00")); !n.Equal(at("2026-10-25 23:15")) || n.Weekday() != time.Sunday {
		t.Fatal("next weekly", n)
	}
	sch.Enabled = false
	if Due(sch, config.BackupRun{}, at("2026-10-30 03:00")) {
		t.Fatal("due while disabled")
	}
}

// sftpServer serves dir over SFTP, accepting the given public key, or the
// password "sftp-pass" for user "backup".
func sftpServer(t *testing.T, dir string, client ssh.PublicKey) (addr string, hostKey ssh.PublicKey) {
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(hk)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == "backup" && string(k.Marshal()) == string(client.Marshal()) {
				return nil, nil
			}
			return nil, io.EOF
		},
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == "backup" && string(p) == "sftp-pass" {
				return nil, nil
			}
			return nil, io.EOF
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, _ := nc.Accept()
					go func() {
						for r := range creqs {
							r.Reply(r.Type == "subsystem" && string(r.Payload[4:]) == "sftp", nil)
							if r.Type == "subsystem" {
								srv, _ := sftp.NewServer(ch, sftp.WithServerWorkingDirectory(dir))
								go func() { srv.Serve(); ch.Close() }()
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), signer.PublicKey()
}

func newScheduler(t *testing.T) (*Scheduler, *config.DB, string) {
	dir := t.TempDir()
	cfg, err := config.Open(filepath.Join(dir, "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cfg.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := &backup.Manager{Dir: dir, Version: "test", Log: log, Snapshot: cfg.Snapshot}
	return &Scheduler{Cfg: cfg, Backups: m, Log: log, RetryDelay: 10 * time.Millisecond}, cfg, dir
}

// runNow runs the schedule and waits for it.
func runNow(t *testing.T, s *Scheduler) config.BackupRun {
	t.Helper()
	time.Sleep(1100 * time.Millisecond) // backup names have one-second resolution
	if err := s.RunNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		if running, _ := s.Running(); !running {
			return s.Cfg.BackupRun()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("run did not finish")
	return config.BackupRun{}
}

func ownFiles(t *testing.T, dir string) (own, other []string) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if backup.IsOwn(e.Name()) {
			own = append(own, e.Name())
		} else {
			other = append(other, e.Name())
		}
	}
	return own, other
}

func TestSFTPDestination(t *testing.T) {
	s, cfg, _ := newScheduler(t)
	signer, _, err := cfg.BackupSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	remote := t.TempDir()
	addr, hostKey := sftpServer(t, remote, signer.PublicKey())
	host, port, _ := net.SplitHostPort(addr)
	var p int
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	d := config.BackupDestination{Type: "sftp", Host: host, Port: p, Username: "backup", SFTPAuth: "key", Path: "backups/tributary"}
	env := Env{SSHKey: signer}

	// First contact: the host key must be confirmed.
	res := Test(context.Background(), d, env, backup.IsOwn)
	if res.OK || res.HostKey == "" || res.Fingerprint != ssh.FingerprintSHA256(hostKey) {
		t.Fatalf("unknown host key: %+v", res)
	}
	d.HostKey = res.HostKey
	if res = Test(context.Background(), d, env, backup.IsOwn); !res.OK {
		t.Fatalf("test: %+v", res)
	}
	// Password authentication works too; a wrong password is explained.
	pw := d
	pw.SFTPAuth, pw.Password = "password", "sftp-pass"
	if res = Test(context.Background(), pw, env, backup.IsOwn); !res.OK {
		t.Fatalf("password: %+v", res)
	}
	pw.Password = "wrong"
	if res = Test(context.Background(), pw, env, backup.IsOwn); res.OK || !strings.Contains(res.Message, "rejected") {
		t.Fatalf("wrong password: %+v", res)
	}

	id, _ := age.GenerateX25519Identity()
	if _, err := cfg.SaveBackupSchedule(config.BackupSchedule{Enabled: true, Frequency: "daily", Time: "03:00", Encryption: "publickey",
		PublicKeys: id.Recipient().String(), KeepLocal: 1, KeepRemote: 2, Destination: d}); err != nil {
		t.Fatal(err)
	}
	// Another appliance's backup and an unrelated file in the same folder.
	os.MkdirAll(filepath.Join(remote, "backups/tributary"), 0o755)
	os.WriteFile(filepath.Join(remote, "backups/tributary", "tributary-otherhost-20200101-000000.tbk"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(remote, "backups/tributary", "notes.txt"), []byte("x"), 0o644)

	for i := 0; i < 3; i++ {
		if run := runNow(t, s); !run.OK || !run.Copied || run.Error != "" {
			t.Fatalf("run %d: %+v", i, run)
		}
	}
	own, other := ownFiles(t, filepath.Join(remote, "backups/tributary"))
	if len(own) != 2 || len(other) != 2 {
		t.Fatalf("remote: own %v, other %v", own, other)
	}
	if list, _ := s.Backups.List(); len(list) != 1 || list[0].Name != own[1] {
		t.Fatalf("local: %+v (remote newest %s)", list, own[1])
	}
	// The copy decrypts with the private key.
	f, _ := os.Open(filepath.Join(remote, "backups/tributary", own[1]))
	r := &backup.Manager{Dir: t.TempDir(), Log: s.Log}
	r.Upload(f, 1<<30)
	f.Close()
	if man, err := r.Inspect(id.String()); err != nil || !man.Scheduled {
		t.Fatalf("restore check: %v", err)
	}

	// A changed host key stops the copy; the backup stays on the appliance.
	_, other2, _ := ed25519.GenerateKey(rand.Reader)
	os2, _ := ssh.NewSignerFromKey(other2)
	sch, _ := cfg.BackupScheduleSecrets()
	sch.Destination.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(os2.PublicKey())))
	sch.Passphrase = ""
	if _, err := cfg.SaveBackupSchedule(sch); err != nil {
		t.Fatal(err)
	}
	run := runNow(t, s)
	if run.OK || !strings.Contains(run.Error, "host key has changed") || run.Name == "" || run.LastSuccess == 0 {
		t.Fatalf("changed host key: %+v", run)
	}
}

func TestS3Destination(t *testing.T) {
	be := s3mem.New()
	be.CreateBucket("backups")
	srv := httptest.NewServer(gofakes3.New(be).Server())
	defer srv.Close()
	d := config.BackupDestination{Type: "s3", Endpoint: srv.URL, Region: "us-east-1", Bucket: "backups", Path: "appliances/a1",
		AccessKey: "AKIATEST", SecretKey: "secret", PathStyle: true}
	if res := Test(context.Background(), d, Env{}, backup.IsOwn); !res.OK {
		t.Fatalf("test: %+v", res)
	}
	missing := d
	missing.Bucket = "nope"
	if res := Test(context.Background(), missing, Env{}, backup.IsOwn); res.OK || !strings.Contains(res.Message, "bucket doesn't exist") {
		t.Fatalf("missing bucket: %+v", res)
	}

	s, cfg, _ := newScheduler(t)
	if _, err := cfg.SaveBackupSchedule(config.BackupSchedule{Enabled: true, Frequency: "weekly", Weekday: 3, Time: "04:00", Encryption: "passphrase",
		Passphrase: "correct horse battery", KeepLocal: 2, KeepRemote: 1, Destination: d}); err != nil {
		t.Fatal(err)
	}
	if v := cfg.BackupSchedule(); !v.HasPassphrase || v.Passphrase != "" || !v.Destination.HasSecretKey || v.Destination.SecretKey != "" {
		t.Fatalf("secrets exposed or lost: %+v", v)
	}
	for i := 0; i < 2; i++ {
		if run := runNow(t, s); !run.OK || !run.Copied {
			t.Fatalf("run %d: %+v", i, run)
		}
	}
	tgt, err := Open(context.Background(), d, Env{})
	if err != nil {
		t.Fatal(err)
	}
	objs, _ := tgt.List(context.Background())
	if len(objs) != 1 || !backup.IsOwn(objs[0].Name) {
		t.Fatalf("remote objects: %+v", objs)
	}
	if list, _ := s.Backups.List(); len(list) != 2 {
		t.Fatalf("local: %d", len(list))
	}
}

// TestSMBLive runs against a real SMB server when NFA_TEST_SMB is set, as
// host:port|share|user|password.
func TestSMBLive(t *testing.T) {
	spec := os.Getenv("NFA_TEST_SMB")
	if spec == "" {
		t.Skip("NFA_TEST_SMB not set")
	}
	f := strings.Split(spec, "|")
	host, port, _ := net.SplitHostPort(f[0])
	p, _ := strconv.Atoi(port)
	d := config.BackupDestination{Type: "smb", Host: host, Port: p, Share: f[1], Username: f[2], Password: f[3], Path: "tributary/backups"}
	if res := Test(context.Background(), d, Env{}, backup.IsOwn); !res.OK {
		t.Fatalf("test: %+v", res)
	}
	bad := d
	bad.Password = "wrong"
	if res := Test(context.Background(), bad, Env{}, backup.IsOwn); res.OK || !strings.Contains(res.Message, "rejected") {
		t.Fatalf("wrong password: %+v", res)
	}
	noshare := d
	noshare.Share = "nosuchshare"
	if res := Test(context.Background(), noshare, Env{}, backup.IsOwn); res.OK || !strings.Contains(res.Message, "no share") {
		t.Fatalf("missing share: %+v", res)
	}
	s, cfg, _ := newScheduler(t)
	if _, err := cfg.SaveBackupSchedule(config.BackupSchedule{Enabled: true, Time: "04:00", Passphrase: "correct horse battery", KeepRemote: 1, Destination: d}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if run := runNow(t, s); !run.OK || !run.Copied {
			t.Fatalf("run %d: %+v", i, run)
		}
	}
	tgt, err := Open(context.Background(), d, Env{})
	if err != nil {
		t.Fatal(err)
	}
	defer tgt.Close()
	objs, _ := tgt.List(context.Background())
	n := 0
	for _, o := range objs {
		if backup.IsOwn(o.Name) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("remote: %+v", objs)
	}
}
