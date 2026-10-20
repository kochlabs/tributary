// Package offsite copies backups to other systems (SMB shares, S3-compatible
// object storage, SFTP servers) and runs the backup schedule.
package offsite

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"nfa/internal/config"
)

// Object is a file at a destination.
type Object struct {
	Name     string
	Size     int64
	Modified time.Time
}

// Target is an open connection to a destination folder (or key prefix).
type Target interface {
	// Put stores size bytes from r as name. Uploads go to a temporary name
	// first where the protocol allows, so a partial file never looks like a
	// backup.
	Put(ctx context.Context, name string, r io.Reader, size int64) error
	Get(ctx context.Context, name string) (io.ReadCloser, error)
	// List returns the files directly in the folder.
	List(ctx context.Context) ([]Object, error)
	Delete(ctx context.Context, name string) error
	Close() error
}

// Env is what destinations need from the appliance.
type Env struct {
	// RootCAs verifies TLS (S3): the system roots plus the trusted CAs.
	RootCAs *x509.CertPool
	// SSHKey authenticates to SFTP servers with key authentication.
	SSHKey ssh.Signer
}

// Open connects to a destination.
func Open(ctx context.Context, d config.BackupDestination, env Env) (Target, error) {
	switch d.Type {
	case "smb":
		return openSMB(ctx, d)
	case "s3":
		return openS3(ctx, d, env)
	case "sftp":
		return openSFTP(ctx, d, env)
	}
	return nil, errors.New("no destination configured")
}

// TestResult describes a destination check.
type TestResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	// Backups is how many of this appliance's backups are there already.
	Backups int `json:"backups"`
	// HostKey and Fingerprint are the SFTP server's key, to confirm and pin.
	HostKey     string `json:"hostKey,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// KeyFile is where OpenSSH keeps that key on the server, for comparing.
	KeyFile string `json:"keyFile,omitempty"`
}

func hostKeyFile(keyType string) string {
	name := "rsa"
	switch {
	case keyType == ssh.KeyAlgoED25519:
		name = "ed25519"
	case strings.HasPrefix(keyType, "ecdsa-"):
		name = "ecdsa"
	}
	return "/etc/ssh/ssh_host_" + name + "_key.pub"
}

// Test connects, writes a small file, reads it back and deletes it, which
// also checks the permissions a backup needs.
func Test(ctx context.Context, d config.BackupDestination, env Env, own func(string) bool) TestResult {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	t, err := Open(ctx, d, env)
	var unknown *UnknownHostKeyError
	if errors.As(err, &unknown) {
		return TestResult{Message: "Connected. Check the server's host key fingerprint and confirm it to continue.",
			HostKey: unknown.AuthorizedKey(), Fingerprint: ssh.FingerprintSHA256(unknown.Key), KeyFile: hostKeyFile(unknown.Key.Type())}
	}
	if err != nil {
		return TestResult{Message: err.Error()}
	}
	defer t.Close()
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	name := ".tributary-test-" + hex.EncodeToString(buf[:6])
	data := []byte("Tributary backup destination test " + hex.EncodeToString(buf) + "\n")
	if err := t.Put(ctx, name, bytes.NewReader(data), int64(len(data))); err != nil {
		return TestResult{Message: "Connected, but writing a file failed: " + err.Error()}
	}
	r, err := t.Get(ctx, name)
	if err != nil {
		_ = t.Delete(ctx, name)
		return TestResult{Message: "Wrote a test file, but reading it back failed: " + err.Error()}
	}
	got, err := io.ReadAll(io.LimitReader(r, 1024))
	r.Close()
	if err != nil || !bytes.Equal(got, data) {
		_ = t.Delete(ctx, name)
		return TestResult{Message: "The test file read back differently from what was written."}
	}
	if err := t.Delete(ctx, name); err != nil {
		return TestResult{Message: "Wrote and read a test file, but deleting it failed (old backups couldn't be pruned): " + err.Error()}
	}
	list, err := t.List(ctx)
	if err != nil {
		return TestResult{Message: "Listing the folder failed: " + err.Error()}
	}
	n := 0
	for _, o := range list {
		if own(o.Name) {
			n++
		}
	}
	return TestResult{OK: true, Backups: n, Message: fmt.Sprintf("Connected, and a test file was written, read back and deleted at %s.", d.Describe())}
}
