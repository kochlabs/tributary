package offsite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/kochlabs/tributary/internal/config"
)

// UnknownHostKeyError reports the key of an SFTP server whose key hasn't
// been confirmed yet.
type UnknownHostKeyError struct{ Key ssh.PublicKey }

func (e *UnknownHostKeyError) Error() string {
	return "the server's host key (" + ssh.FingerprintSHA256(e.Key) + ") hasn't been confirmed"
}

// AuthorizedKey is the key in authorized_keys format, for pinning.
func (e *UnknownHostKeyError) AuthorizedKey() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(e.Key)))
}

type sftpTarget struct {
	ssh *ssh.Client
	c   *sftp.Client
	dir string // "." for the login directory
}

func openSFTP(ctx context.Context, d config.BackupDestination, env Env) (Target, error) {
	var pinned ssh.PublicKey
	if d.HostKey != "" {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(d.HostKey))
		if err != nil {
			return nil, errors.New("the pinned host key is invalid")
		}
		pinned = k
	}
	cfg := &ssh.ClientConfig{
		User:    d.Username,
		Timeout: 15 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			switch {
			case pinned == nil:
				return &UnknownHostKeyError{Key: key}
			case string(key.Marshal()) != string(pinned.Marshal()):
				return fmt.Errorf("the server's host key has changed (now %s, expected %s): if that's expected, test the connection again and confirm the new key",
					ssh.FingerprintSHA256(key), ssh.FingerprintSHA256(pinned))
			}
			return nil
		},
	}
	if d.SFTPAuth == "password" {
		cfg.Auth = []ssh.AuthMethod{ssh.Password(d.Password)}
	} else {
		if env.SSHKey == nil {
			return nil, errors.New("the appliance's SSH key is not available")
		}
		cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(env.SSHKey)}
	}
	// On first contact prefer the strongest common key types, Ed25519 first.
	cfg.HostKeyAlgorithms = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	if pinned != nil {
		// Ask for the pinned key's type, so a server with several host keys
		// presents the one we know. RSA keys sign with SHA-2 (OpenSSH no
		// longer accepts ssh-rsa/SHA-1 signatures).
		cfg.HostKeyAlgorithms = []string{pinned.Type()}
		if pinned.Type() == ssh.KeyAlgoRSA {
			cfg.HostKeyAlgorithms = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
		}
	}
	addr := net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	// The handshake has no context; bound it with a deadline.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		var unknown *UnknownHostKeyError
		if errors.As(err, &unknown) {
			return nil, unknown
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			if d.SFTPAuth == "password" {
				return nil, errors.New("the user name or password was rejected")
			}
			return nil, errors.New("the server rejected the appliance's SSH key (add its public key to the user's authorized_keys)")
		}
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(cc, chans, reqs)
	sc, err := sftp.NewClient(client, sftp.UseConcurrentWrites(true))
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("starting SFTP (is the SFTP subsystem enabled?): %w", err)
	}
	dir := d.Path
	if dir == "" {
		dir = "."
	}
	return &sftpTarget{ssh: client, c: sc, dir: dir}, nil
}

func (t *sftpTarget) path(name string) string { return path.Join(t.dir, name) }

func (t *sftpTarget) Put(ctx context.Context, name string, r io.Reader, size int64) error {
	if t.dir != "." {
		if err := t.c.MkdirAll(t.dir); err != nil {
			return fmt.Errorf("creating the folder: %w", err)
		}
	}
	tmp := t.path(name + ".partial")
	f, err := t.c.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	n, err := f.ReadFrom(r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n != size {
		err = fmt.Errorf("wrote %d of %d bytes", n, size)
	}
	if err != nil {
		_ = t.c.Remove(tmp)
		return err
	}
	if _, ok := t.c.HasExtension("posix-rename@openssh.com"); ok {
		return t.c.PosixRename(tmp, t.path(name))
	}
	return t.c.Rename(tmp, t.path(name))
}

func (t *sftpTarget) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	return t.c.Open(t.path(name))
}

func (t *sftpTarget) List(ctx context.Context) ([]Object, error) {
	entries, err := t.c.ReadDir(t.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // created by the first upload
	}
	if err != nil {
		return nil, err
	}
	out := make([]Object, 0, len(entries))
	for _, e := range entries {
		if e.Mode().IsRegular() {
			out = append(out, Object{Name: e.Name(), Size: e.Size(), Modified: e.ModTime()})
		}
	}
	return out, nil
}

func (t *sftpTarget) Delete(ctx context.Context, name string) error { return t.c.Remove(t.path(name)) }

func (t *sftpTarget) Close() error {
	t.c.Close()
	return t.ssh.Close()
}
