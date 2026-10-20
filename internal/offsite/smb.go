package offsite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"

	"github.com/kochlabs/tributary/internal/config"
)

// smbTarget writes to a folder on an SMB 2/3 share. Message signing is
// required for authenticated sessions; the server decides on encryption
// (SMB 3 shares that require it are encrypted).
type smbTarget struct {
	conn  net.Conn
	sess  *smb2.Session
	share *smb2.Share
	dir   string // backslash-separated, "" for the share root
}

func openSMB(ctx context.Context, d config.BackupDestination) (Target, error) {
	addr := net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	dialer := &smb2.Dialer{
		// Guest sessions can't sign, so only require it with credentials.
		Negotiator: smb2.Negotiator{RequireMessageSigning: d.Username != ""},
		Initiator:  &smb2.NTLMInitiator{User: d.Username, Password: d.Password, Domain: d.Domain},
	}
	sess, err := dialer.DialConn(ctx, conn, addr)
	if err != nil {
		conn.Close()
		return nil, explainSMB(err)
	}
	sess = sess.WithContext(ctx)
	share, err := sess.Mount(`\\` + d.Host + `\` + d.Share)
	if err != nil {
		_ = sess.Logoff()
		conn.Close()
		return nil, fmt.Errorf("opening share %q: %w", d.Share, explainSMB(err))
	}
	return &smbTarget{conn: conn, sess: sess, share: share.WithContext(ctx), dir: strings.ReplaceAll(d.Path, "/", `\`)}, nil
}

// NTSTATUS codes worth explaining.
const (
	statusAccessDenied   = 0xC0000022
	statusLogonFailure   = 0xC000006D
	statusBadNetworkName = 0xC00000CC
	statusAccountLocked  = 0xC0000234
	statusPasswordExpire = 0xC0000071
)

func explainSMB(err error) error {
	var re *smb2.ResponseError
	if !errors.As(err, &re) {
		return err
	}
	switch re.Code {
	case statusLogonFailure:
		return errors.New("the user name or password was rejected")
	case statusBadNetworkName:
		return errors.New("the server has no share with that name")
	case statusAccessDenied:
		return errors.New("access denied (check the account's permissions on the share and folder)")
	case statusAccountLocked:
		return errors.New("the account is locked out")
	case statusPasswordExpire:
		return errors.New("the account's password has expired")
	}
	return err
}

func (t *smbTarget) path(name string) string {
	if t.dir == "" {
		return name
	}
	return t.dir + `\` + name
}

func (t *smbTarget) Put(ctx context.Context, name string, r io.Reader, size int64) error {
	if t.dir != "" {
		if err := t.share.MkdirAll(t.dir, 0o755); err != nil {
			return fmt.Errorf("creating the folder: %w", explainSMB(err))
		}
	}
	tmp := t.path(name + ".partial")
	f, err := t.share.Create(tmp)
	if err != nil {
		return explainSMB(err)
	}
	n, err := io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n != size {
		err = fmt.Errorf("wrote %d of %d bytes", n, size)
	}
	if err != nil {
		_ = t.share.Remove(tmp)
		return explainSMB(err)
	}
	return explainSMB(t.share.Rename(tmp, t.path(name)))
}

func (t *smbTarget) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	f, err := t.share.Open(t.path(name))
	if err != nil {
		return nil, explainSMB(err)
	}
	return f, nil
}

func (t *smbTarget) List(ctx context.Context) ([]Object, error) {
	entries, err := t.share.ReadDir(t.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // created by the first upload
	}
	if err != nil {
		return nil, explainSMB(err)
	}
	out := make([]Object, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, Object{Name: e.Name(), Size: e.Size(), Modified: e.ModTime()})
		}
	}
	return out, nil
}

func (t *smbTarget) Delete(ctx context.Context, name string) error {
	return explainSMB(t.share.Remove(t.path(name)))
}

func (t *smbTarget) Close() error {
	_ = t.share.Umount()
	_ = t.sess.Logoff()
	return t.conn.Close()
}
