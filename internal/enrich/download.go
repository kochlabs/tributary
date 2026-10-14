package enrich

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// UserAgent identifies the appliance to database download servers.
var UserAgent = "Tributary"

const maxDownload = 2 << 30

// fetch downloads url to dest. The body may be the file itself, gzipped, or
// a gzipped tar archive, from which the first entry ending in suffix is
// used (MaxMind ships databases that way). validate checks the result before
// it replaces dest, so a bad download never removes a working database.
func fetch(ctx context.Context, rawURL, user, pass, dest, suffix string, validate func(string) error) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent)
	if user != "" || pass != "" {
		// Go drops the Authorization header when a redirect leaves the host,
		// so credentials aren't sent on to storage buckets.
		req.SetBasicAuth(user, pass)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("access denied (%s): check the account and license key", resp.Status)
	default:
		return fmt.Errorf("server returned %s", resp.Status)
	}
	body, err := unpack(io.LimitReader(resp.Body, maxDownload), suffix)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, io.LimitReader(body, maxDownload)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := validate(tmp.Name()); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}

// unpack strips gzip and tar layers from r.
func unpack(r io.Reader, suffix string) (io.Reader, error) {
	br := bufio.NewReaderSize(r, 4096)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		br = bufio.NewReaderSize(zr, 4096)
	}
	if hdr, _ := br.Peek(262); len(hdr) == 262 && bytes.Equal(hdr[257:262], []byte("ustar")) {
		tr := tar.NewReader(br)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				return nil, fmt.Errorf("archive contains no %s file", suffix)
			}
			if err != nil {
				return nil, err
			}
			if h.Typeflag == tar.TypeReg && strings.HasSuffix(h.Name, suffix) {
				return tr, nil
			}
		}
	}
	return br, nil
}

// openMaybeGzip opens a local file, transparently decompressing gzip.
func openMaybeGzip(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r, err := unpack(f, "")
	if err != nil {
		f.Close()
		return nil, err
	}
	return struct {
		io.Reader
		io.Closer
	}{r, f}, nil
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return "the configured URL"
}

// redact removes a URL (which may embed a license key) from an error.
func redact(err error, raw string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if raw != "" && strings.Contains(msg, raw) {
		msg = strings.ReplaceAll(msg, raw, hostOf(raw))
	}
	if u, perr := url.Parse(raw); perr == nil && u.RawQuery != "" {
		msg = strings.ReplaceAll(msg, u.RawQuery, "…")
	}
	return errors.New(msg)
}
