// Package mail sends email through the configured SMTP server.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kochlabs/tributary/internal/config"
)

// Attachment is a file attached to a message.
type Attachment struct {
	Name        string
	ContentType string
	Data        []byte
}

// Message is one email. Text is required; HTML, if set, is the preferred
// alternative.
type Message struct {
	To          []string
	Subject     string
	Text        string
	HTML        string
	Attachments []Attachment
}

const maxRecipients = 50

// Recipients parses a comma- or newline-separated list of addresses.
func Recipients(list string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ';' || r == '\n' }) {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		a, err := mail.ParseAddress(f)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid address", f)
		}
		if !slices.Contains(out, a.Address) {
			out = append(out, a.Address)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("enter at least one recipient")
	}
	if len(out) > maxRecipients {
		return nil, fmt.Errorf("at most %d recipients", maxRecipients)
	}
	return out, nil
}

// Send delivers m through the server in cfg. roots are the CAs trusted for
// the server's certificate (nil: the system's).
func Send(ctx context.Context, cfg config.Email, roots *x509.CertPool, m Message) error {
	if cfg.Host == "" || cfg.From == "" {
		return errors.New("email is not set up")
	}
	if len(m.To) == 0 {
		return errors.New("no recipients")
	}
	for _, to := range m.To {
		if a, err := mail.ParseAddress(to); err != nil || a.Address != to {
			return fmt.Errorf("%q is not a plain email address", to)
		}
	}
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return fmt.Errorf("sender: %w", err)
	}
	body, err := build(from, m)
	if err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Minute)
		defer cancel()
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	tlsConf := &tls.Config{ServerName: cfg.Host, RootCAs: roots, MinVersion: tls.VersionTLS12}

	d := &net.Dialer{}
	var conn net.Conn
	if cfg.Security == "tls" {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tlsConf}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	// Close the connection if ctx ends first, unblocking any read.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return wrap("greeting", err)
	}
	defer c.Close()
	if h, err := os.Hostname(); err == nil && h != "" {
		if err := c.Hello(h); err != nil {
			return wrap("EHLO", err)
		}
	}
	if cfg.Security == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("the server doesn't offer STARTTLS: choose TLS or None, or check the port")
		}
		if err := c.StartTLS(tlsConf); err != nil {
			return wrap("STARTTLS", err)
		}
	}
	if cfg.Username != "" {
		ok, mechs := c.Extension("AUTH")
		if !ok {
			return errors.New("the server doesn't accept sign-in (no AUTH): clear the username to send without one")
		}
		var a smtp.Auth
		switch fields := strings.Fields(strings.ToUpper(mechs)); {
		case slices.Contains(fields, "PLAIN"):
			a = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		case slices.Contains(fields, "LOGIN"):
			a = &loginAuth{cfg.Username, cfg.Password}
		default:
			return fmt.Errorf("the server offers no supported sign-in method (it offers %s)", mechs)
		}
		if err := c.Auth(a); err != nil {
			return wrap("sign-in", err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return wrap("sender", err)
	}
	for _, to := range m.To {
		if err := c.Rcpt(to); err != nil {
			return wrap("recipient "+to, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return wrap("DATA", err)
	}
	if _, err := w.Write(body); err != nil {
		return wrap("sending the message", err)
	}
	if err := w.Close(); err != nil {
		return wrap("sending the message", err)
	}
	return c.Quit()
}

// wrap names the step that failed, keeping the server's reply.
func wrap(step string, err error) error {
	var tp *textproto.Error
	if errors.As(err, &tp) {
		return fmt.Errorf("%s: the server replied %d %s", step, tp.Code, tp.Msg)
	}
	return fmt.Errorf("%s: %w", step, err)
}

// loginAuth is AUTH LOGIN, for servers that don't offer PLAIN. Like
// smtp.PlainAuth it refuses to send credentials without TLS.
type loginAuth struct{ user, pass string }

func (a *loginAuth) Start(s *smtp.ServerInfo) (string, []byte, error) {
	if !s.TLS {
		return "", nil, errors.New("refusing to send the password without TLS")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch p := strings.ToLower(strings.TrimSpace(string(fromServer))); {
	case strings.HasPrefix(p, "user"):
		return []byte(a.user), nil
	case strings.HasPrefix(p, "pass"):
		return []byte(a.pass), nil
	}
	return nil, fmt.Errorf("unexpected sign-in prompt %q", fromServer)
}

// build renders m as a MIME message.
func build(from *mail.Address, m Message) ([]byte, error) {
	var b bytes.Buffer
	host := "tributary.local"
	if _, h, ok := strings.Cut(from.Address, "@"); ok {
		host = h
	}
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	hdr := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	hdr("From", from.String())
	hdr("To", strings.Join(m.To, ", "))
	hdr("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	hdr("Date", time.Now().Format(time.RFC1123Z))
	hdr("Message-ID", "<"+hex.EncodeToString(id)+"@"+host+">")
	hdr("MIME-Version", "1.0")
	hdr("Auto-Submitted", "auto-generated")

	if m.HTML == "" && len(m.Attachments) == 0 {
		hdr("Content-Type", "text/plain; charset=utf-8")
		hdr("Content-Transfer-Encoding", "quoted-printable")
		b.WriteString("\r\n")
		if err := qp(&b, m.Text); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	}

	mixed := multipart.NewWriter(&b)
	hdr("Content-Type", `multipart/mixed; boundary="`+mixed.Boundary()+`"`)
	b.WriteString("\r\n")

	// The text, with an HTML alternative if given.
	if m.HTML == "" {
		if err := textPart(mixed, "text/plain", m.Text); err != nil {
			return nil, err
		}
	} else {
		var alt bytes.Buffer
		aw := multipart.NewWriter(&alt)
		if err := textPart(aw, "text/plain", m.Text); err != nil {
			return nil, err
		}
		if err := textPart(aw, "text/html", m.HTML); err != nil {
			return nil, err
		}
		if err := aw.Close(); err != nil {
			return nil, err
		}
		p, err := mixed.CreatePart(textproto.MIMEHeader{"Content-Type": {`multipart/alternative; boundary="` + aw.Boundary() + `"`}})
		if err != nil {
			return nil, err
		}
		if _, err := p.Write(alt.Bytes()); err != nil {
			return nil, err
		}
	}

	for _, a := range m.Attachments {
		ct := a.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		p, err := mixed.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {mime.FormatMediaType(ct, map[string]string{"name": a.Name})},
			"Content-Disposition":       {mime.FormatMediaType("attachment", map[string]string{"filename": a.Name})},
			"Content-Transfer-Encoding": {"base64"},
		})
		if err != nil {
			return nil, err
		}
		enc := base64.StdEncoding.EncodeToString(a.Data)
		for len(enc) > 76 {
			fmt.Fprintf(p, "%s\r\n", enc[:76])
			enc = enc[76:]
		}
		fmt.Fprintf(p, "%s\r\n", enc)
	}
	if err := mixed.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func textPart(w *multipart.Writer, ct, s string) error {
	p, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {ct + "; charset=utf-8"}, "Content-Transfer-Encoding": {"quoted-printable"}})
	if err != nil {
		return err
	}
	var b bytes.Buffer
	if err := qp(&b, s); err != nil {
		return err
	}
	_, err = p.Write(b.Bytes())
	return err
}

func qp(b *bytes.Buffer, s string) error {
	w := quotedprintable.NewWriter(b)
	if _, err := w.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n"))); err != nil {
		return err
	}
	return w.Close()
}
