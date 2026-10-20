// Package syslog forwards audit entries to syslog servers over UDP, TCP or
// TLS (RFC 5424 or RFC 3164 messages; octet-counted framing on streams per
// RFC 6587/5425).
package syslog

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kochlabs/tributary/internal/config"
)

// Message is one audit entry to forward.
type Message struct {
	Time     time.Time
	User     string
	Action   string
	Detail   string
	Severity int // 0–7
}

const (
	SeverityWarning = 4
	SeverityNotice  = 5
)

// FromAudit turns an audit entry into a message; failures are warnings.
func FromAudit(e config.AuditEntry) Message {
	sev := SeverityNotice
	if strings.HasSuffix(e.Action, ".failed") || strings.HasSuffix(e.Action, "failed") {
		sev = SeverityWarning
	}
	return Message{Time: time.UnixMilli(e.TS), User: e.Username, Action: e.Action, Detail: e.Detail, Severity: sev}
}

type Status struct {
	Sent        uint64 `json:"sent"`
	Dropped     uint64 `json:"dropped"`
	LastError   string `json:"lastError,omitempty"`
	LastErrorAt int64  `json:"lastErrorAt,omitempty"`
}

// Forwarder sends messages in the background so audit writes never wait on
// the network. If a server is unreachable the message is dropped and counted.
type Forwarder struct {
	log      *slog.Logger
	host     string
	cfg      atomic.Pointer[config.Syslog]
	roots    func() *x509.CertPool
	ch       chan Message
	sent     atomic.Uint64
	dropped  atomic.Uint64
	errMu    sync.Mutex
	lastErr  string
	lastErrT int64
	conns    map[string]net.Conn // by transport+address, used by the run loop only
	reset    atomic.Bool         // settings changed: reconnect
}

// New creates a forwarder; roots returns the CAs trusted for TLS.
func New(log *slog.Logger, roots func() *x509.CertPool) *Forwarder {
	host, _ := os.Hostname()
	if host == "" {
		host = "-"
	}
	f := &Forwarder{log: log, host: host, roots: roots, ch: make(chan Message, 1000), conns: map[string]net.Conn{}}
	d := config.DefaultSyslog()
	f.cfg.Store(&d)
	return f
}

// SetConfig applies new settings; open connections are replaced.
func (f *Forwarder) SetConfig(c config.Syslog) {
	f.cfg.Store(&c)
	f.reset.Store(true)
}

// Send queues m for every configured server; it never blocks.
func (f *Forwarder) Send(m Message) {
	if !f.cfg.Load().Enabled {
		return
	}
	select {
	case f.ch <- m:
	default:
		f.dropped.Add(1)
	}
}

func (f *Forwarder) Status() Status {
	f.errMu.Lock()
	defer f.errMu.Unlock()
	return Status{Sent: f.sent.Load(), Dropped: f.dropped.Load(), LastError: f.lastErr, LastErrorAt: f.lastErrT}
}

func (f *Forwarder) fail(err error) {
	f.errMu.Lock()
	f.lastErr, f.lastErrT = err.Error(), time.Now().UnixMilli()
	f.errMu.Unlock()
}

// Run delivers queued messages until ctx ends.
func (f *Forwarder) Run(ctx context.Context) {
	defer f.closeAll()
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-f.ch:
			if f.reset.Swap(false) {
				f.closeAll()
			}
			c := f.cfg.Load()
			if !c.Enabled {
				continue
			}
			for _, t := range c.Targets {
				if err := f.deliver(ctx, *c, t, m); err != nil {
					f.dropped.Add(1)
					f.fail(fmt.Errorf("%s (%s): %w", t.HostPort(), t.Transport, err))
				} else {
					f.sent.Add(1)
				}
			}
		}
	}
}

// deliver sends m to t, reconnecting once if a stream connection broke.
func (f *Forwarder) deliver(ctx context.Context, c config.Syslog, t config.SyslogTarget, m Message) error {
	frame := f.frame(c, t, m)
	key := t.Transport + "|" + t.HostPort()
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := f.conn(ctx, key, t)
		if err != nil {
			return err
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err = conn.Write(frame); err == nil {
			return nil
		}
		conn.Close()
		delete(f.conns, key)
		if attempt == 1 {
			return err
		}
	}
	return nil
}

func (f *Forwarder) conn(ctx context.Context, key string, t config.SyslogTarget) (net.Conn, error) {
	if c, ok := f.conns[key]; ok {
		return c, nil
	}
	c, err := Dial(ctx, t, f.roots)
	if err != nil {
		return nil, err
	}
	f.conns[key] = c
	return c, nil
}

// Dial connects to a syslog server.
func Dial(ctx context.Context, t config.SyslogTarget, roots func() *x509.CertPool) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addr := t.HostPort()
	switch t.Transport {
	case "udp":
		return (&net.Dialer{}).DialContext(ctx, "udp", addr)
	case "tcp":
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	case "tls":
		host, _, _ := net.SplitHostPort(addr)
		var pool *x509.CertPool
		if roots != nil {
			pool = roots()
		}
		d := &tls.Dialer{Config: &tls.Config{ServerName: host, RootCAs: pool, MinVersion: tls.VersionTLS12}}
		return d.DialContext(ctx, "tcp", addr)
	}
	return nil, fmt.Errorf("unknown transport %q", t.Transport)
}

func (f *Forwarder) closeAll() {
	for k, c := range f.conns {
		c.Close()
		delete(f.conns, k)
	}
}

// frame formats m for t: a bare message over UDP, octet-counted on streams.
func (f *Forwarder) frame(c config.Syslog, t config.SyslogTarget, m Message) []byte {
	msg := Format(c, f.host, m)
	if t.Transport == "udp" {
		return []byte(msg)
	}
	return []byte(strconv.Itoa(len(msg)) + " " + msg)
}

// Format renders m as an RFC 5424 or RFC 3164 message. The structured
// content goes in the message as key=value pairs, which collectors parse
// without a registered SD-ID.
func Format(c config.Syslog, host string, m Message) string {
	if m.Time.IsZero() {
		m.Time = time.Now()
	}
	pri := c.Facility*8 + m.Severity
	body := "user=" + quote(m.User) + " action=" + quote(m.Action)
	if m.Detail != "" {
		body += " detail=" + quote(m.Detail)
	}
	if c.Format == "rfc3164" {
		return fmt.Sprintf("<%d>%s %s tributary: %s", pri, m.Time.Format(time.Stamp), host, body)
	}
	msgid := m.Action
	if msgid == "" || len(msgid) > 32 || strings.ContainsAny(msgid, " \t\"") {
		msgid = "-"
	}
	return fmt.Sprintf("<%d>1 %s %s tributary %d %s - %s", pri, m.Time.UTC().Format("2006-01-02T15:04:05.000Z"), host, os.Getpid(), msgid, body)
}

// quote leaves simple values bare and quotes the rest, escaping quotes and
// backslashes, and replaces line breaks so each entry stays one line.
func quote(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	if s != "" && !strings.ContainsAny(s, " \t\"\\=") {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// Test sends a test message to each target directly and reports per-target
// results (nil on success).
func (f *Forwarder) Test(ctx context.Context, c config.Syslog, user string) []error {
	m := Message{Time: time.Now(), User: user, Action: "syslog.test", Detail: "Test message from Tributary", Severity: SeverityNotice}
	errs := make([]error, len(c.Targets))
	for i, t := range c.Targets {
		conn, err := Dial(ctx, t, f.roots)
		if err != nil {
			errs[i] = err
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write(f.frame(c, t, m))
		conn.Close()
		errs[i] = err
	}
	return errs
}
