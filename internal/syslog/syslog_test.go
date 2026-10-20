package syslog

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfa/internal/config"
)

func TestFormat(t *testing.T) {
	m := Message{Time: time.Date(2026, 10, 19, 8, 5, 3, 120e6, time.UTC), User: "admin", Action: "login.failed", Detail: `from 10.0.0.1 "x"`, Severity: SeverityWarning}
	got := Format(config.Syslog{Format: "rfc5424", Facility: 10}, "nfa1", m)
	if !strings.HasPrefix(got, "<84>1 2026-10-19T08:05:03.120Z nfa1 tributary ") || !strings.HasSuffix(got, ` login.failed - user=admin action=login.failed detail="from 10.0.0.1 \"x\""`) {
		t.Errorf("rfc5424: %s", got)
	}
	got = Format(config.Syslog{Format: "rfc3164", Facility: 16}, "nfa1", Message{Time: m.Time, User: "a b", Action: "x", Severity: SeverityNotice})
	if !strings.HasPrefix(got, "<133>Oct 19 ") || !strings.HasSuffix(got, ` nfa1 tributary: user="a b" action=x`) {
		t.Errorf("rfc3164: %s", got)
	}
	if strings.Contains(Format(config.Syslog{Format: "rfc5424"}, "h", Message{Action: "a", Detail: "line1\nline2"}), "\n") {
		t.Error("newline in message")
	}
}

func TestForwardUDPTCPTLS(t *testing.T) {
	udp, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer udp.Close()
	tcp, _ := net.Listen("tcp", "127.0.0.1:0")
	defer tcp.Close()
	cert, pool := selfSigned(t)
	tl, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	defer tl.Close()

	got := make(chan string, 10)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			got <- "udp:" + string(buf[:n])
		}
	}()
	stream := func(name string, l net.Listener) {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				r := bufio.NewReader(c)
				for {
					n, err := r.ReadString(' ')
					if err != nil {
						return
					}
					size, _ := strconv.Atoi(strings.TrimSpace(n))
					b := make([]byte, size)
					if _, err := io.ReadFull(r, b); err != nil {
						return
					}
					got <- name + ":" + string(b)
				}
			}()
		}
	}
	go stream("tcp", tcp)
	go stream("tls", tl)

	f := New(slog.New(slog.NewTextHandler(io.Discard, nil)), func() *x509.CertPool { return pool })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)
	cfg := config.Syslog{Enabled: true, Format: "rfc5424", Facility: 10, Targets: []config.SyslogTarget{
		{Address: udp.LocalAddr().String(), Transport: "udp"},
		{Address: tcp.Addr().String(), Transport: "tcp"},
		{Address: "localhost:" + strconv.Itoa(tl.Addr().(*net.TCPAddr).Port), Transport: "tls"},
	}}
	f.SetConfig(cfg)
	if errs := f.Test(ctx, cfg, "admin"); errs[0] != nil || errs[1] != nil || errs[2] != nil {
		t.Fatalf("test: %v", errs)
	}
	f.Send(FromAudit(config.AuditEntry{TS: time.Now().UnixMilli(), Username: "admin", Action: "settings.update"}))
	f.Send(FromAudit(config.AuditEntry{TS: time.Now().UnixMilli(), Username: "eve", Action: "login.failed", Detail: "10.0.0.9"}))
	seen := map[string]int{}
	timeout := time.After(5 * time.Second)
	for len(seen) < 3 || seen["udp"]+seen["tcp"]+seen["tls"] < 9 {
		select {
		case m := <-got:
			proto, msg, _ := strings.Cut(m, ":")
			seen[proto]++
			if strings.Contains(msg, "login.failed") && !strings.HasPrefix(msg, "<84>") {
				t.Errorf("failed login should be a warning: %s", msg)
			}
		case <-timeout:
			t.Fatalf("received %v", seen)
		}
	}
	// The counter is bumped after the write returns, possibly after the
	// listener already has the message.
	for wait := time.Now().Add(2 * time.Second); f.Status().Sent < 6 && time.Now().Before(wait); {
		time.Sleep(10 * time.Millisecond)
	}
	if st := f.Status(); st.Sent != 6 || st.Dropped != 0 {
		t.Fatalf("status %+v", st)
	}

	// An unreachable server is counted and reported, and others still get messages.
	tcp.Close()
	f.SetConfig(config.Syslog{Enabled: true, Format: "rfc5424", Facility: 10, Targets: []config.SyslogTarget{{Address: tcp.Addr().String(), Transport: "tcp"}}})
	f.Send(Message{Action: "x"})
	deadline := time.Now().Add(5 * time.Second)
	for f.Status().Dropped == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if st := f.Status(); st.Dropped != 1 || st.LastError == "" {
		t.Fatalf("status after failure %+v", st)
	}
	// Disabled: nothing is queued.
	f.SetConfig(config.Syslog{})
	f.Send(Message{Action: "y"})
	time.Sleep(100 * time.Millisecond)
	if f.Status().Dropped != 1 {
		t.Fatal("sent while disabled")
	}
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pool
}
