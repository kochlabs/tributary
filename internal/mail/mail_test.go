package mail

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"mime"
	"net"
	stdmail "net/mail"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kochlabs/tributary/internal/config"
)

// fakeServer is a minimal SMTP server: EHLO, STARTTLS or implicit TLS,
// AUTH PLAIN/LOGIN, MAIL, RCPT, DATA.
type fakeServer struct {
	ln       net.Listener
	tls      *tls.Config
	implicit bool
	starttls bool
	auth     string // offered mechanisms, e.g. "PLAIN LOGIN"; "" = no AUTH
	user     string
	pass     string

	mu     sync.Mutex
	from   string
	rcpts  []string
	data   string
	authed bool
}

func newCert(t *testing.T) (*tls.Config, *x509.CertPool) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

func (s *fakeServer) start(t *testing.T) config.Email {
	var err error
	s.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.ln.Close() })
	go func() {
		for {
			c, err := s.ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	port, _ := strconv.Atoi(strings.Split(s.ln.Addr().String(), ":")[1])
	return config.Email{Host: "127.0.0.1", Port: port, From: "Tributary <nfa@example.com>"}
}

func (s *fakeServer) serve(c net.Conn) {
	defer c.Close()
	if s.implicit {
		c = tls.Server(c, s.tls)
	}
	r, w := bufio.NewReader(c), c
	say := func(l string) { io.WriteString(w, l+"\r\n") }
	say("220 fake ESMTP")
	secure := s.implicit
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		up := strings.ToUpper(cmd)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			say("250-fake")
			if s.starttls && !secure {
				say("250-STARTTLS")
			}
			if s.auth != "" {
				say("250-AUTH " + s.auth)
			}
			say("250 8BITMIME")
		case up == "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, s.tls)
			if tc.Handshake() != nil {
				return
			}
			c, secure = tc, true
			r, w = bufio.NewReader(tc), tc
		case strings.HasPrefix(up, "AUTH PLAIN"):
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(cmd[len("AUTH PLAIN"):]))
			parts := strings.Split(string(raw), "\x00")
			s.finishAuth(say, len(parts) == 3 && parts[1] == s.user && parts[2] == s.pass)
		case up == "AUTH LOGIN":
			say("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
			u, _ := r.ReadString('\n')
			say("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
			p, _ := r.ReadString('\n')
			ub, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(u))
			pb, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
			s.finishAuth(say, string(ub) == s.user && string(pb) == s.pass)
		case strings.HasPrefix(up, "MAIL FROM:"):
			if s.user != "" && !s.authed {
				say("530 authentication required")
				continue
			}
			s.mu.Lock()
			s.from, _, _ = strings.Cut(strings.TrimLeft(cmd[len("MAIL FROM:"):], "< "), ">")
			s.mu.Unlock()
			say("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			to := strings.Trim(cmd[len("RCPT TO:"):], "<> ")
			if strings.HasPrefix(to, "nobody@") {
				say("550 no such user")
				continue
			}
			s.mu.Lock()
			s.rcpts = append(s.rcpts, to)
			s.mu.Unlock()
			say("250 ok")
		case up == "DATA":
			say("354 end with .")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.data = b.String()
			s.mu.Unlock()
			say("250 queued")
		case up == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (s *fakeServer) finishAuth(say func(string), ok bool) {
	if ok {
		s.mu.Lock()
		s.authed = true
		s.mu.Unlock()
		say("235 ok")
	} else {
		say("535 bad credentials")
	}
}

func TestSend(t *testing.T) {
	tlsConf, pool := newCert(t)
	ctx := context.Background()
	msg := Message{To: []string{"ops@example.com", "noc@example.com"}, Subject: "Weekly summary — résumé", Text: "Line one\nLine two"}

	t.Run("starttls with PLAIN", func(t *testing.T) {
		s := &fakeServer{tls: tlsConf, starttls: true, auth: "PLAIN LOGIN", user: "u", pass: "p"}
		cfg := s.start(t)
		cfg.Security, cfg.Username, cfg.Password = "starttls", "u", "p"
		if err := Send(ctx, cfg, pool, msg); err != nil {
			t.Fatal(err)
		}
		if s.from != "nfa@example.com" || len(s.rcpts) != 2 {
			t.Fatalf("from %q rcpts %v", s.from, s.rcpts)
		}
		parsed, err := stdmail.ReadMessage(strings.NewReader(s.data))
		if err != nil {
			t.Fatal(err)
		}
		if subj, _ := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject")); subj != msg.Subject {
			t.Fatalf("subject %q", subj)
		}
		if body, _ := io.ReadAll(parsed.Body); !strings.Contains(string(body), "Line one\r\nLine two") {
			t.Fatalf("body %q", body)
		}
	})

	t.Run("implicit TLS with LOGIN", func(t *testing.T) {
		s := &fakeServer{tls: tlsConf, implicit: true, auth: "LOGIN", user: "u", pass: "p"}
		cfg := s.start(t)
		cfg.Security, cfg.Username, cfg.Password = "tls", "u", "p"
		if err := Send(ctx, cfg, pool, msg); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("relay without auth", func(t *testing.T) {
		s := &fakeServer{}
		cfg := s.start(t)
		cfg.Security = "none"
		m := msg
		m.HTML = "<p>Hi</p>"
		m.Attachments = []Attachment{{Name: "report.pdf", ContentType: "application/pdf", Data: []byte("%PDF-1.7 fake")}}
		if err := Send(ctx, cfg, nil, m); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"multipart/mixed", "multipart/alternative", "text/html", "filename=report.pdf", base64.StdEncoding.EncodeToString([]byte("%PDF-1.7 fake"))} {
			if !strings.Contains(s.data, want) {
				t.Fatalf("message lacks %q:\n%s", want, s.data)
			}
		}
	})

	errCases := []struct {
		name  string
		srv   *fakeServer
		set   func(*config.Email)
		roots *x509.CertPool
		want  string
	}{
		{"bad password", &fakeServer{tls: tlsConf, starttls: true, auth: "PLAIN", user: "u", pass: "p"}, func(c *config.Email) { c.Security, c.Username, c.Password = "starttls", "u", "wrong" }, pool, "535"},
		{"no STARTTLS offered", &fakeServer{}, func(c *config.Email) { c.Security = "starttls" }, pool, "doesn't offer STARTTLS"},
		{"untrusted certificate", &fakeServer{tls: tlsConf, starttls: true}, func(c *config.Email) { c.Security = "starttls" }, x509.NewCertPool(), "certificate"},
		{"no AUTH", &fakeServer{tls: tlsConf, starttls: true}, func(c *config.Email) { c.Security, c.Username, c.Password = "starttls", "u", "p" }, pool, "no AUTH"},
		{"rejected recipient", &fakeServer{}, func(c *config.Email) { c.Security = "none" }, nil, "recipient nobody@example.com: the server replied 550"},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.srv.start(t)
			tc.set(&cfg)
			m := msg
			if strings.Contains(tc.name, "recipient") {
				m.To = []string{"ops@example.com", "nobody@example.com"}
			}
			err := Send(ctx, cfg, tc.roots, m)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}

	t.Run("header injection", func(t *testing.T) {
		s := &fakeServer{}
		cfg := s.start(t)
		cfg.Security = "none"
		m := msg
		m.To = []string{"a@example.com\r\nBcc: evil@example.com"}
		if err := Send(ctx, cfg, nil, m); err == nil {
			t.Fatal("accepted a recipient with a line break")
		}
	})
}

func TestRecipients(t *testing.T) {
	got, err := Recipients("a@example.com, Bob <b@example.com>\nA@example.com; a@example.com")
	if err != nil || strings.Join(got, ",") != "a@example.com,b@example.com,A@example.com" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"", " , ", "not an address", "a@example.com, @"} {
		if _, err := Recipients(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
