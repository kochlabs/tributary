package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Syslog configures forwarding of the audit log to syslog servers.
type Syslog struct {
	Enabled  bool           `json:"enabled"`
	Targets  []SyslogTarget `json:"targets"`
	Format   string         `json:"format"`   // rfc5424 | rfc3164
	Facility int            `json:"facility"` // 0–23; default 10 (authpriv)
}

type SyslogTarget struct {
	Address   string `json:"address"`   // host or host:port
	Transport string `json:"transport"` // udp | tcp | tls
}

func DefaultSyslog() Syslog {
	return Syslog{Format: "rfc5424", Facility: 10, Targets: []SyslogTarget{}}
}

// DefaultSyslogPort is the standard port for a transport.
func DefaultSyslogPort(transport string) string {
	if transport == "tls" {
		return "6514"
	}
	return "514"
}

// HostPort returns the target address with the transport's default port
// added when none is given.
func (t SyslogTarget) HostPort() string {
	if _, _, err := net.SplitHostPort(t.Address); err == nil {
		return t.Address
	}
	return net.JoinHostPort(strings.Trim(t.Address, "[]"), DefaultSyslogPort(t.Transport))
}

func (s *Syslog) validate() error {
	if s.Format == "" {
		s.Format = "rfc5424"
	}
	if s.Format != "rfc5424" && s.Format != "rfc3164" {
		return fmt.Errorf("unknown syslog format %q", s.Format)
	}
	if s.Facility < 0 || s.Facility > 23 {
		return errors.New("syslog facility must be between 0 and 23")
	}
	if len(s.Targets) > 4 {
		return errors.New("at most 4 syslog servers")
	}
	var out []SyslogTarget
	for _, t := range s.Targets {
		t.Address = strings.TrimSpace(t.Address)
		if t.Address == "" {
			continue
		}
		switch t.Transport {
		case "udp", "tcp", "tls":
		default:
			return fmt.Errorf("unknown syslog transport %q", t.Transport)
		}
		host := t.Address
		if h, p, err := net.SplitHostPort(t.Address); err == nil {
			if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("invalid port in %q", t.Address)
			}
			host = h
		}
		host = strings.Trim(host, "[]")
		if host == "" || strings.ContainsAny(host, " /\\") {
			return fmt.Errorf("invalid syslog server %q", t.Address)
		}
		out = append(out, t)
	}
	if out == nil {
		out = []SyslogTarget{}
	}
	s.Targets = out
	if s.Enabled && len(s.Targets) == 0 {
		return errors.New("add a syslog server, or turn forwarding off")
	}
	return nil
}

// ValidateSyslog checks and normalises s (e.g. before a test send).
func ValidateSyslog(s *Syslog) error { return s.validate() }

func (c *DB) Syslog() Syslog {
	s := DefaultSyslog()
	var v string
	if err := c.db.QueryRow("SELECT value FROM settings WHERE key = 'syslog'").Scan(&v); err == nil {
		_ = json.Unmarshal([]byte(v), &s)
	}
	if s.Targets == nil {
		s.Targets = []SyslogTarget{}
	}
	return s
}

func (c *DB) SaveSyslog(s Syslog) (Syslog, error) {
	if err := s.validate(); err != nil {
		return s, err
	}
	b, _ := json.Marshal(s)
	_, err := c.db.Exec("INSERT INTO settings(key, value) VALUES('syslog', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", string(b))
	return s, err
}
