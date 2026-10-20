package config

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const snmpSchema = `
CREATE TABLE IF NOT EXISTS exporter_snmp (
	addr       TEXT PRIMARY KEY,
	config     TEXT NOT NULL,
	sys_name   TEXT NOT NULL DEFAULT '',
	sys_descr  TEXT NOT NULL DEFAULT '',
	last_poll  INTEGER NOT NULL DEFAULT 0,
	last_error TEXT NOT NULL DEFAULT '',
	if_count   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS interface_snmp (
	exporter TEXT NOT NULL,
	idx      INTEGER NOT NULL,
	name     TEXT NOT NULL DEFAULT '',
	alias    TEXT NOT NULL DEFAULT '',
	speed    INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (exporter, idx)
);
`

func (c *DB) migrateSNMP() error {
	if _, err := c.db.Exec(snmpSchema); err != nil {
		return err
	}
	// Names learned from NetFlow options are marked so SNMP can replace them;
	// names an administrator typed (learned = 0) always win.
	var n int
	if err := c.db.QueryRow("SELECT count(*) FROM pragma_table_info('interfaces') WHERE name = 'learned'").Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := c.db.Exec("ALTER TABLE interfaces ADD COLUMN learned INTEGER NOT NULL DEFAULT 0"); err != nil {
			return err
		}
	}
	return nil
}

// SNMPConfig is how to poll an exporter. Version "" turns polling off.
// Secrets (community, passphrases) are write-only through the API.
type SNMPConfig struct {
	Version   string `json:"version"` // "" | 2c | 3
	Host      string `json:"host"`    // agent address; "" = the exporter's address
	Port      int    `json:"port"`    // 0 = 161
	Community string `json:"community,omitempty"`
	User      string `json:"user"`
	AuthProto string `json:"authProto"` // "" | MD5 | SHA | SHA256 | SHA512
	AuthPass  string `json:"authPass,omitempty"`
	PrivProto string `json:"privProto"` // "" | DES | AES | AES256
	PrivPass  string `json:"privPass,omitempty"`
}

// SNMPStatus is the outcome of the last poll.
type SNMPStatus struct {
	SysName    string `json:"sysName"`
	SysDescr   string `json:"sysDescr"`
	LastPoll   int64  `json:"lastPoll"` // unix ms, 0 = never
	LastError  string `json:"lastError"`
	Interfaces int    `json:"interfaces"`
}

// SNMPView is an exporter's SNMP settings for the API, secrets redacted.
type SNMPView struct {
	SNMPConfig
	HasCommunity bool       `json:"hasCommunity"`
	HasAuthPass  bool       `json:"hasAuthPass"`
	HasPrivPass  bool       `json:"hasPrivPass"`
	Status       SNMPStatus `json:"status"`
}

func (s SNMPConfig) View(st SNMPStatus) SNMPView {
	v := SNMPView{SNMPConfig: s, HasCommunity: s.Community != "", HasAuthPass: s.AuthPass != "", HasPrivPass: s.PrivPass != "", Status: st}
	v.Community, v.AuthPass, v.PrivPass = "", "", ""
	return v
}

// Target is the agent address to poll.
func (s SNMPConfig) Target(exporter string) (host string, port uint16) {
	host = strings.TrimSpace(s.Host)
	if host == "" {
		host = exporter
	}
	port = 161
	if s.Port > 0 {
		port = uint16(s.Port)
	}
	return host, port
}

func (s *SNMPConfig) validate(stored SNMPConfig) error {
	s.Host, s.User = strings.TrimSpace(s.Host), strings.TrimSpace(s.User)
	if s.Port < 0 || s.Port > 65535 {
		return errors.New("SNMP port must be between 1 and 65535")
	}
	if s.Host != "" && (strings.ContainsAny(s.Host, " /\\") || len(s.Host) > 253) {
		return fmt.Errorf("invalid SNMP host %q", s.Host)
	}
	switch s.Version {
	case "":
		return nil
	case "2c":
		if s.Community == "" && stored.Community == "" {
			return errors.New("enter the SNMP community")
		}
	case "3":
		if s.User == "" {
			return errors.New("enter the SNMPv3 user name")
		}
		switch s.AuthProto {
		case "", "MD5", "SHA", "SHA256", "SHA512":
		default:
			return fmt.Errorf("unknown SNMPv3 authentication protocol %q", s.AuthProto)
		}
		switch s.PrivProto {
		case "", "DES", "AES", "AES256":
		default:
			return fmt.Errorf("unknown SNMPv3 privacy protocol %q", s.PrivProto)
		}
		if s.PrivProto != "" && s.AuthProto == "" {
			return errors.New("SNMPv3 privacy (encryption) requires authentication")
		}
		if s.AuthProto != "" && s.AuthPass == "" && stored.AuthPass == "" {
			return errors.New("enter the SNMPv3 authentication passphrase")
		}
		if s.PrivProto != "" && s.PrivPass == "" && stored.PrivPass == "" {
			return errors.New("enter the SNMPv3 privacy passphrase")
		}
		for _, p := range []string{s.AuthPass, s.PrivPass} {
			if p != "" && len(p) < 8 {
				return errors.New("SNMPv3 passphrases must be at least 8 characters")
			}
		}
	default:
		return fmt.Errorf("unknown SNMP version %q (use 2c or 3)", s.Version)
	}
	return nil
}

func (c *DB) loadSNMP(addr string) (SNMPConfig, SNMPStatus, error) {
	var raw string
	var st SNMPStatus
	err := c.db.QueryRow("SELECT config, sys_name, sys_descr, last_poll, last_error, if_count FROM exporter_snmp WHERE addr = ?", addr).
		Scan(&raw, &st.SysName, &st.SysDescr, &st.LastPoll, &st.LastError, &st.Interfaces)
	if errors.Is(err, sql.ErrNoRows) {
		return SNMPConfig{}, st, nil
	}
	if err != nil {
		return SNMPConfig{}, st, err
	}
	var s SNMPConfig
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return SNMPConfig{}, st, err
	}
	return s, st, nil
}

// SNMP returns an exporter's settings with secrets decrypted, and its status.
func (c *DB) SNMP(addr string) (SNMPConfig, SNMPStatus, error) {
	s, st, err := c.loadSNMP(addr)
	if err != nil {
		return s, st, err
	}
	for _, p := range []*string{&s.Community, &s.AuthPass, &s.PrivPass} {
		if *p != "" {
			if *p, err = c.decrypt(*p); err != nil {
				return s, st, fmt.Errorf("stored SNMP credentials can't be decrypted: %w", err)
			}
		}
	}
	return s, st, nil
}

// SaveSNMP stores an exporter's SNMP settings. Empty secrets keep the stored
// ones; secrets that the new settings don't use are dropped.
func (c *DB) SaveSNMP(addr string, s SNMPConfig) error {
	stored, _, err := c.loadSNMP(addr)
	if err != nil {
		return err
	}
	if err := s.validate(stored); err != nil {
		return err
	}
	keep := func(in *string, old string, used bool) error {
		switch {
		case !used:
			*in = ""
		case *in == "":
			*in = old // already encrypted
		default:
			enc, err := c.encrypt(*in)
			if err != nil {
				return err
			}
			*in = enc
		}
		return nil
	}
	if err := keep(&s.Community, stored.Community, s.Version == "2c"); err != nil {
		return err
	}
	if err := keep(&s.AuthPass, stored.AuthPass, s.Version == "3" && s.AuthProto != ""); err != nil {
		return err
	}
	if err := keep(&s.PrivPass, stored.PrivPass, s.Version == "3" && s.PrivProto != ""); err != nil {
		return err
	}
	if s.Version != "3" {
		s.User, s.AuthProto, s.PrivProto = "", "", ""
	}
	b, _ := json.Marshal(s)
	_, err = c.db.Exec(`INSERT INTO exporter_snmp(addr, config) VALUES(?, ?)
		ON CONFLICT(addr) DO UPDATE SET config = excluded.config, last_error = ''`, addr, string(b))
	if err == nil && s.Version == "" {
		// Off: forget what was polled so names fall back to other sources.
		_, _ = c.db.Exec("DELETE FROM interface_snmp WHERE exporter = ?", addr)
		_, _ = c.db.Exec("UPDATE exporter_snmp SET sys_name = '', sys_descr = '', last_poll = 0, if_count = 0 WHERE addr = ?", addr)
		err = c.reload()
	}
	return err
}

// SNMPEnabled lists exporters with SNMP polling turned on.
func (c *DB) SNMPEnabled() ([]string, error) {
	rows, err := c.db.Query("SELECT addr, config FROM exporter_snmp")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var addr, raw string
		if err := rows.Scan(&addr, &raw); err != nil {
			return nil, err
		}
		var s SNMPConfig
		if json.Unmarshal([]byte(raw), &s) == nil && s.Version != "" {
			out = append(out, addr)
		}
	}
	return out, rows.Err()
}

// SNMPInterface is what a poll learned about one interface.
type SNMPInterface struct {
	Index uint32
	Name  string
	Alias string
	Speed uint64
}

// SaveSNMPPoll records a successful poll, replacing the interfaces learned
// before; pollErr records a failed one (keeping the previous data).
func (c *DB) SaveSNMPPoll(addr, sysName, sysDescr string, ifs []SNMPInterface, pollErr error) error {
	now := time.Now().UnixMilli()
	if pollErr != nil {
		_, err := c.db.Exec("UPDATE exporter_snmp SET last_poll = ?, last_error = ? WHERE addr = ?", now, pollErr.Error(), addr)
		return err
	}
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM interface_snmp WHERE exporter = ?", addr); err != nil {
		return err
	}
	for _, i := range ifs {
		if _, err := tx.Exec("INSERT INTO interface_snmp(exporter, idx, name, alias, speed) VALUES(?, ?, ?, ?, ?)", addr, i.Index, i.Name, i.Alias, i.Speed); err != nil {
			return err
		}
	}
	if _, err := tx.Exec("UPDATE exporter_snmp SET sys_name = ?, sys_descr = ?, last_poll = ?, last_error = '', if_count = ? WHERE addr = ?",
		sysName, sysDescr, now, len(ifs), addr); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return c.reload()
}
