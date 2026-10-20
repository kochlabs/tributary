// Package config keeps appliance configuration — users, sessions, settings,
// exporter and interface metadata — in a local SQLite database.
package config

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type DB struct {
	// OnAudit, when set, receives every audit entry after it is stored
	// (e.g. to forward it to syslog). It must not block.
	OnAudit func(AuditEntry)

	db  *sql.DB
	key []byte // encrypts secrets at rest (identity source client secrets)

	mu    sync.RWMutex
	names map[string]Exporter // cached exporter metadata by address
	ifs   map[string]string   // "exporter|index" -> name
}

var ErrNotFound = errors.New("not found")

const schema = `
CREATE TABLE IF NOT EXISTS users (
	username   TEXT PRIMARY KEY,
	password   TEXT NOT NULL,
	role       TEXT NOT NULL DEFAULT 'viewer',
	full_name  TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	last_login INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exporters (
	addr        TEXT PRIMARY KEY,
	name        TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	location    TEXT NOT NULL DEFAULT '',
	sampling    INTEGER NOT NULL DEFAULT 0,
	first_seen  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS interfaces (
	exporter    TEXT NOT NULL,
	idx         INTEGER NOT NULL,
	name        TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	speed       INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (exporter, idx)
);
CREATE TABLE IF NOT EXISTS audit (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	ts       INTEGER NOT NULL,
	username TEXT NOT NULL,
	action   TEXT NOT NULL,
	detail   TEXT NOT NULL DEFAULT ''
);
`

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("config schema: %w", err)
	}
	key, err := loadKey(filepath.Join(filepath.Dir(path), "secret.key"))
	if err != nil {
		return nil, fmt.Errorf("secret key: %w", err)
	}
	c := &DB{db: db, key: key}
	if err := c.migrateSNMP(); err != nil {
		return nil, err
	}
	if err := c.migrateMFA(); err != nil {
		return nil, err
	}
	if err := c.migrateIdentity(); err != nil {
		return nil, fmt.Errorf("identity schema: %w", err)
	}
	if err := c.reload(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *DB) Close() error { return c.db.Close() }

// ---- settings ----

// Settings are the user-tunable appliance settings.
type Settings struct {
	RawRetentionDays    int    `json:"rawRetentionDays"`
	RollupRetentionDays int    `json:"rollupRetentionDays"`
	NetFlowPort         int    `json:"netflowPort"`
	IPFIXPort           int    `json:"ipfixPort"`
	SFlowPort           int    `json:"sflowPort"`
	ApplianceName       string `json:"applianceName"`
	SessionHours        int    `json:"sessionHours"`
	// RequireMFAAdmins makes administrators who sign in with a password set
	// up two-factor authentication before they can continue.
	RequireMFAAdmins bool     `json:"requireMfaAdmins"`
	ReverseDNS       bool     `json:"reverseDns"`
	OnlineASNLookup  bool     `json:"onlineAsnLookup"`
	LocalNetworks    []string `json:"localNetworks"`
	DNSServers       []string `json:"dnsServers"` // empty = system resolvers
	// ExporterAllowlist limits which source addresses may send flows (IPs or
	// CIDR prefixes); empty accepts every source.
	ExporterAllowlist []string `json:"exporterAllowlist"`
}

// AllowedExporterPrefixes parses ExporterAllowlist (validated by Validate);
// single addresses become /32 or /128 prefixes.
func (s Settings) AllowedExporterPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, n := range s.ExporterAllowlist {
		if p, ok := parseAddrOrPrefix(n); ok {
			out = append(out, p)
		}
	}
	return out
}

func parseAddrOrPrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// LocalPrefixes parses LocalNetworks (validated by Validate).
func (s Settings) LocalPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, n := range s.LocalNetworks {
		if p, err := netip.ParsePrefix(strings.TrimSpace(n)); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

func DefaultSettings() Settings {
	return Settings{RawRetentionDays: 7, RollupRetentionDays: 365, NetFlowPort: 2055, IPFIXPort: 4739, SFlowPort: 6343, ApplianceName: "Tributary", SessionHours: 12, ReverseDNS: true, OnlineASNLookup: true, LocalNetworks: []string{}, DNSServers: []string{}, ExporterAllowlist: []string{}}
}

func (s Settings) Validate() error {
	for _, p := range []int{s.NetFlowPort, s.IPFIXPort, s.SFlowPort} {
		if p < 0 || p > 65535 {
			return fmt.Errorf("port %d out of range", p)
		}
	}
	if s.NetFlowPort != 0 && (s.NetFlowPort == s.IPFIXPort || s.NetFlowPort == s.SFlowPort) || s.IPFIXPort != 0 && s.IPFIXPort == s.SFlowPort {
		return errors.New("collector ports must be distinct")
	}
	if s.RawRetentionDays < 1 || s.RawRetentionDays > 3650 || s.RollupRetentionDays < 1 || s.RollupRetentionDays > 3650 {
		return errors.New("retention must be between 1 and 3650 days")
	}
	if s.SessionHours < 1 || s.SessionHours > 24*30 {
		return errors.New("session lifetime must be between 1 and 720 hours")
	}
	if len(s.DNSServers) > 5 {
		return errors.New("at most 5 DNS servers")
	}
	for _, d := range s.DNSServers {
		if _, err := netip.ParseAddrPort(strings.TrimSpace(d)); err != nil {
			if _, err := netip.ParseAddr(strings.TrimSpace(d)); err != nil {
				return fmt.Errorf("DNS server %q must be an IP address, optionally with :port", d)
			}
		}
	}
	if len(s.LocalNetworks) > 256 {
		return errors.New("at most 256 local networks")
	}
	for _, n := range s.LocalNetworks {
		if _, err := netip.ParsePrefix(strings.TrimSpace(n)); err != nil {
			return fmt.Errorf("local network %q is not a valid CIDR prefix", n)
		}
	}
	if len(s.ExporterAllowlist) > 256 {
		return errors.New("at most 256 allowed exporter entries")
	}
	for _, n := range s.ExporterAllowlist {
		if _, ok := parseAddrOrPrefix(n); !ok {
			return fmt.Errorf("allowed exporter %q is not an IP address or CIDR prefix", n)
		}
	}
	if strings.TrimSpace(s.ApplianceName) == "" {
		return errors.New("appliance name is required")
	}
	return nil
}

func (c *DB) Settings() Settings {
	s := DefaultSettings()
	var v string
	if err := c.db.QueryRow("SELECT value FROM settings WHERE key = 'settings'").Scan(&v); err == nil {
		_ = json.Unmarshal([]byte(v), &s)
	}
	return s
}

func (c *DB) SaveSettings(s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	b, _ := json.Marshal(s)
	_, err := c.db.Exec("INSERT INTO settings(key, value) VALUES('settings', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", string(b))
	return err
}

// ---- users ----

type User struct {
	Username  string `json:"username"`
	Role      string `json:"role"` // admin | viewer
	FullName  string `json:"fullName"`
	CreatedAt int64  `json:"createdAt"`
	LastLogin int64  `json:"lastLogin"`
	SourceID  int64  `json:"sourceId"`         // 0 = local account
	Source    string `json:"source,omitempty"` // identity source name
	MFA       bool   `json:"mfa"`              // two-factor authentication on
}

func validRole(r string) bool { return r == "admin" || r == "viewer" }

func validatePassword(p string) error {
	if len(p) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	return nil
}

func (c *DB) UserCount() (int, error) {
	var n int
	err := c.db.QueryRow("SELECT count(*) FROM users").Scan(&n)
	return n, err
}

func (c *DB) CreateUser(u User, password string) error {
	u.Username = strings.TrimSpace(u.Username)
	if u.Username == "" || len(u.Username) > 64 || strings.ContainsAny(u.Username, " \t/\\") {
		return errors.New("invalid username")
	}
	if !validRole(u.Role) {
		return errors.New("role must be admin or viewer")
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = c.db.Exec("INSERT INTO users(username, password, role, full_name, created_at) VALUES(?, ?, ?, ?, ?)",
		u.Username, string(h), u.Role, u.FullName, time.Now().UnixMilli())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return errors.New("user already exists")
	}
	return err
}

func (c *DB) UpdateUser(username string, role, fullName *string, password *string) error {
	var src int64
	if err := c.db.QueryRow("SELECT source_id FROM users WHERE username = ?", username).Scan(&src); err != nil {
		return ErrNotFound
	}
	if src != 0 && (password != nil || role != nil) {
		return errors.New("this account is managed by an identity source: its password and role come from the provider")
	}
	if role != nil {
		if !validRole(*role) {
			return errors.New("role must be admin or viewer")
		}
		if *role != "admin" {
			if err := c.ensureOtherAdmin(username); err != nil {
				return err
			}
		}
		if _, err := c.db.Exec("UPDATE users SET role = ? WHERE username = ?", *role, username); err != nil {
			return err
		}
	}
	if fullName != nil {
		if _, err := c.db.Exec("UPDATE users SET full_name = ? WHERE username = ?", *fullName, username); err != nil {
			return err
		}
	}
	if password != nil {
		if err := validatePassword(*password); err != nil {
			return err
		}
		h, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		if _, err := c.db.Exec("UPDATE users SET password = ? WHERE username = ?", string(h), username); err != nil {
			return err
		}
		// Changing a password ends that user's other sessions.
		if _, err := c.db.Exec("DELETE FROM sessions WHERE username = ?", username); err != nil {
			return err
		}
	}
	return nil
}

func (c *DB) ensureOtherAdmin(username string) error {
	var n int
	if err := c.db.QueryRow("SELECT count(*) FROM users WHERE role = 'admin' AND username != ?", username).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return errors.New("at least one administrator is required")
	}
	return nil
}

func (c *DB) DeleteUser(username string) error {
	if err := c.ensureOtherAdmin(username); err != nil {
		return err
	}
	res, err := c.db.Exec("DELETE FROM users WHERE username = ?", username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (c *DB) Users() ([]User, error) {
	rows, err := c.db.Query(`SELECT u.username, u.role, u.full_name, u.created_at, u.last_login, u.source_id, coalesce(s.name, ''), u.totp_enabled
		FROM users u LEFT JOIN identity_sources s ON s.id = u.source_id ORDER BY u.username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Username, &u.Role, &u.FullName, &u.CreatedAt, &u.LastLogin, &u.SourceID, &u.Source, &u.MFA); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// dummyHash makes failed logins for unknown users cost the same as real ones.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)

// Authenticate verifies credentials and returns the user.
func (c *DB) Authenticate(username, password string) (*User, error) {
	var u User
	var hash string
	err := c.db.QueryRow("SELECT username, password, role, full_name, created_at, last_login FROM users WHERE username = ? AND source_id = 0", username).
		Scan(&u.Username, &hash, &u.Role, &u.FullName, &u.CreatedAt, &u.LastLogin)
	if err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return nil, errors.New("invalid credentials")
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return nil, errors.New("invalid credentials")
	}
	_, _ = c.db.Exec("UPDATE users SET last_login = ? WHERE username = ?", time.Now().UnixMilli(), username)
	return &u, nil
}

// PasswordMatches reports whether a local account's password is password,
// without counting as a sign-in.
func (c *DB) PasswordMatches(username, password string) bool {
	var hash string
	if c.db.QueryRow("SELECT password FROM users WHERE username = ? AND source_id = 0", username).Scan(&hash) != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// ---- sessions ----

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// CreateSession returns a new random session token. Only its hash is stored.
func (c *DB) CreateSession(username string, ttl time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	_, err := c.db.Exec("INSERT INTO sessions(token_hash, username, expires_at) VALUES(?, ?, ?)", hashToken(tok), username, time.Now().Add(ttl).UnixMilli())
	return tok, err
}

func (c *DB) SessionUser(token string) (*User, error) {
	var u User
	err := c.db.QueryRow(`SELECT u.username, u.role, u.full_name, u.created_at, u.last_login, u.source_id, u.totp_enabled FROM sessions s
		JOIN users u ON u.username = s.username WHERE s.token_hash = ? AND s.expires_at > ?`, hashToken(token), time.Now().UnixMilli()).
		Scan(&u.Username, &u.Role, &u.FullName, &u.CreatedAt, &u.LastLogin, &u.SourceID, &u.MFA)
	if err != nil {
		return nil, ErrNotFound
	}
	return &u, nil
}

// SessionUserByName loads an account as SessionUser would (after sign-in).
func (c *DB) SessionUserByName(username string) (*User, error) {
	var u User
	err := c.db.QueryRow(`SELECT username, role, full_name, created_at, last_login, source_id, totp_enabled FROM users WHERE username = ?`, username).
		Scan(&u.Username, &u.Role, &u.FullName, &u.CreatedAt, &u.LastLogin, &u.SourceID, &u.MFA)
	if err != nil {
		return nil, ErrNotFound
	}
	return &u, nil
}

// DeleteUserSessions signs a user out everywhere.
func (c *DB) DeleteUserSessions(username string) error {
	_, err := c.db.Exec("DELETE FROM sessions WHERE username = ?", username)
	return err
}

func (c *DB) DeleteSession(token string) error {
	_, err := c.db.Exec("DELETE FROM sessions WHERE token_hash = ?", hashToken(token))
	return err
}

// Snapshot writes a consistent copy of the configuration database to path
// (which must not exist), safe to take while the appliance is running.
func (c *DB) Snapshot(path string) error {
	_, err := c.db.Exec("VACUUM INTO ?", path)
	return err
}

// DeleteAllSessions signs everyone out, e.g. after restoring a backup.
func (c *DB) DeleteAllSessions() error {
	_, err := c.db.Exec("DELETE FROM sessions")
	return err
}

func (c *DB) PurgeSessions() {
	_, _ = c.db.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now().UnixMilli())
}

// ---- audit ----

type AuditEntry struct {
	ID       int64  `json:"id"`
	TS       int64  `json:"ts"`
	Username string `json:"username"`
	Action   string `json:"action"`
	Detail   string `json:"detail"`
}

func (c *DB) Audit(username, action, detail string) {
	ts := time.Now().UnixMilli()
	_, _ = c.db.Exec("INSERT INTO audit(ts, username, action, detail) VALUES(?, ?, ?, ?)", ts, username, action, detail)
	_, _ = c.db.Exec("DELETE FROM audit WHERE id <= (SELECT max(id) - 10000 FROM audit)")
	if f := c.OnAudit; f != nil {
		f(AuditEntry{TS: ts, Username: username, Action: action, Detail: detail})
	}
}

func (c *DB) AuditLog(limit int) ([]AuditEntry, error) {
	rows, err := c.db.Query("SELECT id, ts, username, action, detail FROM audit ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Username, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- exporters & interfaces ----

type Exporter struct {
	Addr        string `json:"addr"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Sampling    uint32 `json:"sampling"` // manual override, 0 = use exported value
	FirstSeen   int64  `json:"firstSeen"`
}

type Interface struct {
	Exporter    string `json:"exporter"`
	Index       uint32 `json:"index"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Speed       uint64 `json:"speed"` // bits per second, 0 = unknown
	// Learned is set when Name/Description came from NetFlow options rather
	// than an administrator; SNMP values then take precedence.
	Learned bool `json:"learned"`
	// What SNMP polling reported, if enabled for the exporter.
	SNMPName  string `json:"snmpName"`
	SNMPAlias string `json:"snmpAlias"`
	SNMPSpeed uint64 `json:"snmpSpeed"`
}

func (c *DB) reload() error {
	names := map[string]Exporter{}
	rows, err := c.db.Query("SELECT addr, name, description, location, sampling, first_seen FROM exporters")
	if err != nil {
		return err
	}
	for rows.Next() {
		var e Exporter
		if err := rows.Scan(&e.Addr, &e.Name, &e.Description, &e.Location, &e.Sampling, &e.FirstSeen); err != nil {
			rows.Close()
			return err
		}
		names[e.Addr] = e
	}
	rows.Close()
	ifs := map[string]string{}
	// Effective name: typed by an administrator, else polled over SNMP,
	// else learned from NetFlow options.
	rows, err = c.db.Query(`SELECT exporter, idx, name FROM (
		SELECT k.exporter, k.idx, COALESCE(
			NULLIF(CASE WHEN i.learned = 0 THEN i.name END, ''), NULLIF(s.name, ''), i.name, '') AS name
		FROM (SELECT exporter, idx FROM interfaces UNION SELECT exporter, idx FROM interface_snmp) k
		LEFT JOIN interfaces i ON i.exporter = k.exporter AND i.idx = k.idx
		LEFT JOIN interface_snmp s ON s.exporter = k.exporter AND s.idx = k.idx
	) WHERE name != ''`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var e, n string
		var i uint32
		if err := rows.Scan(&e, &i, &n); err != nil {
			return err
		}
		ifs[fmt.Sprintf("%s|%d", e, i)] = n
	}
	c.mu.Lock()
	c.names, c.ifs = names, ifs
	c.mu.Unlock()
	return rows.Err()
}

// SeenExporter registers an exporter the first time it sends data.
func (c *DB) SeenExporter(addr string) {
	c.mu.RLock()
	_, ok := c.names[addr]
	c.mu.RUnlock()
	if ok {
		return
	}
	now := time.Now().UnixMilli()
	_, _ = c.db.Exec("INSERT OR IGNORE INTO exporters(addr, first_seen) VALUES(?, ?)", addr, now)
	c.mu.Lock()
	if _, ok := c.names[addr]; !ok {
		c.names[addr] = Exporter{Addr: addr, FirstSeen: now}
	}
	c.mu.Unlock()
}

func (c *DB) Exporters() []Exporter {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Exporter, 0, len(c.names))
	for _, e := range c.names {
		out = append(out, e)
	}
	return out
}

func (c *DB) Exporter(addr string) (Exporter, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.names[addr]
	return e, ok
}

func (c *DB) UpdateExporter(e Exporter) error {
	res, err := c.db.Exec("UPDATE exporters SET name = ?, description = ?, location = ?, sampling = ? WHERE addr = ?",
		e.Name, e.Description, e.Location, e.Sampling, e.Addr)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return c.reload()
}

func (c *DB) DeleteExporter(addr string) error {
	if _, err := c.db.Exec("DELETE FROM interfaces WHERE exporter = ?", addr); err != nil {
		return err
	}
	if _, err := c.db.Exec("DELETE FROM exporters WHERE addr = ?", addr); err != nil {
		return err
	}
	return c.reload()
}

func (c *DB) Interfaces(exporter string) ([]Interface, error) {
	rows, err := c.db.Query(`SELECT k.exporter, k.idx, COALESCE(i.name, ''), COALESCE(i.description, ''), COALESCE(i.speed, 0), COALESCE(i.learned, 0),
			COALESCE(s.name, ''), COALESCE(s.alias, ''), COALESCE(s.speed, 0)
		FROM (SELECT exporter, idx FROM interfaces WHERE exporter = ? UNION SELECT exporter, idx FROM interface_snmp WHERE exporter = ?) k
		LEFT JOIN interfaces i ON i.exporter = k.exporter AND i.idx = k.idx
		LEFT JOIN interface_snmp s ON s.exporter = k.exporter AND s.idx = k.idx
		ORDER BY k.idx`, exporter, exporter)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Interface{}
	for rows.Next() {
		var i Interface
		if err := rows.Scan(&i.Exporter, &i.Index, &i.Name, &i.Description, &i.Speed, &i.Learned, &i.SNMPName, &i.SNMPAlias, &i.SNMPSpeed); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (c *DB) SaveInterface(i Interface) error {
	// An empty name keeps a name learned from the exporter (still marked as
	// learned, so SNMP can replace it); anything typed counts as manual.
	_, err := c.db.Exec(`INSERT INTO interfaces(exporter, idx, name, description, speed, learned) VALUES(?, ?, ?, ?, ?, 0)
		ON CONFLICT(exporter, idx) DO UPDATE SET
			learned = CASE WHEN excluded.name = '' AND excluded.description = '' AND interfaces.learned = 1 THEN 1 ELSE 0 END,
			name = CASE WHEN excluded.name = '' AND interfaces.learned = 1 THEN interfaces.name ELSE excluded.name END,
			description = CASE WHEN excluded.description = '' AND interfaces.learned = 1 THEN interfaces.description ELSE excluded.description END,
			speed = excluded.speed`,
		i.Exporter, i.Index, i.Name, i.Description, i.Speed)
	if err != nil {
		return err
	}
	return c.reload()
}

// LearnInterface records an interface name announced by the exporter. It
// never overwrites a name an administrator set, and skips unchanged values.
func (c *DB) LearnInterface(exporter string, idx uint32, name, desc string) {
	key := fmt.Sprintf("%s|%d", exporter, idx)
	c.mu.RLock()
	cur, known := c.ifs[key]
	c.mu.RUnlock()
	if known && cur != "" {
		return
	}
	_, err := c.db.Exec(`INSERT INTO interfaces(exporter, idx, name, description, learned) VALUES(?, ?, ?, ?, 1)
		ON CONFLICT(exporter, idx) DO UPDATE SET name = excluded.name, learned = 1,
			description = CASE WHEN interfaces.description = '' THEN excluded.description ELSE interfaces.description END
		WHERE interfaces.name = ''`, exporter, idx, name, desc)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.ifs[key] = name
	c.mu.Unlock()
}

// LearnedRate is a sampling rate an exporter announced. SystemWide rates
// apply to all its flows; otherwise only to records tagged with a sampler ID.
type LearnedRate struct {
	Rate       uint32
	SystemWide bool
}

// SetLearnedSampling persists the sampling rate an exporter last announced.
func (c *DB) SetLearnedSampling(exporter string, rate uint32, systemWide bool) {
	if rate == 0 { // withdrawn by the exporter
		_, _ = c.db.Exec("DELETE FROM settings WHERE key = ?", "sampling:"+exporter)
		return
	}
	v := fmt.Sprint(rate)
	if systemWide {
		v += "/system"
	}
	_, _ = c.db.Exec("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		"sampling:"+exporter, v)
}

// LearnedSampling returns all persisted exporter sampling rates.
func (c *DB) LearnedSampling() map[string]LearnedRate {
	out := map[string]LearnedRate{}
	rows, err := c.db.Query("SELECT key, value FROM settings WHERE key LIKE 'sampling:%'")
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		var n uint32
		if rows.Scan(&k, &v) == nil {
			num, sys := strings.CutSuffix(v, "/system")
			if _, err := fmt.Sscan(num, &n); err == nil {
				out[strings.TrimPrefix(k, "sampling:")] = LearnedRate{Rate: n, SystemWide: sys}
			}
		}
	}
	return out
}

// ExporterName returns the configured display name or "".
func (c *DB) ExporterName(addr string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.names[addr].Name
}

// SamplingOverride returns the manual sampling rate for an exporter (0 = none).
func (c *DB) SamplingOverride(addr string) uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.names[addr].Sampling
}

// InterfaceName returns the configured interface name or "".
func (c *DB) InterfaceName(exporter string, idx uint32) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ifs[fmt.Sprintf("%s|%d", exporter, idx)]
}
