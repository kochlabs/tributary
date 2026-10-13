package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Identity sources let users sign in through an external provider. Only
// OpenID Connect is implemented; the type field leaves room for LDAP,
// RADIUS and SAML.

const identitySchema = `
CREATE TABLE IF NOT EXISTS identity_sources (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	type         TEXT NOT NULL,
	name         TEXT NOT NULL,
	enabled      INTEGER NOT NULL DEFAULT 1,
	priority     INTEGER NOT NULL DEFAULT 10,
	config       TEXT NOT NULL DEFAULT '{}',
	mappings     TEXT NOT NULL DEFAULT '[]',
	default_role TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL
);
`

var (
	ErrUnsupportedSource = errors.New("this identity source type is not supported yet")
	ErrAccountConflict   = errors.New("an account with this username already exists and is not managed by this identity source")
)

type RoleMapping struct {
	Group string `json:"group"`
	Role  string `json:"role"`
}

type OIDCConfig struct {
	Issuer        string   `json:"issuer"`
	ClientID      string   `json:"clientId"`
	ClientSecret  string   `json:"clientSecret,omitempty"` // write-only: never returned by the API
	Scopes        []string `json:"scopes"`
	UsernameClaim string   `json:"usernameClaim"`
	GroupsClaim   string   `json:"groupsClaim"`
}

type IdentitySource struct {
	ID          int64         `json:"id"`
	Type        string        `json:"type"` // oidc
	Name        string        `json:"name"`
	Enabled     bool          `json:"enabled"`
	Priority    int           `json:"priority"`
	OIDC        *OIDCConfig   `json:"oidc,omitempty"`
	Mappings    []RoleMapping `json:"mappings"`
	DefaultRole string        `json:"defaultRole"` // "" denies users matching no mapping
	HasSecret   bool          `json:"hasSecret"`
	Users       int           `json:"users"`
	CreatedAt   int64         `json:"createdAt"`
}

func (c *DB) migrateIdentity() error {
	if _, err := c.db.Exec(identitySchema + trustedSchema); err != nil {
		return err
	}
	// Users created by an identity source carry its id; 0 means local.
	var n int
	if err := c.db.QueryRow("SELECT count(*) FROM pragma_table_info('users') WHERE name = 'source_id'").Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := c.db.Exec("ALTER TABLE users ADD COLUMN source_id INTEGER NOT NULL DEFAULT 0"); err != nil {
			return err
		}
	}
	return nil
}

// ---- secret encryption ----

// loadKey reads or creates the 256-bit key used to encrypt secrets at rest.
func loadKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil && len(b) == 32 {
		return b, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

func (c *DB) encrypt(plain string) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return "enc:" + base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plain), nil)), nil
}

func (c *DB) decrypt(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "enc:"))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	out, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	return string(out), err
}

// ---- validation ----

func validIssuer(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return errors.New("issuer URL is not a valid URL")
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return errors.New("issuer URL must use https")
	}
	return nil
}

func (s *IdentitySource) normalize() error {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" || len(s.Name) > 64 {
		return errors.New("name is required (up to 64 characters)")
	}
	if s.Type != "oidc" {
		return ErrUnsupportedSource
	}
	if s.Priority < 0 || s.Priority > 1000 {
		return errors.New("priority must be between 0 and 1000")
	}
	if s.DefaultRole != "" && !validRole(s.DefaultRole) {
		return errors.New("default role must be empty (deny), viewer or admin")
	}
	var maps []RoleMapping
	for _, m := range s.Mappings {
		m.Group = strings.TrimSpace(m.Group)
		if m.Group == "" {
			continue
		}
		if !validRole(m.Role) {
			return fmt.Errorf("mapping for %q: role must be viewer or admin", m.Group)
		}
		maps = append(maps, m)
	}
	s.Mappings = maps
	if s.Mappings == nil {
		s.Mappings = []RoleMapping{}
	}
	o := s.OIDC
	if o == nil {
		return errors.New("OpenID Connect settings are required")
	}
	o.Issuer = strings.TrimRight(strings.TrimSpace(o.Issuer), " ")
	o.ClientID = strings.TrimSpace(o.ClientID)
	if err := validIssuer(o.Issuer); err != nil {
		return err
	}
	if o.ClientID == "" {
		return errors.New("client ID is required")
	}
	var scopes []string
	hasOpenID := false
	for _, sc := range o.Scopes {
		if sc = strings.TrimSpace(sc); sc != "" {
			scopes = append(scopes, sc)
			hasOpenID = hasOpenID || sc == "openid"
		}
	}
	if !hasOpenID {
		scopes = append([]string{"openid"}, scopes...)
	}
	o.Scopes = scopes
	if o.UsernameClaim = strings.TrimSpace(o.UsernameClaim); o.UsernameClaim == "" {
		o.UsernameClaim = "preferred_username"
	}
	if o.GroupsClaim = strings.TrimSpace(o.GroupsClaim); o.GroupsClaim == "" {
		o.GroupsClaim = "groups"
	}
	return nil
}

// ---- storage ----

func (c *DB) scanSource(row interface{ Scan(...any) error }, withSecret bool) (*IdentitySource, error) {
	var s IdentitySource
	var cfg, maps string
	var enabled int
	if err := row.Scan(&s.ID, &s.Type, &s.Name, &enabled, &s.Priority, &cfg, &maps, &s.DefaultRole, &s.CreatedAt, &s.Users); err != nil {
		return nil, err
	}
	s.Enabled = enabled == 1
	if err := json.Unmarshal([]byte(maps), &s.Mappings); err != nil {
		return nil, err
	}
	if s.Type == "oidc" {
		s.OIDC = &OIDCConfig{}
		if err := json.Unmarshal([]byte(cfg), s.OIDC); err != nil {
			return nil, err
		}
		s.HasSecret = s.OIDC.ClientSecret != ""
		if withSecret {
			plain, err := c.decrypt(s.OIDC.ClientSecret)
			if err != nil {
				return nil, fmt.Errorf("decrypt client secret: %w", err)
			}
			s.OIDC.ClientSecret = plain
		} else {
			s.OIDC.ClientSecret = ""
		}
	}
	return &s, nil
}

const sourceCols = `id, type, name, enabled, priority, config, mappings, default_role, created_at,
	(SELECT count(*) FROM users u WHERE u.source_id = identity_sources.id)`

// IdentitySources lists sources by priority. Secrets are never included.
func (c *DB) IdentitySources() ([]IdentitySource, error) {
	rows, err := c.db.Query("SELECT " + sourceCols + " FROM identity_sources ORDER BY priority, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IdentitySource{}
	for rows.Next() {
		s, err := c.scanSource(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// IdentitySource returns one source; withSecret decrypts the client secret
// for server-side use only.
func (c *DB) IdentitySource(id int64, withSecret bool) (*IdentitySource, error) {
	s, err := c.scanSource(c.db.QueryRow("SELECT "+sourceCols+" FROM identity_sources WHERE id = ?", id), withSecret)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return s, err
}

// SaveIdentitySource creates (ID 0) or updates a source. On update an empty
// client secret keeps the stored one.
func (c *DB) SaveIdentitySource(s IdentitySource) (int64, error) {
	if err := s.normalize(); err != nil {
		return 0, err
	}
	secret := s.OIDC.ClientSecret
	if s.ID != 0 && secret == "" {
		var stored OIDCConfig
		var cfg string
		err := c.db.QueryRow("SELECT config FROM identity_sources WHERE id = ?", s.ID).Scan(&cfg)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		if err != nil {
			return 0, err
		}
		if err := json.Unmarshal([]byte(cfg), &stored); err != nil {
			return 0, err
		}
		s.OIDC.ClientSecret = stored.ClientSecret // already encrypted
	} else if secret != "" {
		enc, err := c.encrypt(secret)
		if err != nil {
			return 0, err
		}
		s.OIDC.ClientSecret = enc
	}
	cfg, _ := json.Marshal(s.OIDC)
	maps, _ := json.Marshal(s.Mappings)
	enabled := 0
	if s.Enabled {
		enabled = 1
	}
	if s.ID == 0 {
		res, err := c.db.Exec(`INSERT INTO identity_sources(type, name, enabled, priority, config, mappings, default_role, created_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, s.Type, s.Name, enabled, s.Priority, string(cfg), string(maps), s.DefaultRole, time.Now().UnixMilli())
		if err != nil {
			return 0, err
		}
		return res.LastInsertId()
	}
	res, err := c.db.Exec(`UPDATE identity_sources SET name = ?, enabled = ?, priority = ?, config = ?, mappings = ?, default_role = ?
		WHERE id = ? AND type = ?`, s.Name, enabled, s.Priority, string(cfg), string(maps), s.DefaultRole, s.ID, s.Type)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNotFound
	}
	if !s.Enabled {
		// Disabling a source signs its users out.
		_, _ = c.db.Exec("DELETE FROM sessions WHERE username IN (SELECT username FROM users WHERE source_id = ?)", s.ID)
	}
	return s.ID, nil
}

// DeleteIdentitySource removes a source and the accounts it created (and,
// through the foreign key, their sessions).
func (c *DB) DeleteIdentitySource(id int64) error {
	if _, err := c.db.Exec("DELETE FROM users WHERE source_id = ?", id); err != nil {
		return err
	}
	res, err := c.db.Exec("DELETE FROM identity_sources WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ResolveRole applies a source's mappings to a user's groups: the highest
// matching role wins, else the default role ("" = deny).
func (s *IdentitySource) ResolveRole(groups []string) string {
	have := map[string]bool{}
	for _, g := range groups {
		have[g] = true
	}
	role := ""
	for _, m := range s.Mappings {
		if have[m.Group] && (role == "" || m.Role == "admin") {
			role = m.Role
		}
	}
	if role == "" {
		role = s.DefaultRole
	}
	return role
}

// UpsertExternalUser creates or updates an account owned by an identity
// source. It refuses to touch local accounts or accounts of another source,
// so a provider can never take over an existing login.
func (c *DB) UpsertExternalUser(sourceID int64, username, fullName, role string) (*User, error) {
	if username == "" || len(username) > 128 || strings.ContainsAny(username, " \t/\\") {
		return nil, errors.New("the provider returned an unusable username")
	}
	var owner int64
	err := c.db.QueryRow("SELECT source_id FROM users WHERE username = ?", username).Scan(&owner)
	now := time.Now().UnixMilli()
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// No password: external accounts can never sign in locally.
		_, err = c.db.Exec(`INSERT INTO users(username, password, role, full_name, created_at, last_login, source_id) VALUES(?, '', ?, ?, ?, ?, ?)`,
			username, role, fullName, now, now, sourceID)
	case err != nil:
		return nil, err
	case owner != sourceID:
		return nil, ErrAccountConflict
	default:
		_, err = c.db.Exec("UPDATE users SET role = ?, full_name = ?, last_login = ? WHERE username = ?", role, fullName, now, username)
	}
	if err != nil {
		return nil, err
	}
	return &User{Username: username, Role: role, FullName: fullName, CreatedAt: now, LastLogin: now, SourceID: sourceID}, nil
}
