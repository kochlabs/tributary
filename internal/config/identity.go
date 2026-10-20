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

// Identity sources let users sign in through an external provider: OpenID
// Connect and SAML 2.0 (redirect-based single sign-on), or LDAP/Active
// Directory and RADIUS (username and password checked against the directory
// or server).

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

// LDAPConfig authenticates against an LDAP directory or Active Directory:
// bind as the service account, find the user, bind as the user to check the
// password, then read the user's groups.
type LDAPConfig struct {
	URL          string `json:"url"`      // ldap://host[:port] or ldaps://host[:port]
	StartTLS     bool   `json:"startTls"` // upgrade ldap:// connections
	BindDN       string `json:"bindDn"`
	BindPassword string `json:"bindPassword,omitempty"` // write-only
	BaseDN       string `json:"baseDn"`
	UserFilter   string `json:"userFilter"` // {username} is replaced (escaped)
	UsernameAttr string `json:"usernameAttr"`
	NameAttr     string `json:"nameAttr"`
	GroupAttr    string `json:"groupAttr"`    // attribute on the user listing its groups (memberOf)
	NestedGroups bool   `json:"nestedGroups"` // Active Directory: include groups of groups
}

// RADIUSConfig authenticates with PAP against RADIUS servers, tried in order.
type RADIUSConfig struct {
	Servers       []string `json:"servers"` // host[:port], default port 1812
	Secret        string   `json:"secret,omitempty"`
	NASIdentifier string   `json:"nasIdentifier"`
	TimeoutSec    int      `json:"timeoutSec"`
	// RoleAttribute names the reply attribute whose values are matched
	// against the role mappings: Class or Filter-Id.
	RoleAttribute string `json:"roleAttribute"`
}

type IdentitySource struct {
	ID          int64         `json:"id"`
	Type        string        `json:"type"` // oidc | saml | ldap | radius
	Name        string        `json:"name"`
	Enabled     bool          `json:"enabled"`
	Priority    int           `json:"priority"`
	OIDC        *OIDCConfig   `json:"oidc,omitempty"`
	SAML        *SAMLConfig   `json:"saml,omitempty"`
	LDAP        *LDAPConfig   `json:"ldap,omitempty"`
	RADIUS      *RADIUSConfig `json:"radius,omitempty"`
	Mappings    []RoleMapping `json:"mappings"`
	DefaultRole string        `json:"defaultRole"` // "" denies users matching no mapping
	HasSecret   bool          `json:"hasSecret"`
	Users       int           `json:"users"`
	CreatedAt   int64         `json:"createdAt"`
}

func (c *DB) migrateIdentity() error {
	if _, err := c.db.Exec(identitySchema + trustedSchema + deviceSchema); err != nil {
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
	switch s.Type {
	case "oidc", "saml", "ldap", "radius":
	default:
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
	switch s.Type {
	case "ldap":
		s.OIDC, s.SAML, s.RADIUS = nil, nil, nil
		return s.LDAP.normalize()
	case "radius":
		s.OIDC, s.SAML, s.LDAP = nil, nil, nil
		return s.RADIUS.normalize()
	case "saml":
		s.OIDC, s.LDAP, s.RADIUS = nil, nil, nil
		return s.SAML.normalize()
	}
	s.SAML, s.LDAP, s.RADIUS = nil, nil, nil
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
	var target any
	switch s.Type {
	case "oidc":
		s.OIDC = &OIDCConfig{}
		target = s.OIDC
	case "saml":
		s.SAML = &SAMLConfig{}
		target = s.SAML
	case "ldap":
		s.LDAP = &LDAPConfig{}
		target = s.LDAP
	case "radius":
		s.RADIUS = &RADIUSConfig{}
		target = s.RADIUS
	default:
		return &s, nil
	}
	if err := json.Unmarshal([]byte(cfg), target); err != nil {
		return nil, err
	}
	sec := s.secret()
	s.HasSecret = *sec != ""
	if withSecret {
		plain, err := c.decrypt(*sec)
		if err != nil {
			return nil, fmt.Errorf("decrypt secret: %w", err)
		}
		*sec = plain
	} else {
		*sec = ""
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
	sec := s.secret()
	if s.Type == "saml" {
		// The appliance's own key pair, never taken from the request.
		if err := c.prepareSAMLKeys(&s); err != nil {
			return 0, err
		}
	} else if s.ID != 0 && *sec == "" {
		typ, cfg, err := c.storedSourceConfig(s.ID)
		if err != nil {
			return 0, err
		}
		if typ != s.Type {
			return 0, errors.New("the type of an identity source can't be changed")
		}
		var raw map[string]any
		if err := json.Unmarshal(cfg, &raw); err != nil {
			return 0, err
		}
		*sec, _ = raw[secretField[s.Type]].(string) // already encrypted
	} else if *sec != "" {
		enc, err := c.encrypt(*sec)
		if err != nil {
			return 0, err
		}
		*sec = enc
	}
	if s.PasswordBased() && *sec == "" {
		return 0, fmt.Errorf("the %s is required", secretLabel[s.Type])
	}
	cfg, _ := json.Marshal(s.config())
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

// Validate checks and normalises the settings (as saving would).
func (s *IdentitySource) Validate() error { return s.normalize() }

// secretField names each type's secret in the stored JSON.
var secretField = map[string]string{"oidc": "clientSecret", "saml": "spKey", "ldap": "bindPassword", "radius": "secret"}
var secretLabel = map[string]string{"oidc": "client secret", "ldap": "bind password", "radius": "shared secret"}

// secret points at the type's write-only secret.
func (s *IdentitySource) secret() *string {
	switch {
	case s.LDAP != nil:
		return &s.LDAP.BindPassword
	case s.RADIUS != nil:
		return &s.RADIUS.Secret
	case s.SAML != nil:
		return &s.SAML.SPKey
	case s.OIDC != nil:
		return &s.OIDC.ClientSecret
	}
	var none string
	return &none
}

func (s *IdentitySource) config() any {
	switch s.Type {
	case "ldap":
		return s.LDAP
	case "radius":
		return s.RADIUS
	case "saml":
		return s.SAML
	}
	return s.OIDC
}

// PasswordBased reports whether users of this source sign in with the
// regular username/password form.
func (s *IdentitySource) PasswordBased() bool { return s.Type == "ldap" || s.Type == "radius" }

// ExternalUserSource returns the identity source that owns username (0 for
// a local account), and whether the account exists.
func (c *DB) ExternalUserSource(username string) (int64, bool) {
	var id int64
	if err := c.db.QueryRow("SELECT source_id FROM users WHERE username = ?", username).Scan(&id); err != nil {
		return 0, false
	}
	return id, true
}

// ResolveRole applies a source's mappings to a user's groups: the highest
// matching role wins, else the default role ("" = deny).
func (s *IdentitySource) ResolveRole(groups []string) string {
	// Directory-style group names compare case-insensitively (AD FS and Entra
	// ID send AD group names or object IDs); OIDC claims compare exactly.
	fold := s.Type != "oidc"
	have := map[string]bool{}
	for _, g := range groups {
		have[g] = true
		if fold {
			// Directory names compare case-insensitively, and an LDAP group
			// can be mapped by its full DN or just its CN.
			have[strings.ToLower(g)] = true
			if cn := groupCN(g); cn != "" {
				have[strings.ToLower(cn)] = true
			}
		}
	}
	if fold {
		for i := range s.Mappings {
			s.Mappings[i].Group = strings.ToLower(s.Mappings[i].Group)
		}
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

// groupCN returns the CN of an LDAP DN ("CN=Net Admins,OU=Groups,DC=corp,DC=example" -> "Net Admins").
func groupCN(dn string) string {
	first, _, _ := strings.Cut(dn, ",")
	k, v, ok := strings.Cut(first, "=")
	if !ok || !strings.EqualFold(strings.TrimSpace(k), "cn") {
		return ""
	}
	return strings.TrimSpace(v)
}
