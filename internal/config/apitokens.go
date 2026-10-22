package config

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"strings"
	"time"
)

// API tokens let programs act as a user without a browser session. They are
// accepted only by the MCP endpoint, are shown once when created, and only
// their hashes are stored.

const apiTokenSchema = `
CREATE TABLE IF NOT EXISTS api_tokens (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
	name       TEXT NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	prefix     TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL DEFAULT 0,
	last_used  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS api_tokens_user ON api_tokens(username);
`

// APITokenPrefix starts every token, so leaked tokens are easy to recognize
// (and to search for in code and logs).
const APITokenPrefix = "trb_"

// MaxAPITokens is how many tokens one user may have.
const MaxAPITokens = 20

type APIToken struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	// Prefix is the start of the token, to tell tokens apart.
	Prefix    string `json:"prefix"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"` // 0 = never
	LastUsed  int64  `json:"lastUsed"`
}

var (
	ErrTooManyTokens = errors.New("too many API tokens: revoke one first")
	ErrTokenName     = errors.New("give the token a name (up to 64 characters)")
)

func (c *DB) migrateAPITokens() error {
	_, err := c.db.Exec(apiTokenSchema)
	return err
}

// CreateAPIToken makes a token for username, valid for ttl (0 = no expiry).
// The returned secret is not stored and can't be shown again.
func (c *DB) CreateAPIToken(username, name string, ttl time.Duration) (string, APIToken, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return "", APIToken{}, ErrTokenName
	}
	var n int
	if err := c.db.QueryRow("SELECT count(*) FROM api_tokens WHERE username = ?", username).Scan(&n); err != nil {
		return "", APIToken{}, err
	}
	if n >= MaxAPITokens {
		return "", APIToken{}, ErrTooManyTokens
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", APIToken{}, err
	}
	secret := APITokenPrefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	t := APIToken{Username: username, Name: name, Prefix: secret[:len(APITokenPrefix)+8], CreatedAt: time.Now().UnixMilli()}
	if ttl > 0 {
		t.ExpiresAt = time.Now().Add(ttl).UnixMilli()
	}
	res, err := c.db.Exec("INSERT INTO api_tokens(username, name, token_hash, prefix, created_at, expires_at) VALUES(?, ?, ?, ?, ?, ?)",
		username, t.Name, hashToken(secret), t.Prefix, t.CreatedAt, t.ExpiresAt)
	if err != nil {
		return "", APIToken{}, err
	}
	t.ID, _ = res.LastInsertId()
	return secret, t, nil
}

// APITokens lists a user's tokens, or everyone's when username is empty.
func (c *DB) APITokens(username string) ([]APIToken, error) {
	q := "SELECT id, username, name, prefix, created_at, expires_at, last_used FROM api_tokens"
	var args []any
	if username != "" {
		q += " WHERE username = ?"
		args = append(args, username)
	}
	rows, err := c.db.Query(q+" ORDER BY created_at DESC", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.Username, &t.Name, &t.Prefix, &t.CreatedAt, &t.ExpiresAt, &t.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteAPIToken revokes a token. A non-empty username restricts it to that
// user's own tokens.
func (c *DB) DeleteAPIToken(id int64, username string) (APIToken, error) {
	var t APIToken
	err := c.db.QueryRow("SELECT id, username, name, prefix, created_at, expires_at, last_used FROM api_tokens WHERE id = ?", id).
		Scan(&t.ID, &t.Username, &t.Name, &t.Prefix, &t.CreatedAt, &t.ExpiresAt, &t.LastUsed)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && username != "" && t.Username != username) {
		return t, ErrNotFound
	}
	if err != nil {
		return t, err
	}
	_, err = c.db.Exec("DELETE FROM api_tokens WHERE id = ?", id)
	return t, err
}

// DeleteUserAPITokens revokes all of a user's tokens.
func (c *DB) DeleteUserAPITokens(username string) (int64, error) {
	res, err := c.db.Exec("DELETE FROM api_tokens WHERE username = ?", username)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// APITokenUser returns the user a token acts as. Expired tokens, and tokens
// of users whose identity source is disabled, are refused.
func (c *DB) APITokenUser(secret string) (*User, *APIToken, error) {
	if !strings.HasPrefix(secret, APITokenPrefix) {
		return nil, nil, ErrNotFound
	}
	var u User
	var t APIToken
	err := c.db.QueryRow(`SELECT u.username, u.role, u.full_name, u.created_at, u.last_login, u.source_id, u.totp_enabled,
			t.id, t.name, t.prefix, t.created_at, t.expires_at, t.last_used
		FROM api_tokens t JOIN users u ON u.username = t.username
		LEFT JOIN identity_sources s ON s.id = u.source_id
		WHERE t.token_hash = ? AND (t.expires_at = 0 OR t.expires_at > ?) AND (u.source_id = 0 OR s.enabled = 1)`,
		hashToken(secret), time.Now().UnixMilli()).
		Scan(&u.Username, &u.Role, &u.FullName, &u.CreatedAt, &u.LastLogin, &u.SourceID, &u.MFA,
			&t.ID, &t.Name, &t.Prefix, &t.CreatedAt, &t.ExpiresAt, &t.LastUsed)
	if err != nil {
		return nil, nil, ErrNotFound
	}
	t.Username = u.Username
	// Record use at most once a minute.
	if now := time.Now().UnixMilli(); now-t.LastUsed > 60_000 {
		_, _ = c.db.Exec("UPDATE api_tokens SET last_used = ? WHERE id = ?", now, t.ID)
		t.LastUsed = now
	}
	return &u, &t, nil
}
