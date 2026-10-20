package config

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/kochlabs/tributary/internal/totp"
)

// Two-factor authentication (authenticator app codes) for accounts that sign
// in with a password (local, LDAP or RADIUS). Single sign-on users get MFA
// from their identity provider instead.

func (c *DB) migrateMFA() error {
	for _, col := range []struct{ name, def string }{
		{"totp_secret", "TEXT NOT NULL DEFAULT ''"}, // encrypted; set while enrolling
		{"totp_enabled", "INTEGER NOT NULL DEFAULT 0"},
		{"totp_last", "INTEGER NOT NULL DEFAULT 0"}, // last accepted time step (no replays)
		{"recovery", "TEXT NOT NULL DEFAULT '[]'"},  // SHA-256 of unused recovery codes
	} {
		var n int
		if err := c.db.QueryRow("SELECT count(*) FROM pragma_table_info('users') WHERE name = ?", col.name).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := c.db.Exec("ALTER TABLE users ADD COLUMN " + col.name + " " + col.def); err != nil {
				return err
			}
		}
	}
	return nil
}

// MFAEnabled reports whether the account has two-factor authentication on.
func (c *DB) MFAEnabled(username string) bool {
	var on int
	_ = c.db.QueryRow("SELECT totp_enabled FROM users WHERE username = ?", username).Scan(&on)
	return on == 1
}

// BeginMFA creates a new (not yet active) secret for the account.
func (c *DB) BeginMFA(username string) (string, error) {
	secret := totp.NewSecret()
	enc, err := c.encrypt(secret)
	if err != nil {
		return "", err
	}
	res, err := c.db.Exec("UPDATE users SET totp_secret = ? WHERE username = ? AND totp_enabled = 0", enc, username)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", errors.New("two-factor authentication is already on for this account")
	}
	return secret, nil
}

// ErrBadCode is returned for a wrong, expired or reused code.
var ErrBadCode = errors.New("that code isn't valid; check the time on your device and try the current code")

// EnableMFA activates the secret from BeginMFA once the user proves it works,
// and returns one-time recovery codes (shown once, stored hashed).
func (c *DB) EnableMFA(username, code string) ([]string, error) {
	var enc string
	var on int
	if err := c.db.QueryRow("SELECT totp_secret, totp_enabled FROM users WHERE username = ?", username).Scan(&enc, &on); err != nil {
		return nil, ErrNotFound
	}
	if on == 1 {
		return nil, errors.New("two-factor authentication is already on for this account")
	}
	if enc == "" {
		return nil, errors.New("start the setup first")
	}
	secret, err := c.decrypt(enc)
	if err != nil {
		return nil, err
	}
	step, ok := totp.Validate(secret, code, time.Now(), 0)
	if !ok {
		return nil, ErrBadCode
	}
	codes, hashes := newRecoveryCodes(10)
	hb, _ := json.Marshal(hashes)
	_, err = c.db.Exec("UPDATE users SET totp_enabled = 1, totp_last = ?, recovery = ? WHERE username = ?", step, string(hb), username)
	return codes, err
}

// VerifyMFA checks a code from the authenticator app, or consumes a
// recovery code.
func (c *DB) VerifyMFA(username, code string) (recoveryUsed bool, err error) {
	var enc, rec string
	var on int
	var last int64
	if err := c.db.QueryRow("SELECT totp_secret, totp_enabled, totp_last, recovery FROM users WHERE username = ?", username).Scan(&enc, &on, &last, &rec); err != nil || on != 1 {
		return false, ErrBadCode
	}
	secret, err := c.decrypt(enc)
	if err != nil {
		return false, err
	}
	if step, ok := totp.Validate(secret, code, time.Now(), last); ok {
		// Only one sign-in per step: a concurrent replay loses the race here.
		res, err := c.db.Exec("UPDATE users SET totp_last = ? WHERE username = ? AND totp_last < ?", step, username, step)
		if err != nil {
			return false, err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return false, nil
		}
		return false, ErrBadCode
	}
	norm := normalizeRecovery(code)
	if norm == "" {
		return false, ErrBadCode
	}
	var hashes []string
	_ = json.Unmarshal([]byte(rec), &hashes)
	h := hashRecovery(norm)
	for i, x := range hashes {
		if subtle.ConstantTimeCompare([]byte(x), []byte(h)) == 1 {
			hashes = append(hashes[:i], hashes[i+1:]...)
			hb, _ := json.Marshal(hashes)
			_, err := c.db.Exec("UPDATE users SET recovery = ? WHERE username = ?", string(hb), username)
			return true, err
		}
	}
	return false, ErrBadCode
}

// RecoveryCodesLeft is the number of unused recovery codes.
func (c *DB) RecoveryCodesLeft(username string) int {
	var rec string
	_ = c.db.QueryRow("SELECT recovery FROM users WHERE username = ?", username).Scan(&rec)
	var hashes []string
	_ = json.Unmarshal([]byte(rec), &hashes)
	return len(hashes)
}

// DisableMFA turns two-factor authentication off (by the user, or reset by
// an administrator for someone who lost their device).
func (c *DB) DisableMFA(username string) error {
	res, err := c.db.Exec("UPDATE users SET totp_secret = '', totp_enabled = 0, totp_last = 0, recovery = '[]' WHERE username = ?", username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// newRecoveryCodes returns n codes like "k7dq-2mfx-9hzt" and their hashes.
func newRecoveryCodes(n int) (codes, hashes []string) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no look-alikes
	for i := 0; i < n; i++ {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		var sb strings.Builder
		for j, x := range b {
			if j > 0 && j%4 == 0 {
				sb.WriteByte('-')
			}
			sb.WriteByte(alphabet[int(x)%len(alphabet)])
		}
		codes = append(codes, sb.String())
		hashes = append(hashes, hashRecovery(normalizeRecovery(sb.String())))
	}
	return codes, hashes
}

func normalizeRecovery(s string) string {
	s = strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
	if len(s) != 12 {
		return ""
	}
	return s
}

func hashRecovery(s string) string {
	h := sha256.Sum256([]byte("tributary-recovery:" + s))
	return hex.EncodeToString(h[:])
}
