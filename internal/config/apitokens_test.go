package config

import (
	"strings"
	"testing"
	"time"
)

func TestAPITokens(t *testing.T) {
	c := openTestDB(t)
	c.CreateUser(User{Username: "alice", Role: "viewer"}, "Alice-pass-1")
	c.CreateUser(User{Username: "bob", Role: "admin"}, "Bob-pass-12")

	if _, _, err := c.CreateAPIToken("alice", " ", 0); err != ErrTokenName {
		t.Fatalf("blank name: %v", err)
	}
	secret, tok, err := c.CreateAPIToken("alice", "laptop", 0)
	if err != nil || !strings.HasPrefix(secret, APITokenPrefix) || len(secret) < 50 || !strings.HasPrefix(secret, tok.Prefix) || tok.ExpiresAt != 0 {
		t.Fatalf("create: %q %+v %v", secret, tok, err)
	}
	var stored string
	c.db.QueryRow("SELECT token_hash FROM api_tokens WHERE id = ?", tok.ID).Scan(&stored)
	if stored == secret || stored != hashToken(secret) {
		t.Fatal("token not stored as a hash")
	}
	u, used, err := c.APITokenUser(secret)
	if err != nil || u.Username != "alice" || u.Role != "viewer" || used.LastUsed == 0 {
		t.Fatalf("use: %+v %+v %v", u, used, err)
	}
	for _, bad := range []string{"", "trb_nope", secret + "x", strings.TrimPrefix(secret, APITokenPrefix)} {
		if _, _, err := c.APITokenUser(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}

	// Expiry.
	short, st, _ := c.CreateAPIToken("alice", "short", time.Hour)
	if st.ExpiresAt == 0 {
		t.Fatal("no expiry set")
	}
	c.db.Exec("UPDATE api_tokens SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Minute).UnixMilli(), st.ID)
	if _, _, err := c.APITokenUser(short); err == nil {
		t.Fatal("expired token accepted")
	}

	// Users only revoke their own; admins (empty username) any.
	if _, err := c.DeleteAPIToken(tok.ID, "bob"); err != ErrNotFound {
		t.Fatalf("bob revoked alice's token: %v", err)
	}
	if list, _ := c.APITokens("alice"); len(list) != 2 {
		t.Fatalf("alice has %d tokens", len(list))
	}
	if all, _ := c.APITokens(""); len(all) != 2 {
		t.Fatalf("all: %d", len(all))
	}
	if _, err := c.DeleteAPIToken(tok.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.APITokenUser(secret); err == nil {
		t.Fatal("revoked token accepted")
	}

	// A limit per user.
	for i := 0; i < MaxAPITokens; i++ {
		c.CreateAPIToken("bob", "t", 0)
	}
	if _, _, err := c.CreateAPIToken("bob", "one too many", 0); err != ErrTooManyTokens {
		t.Fatalf("limit: %v", err)
	}
	if n, _ := c.DeleteUserAPITokens("bob"); n != MaxAPITokens {
		t.Fatalf("revoke all: %d", n)
	}

	// Tokens of an identity source's users stop while the source is disabled,
	// and go when the account does.
	id, err := c.SaveIdentitySource(IdentitySource{Type: "radius", Name: "R", Enabled: true, Priority: 1,
		RADIUS: &RADIUSConfig{Servers: []string{"127.0.0.1"}, Secret: "s3cret"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpsertExternalUser(id, "carol", "Carol", "viewer"); err != nil {
		t.Fatal(err)
	}
	cs, _, _ := c.CreateAPIToken("carol", "script", 0)
	if _, _, err := c.APITokenUser(cs); err != nil {
		t.Fatal(err)
	}
	src, _ := c.IdentitySource(id, true)
	src.Enabled = false
	c.SaveIdentitySource(*src)
	if _, _, err := c.APITokenUser(cs); err == nil {
		t.Fatal("token of a disabled source's user accepted")
	}
	c.DeleteIdentitySource(id)
	if all, _ := c.APITokens("carol"); len(all) != 0 {
		t.Fatal("tokens outlived their user")
	}
}
