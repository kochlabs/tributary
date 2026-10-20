package dirauth

import (
	"context"
	"crypto/x509"
	"os"
	"strings"
	"testing"

	"github.com/kochlabs/tributary/internal/config"
)

// Runs against a test OpenLDAP: NFA_TEST_LDAP=<dir with ca.crt>, serving
// ldap://127.0.0.1:3389 and ldaps://127.0.0.1:3636 (see the session notes).
func TestLDAPLive(t *testing.T) {
	dir := os.Getenv("NFA_TEST_LDAP")
	if dir == "" {
		t.Skip("set NFA_TEST_LDAP to run against an LDAP server")
	}
	pem, err := os.ReadFile(dir + "/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	base := config.LDAPConfig{BindDN: "cn=svc-tributary,ou=People,dc=example,dc=com", BindPassword: "SvcPass-123", BaseDN: "dc=example,dc=com",
		UserFilter: "(&(objectClass=inetOrgPerson)(uid={username}))", UsernameAttr: "uid", NameAttr: "displayName", GroupAttr: "memberOf"}
	ctx := context.Background()
	for _, tc := range []struct {
		name, url string
		startTLS  bool
	}{{"plain", "ldap://127.0.0.1:3389", false}, {"starttls", "ldap://localhost:3389", true}, {"ldaps", "ldaps://localhost:3636", false}} {
		cfg := base
		cfg.URL, cfg.StartTLS = tc.url, tc.startTLS
		res, err := LDAP(ctx, &cfg, roots, "alice", "AlicePass-1")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if res.Username != "alice" || res.FullName != "Alice Admin" || len(res.Groups) != 1 || !strings.EqualFold(res.Groups[0], "cn=Net Admins,ou=Groups,dc=example,dc=com") {
			t.Fatalf("%s: %+v", tc.name, res)
		}
	}
	cfg := base
	cfg.URL = "ldap://127.0.0.1:3389"
	for _, bad := range []struct{ user, pass string }{{"alice", "wrong"}, {"alice", ""}, {"nobody", "x"}, {"*", "AlicePass-1"}, {"alice)(uid=*", "AlicePass-1"}} {
		if _, err := LDAP(ctx, &cfg, roots, bad.user, bad.pass); err != ErrInvalid {
			t.Errorf("%q/%q: %v", bad.user, bad.pass, err)
		}
	}
	// TLS to a server whose CA isn't trusted fails.
	untrusted := base
	untrusted.URL = "ldaps://localhost:3636"
	if _, err := LDAP(ctx, &untrusted, x509.NewCertPool(), "alice", "AlicePass-1"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("untrusted CA: %v", err)
	}
	wrongSvc := cfg
	wrongSvc.BindPassword = "nope"
	if _, err := LDAP(ctx, &wrongSvc, roots, "alice", "AlicePass-1"); err == nil || !strings.Contains(err.Error(), "service account") {
		t.Errorf("wrong service password: %v", err)
	}
	dn, groups, err := TestLDAP(ctx, &cfg, roots, "bob")
	if err != nil || !strings.HasPrefix(dn, "uid=bob") || len(groups) != 1 {
		t.Errorf("test lookup: %s %v %v", dn, groups, err)
	}
	// Group mapping by CN, case-insensitive.
	src := config.IdentitySource{Type: "ldap", Mappings: []config.RoleMapping{{Group: "net admins", Role: "admin"}, {Group: "cn=NOC,ou=Groups,dc=example,dc=com", Role: "viewer"}}}
	if r := src.ResolveRole([]string{"cn=Net Admins,ou=Groups,dc=example,dc=com"}); r != "admin" {
		t.Errorf("CN mapping: %q", r)
	}
	if r := src.ResolveRole([]string{"CN=NOC,OU=Groups,DC=example,DC=com"}); r != "viewer" {
		t.Errorf("DN mapping: %q", r)
	}
}
