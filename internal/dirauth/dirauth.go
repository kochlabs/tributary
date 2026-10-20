// Package dirauth checks usernames and passwords against LDAP directories
// (including Active Directory) and RADIUS servers, and returns the groups
// used to map users to roles.
package dirauth

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"

	"github.com/kochlabs/tributary/internal/config"
)

// ErrInvalid means the server rejected the credentials (or the user doesn't
// exist): try no other server for this source.
var ErrInvalid = errors.New("invalid username or password")

// Result describes an authenticated user.
type Result struct {
	Username string
	FullName string
	Groups   []string
}

// ---- LDAP ----

const ldapTimeout = 10 * time.Second

// ldapDial connects (and upgrades with StartTLS when configured), verifying
// certificates against roots.
func ldapDial(cfg *config.LDAPConfig, roots *x509.CertPool) (*ldap.Conn, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{ServerName: u.Hostname(), RootCAs: roots, MinVersion: tls.VersionTLS12}
	conn, err := ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(tc), ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}))
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", u.Host, err)
	}
	conn.SetTimeout(ldapTimeout)
	if cfg.StartTLS {
		if err := conn.StartTLS(tc); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS: %w", err)
		}
	}
	return conn, nil
}

func isInvalidCredentials(err error) bool {
	return ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials)
}

// LDAP authenticates username/password: bind as the service account, find the
// user, bind as the user, then collect the user's groups.
func LDAP(ctx context.Context, cfg *config.LDAPConfig, roots *x509.CertPool, username, password string) (*Result, error) {
	username = strings.TrimSpace(username)
	// An empty password would be an "unauthenticated bind", which many
	// servers accept without checking anything.
	if username == "" || password == "" {
		return nil, ErrInvalid
	}
	conn, err := ldapDial(cfg, roots)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		if isInvalidCredentials(err) {
			return nil, errors.New("the service account (bind DN) was rejected; check its DN and password")
		}
		return nil, fmt.Errorf("service account bind: %w", err)
	}
	filter := strings.ReplaceAll(cfg.UserFilter, "{username}", ldap.EscapeFilter(username))
	attrs := []string{cfg.UsernameAttr, cfg.NameAttr, cfg.GroupAttr}
	res, err := conn.Search(ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(ldapTimeout/time.Second), false, filter, attrs, nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, fmt.Errorf("searching for the user: %w", err)
	}
	if res == nil || len(res.Entries) == 0 {
		return nil, ErrInvalid
	}
	if len(res.Entries) > 1 {
		return nil, fmt.Errorf("the user filter matches more than one entry for %q; make it more specific", username)
	}
	entry := res.Entries[0]
	if err := conn.Bind(entry.DN, password); err != nil {
		if isInvalidCredentials(err) {
			return nil, ErrInvalid
		}
		return nil, fmt.Errorf("checking the password: %w", err)
	}
	out := &Result{Username: entry.GetAttributeValue(cfg.UsernameAttr), FullName: entry.GetAttributeValue(cfg.NameAttr), Groups: entry.GetAttributeValues(cfg.GroupAttr)}
	if out.Username == "" {
		out.Username = username
	}
	if cfg.NestedGroups {
		// Active Directory's LDAP_MATCHING_RULE_IN_CHAIN lists every group the
		// user belongs to, directly or through other groups.
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err == nil {
			f := "(member:1.2.840.113556.1.4.1941:=" + ldap.EscapeFilter(entry.DN) + ")"
			if gr, err := conn.Search(ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, int(ldapTimeout/time.Second), false, f, []string{"dn"}, nil)); err == nil {
				for _, g := range gr.Entries {
					out.Groups = append(out.Groups, g.DN)
				}
			}
		}
	}
	return out, nil
}

// TestLDAP checks the connection and service account, and optionally looks
// up a user (without a password) to show which groups they'd get.
func TestLDAP(ctx context.Context, cfg *config.LDAPConfig, roots *x509.CertPool, lookup string) (string, []string, error) {
	conn, err := ldapDial(cfg, roots)
	if err != nil {
		return "", nil, err
	}
	defer conn.Close()
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		if isInvalidCredentials(err) {
			return "", nil, errors.New("the service account (bind DN) was rejected; check its DN and password")
		}
		return "", nil, fmt.Errorf("service account bind: %w", err)
	}
	if lookup == "" {
		return "", nil, nil
	}
	filter := strings.ReplaceAll(cfg.UserFilter, "{username}", ldap.EscapeFilter(lookup))
	res, err := conn.Search(ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(ldapTimeout/time.Second), false, filter, []string{cfg.GroupAttr}, nil))
	if err != nil {
		return "", nil, fmt.Errorf("searching for %q: %w", lookup, err)
	}
	if len(res.Entries) == 0 {
		return "", nil, fmt.Errorf("no entry matches the user filter for %q under %s", lookup, cfg.BaseDN)
	}
	return res.Entries[0].DN, res.Entries[0].GetAttributeValues(cfg.GroupAttr), nil
}

// ---- RADIUS ----

const attrMessageAuthenticator = 80

// RADIUS authenticates with PAP against the configured servers in order;
// an unreachable server moves on to the next, a rejection stops.
func RADIUS(ctx context.Context, cfg *config.RADIUSConfig, username, password string) (*Result, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, ErrInvalid
	}
	var lastErr error
	for _, server := range cfg.Servers {
		res, err := radiusOnce(ctx, cfg, config.RADIUSAddr(server), username, password)
		if err == nil || errors.Is(err, ErrInvalid) {
			return res, err
		}
		lastErr = fmt.Errorf("%s: %w", server, err)
	}
	return nil, lastErr
}

func radiusOnce(ctx context.Context, cfg *config.RADIUSConfig, addr, username, password string) (*Result, error) {
	secret := []byte(cfg.Secret)
	p := radius.New(radius.CodeAccessRequest, secret)
	if err := rfc2865.UserName_SetString(p, username); err != nil {
		return nil, err
	}
	if err := rfc2865.UserPassword_SetString(p, password); err != nil {
		return nil, err
	}
	_ = rfc2865.NASIdentifier_SetString(p, cfg.NASIdentifier)
	if err := addMessageAuthenticator(p); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.TimeoutSec)*time.Second)
	defer cancel()
	client := &radius.Client{Retry: time.Second, MaxPacketErrors: 10}
	resp, err := client.Exchange(ctx, p, addr)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, errors.New("no response (check the address, port and shared secret, and that the server lists this appliance as a client)")
		}
		return nil, err
	}
	if !validMessageAuthenticator(resp, p.Authenticator) {
		return nil, errors.New("the response's Message-Authenticator is invalid (wrong shared secret?)")
	}
	switch resp.Code {
	case radius.CodeAccessAccept:
	case radius.CodeAccessReject:
		return nil, ErrInvalid
	case radius.CodeAccessChallenge:
		return nil, errors.New("the server asked for a further challenge (such as a one-time code), which isn't supported")
	default:
		return nil, fmt.Errorf("unexpected response %v", resp.Code)
	}
	out := &Result{Username: username}
	switch cfg.RoleAttribute {
	case "Filter-Id":
		out.Groups, _ = rfc2865.FilterID_GetStrings(resp)
	default:
		vals, _ := rfc2865.Class_Gets(resp)
		for _, v := range vals {
			out.Groups = append(out.Groups, string(v))
		}
	}
	return out, nil
}

// addMessageAuthenticator signs an Access-Request (RFC 3579), placing the
// attribute first as recommended against the "BlastRADIUS" attack.
func addMessageAuthenticator(p *radius.Packet) error {
	p.Attributes = append(radius.Attributes{{Type: attrMessageAuthenticator, Attribute: make(radius.Attribute, 16)}}, p.Attributes...)
	wire, err := p.MarshalBinary()
	if err != nil {
		return err
	}
	mac := hmac.New(md5.New, p.Secret)
	mac.Write(wire)
	copy(p.Attributes[0].Attribute, mac.Sum(nil))
	return nil
}

// validMessageAuthenticator checks a response's Message-Authenticator when
// present (computed with the request's authenticator in place).
func validMessageAuthenticator(resp *radius.Packet, reqAuth [16]byte) bool {
	idx := -1
	for i, a := range resp.Attributes {
		if a.Type == attrMessageAuthenticator {
			idx = i
			break
		}
	}
	if idx < 0 {
		return true
	}
	got := append([]byte(nil), resp.Attributes[idx].Attribute...)
	if len(got) != 16 {
		return false
	}
	saved := resp.Authenticator
	resp.Authenticator = reqAuth
	resp.Attributes[idx].Attribute = make(radius.Attribute, 16)
	wire, err := resp.MarshalBinary()
	resp.Authenticator = saved
	resp.Attributes[idx].Attribute = got
	if err != nil {
		return false
	}
	mac := hmac.New(md5.New, resp.Secret)
	mac.Write(wire)
	return hmac.Equal(mac.Sum(nil), got)
}
