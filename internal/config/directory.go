package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Active Directory defaults; OpenLDAP users change the filter to
// (uid={username}) and the attributes to uid/cn.
const (
	DefaultLDAPFilter       = "(&(objectClass=user)(sAMAccountName={username}))"
	DefaultLDAPUsernameAttr = "sAMAccountName"
	DefaultLDAPNameAttr     = "displayName"
	DefaultLDAPGroupAttr    = "memberOf"
)

func (l *LDAPConfig) normalize() error {
	if l == nil {
		return errors.New("LDAP settings are required")
	}
	l.URL = strings.TrimSpace(l.URL)
	u, err := url.Parse(l.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return errors.New("server URL must look like ldaps://dc1.example.com or ldap://dc1.example.com:389")
	}
	if u.Scheme == "ldaps" && l.StartTLS {
		l.StartTLS = false // already encrypted
	}
	l.BindDN, l.BaseDN = strings.TrimSpace(l.BindDN), strings.TrimSpace(l.BaseDN)
	if l.BindDN == "" {
		return errors.New("bind DN (service account) is required")
	}
	if l.BaseDN == "" {
		return errors.New("base DN to search for users is required")
	}
	if l.UserFilter = strings.TrimSpace(l.UserFilter); l.UserFilter == "" {
		l.UserFilter = DefaultLDAPFilter
	}
	if !strings.Contains(l.UserFilter, "{username}") || !strings.HasPrefix(l.UserFilter, "(") {
		return errors.New("user filter must be an LDAP filter containing {username}")
	}
	for _, a := range []*string{&l.UsernameAttr, &l.NameAttr, &l.GroupAttr} {
		*a = strings.TrimSpace(*a)
	}
	if l.UsernameAttr == "" {
		l.UsernameAttr = DefaultLDAPUsernameAttr
	}
	if l.NameAttr == "" {
		l.NameAttr = DefaultLDAPNameAttr
	}
	if l.GroupAttr == "" {
		l.GroupAttr = DefaultLDAPGroupAttr
	}
	return nil
}

// Insecure reports whether passwords would cross the network in clear text.
func (l *LDAPConfig) Insecure() bool {
	return strings.HasPrefix(l.URL, "ldap://") && !l.StartTLS
}

func (r *RADIUSConfig) normalize() error {
	if r == nil {
		return errors.New("RADIUS settings are required")
	}
	var servers []string
	for _, s := range r.Servers {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		host := s
		if h, p, err := net.SplitHostPort(s); err == nil {
			if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("invalid port in %q", s)
			}
			host = h
		}
		if host == "" || strings.ContainsAny(host, " /\\") {
			return fmt.Errorf("invalid RADIUS server %q", s)
		}
		servers = append(servers, s)
	}
	if len(servers) == 0 {
		return errors.New("add at least one RADIUS server")
	}
	if len(servers) > 4 {
		return errors.New("at most 4 RADIUS servers")
	}
	r.Servers = servers
	r.NASIdentifier = strings.TrimSpace(r.NASIdentifier)
	if r.NASIdentifier == "" {
		r.NASIdentifier = "tributary"
	}
	if r.TimeoutSec <= 0 {
		r.TimeoutSec = 5
	}
	if r.TimeoutSec > 30 {
		return errors.New("timeout must be at most 30 seconds")
	}
	switch r.RoleAttribute {
	case "":
		r.RoleAttribute = "Class"
	case "Class", "Filter-Id":
	default:
		return errors.New("role attribute must be Class or Filter-Id")
	}
	return nil
}

// RADIUSAddr returns a server address with the default port added.
func RADIUSAddr(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(strings.Trim(s, "[]"), "1812")
}
