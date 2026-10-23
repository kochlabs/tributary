package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"strings"
	"time"
)

// Email is the SMTP server the appliance sends mail through (reports and
// alerts). The password is stored encrypted and never returned by the API.
type Email struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	// Security: starttls (upgrade on the submission port, usually 587), tls
	// (implicit TLS, usually 465) or none (a relay on a trusted network).
	Security    string `json:"security"`
	Username    string `json:"username"` // empty: no authentication
	Password    string `json:"password,omitempty"`
	HasPassword bool   `json:"hasPassword"`
	// From is the sender, an address or "Name <address>".
	From    string `json:"from"`
	Updated int64  `json:"updated"`
}

func DefaultEmail() Email {
	return Email{Port: 587, Security: "starttls"}
}

// ValidateEmail checks and normalises e (e.g. before a test send).
func ValidateEmail(e *Email) error {
	e.Host = strings.TrimSpace(e.Host)
	e.Username = strings.TrimSpace(e.Username)
	e.From = strings.TrimSpace(e.From)
	switch e.Security {
	case "", "starttls":
		e.Security = "starttls"
	case "tls", "none":
	default:
		return fmt.Errorf("unknown security %q", e.Security)
	}
	if e.Port == 0 {
		e.Port = map[string]int{"starttls": 587, "tls": 465, "none": 25}[e.Security]
	}
	if e.Port < 1 || e.Port > 65535 {
		return errors.New("the port must be between 1 and 65535")
	}
	if e.Host == "" && !e.Enabled && e.From == "" {
		return nil // nothing set up yet
	}
	e.Host = strings.Trim(e.Host, "[]")
	if _, err := netip.ParseAddr(e.Host); e.Host == "" || strings.ContainsAny(e.Host, " /\\@") || strings.Contains(e.Host, ":") && err != nil {
		return errors.New("enter the SMTP server's host name or address (without a port)")
	}
	if e.From == "" {
		return errors.New("enter the sender address")
	}
	if _, err := mail.ParseAddress(e.From); err != nil {
		return fmt.Errorf("the sender address is not valid: %w", err)
	}
	if e.Username != "" && e.Security == "none" {
		return errors.New("signing in needs STARTTLS or TLS, so the password isn't sent in the clear")
	}
	return nil
}

func (c *DB) storedEmail() Email {
	e := DefaultEmail()
	c.settingJSON("email", &e)
	return e
}

// Email returns the configuration for display: the password omitted.
func (c *DB) Email() Email {
	e := c.storedEmail()
	e.HasPassword, e.Password = e.Password != "", ""
	return e
}

// EmailSecrets returns the configuration with the password decrypted, for
// sending.
func (c *DB) EmailSecrets() (Email, error) {
	e := c.storedEmail()
	plain, err := c.decrypt(e.Password)
	if err != nil {
		return e, fmt.Errorf("decrypting the SMTP password: %w", err)
	}
	e.Password = plain
	return e, nil
}

// FillEmailSecrets completes a configuration from the form with the stored
// password when the form left it empty and the account is unchanged (for
// testing before saving).
func (c *DB) FillEmailSecrets(e *Email) error {
	if e.Password != "" || e.Username == "" {
		return nil
	}
	stored, err := c.EmailSecrets()
	if err != nil {
		return err
	}
	if stored.Username == e.Username && stored.Host == e.Host {
		e.Password = stored.Password
	}
	return nil
}

// SaveEmail validates and stores the configuration. An empty password keeps
// the stored one unless the account changed; no username drops it.
func (c *DB) SaveEmail(e Email) (Email, error) {
	if err := ValidateEmail(&e); err != nil {
		return Email{}, err
	}
	stored := c.storedEmail()
	switch {
	case e.Username == "":
		e.Password = ""
	case e.Password == "" && stored.Username == e.Username && stored.Host == e.Host:
		e.Password = stored.Password // already encrypted
	case e.Password != "":
		enc, err := c.encrypt(e.Password)
		if err != nil {
			return Email{}, err
		}
		e.Password = enc
	}
	if e.Enabled && e.Username != "" && e.Password == "" {
		return Email{}, errors.New("enter the password")
	}
	e.HasPassword = false
	e.Updated = time.Now().UnixMilli()
	if err := c.saveSettingJSON("email", e); err != nil {
		return Email{}, err
	}
	return c.Email(), nil
}
