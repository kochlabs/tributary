package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

// BackupSchedule makes encrypted backups unattended and copies them to
// another system (an SMB share, S3-compatible object storage or an SFTP
// server), keeping a set number at each place.
type BackupSchedule struct {
	Enabled      bool   `json:"enabled"`
	Frequency    string `json:"frequency"` // daily | weekly
	Weekday      int    `json:"weekday"`   // 0 = Sunday; weekly only
	Time         string `json:"time"`      // HH:MM, appliance local time
	IncludeFlows bool   `json:"includeFlows"`
	// Encryption is "passphrase" (stored here, encrypted) or "publickey":
	// backups are encrypted to age public keys whose private keys never
	// touch the appliance.
	Encryption    string            `json:"encryption"`
	Passphrase    string            `json:"passphrase,omitempty"` // write-only
	HasPassphrase bool              `json:"hasPassphrase"`
	PublicKeys    string            `json:"publicKeys"` // age1… recipients, one per line
	KeepLocal     int               `json:"keepLocal"`  // scheduled backups kept on the appliance
	KeepRemote    int               `json:"keepRemote"` // kept at the destination
	Destination   BackupDestination `json:"destination"`
	Updated       int64             `json:"updated"` // when the schedule was saved (Unix ms)
}

// BackupDestination is where scheduled backups are copied. Fields apply by
// type; secrets are write-only.
type BackupDestination struct {
	Type string `json:"type"` // "" (this appliance only) | smb | s3 | sftp

	Host     string `json:"host"` // smb, sftp
	Port     int    `json:"port"`
	Share    string `json:"share"`  // smb
	Domain   string `json:"domain"` // smb
	Username string `json:"username"`
	// Path is the folder (smb, sftp) or key prefix (s3) to write to.
	Path        string `json:"path"`
	Password    string `json:"password,omitempty"` // smb, sftp password auth
	HasPassword bool   `json:"hasPassword"`

	Endpoint     string `json:"endpoint"` // s3: empty for AWS
	Region       string `json:"region"`
	Bucket       string `json:"bucket"`
	AccessKey    string `json:"accessKey"`
	SecretKey    string `json:"secretKey,omitempty"`
	HasSecretKey bool   `json:"hasSecretKey"`
	PathStyle    bool   `json:"pathStyle"`

	SFTPAuth string `json:"sftpAuth"` // password | key (the appliance's SSH key)
	// HostKey pins the SFTP server's key (authorized_keys format); it is
	// learned by testing the connection and confirmed by the administrator.
	HostKey string `json:"hostKey"`
}

// BackupRun is the result of the last scheduled (or run-now) backup.
type BackupRun struct {
	Started     int64  `json:"started"`
	Finished    int64  `json:"finished"`
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
	Name        string `json:"name,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Copied      bool   `json:"copied"` // to the destination
	LastSuccess int64  `json:"lastSuccess"`
}

func DefaultBackupSchedule() BackupSchedule {
	return BackupSchedule{Frequency: "daily", Time: "02:30", Encryption: "passphrase", KeepLocal: 3, KeepRemote: 14,
		Destination: BackupDestination{SFTPAuth: "key"}}
}

const minBackupPassphrase = 12

var hhmm = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

// ValidateBackupSchedule checks and normalises a schedule. Secrets may be
// empty when a stored one is kept.
func ValidateBackupSchedule(s *BackupSchedule) error {
	if s.Frequency == "" {
		s.Frequency = "daily"
	}
	if s.Frequency != "daily" && s.Frequency != "weekly" {
		return errors.New("frequency must be daily or weekly")
	}
	if s.Weekday < 0 || s.Weekday > 6 {
		return errors.New("invalid day of the week")
	}
	if s.Time = strings.TrimSpace(s.Time); !hhmm.MatchString(s.Time) {
		return errors.New("the time must be HH:MM (24-hour)")
	}
	if s.KeepLocal == 0 {
		s.KeepLocal = 3
	}
	if s.KeepRemote == 0 {
		s.KeepRemote = 14
	}
	if s.KeepLocal < 1 || s.KeepLocal > 100 || s.KeepRemote < 1 || s.KeepRemote > 1000 {
		return errors.New("keep between 1 and 100 backups on the appliance, and 1 and 1000 at the destination")
	}
	switch s.Encryption {
	case "", "passphrase":
		s.Encryption, s.PublicKeys = "passphrase", ""
		if s.Passphrase != "" && len(s.Passphrase) < minBackupPassphrase {
			return fmt.Errorf("the passphrase must be at least %d characters", minBackupPassphrase)
		}
	case "publickey":
		s.Passphrase = ""
		s.PublicKeys = strings.TrimSpace(s.PublicKeys)
		if s.PublicKeys == "" {
			return errors.New("enter at least one age public key (age1…)")
		}
		if _, err := age.ParseRecipients(strings.NewReader(s.PublicKeys)); err != nil {
			return fmt.Errorf("invalid public key: %w", err)
		}
	default:
		return errors.New("encryption must be passphrase or publickey")
	}
	return s.Destination.validate()
}

// ValidateBackupDestination checks and normalises just a destination.
func ValidateBackupDestination(d *BackupDestination) error { return d.validate() }

func (d *BackupDestination) validate() error {
	for _, f := range []*string{&d.Host, &d.Share, &d.Domain, &d.Username, &d.Endpoint, &d.Region, &d.Bucket, &d.AccessKey, &d.HostKey} {
		*f = strings.TrimSpace(*f)
	}
	d.Path = cleanRemotePath(d.Path)
	keep := *d
	*d = BackupDestination{Type: keep.Type, Path: keep.Path, Password: keep.Password, SecretKey: keep.SecretKey}
	host := func(def int) error {
		if keep.Host == "" || strings.ContainsAny(keep.Host, "/\\ ") {
			return errors.New("enter the server's host name or address")
		}
		if keep.Port == 0 {
			keep.Port = def
		}
		if keep.Port < 1 || keep.Port > 65535 {
			return errors.New("invalid port")
		}
		d.Host, d.Port = keep.Host, keep.Port
		return nil
	}
	switch keep.Type {
	case "":
		d.Path, d.Password, d.SecretKey = "", "", ""
	case "smb":
		if err := host(445); err != nil {
			return err
		}
		share := strings.Trim(keep.Share, `/\`)
		if share == "" || strings.ContainsAny(share, `/\`) {
			return errors.New("enter the share name (just the share; put folders in Path)")
		}
		d.Share, d.Domain, d.Username = share, keep.Domain, keep.Username
		d.SecretKey = ""
	case "s3":
		if keep.Bucket == "" {
			return errors.New("enter the bucket")
		}
		if keep.Endpoint != "" {
			ep := keep.Endpoint
			if !strings.Contains(ep, "://") {
				ep = "https://" + ep
			}
			u, err := url.Parse(ep)
			if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || (u.Path != "" && u.Path != "/") {
				return errors.New("the endpoint must be a host name, host:port or URL such as https://minio.example.com:9000")
			}
			keep.Endpoint = u.Scheme + "://" + u.Host
		}
		if keep.AccessKey == "" {
			return errors.New("enter the access key")
		}
		if keep.Region == "" {
			keep.Region = "us-east-1"
		}
		d.Endpoint, d.Region, d.Bucket, d.AccessKey, d.PathStyle = keep.Endpoint, keep.Region, keep.Bucket, keep.AccessKey, keep.PathStyle
		d.Password = ""
	case "sftp":
		if err := host(22); err != nil {
			return err
		}
		if keep.Username == "" {
			return errors.New("enter the user name")
		}
		if keep.SFTPAuth != "password" {
			keep.SFTPAuth = "key"
			d.Password = ""
		}
		if keep.HostKey != "" {
			if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keep.HostKey)); err != nil {
				return errors.New("the pinned host key is invalid; test the connection again")
			}
		}
		d.Username, d.SFTPAuth, d.HostKey = keep.Username, keep.SFTPAuth, keep.HostKey
		d.SecretKey = ""
	default:
		return errors.New("unknown destination type")
	}
	return nil
}

// cleanRemotePath normalises a folder or prefix: forward slashes, no leading
// or trailing slash, no "." or ".." segments.
func cleanRemotePath(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), `\`, "/")
	p = path.Clean("/" + p)
	return strings.Trim(p, "/")
}

// Describe is a short human description of the destination.
func (d BackupDestination) Describe() string {
	join := func(base, p string) string {
		if p == "" {
			return base
		}
		return base + "/" + p
	}
	switch d.Type {
	case "smb":
		return join(`\\`+d.Host+`\`+d.Share, d.Path)
	case "s3":
		ep := d.Endpoint
		if ep == "" {
			ep = "s3"
		}
		return join(ep+"://"+d.Bucket, d.Path)
	case "sftp":
		return join("sftp://"+d.Username+"@"+net.JoinHostPort(d.Host, fmt.Sprint(d.Port)), d.Path)
	}
	return "this appliance"
}

// ---- storage ----

func (c *DB) settingJSON(key string, v any) bool {
	var s string
	if err := c.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&s); err != nil {
		return false
	}
	return json.Unmarshal([]byte(s), v) == nil
}

func (c *DB) saveSettingJSON(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.db.Exec("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, string(b))
	return err
}

// storedBackupSchedule returns the schedule with secrets still encrypted.
func (c *DB) storedBackupSchedule() BackupSchedule {
	s := DefaultBackupSchedule()
	c.settingJSON("backup_schedule", &s)
	return s
}

// BackupSchedule returns the schedule for display: secrets omitted.
func (c *DB) BackupSchedule() BackupSchedule {
	s := c.storedBackupSchedule()
	s.HasPassphrase, s.Destination.HasPassword, s.Destination.HasSecretKey = s.Passphrase != "", s.Destination.Password != "", s.Destination.SecretKey != ""
	s.Passphrase, s.Destination.Password, s.Destination.SecretKey = "", "", ""
	return s
}

// BackupScheduleSecrets returns the schedule with secrets decrypted, for
// running it.
func (c *DB) BackupScheduleSecrets() (BackupSchedule, error) {
	s := c.storedBackupSchedule()
	for _, f := range []*string{&s.Passphrase, &s.Destination.Password, &s.Destination.SecretKey} {
		plain, err := c.decrypt(*f)
		if err != nil {
			return s, fmt.Errorf("decrypting a stored backup secret: %w", err)
		}
		*f = plain
	}
	return s, nil
}

// FillBackupSecrets completes a schedule from the form with the stored
// secrets the form left empty (for testing before saving).
func (c *DB) FillBackupSecrets(s *BackupSchedule) error {
	stored, err := c.BackupScheduleSecrets()
	if err != nil {
		return err
	}
	if s.Passphrase == "" {
		s.Passphrase = stored.Passphrase
	}
	if s.Destination.Password == "" && s.Destination.Type == stored.Destination.Type {
		s.Destination.Password = stored.Destination.Password
	}
	if s.Destination.SecretKey == "" && s.Destination.Type == stored.Destination.Type {
		s.Destination.SecretKey = stored.Destination.SecretKey
	}
	return nil
}

// SaveBackupSchedule validates and stores a schedule. Empty secrets keep the
// stored ones; secrets the settings no longer use are dropped.
func (c *DB) SaveBackupSchedule(s BackupSchedule) (BackupSchedule, error) {
	if err := ValidateBackupSchedule(&s); err != nil {
		return BackupSchedule{}, err
	}
	stored := c.storedBackupSchedule()
	sameType := stored.Destination.Type == s.Destination.Type
	secret := func(plain *string, old string, used, keepOld bool) error {
		switch {
		case !used:
			*plain = ""
		case *plain == "" && keepOld:
			*plain = old
		case *plain != "":
			enc, err := c.encrypt(*plain)
			if err != nil {
				return err
			}
			*plain = enc
		}
		return nil
	}
	d := &s.Destination
	if err := secret(&s.Passphrase, stored.Passphrase, s.Encryption == "passphrase", true); err != nil {
		return BackupSchedule{}, err
	}
	if err := secret(&d.Password, stored.Destination.Password, d.Type == "smb" || (d.Type == "sftp" && d.SFTPAuth == "password"), sameType); err != nil {
		return BackupSchedule{}, err
	}
	if err := secret(&d.SecretKey, stored.Destination.SecretKey, d.Type == "s3", sameType); err != nil {
		return BackupSchedule{}, err
	}
	if s.Enabled {
		switch {
		case s.Encryption == "passphrase" && s.Passphrase == "":
			return BackupSchedule{}, errors.New("enter a passphrase for scheduled backups")
		case d.Type == "s3" && d.SecretKey == "":
			return BackupSchedule{}, errors.New("enter the secret key")
		case d.Type == "sftp" && d.SFTPAuth == "password" && d.Password == "":
			return BackupSchedule{}, errors.New("enter the password")
		case d.Type == "sftp" && d.HostKey == "":
			return BackupSchedule{}, errors.New("test the connection first to confirm the SFTP server's host key")
		}
	}
	s.HasPassphrase, d.HasPassword, d.HasSecretKey = false, false, false
	s.Updated = time.Now().UnixMilli()
	if err := c.saveSettingJSON("backup_schedule", s); err != nil {
		return BackupSchedule{}, err
	}
	return c.BackupSchedule(), nil
}

// BackupRun returns the last scheduled run.
func (c *DB) BackupRun() BackupRun {
	var r BackupRun
	c.settingJSON("backup_run", &r)
	return r
}

func (c *DB) SaveBackupRun(r BackupRun) error { return c.saveSettingJSON("backup_run", r) }

// BackupSSHKey returns the appliance's SSH key for SFTP destinations,
// creating it on first use, and its public half in authorized_keys format.
func (c *DB) BackupSSHKey() (ssh.Signer, string, error) {
	var enc string
	err := c.db.QueryRow("SELECT value FROM settings WHERE key = 'backup_ssh_key'").Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		_, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, "", gerr
		}
		block, merr := ssh.MarshalPrivateKey(priv, "tributary backup")
		if merr != nil {
			return nil, "", merr
		}
		if enc, err = c.encrypt(string(pem.EncodeToMemory(block))); err != nil {
			return nil, "", err
		}
		if _, err = c.db.Exec("INSERT INTO settings(key, value) VALUES('backup_ssh_key', ?)", enc); err != nil {
			return nil, "", err
		}
	} else if err != nil {
		return nil, "", err
	}
	plain, err := c.decrypt(enc)
	if err != nil {
		return nil, "", err
	}
	signer, err := ssh.ParsePrivateKey([]byte(plain))
	if err != nil {
		return nil, "", err
	}
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " tributary-backup"
	return signer, pub, nil
}
