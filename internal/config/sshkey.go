package config

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// The appliance's SSH key signs in to SFTP backup destinations. It is
// generated (Ed25519, from crypto/rand) on first use, so it is unique to
// each installation, and can be regenerated or replaced by an
// administrator's own key. Restoring a backup restores the key with the
// rest of the configuration, so a replacement appliance keeps working.

// SSHKeyInfo describes the appliance's SSH key; it never includes the
// private key.
type SSHKeyInfo struct {
	PublicKey   string `json:"publicKey"` // authorized_keys line
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
	Created     int64  `json:"created"` // Unix ms; 0 if unknown
	Source      string `json:"source"`  // generated | uploaded
}

type storedSSHKey struct {
	Key     string `json:"key"` // OpenSSH private key PEM, encrypted
	Created int64  `json:"created"`
	Source  string `json:"source"`
}

const sshKeyComment = "tributary-backup"

func (c *DB) loadSSHKey() (*storedSSHKey, error) {
	var v string
	err := c.db.QueryRow("SELECT value FROM settings WHERE key = 'backup_ssh_key'").Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var k storedSSHKey
	if strings.HasPrefix(v, "{") {
		if err := json.Unmarshal([]byte(v), &k); err != nil {
			return nil, err
		}
	} else {
		k = storedSSHKey{Key: v, Source: "generated"} // first format: the encrypted key alone
	}
	return &k, nil
}

func (c *DB) storeSSHKey(priv any, source string) (*storedSSHKey, error) {
	block, err := ssh.MarshalPrivateKey(priv, sshKeyComment)
	if err != nil {
		return nil, err
	}
	enc, err := c.encrypt(string(pem.EncodeToMemory(block)))
	if err != nil {
		return nil, err
	}
	k := &storedSSHKey{Key: enc, Created: time.Now().UnixMilli(), Source: source}
	b, _ := json.Marshal(k)
	_, err = c.db.Exec("INSERT INTO settings(key, value) VALUES('backup_ssh_key', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", string(b))
	return k, err
}

func newSSHKey() (any, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// sshKey returns the stored key, creating one on first use.
func (c *DB) sshKey() (ssh.Signer, *storedSSHKey, error) {
	k, err := c.loadSSHKey()
	if err != nil {
		return nil, nil, err
	}
	if k == nil {
		priv, err := newSSHKey()
		if err != nil {
			return nil, nil, err
		}
		if k, err = c.storeSSHKey(priv, "generated"); err != nil {
			return nil, nil, err
		}
	}
	plain, err := c.decrypt(k.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting the SSH key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(plain))
	if err != nil {
		return nil, nil, err
	}
	return signer, k, nil
}

func keyInfo(signer ssh.Signer, k *storedSSHKey) SSHKeyInfo {
	pub := signer.PublicKey()
	return SSHKeyInfo{
		PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + sshKeyComment,
		Fingerprint: ssh.FingerprintSHA256(pub),
		Type:        pub.Type(),
		Created:     k.Created,
		Source:      k.Source,
	}
}

// BackupSSHKey returns the appliance's SSH key for SFTP destinations,
// creating it on first use.
func (c *DB) BackupSSHKey() (ssh.Signer, SSHKeyInfo, error) {
	signer, k, err := c.sshKey()
	if err != nil {
		return nil, SSHKeyInfo{}, err
	}
	return signer, keyInfo(signer, k), nil
}

// RegenerateBackupSSHKey replaces the key with a new Ed25519 key. Servers
// that trusted the old one must be given the new public key.
func (c *DB) RegenerateBackupSSHKey() (SSHKeyInfo, error) {
	priv, err := newSSHKey()
	if err != nil {
		return SSHKeyInfo{}, err
	}
	if _, err := c.storeSSHKey(priv, "generated"); err != nil {
		return SSHKeyInfo{}, err
	}
	_, info, err := c.BackupSSHKey()
	return info, err
}

// SetBackupSSHKey replaces the key with an administrator's own private key
// (OpenSSH or PEM format, optionally passphrase-protected). It is stored
// decrypted from its passphrase but encrypted with the appliance's key.
func (c *DB) SetBackupSSHKey(privateKey, passphrase string) (SSHKeyInfo, error) {
	privateKey = strings.TrimSpace(privateKey)
	if len(privateKey) > 32<<10 {
		return SSHKeyInfo{}, errors.New("that is too large to be an SSH private key")
	}
	if !strings.Contains(privateKey, "PRIVATE KEY") {
		if strings.HasPrefix(privateKey, "ssh-") || strings.HasPrefix(privateKey, "ecdsa-") {
			return SSHKeyInfo{}, errors.New("that is a public key; paste the private key (its file usually has no .pub extension)")
		}
		return SSHKeyInfo{}, errors.New("not an SSH private key: expected a block starting with -----BEGIN … PRIVATE KEY-----")
	}
	var raw any
	var err error
	if passphrase != "" {
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
	} else {
		raw, err = ssh.ParseRawPrivateKey([]byte(privateKey))
	}
	var missing *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		return SSHKeyInfo{}, errors.New("the key is protected by a passphrase: enter it")
	case errors.Is(err, x509.IncorrectPasswordError):
		return SSHKeyInfo{}, errors.New("wrong passphrase for the key")
	case err != nil:
		return SSHKeyInfo{}, fmt.Errorf("the key could not be read: %w", err)
	}
	// Check what we accept; ssh.MarshalPrivateKey takes Ed25519 keys by value.
	switch k := raw.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return SSHKeyInfo{}, fmt.Errorf("RSA keys must be at least 2048 bits (this one has %d); Ed25519 is recommended", k.N.BitLen())
		}
	case *ecdsa.PrivateKey:
	case *ed25519.PrivateKey:
		raw = *k
	case ed25519.PrivateKey:
	default:
		return SSHKeyInfo{}, fmt.Errorf("unsupported key type %T: use Ed25519, ECDSA or RSA", raw)
	}
	if _, err := c.storeSSHKey(raw, "uploaded"); err != nil {
		return SSHKeyInfo{}, err
	}
	_, info, err := c.BackupSSHKey()
	return info, err
}
