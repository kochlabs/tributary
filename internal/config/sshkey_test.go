package config

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	c, err := Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestBackupSSHKey(t *testing.T) {
	a, b := openTestDB(t), openTestDB(t)
	_, ka, err := a.BackupSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	_, kb, _ := b.BackupSSHKey()
	if ka.Fingerprint == kb.Fingerprint || ka.Type != ssh.KeyAlgoED25519 || ka.Source != "generated" || ka.Created == 0 {
		t.Fatalf("keys: %+v %+v", ka, kb)
	}
	if _, again, _ := a.BackupSSHKey(); again.Fingerprint != ka.Fingerprint {
		t.Fatal("key changed between uses")
	}
	var raw string
	a.db.QueryRow("SELECT value FROM settings WHERE key = 'backup_ssh_key'").Scan(&raw)
	if strings.Contains(raw, "PRIVATE KEY") {
		t.Fatal("private key stored unencrypted")
	}

	// Regenerating gives a new key.
	re, err := a.RegenerateBackupSSHKey()
	if err != nil || re.Fingerprint == ka.Fingerprint || re.Source != "generated" {
		t.Fatalf("regenerate: %+v %v", re, err)
	}

	// The first stored format (the encrypted key alone) still loads.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	enc, _ := a.encrypt(string(pem.EncodeToMemory(block)))
	a.db.Exec("UPDATE settings SET value = ? WHERE key = 'backup_ssh_key'", enc)
	signer, legacy, err := a.BackupSSHKey()
	if err != nil || legacy.Created != 0 || !strings.HasPrefix(legacy.PublicKey, "ssh-ed25519 ") || signer == nil {
		t.Fatalf("legacy: %+v %v", legacy, err)
	}
}

func TestUploadBackupSSHKey(t *testing.T) {
	c := openTestDB(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub, _ := ssh.NewPublicKey(priv.Public())
	protected, _ := ssh.MarshalPrivateKeyWithPassphrase(priv, "me@laptop", []byte("key-pass"))
	pemText := string(pem.EncodeToMemory(protected))

	if _, err := c.SetBackupSSHKey(pemText, ""); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("missing passphrase: %v", err)
	}
	if _, err := c.SetBackupSSHKey(pemText, "wrong"); err == nil || !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("wrong passphrase: %v", err)
	}
	info, err := c.SetBackupSSHKey(pemText, "key-pass")
	if err != nil || info.Fingerprint != ssh.FingerprintSHA256(pub) || info.Source != "uploaded" {
		t.Fatalf("upload: %+v %v", info, err)
	}
	// The appliance can use it afterwards (no passphrase needed).
	if signer, _, err := c.BackupSSHKey(); err != nil || ssh.FingerprintSHA256(signer.PublicKey()) != info.Fingerprint {
		t.Fatalf("use: %v", err)
	}

	// Other formats and types.
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalECPrivateKey(ec)
	if info, err := c.SetBackupSSHKey(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})), ""); err != nil || info.Type != "ecdsa-sha2-nistp256" {
		t.Fatalf("ecdsa: %+v %v", info, err)
	}
	r2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := c.SetBackupSSHKey(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(r2048)})), ""); err != nil {
		t.Fatalf("rsa 2048: %v", err)
	}
	r1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := c.SetBackupSSHKey(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(r1024)})), ""); err == nil {
		t.Fatal("1024-bit RSA accepted")
	}
	if _, err := c.SetBackupSSHKey(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), ""); err == nil || !strings.Contains(err.Error(), "public key") {
		t.Fatalf("public key: %v", err)
	}
	if _, err := c.SetBackupSSHKey("hello", ""); err == nil {
		t.Fatal("garbage accepted")
	}
}
