package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// SAMLConfig is a SAML 2.0 identity provider. The appliance is the service
// provider: it signs its requests with its own key pair (generated when the
// source is created) and accepts only signed assertions answering requests
// it sent.
type SAMLConfig struct {
	// MetadataURL is where the identity provider publishes its metadata; when
	// set, the metadata is fetched on save and refreshed daily.
	MetadataURL string `json:"metadataUrl"`
	// MetadataXML is the identity provider's metadata: fetched from
	// MetadataURL, or pasted when the provider has no metadata URL.
	MetadataXML string `json:"metadataXml"`
	// MetadataFetched is when MetadataXML was last fetched (Unix ms).
	MetadataFetched int64 `json:"metadataFetched"`
	// EntityID identifies this appliance to the provider; empty means the
	// appliance's metadata URL.
	EntityID string `json:"entityId"`
	// Attribute names (Name or FriendlyName) for the username (empty: the
	// NameID), display name and groups.
	UsernameAttr string `json:"usernameAttr"`
	NameAttr     string `json:"nameAttr"`
	GroupsAttr   string `json:"groupsAttr"`
	SignRequests bool   `json:"signRequests"`
	// SPCert and SPKey are the appliance's signing and decryption key pair
	// (PEM). Both are managed by the appliance: values sent by clients are
	// ignored, and the key is never returned.
	SPCert string `json:"spCert"`
	SPKey  string `json:"spKey,omitempty"`
}

// MetadataMaxAge is how old fetched provider metadata may get before it is
// fetched again (keeping up with signing certificate rollovers).
const MetadataMaxAge = 24 * time.Hour

const maxMetadataBytes = 1 << 20

func (s *SAMLConfig) normalize() error {
	if s == nil {
		return errors.New("SAML settings are required")
	}
	s.MetadataURL = strings.TrimSpace(s.MetadataURL)
	s.MetadataXML = strings.TrimSpace(s.MetadataXML)
	s.EntityID = strings.TrimSpace(s.EntityID)
	if s.MetadataURL != "" {
		u, err := url.Parse(s.MetadataURL)
		if err != nil || u.Host == "" {
			return errors.New("the metadata URL is not a valid URL")
		}
		local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
		if u.Scheme != "https" && !(u.Scheme == "http" && local) {
			return errors.New("the metadata URL must use https")
		}
	}
	if s.MetadataXML == "" {
		return errors.New("the identity provider's metadata is required: enter its URL or paste the XML")
	}
	if len(s.MetadataXML) > maxMetadataBytes {
		return errors.New("the metadata is too large")
	}
	if len(s.EntityID) > 512 {
		return errors.New("the entity ID is too long")
	}
	for _, a := range []*string{&s.UsernameAttr, &s.NameAttr, &s.GroupsAttr} {
		*a = strings.TrimSpace(*a)
	}
	return nil
}

// newSAMLKeyPair creates the appliance's self-signed signing certificate for
// a SAML source. Providers trust it through the appliance's metadata, so it
// needs no CA; it is long-lived because replacing it means updating the
// provider.
func newSAMLKeyPair() (certPEM, keyPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Tributary SAML service provider"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(key)}))
	return certPEM, keyPEM, nil
}

func mustPKCS8(key *rsa.PrivateKey) []byte {
	b, _ := x509.MarshalPKCS8PrivateKey(key) // cannot fail for an RSA key
	return b
}

// prepareSAMLKeys sets the key pair on a SAML source being saved: the stored
// one on update, a new one on create. The key is returned encrypted.
func (c *DB) prepareSAMLKeys(s *IdentitySource) error {
	if s.ID == 0 {
		cert, key, err := newSAMLKeyPair()
		if err != nil {
			return err
		}
		enc, err := c.encrypt(key)
		if err != nil {
			return err
		}
		s.SAML.SPCert, s.SAML.SPKey = cert, enc
		return nil
	}
	typ, raw, err := c.storedSourceConfig(s.ID)
	if err != nil {
		return err
	}
	if typ != s.Type {
		return errors.New("the type of an identity source can't be changed")
	}
	var stored SAMLConfig
	if err := json.Unmarshal(raw, &stored); err != nil {
		return err
	}
	s.SAML.SPCert, s.SAML.SPKey = stored.SPCert, stored.SPKey
	return nil
}

// storedSourceConfig returns a source's type and raw stored settings (secrets
// still encrypted).
func (c *DB) storedSourceConfig(id int64) (string, []byte, error) {
	var typ, cfg string
	if err := c.db.QueryRow("SELECT type, config FROM identity_sources WHERE id = ?", id).Scan(&typ, &cfg); err != nil {
		return "", nil, ErrNotFound
	}
	return typ, []byte(cfg), nil
}

// SaveSAMLMetadata stores freshly fetched provider metadata for a source.
func (c *DB) SaveSAMLMetadata(id int64, xml string, fetched time.Time) error {
	typ, raw, err := c.storedSourceConfig(id)
	if err != nil {
		return err
	}
	if typ != "saml" {
		return ErrNotFound
	}
	var s SAMLConfig
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	s.MetadataXML, s.MetadataFetched = strings.TrimSpace(xml), fetched.UnixMilli()
	b, _ := json.Marshal(s)
	_, err = c.db.Exec("UPDATE identity_sources SET config = ? WHERE id = ?", string(b), id)
	return err
}
