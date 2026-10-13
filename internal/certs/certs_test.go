package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCA issues certificates for CSRs, with an intermediate between the root
// and the leaf like a real enterprise CA.
type testCA struct {
	root, inter       *x509.Certificate
	rootKey, interKey crypto.Signer
}

func newTestCA(t *testing.T) *testCA {
	mk := func(cn string, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, key
	}
	ca := &testCA{}
	ca.root, ca.rootKey = mk("Test Root CA", nil, nil)
	ca.inter, ca.interKey = mk("Test Issuing CA", ca.root, ca.rootKey)
	return ca
}

func (ca *testCA) sign(t *testing.T, csrPEM string, notAfter time.Time) []byte {
	b, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: csr.Subject, DNSNames: csr.DNSNames,
		IPAddresses: csr.IPAddresses, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.inter, csr.PublicKey, ca.interKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func served(t *testing.T, m *Manager) *x509.Certificate {
	c, err := m.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	return leaf
}

var appliance = Identity{CommonName: "flows.example.com", DNSNames: []string{"flows.example.com"}, IPAddresses: []string{"192.0.2.10"}}

func TestFirstStartCreatesSelfSigned(t *testing.T) {
	m := NewManager(t.TempDir())
	created, err := m.Load()
	if err != nil || !created {
		t.Fatalf("load: %v created=%v", err, created)
	}
	st, _ := m.Status()
	if !st.Certificate.SelfSigned || st.Certificate.Key != "ECDSA P-256" || st.Certificate.DaysLeft < 800 {
		t.Fatalf("unexpected first certificate: %+v", st.Certificate)
	}
	if created, _ := m.Load(); created {
		t.Fatal("second start regenerated the certificate")
	}
}

func TestCSRRoundTripHotSwap(t *testing.T) {
	m := NewManager(t.TempDir())
	m.Load()
	ca := newTestCA(t)
	info, err := m.GenerateCSR(appliance, "rsa-2048")
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := m.Status(); st.Pending == nil || st.Pending.CommonName != "flows.example.com" {
		t.Fatal("pending CSR not reported")
	}
	// The CA returns leaf + intermediate, intermediate first (common in practice).
	signed := append(pemOf(ca.inter), ca.sign(t, info.PEM, time.Now().AddDate(1, 0, 0))...)
	d, err := m.Upload(signed, nil) // no key: the CSR's key on the appliance is used
	if err != nil {
		t.Fatal(err)
	}
	if d.CommonName != "flows.example.com" || d.Chain != 2 || d.SelfSigned || d.Key != "RSA 2048" {
		t.Fatalf("details: %+v", d)
	}
	leaf := served(t, m)
	if leaf.Subject.CommonName != "flows.example.com" {
		t.Fatalf("not hot-swapped: serving %s", leaf.Subject.CommonName)
	}
	// Leaf first, then the intermediate: a client trusting the root verifies it.
	c, _ := m.GetCertificate(nil)
	inter, _ := x509.ParseCertificate(c.Certificate[1])
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(ca.root)
	inters.AddCert(inter)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "flows.example.com"}); err != nil {
		t.Fatalf("served chain does not verify: %v", err)
	}
	if st, _ := m.Status(); st.Pending != nil || !st.HasPrevious {
		t.Fatalf("pending CSR not cleared or no backup: %+v", st)
	}
	// Restore returns to the self-signed certificate.
	if d, err := m.Restore(); err != nil || !d.SelfSigned {
		t.Fatalf("restore: %v %+v", err, d)
	}
}

func TestUploadRejections(t *testing.T) {
	m := NewManager(t.TempDir())
	m.Load()
	ca := newTestCA(t)
	before := served(t, m).SerialNumber

	info, _ := m.GenerateCSR(appliance, "ecdsa-p256")
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(otherKey)
	wrongKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	weakTmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "weak"}, DNSNames: []string{"weak"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0)}
	weakDER, _ := x509.CreateCertificate(rand.Reader, weakTmpl, weakTmpl, &weak.PublicKey, weak)

	cases := map[string]struct {
		cert, key []byte
		want      string
	}{
		"wrong key":      {ca.sign(t, info.PEM, time.Now().AddDate(1, 0, 0)), wrongKey, "do not match"},
		"expired":        {ca.sign(t, info.PEM, time.Now().Add(-time.Minute)), nil, "expired"},
		"CA certificate": {pemOf(ca.root), wrongKey, "CA certificate"},
		"weak RSA":       {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: weakDER}), wrongKey, "2048"},
		"not PEM":        {[]byte("hello"), nil, "no PEM certificate"},
	}
	for name, c := range cases {
		if _, err := m.Upload(c.cert, c.key); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", name, err, c.want)
		}
	}
	if served(t, m).SerialNumber.Cmp(before) != 0 {
		t.Fatal("a rejected upload changed the served certificate")
	}
}

func TestSelfSignedValidation(t *testing.T) {
	m := NewManager(t.TempDir())
	m.Load()
	if _, err := m.RegenerateSelfSigned(Identity{CommonName: "x"}, "ecdsa-p256", 365); err == nil {
		t.Error("certificate without DNS names or IPs accepted")
	}
	if _, err := m.RegenerateSelfSigned(appliance, "ecdsa-p256", 3650); err == nil {
		t.Error("validity over 825 days accepted")
	}
	if _, err := m.RegenerateSelfSigned(Identity{CommonName: "x", IPAddresses: []string{"not-an-ip"}}, "", 30); err == nil {
		t.Error("invalid IP accepted")
	}
	d, err := m.RegenerateSelfSigned(appliance, "ecdsa-p384", 90)
	if err != nil || d.Key != "ECDSA P-384" || d.DaysLeft < 88 || served(t, m).Subject.CommonName != "flows.example.com" {
		t.Fatalf("regenerate: %v %+v", err, d)
	}
}
