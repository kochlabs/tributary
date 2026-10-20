// Package certs manages the appliance's HTTPS certificate (with hot reload,
// CSRs and self-signed generation) and the trusted CA store used for outbound
// TLS connections.
package certs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Manager owns <dir>/tls.crt and tls.key. The HTTPS server reads the
// certificate through GetCertificate, so replacements apply to the next
// connection without a restart.
type Manager struct {
	dir     string
	current atomic.Pointer[tls.Certificate]
	mu      sync.Mutex // serialises changes
}

func NewManager(dir string) *Manager { return &Manager{dir: dir} }

func (m *Manager) certPath() string       { return filepath.Join(m.dir, "tls.crt") }
func (m *Manager) keyPath() string        { return filepath.Join(m.dir, "tls.key") }
func (m *Manager) pendingKey() string     { return filepath.Join(m.dir, "tls.pending.key") }
func (m *Manager) pendingCSR() string     { return filepath.Join(m.dir, "tls.pending.csr") }
func (m *Manager) backup(p string) string { return p + ".previous" }

// Load reads the certificate, creating a self-signed one on first start.
// It returns true if a certificate was created.
func (m *Manager) Load() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	created := false
	if _, err := os.Stat(m.certPath()); errors.Is(err, os.ErrNotExist) {
		certPEM, keyPEM, err := SelfSigned(DefaultIdentity(), "ecdsa-p256", 825)
		if err != nil {
			return false, err
		}
		if err := m.write(certPEM, keyPEM); err != nil {
			return false, err
		}
		created = true
	}
	c, err := tls.LoadX509KeyPair(m.certPath(), m.keyPath())
	if err != nil {
		return false, err
	}
	m.current.Store(&c)
	return created, nil
}

func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := m.current.Load(); c != nil {
		return c, nil
	}
	return nil, errors.New("no certificate loaded")
}

// write installs a new pair, keeping the previous one as *.previous.
func (m *Manager) write(certPEM, keyPEM []byte) error {
	for _, p := range []string{m.certPath(), m.keyPath()} {
		if _, err := os.Stat(p); err == nil {
			if err := os.Rename(p, m.backup(p)); err != nil {
				return err
			}
		}
	}
	if err := writeFile(m.keyPath(), keyPEM, 0o600); err != nil {
		return err
	}
	return writeFile(m.certPath(), certPEM, 0o644)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// install validates and activates a certificate chain and key.
func (m *Manager) install(certPEM, keyPEM []byte) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("the certificate and private key do not match or cannot be read: %w", err)
	}
	if err := m.write(certPEM, keyPEM); err != nil {
		return err
	}
	m.current.Store(&pair)
	return nil
}

// ---- inspection ----

type Details struct {
	CommonName  string   `json:"commonName"`
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	SelfSigned  bool     `json:"selfSigned"`
	DNSNames    []string `json:"dnsNames"`
	IPAddresses []string `json:"ipAddresses"`
	NotBefore   int64    `json:"notBefore"`
	NotAfter    int64    `json:"notAfter"`
	DaysLeft    int      `json:"daysLeft"`
	Key         string   `json:"key"`
	Chain       int      `json:"chain"`
	Serial      string   `json:"serial"`
	SHA256      string   `json:"sha256"`
	IsCA        bool     `json:"isCa"`
}

func keyDescription(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return "unknown"
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func Describe(c *x509.Certificate, chain int) Details {
	d := Details{
		CommonName: c.Subject.CommonName, Subject: c.Subject.String(), Issuer: c.Issuer.String(),
		// CheckSignatureFrom would reject this: a self-signed server
		// certificate is not a CA. Verify the signature with its own key.
		SelfSigned: bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil,
		DNSNames:   c.DNSNames, NotBefore: c.NotBefore.UnixMilli(), NotAfter: c.NotAfter.UnixMilli(),
		DaysLeft: int(time.Until(c.NotAfter).Hours() / 24), Key: keyDescription(c.PublicKey), Chain: chain,
		Serial: strings.ToUpper(c.SerialNumber.Text(16)), SHA256: fingerprint(c.Raw), IsCA: c.IsCA,
	}
	if d.DNSNames == nil {
		d.DNSNames = []string{}
	}
	d.IPAddresses = []string{}
	for _, ip := range c.IPAddresses {
		d.IPAddresses = append(d.IPAddresses, ip.String())
	}
	return d
}

type Status struct {
	Certificate Details  `json:"certificate"`
	Pending     *CSRInfo `json:"pendingCsr,omitempty"`
	HasPrevious bool     `json:"hasPrevious"`
}

type CSRInfo struct {
	CommonName string   `json:"commonName"`
	DNSNames   []string `json:"dnsNames"`
	IPs        []string `json:"ipAddresses"`
	Key        string   `json:"key"`
	Created    int64    `json:"created"`
	PEM        string   `json:"pem"`
}

func (m *Manager) Status() (*Status, error) {
	c := m.current.Load()
	if c == nil || len(c.Certificate) == 0 {
		return nil, errors.New("no certificate loaded")
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, err
	}
	st := &Status{Certificate: Describe(leaf, len(c.Certificate))}
	if b, err := os.ReadFile(m.pendingCSR()); err == nil {
		if info, err := parseCSRInfo(b); err == nil {
			if fi, err := os.Stat(m.pendingCSR()); err == nil {
				info.Created = fi.ModTime().UnixMilli()
			}
			st.Pending = info
		}
	}
	_, err = os.Stat(m.backup(m.certPath()))
	st.HasPrevious = err == nil
	return st, nil
}

// CertificatePEM returns the active chain for download.
func (m *Manager) CertificatePEM() ([]byte, error) {
	return os.ReadFile(m.certPath())
}

// ---- parsing uploads ----

// ParseCertificates returns every CERTIFICATE block in PEM data.
func ParseCertificates(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unreadable certificate: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no PEM certificate found (expected -----BEGIN CERTIFICATE-----)")
	}
	return out, nil
}

func checkKeyStrength(pub any) error {
	if k, ok := pub.(*rsa.PublicKey); ok && k.N.BitLen() < 2048 {
		return fmt.Errorf("RSA keys must be at least 2048 bits (got %d)", k.N.BitLen())
	}
	return nil
}

// orderChain puts the leaf first and each issuer after its subject, so
// clients receive a chain they can follow.
func orderChain(certs []*x509.Certificate) []*x509.Certificate {
	if len(certs) < 2 {
		return certs
	}
	// The leaf is the certificate that issued nothing else in the set.
	isIssuer := map[int]bool{}
	for i, a := range certs {
		for j, b := range certs {
			if i != j && bytes.Equal(b.RawIssuer, a.RawSubject) {
				isIssuer[i] = true
			}
		}
	}
	leaf := 0
	for i := range certs {
		if !isIssuer[i] && !certs[i].IsCA {
			leaf = i
			break
		}
	}
	ordered := []*x509.Certificate{certs[leaf]}
	used := map[int]bool{leaf: true}
	for {
		last := ordered[len(ordered)-1]
		next := -1
		for i, c := range certs {
			if !used[i] && bytes.Equal(last.RawIssuer, c.RawSubject) {
				next = i
				break
			}
		}
		if next < 0 {
			break
		}
		used[next] = true
		ordered = append(ordered, certs[next])
	}
	for i, c := range certs { // keep anything unrelated at the end
		if !used[i] {
			ordered = append(ordered, c)
		}
	}
	return ordered
}

func encodeCerts(certs []*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return buf.Bytes()
}

// Upload installs a certificate (plus optional chain). keyPEM may be empty
// when the certificate answers the pending CSR, whose key is used.
func (m *Manager) Upload(certPEM, keyPEM []byte) (*Details, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	certs, err := ParseCertificates(certPEM)
	if err != nil {
		return nil, err
	}
	certs = orderChain(certs)
	leaf := certs[0]
	if time.Now().After(leaf.NotAfter) {
		return nil, fmt.Errorf("the certificate expired on %s", leaf.NotAfter.Format("2006-01-02"))
	}
	if leaf.IsCA {
		return nil, errors.New("this is a CA certificate; upload the server certificate issued for the appliance")
	}
	if err := checkKeyStrength(leaf.PublicKey); err != nil {
		return nil, err
	}
	usePending := len(bytes.TrimSpace(keyPEM)) == 0
	if usePending {
		if keyPEM, err = os.ReadFile(m.pendingKey()); err != nil {
			return nil, errors.New("no private key supplied and no CSR is pending; include the private key")
		}
	}
	if err := m.install(encodeCerts(certs), keyPEM); err != nil {
		if usePending {
			return nil, errors.New("this certificate was not issued for the pending CSR's key")
		}
		return nil, err
	}
	if usePending {
		_ = os.Remove(m.pendingKey())
		_ = os.Remove(m.pendingCSR())
	}
	d := Describe(leaf, len(certs))
	return &d, nil
}

// ---- generation ----

// Identity is the subject and names for a new certificate or CSR.
type Identity struct {
	CommonName   string   `json:"commonName"`
	Organization string   `json:"organization"`
	DNSNames     []string `json:"dnsNames"`
	IPAddresses  []string `json:"ipAddresses"`
}

// DefaultIdentity names this appliance the way clients reach it: the host
// name and its fully qualified name, the Tailscale MagicDNS name when the
// host is on a tailnet, and every address except link-local ones (which
// can't be used in URLs without a zone and don't belong in certificates).
func DefaultIdentity() Identity {
	host, _ := os.Hostname()
	id := Identity{Organization: "Tributary"}
	seenDNS := map[string]bool{}
	addDNS := func(n string) {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n != "" && !seenDNS[n] {
			seenDNS[n] = true
			id.DNSNames = append(id.DNSNames, n)
		}
	}
	seenIP := map[string]bool{}
	addIP := func(ip net.IP) {
		if ip == nil || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || seenIP[ip.String()] {
			return
		}
		seenIP[ip.String()] = true
		id.IPAddresses = append(id.IPAddresses, ip.String())
	}

	addDNS(host)
	fqdn := lookupFQDN(host)
	addDNS(fqdn)
	id.CommonName = commonName(host, fqdn)
	ts := tailscaleSelf()
	if ts.DNSName != "" {
		addDNS(ts.DNSName)
	}
	addDNS("localhost")
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				addIP(ipn.IP)
			}
		}
	}
	for _, s := range ts.IPs {
		addIP(net.ParseIP(s))
	}
	return id
}

// maxCommonName is the X.509 upper bound for a common name (RFC 5280).
const maxCommonName = 64

// commonName picks the certificate's common name: the fully qualified name
// when it fits, else the host name. Long names (cloud VMs often have FQDNs
// over 64 characters) still go in the DNS names, which have no such limit
// and are what clients check.
func commonName(host, fqdn string) string {
	for _, n := range []string{fqdn, host} {
		if n != "" && len(n) <= maxCommonName {
			return n
		}
	}
	return "tributary"
}

// lookupFQDN returns the fully qualified name of host using the resolver's
// search domains, like `hostname -f`, or "" if it has none.
func lookupFQDN(host string) string {
	if host == "" || strings.Contains(host, ".") {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cname, err := net.DefaultResolver.LookupCNAME(ctx, host)
	cname = strings.TrimSuffix(cname, ".")
	if err != nil || !strings.Contains(cname, ".") || !strings.HasPrefix(strings.ToLower(cname), strings.ToLower(host)+".") {
		return ""
	}
	return cname
}

type tailscaleInfo struct {
	DNSName string
	IPs     []string
}

// tailscaleSocket is tailscaled's local API, readable by unprivileged users.
var tailscaleSocket = "/var/run/tailscale/tailscaled.sock"

// tailscaleSelf asks the local tailscaled for this node's MagicDNS name and
// tailnet addresses. It returns nothing when Tailscale isn't running.
func tailscaleSelf() tailscaleInfo {
	if _, err := os.Stat(tailscaleSocket); err != nil {
		return tailscaleInfo{}
	}
	client := &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", tailscaleSocket)
		}},
	}
	req, _ := http.NewRequest(http.MethodGet, "http://local-tailscaled.sock/localapi/v0/status?peers=false", nil)
	resp, err := client.Do(req)
	if err != nil {
		return tailscaleInfo{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return tailscaleInfo{}
	}
	var st struct {
		Self struct {
			DNSName      string
			TailscaleIPs []string
		}
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st) != nil {
		return tailscaleInfo{}
	}
	return tailscaleInfo{DNSName: st.Self.DNSName, IPs: st.Self.TailscaleIPs}
}

func (id *Identity) validate() error {
	id.CommonName = strings.TrimSpace(id.CommonName)
	if id.CommonName == "" || len(id.CommonName) > maxCommonName {
		return errors.New("common name is required (up to 64 characters)")
	}
	var dns []string
	for _, d := range id.DNSNames {
		if d = strings.TrimSpace(d); d != "" {
			if len(d) > 253 || strings.ContainsAny(d, " /\\:") {
				return fmt.Errorf("invalid DNS name %q", d)
			}
			dns = append(dns, d)
		}
	}
	id.DNSNames = dns
	var ips []string
	for _, s := range id.IPAddresses {
		if s = strings.TrimSpace(s); s != "" {
			if net.ParseIP(s) == nil {
				return fmt.Errorf("invalid IP address %q", s)
			}
			ips = append(ips, s)
		}
	}
	id.IPAddresses = ips
	if len(id.DNSNames)+len(id.IPAddresses) == 0 {
		return errors.New("add at least one DNS name or IP address; browsers ignore the common name")
	}
	return nil
}

func newKey(kind string) (crypto.Signer, error) {
	switch kind {
	case "", "ecdsa-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	case "rsa-4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	return nil, fmt.Errorf("unknown key type %q", kind)
}

func encodeKey(k crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func (id Identity) subject() pkix.Name {
	n := pkix.Name{CommonName: id.CommonName}
	if id.Organization != "" {
		n.Organization = []string{id.Organization}
	}
	return n
}

func (id Identity) ips() []net.IP {
	var out []net.IP
	for _, s := range id.IPAddresses {
		out = append(out, net.ParseIP(s))
	}
	return out
}

// SelfSigned creates a certificate and key. Validity is capped at 825 days,
// the maximum browsers accept for server certificates.
func SelfSigned(id Identity, keyType string, days int) (certPEM, keyPEM []byte, err error) {
	if err := id.validate(); err != nil {
		return nil, nil, err
	}
	if days < 1 || days > 825 {
		return nil, nil, errors.New("validity must be between 1 and 825 days")
	}
	key, err := newKey(keyType)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: id.subject(),
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, days),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
		DNSNames: id.DNSNames, IPAddresses: id.ips(),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM, nil
}

// RegenerateSelfSigned replaces the active certificate with a new
// self-signed one.
func (m *Manager) RegenerateSelfSigned(id Identity, keyType string, days int) (*Details, error) {
	certPEM, keyPEM, err := SelfSigned(id, keyType, days)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.install(certPEM, keyPEM); err != nil {
		return nil, err
	}
	c, _ := ParseCertificates(certPEM)
	d := Describe(c[0], 1)
	return &d, nil
}

// GenerateCSR creates a new key (kept on the appliance) and a CSR for it.
// It replaces any previously pending CSR.
func (m *Manager) GenerateCSR(id Identity, keyType string) (*CSRInfo, error) {
	if err := id.validate(); err != nil {
		return nil, err
	}
	key, err := newKey(keyType)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: id.subject(), DNSNames: id.DNSNames, IPAddresses: id.ips(),
	}, key)
	if err != nil {
		return nil, err
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := writeFile(m.pendingKey(), keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFile(m.pendingCSR(), csrPEM, 0o644); err != nil {
		return nil, err
	}
	info, err := parseCSRInfo(csrPEM)
	if err != nil {
		return nil, err
	}
	info.Created = time.Now().UnixMilli()
	return info, nil
}

// DiscardCSR drops the pending CSR and its key.
func (m *Manager) DiscardCSR() {
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = os.Remove(m.pendingKey())
	_ = os.Remove(m.pendingCSR())
}

func parseCSRInfo(b []byte) (*CSRInfo, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("bad CSR")
	}
	r, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, err
	}
	info := &CSRInfo{CommonName: r.Subject.CommonName, DNSNames: r.DNSNames, Key: keyDescription(r.PublicKey), PEM: string(b), IPs: []string{}}
	if info.DNSNames == nil {
		info.DNSNames = []string{}
	}
	for _, ip := range r.IPAddresses {
		info.IPs = append(info.IPs, ip.String())
	}
	return info, nil
}

// Restore swaps back to the previous certificate.
func (m *Manager) Restore() (*Details, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	certPEM, err := os.ReadFile(m.backup(m.certPath()))
	if err != nil {
		return nil, errors.New("no previous certificate is available")
	}
	keyPEM, err := os.ReadFile(m.backup(m.keyPath()))
	if err != nil {
		return nil, errors.New("the previous certificate's key is missing")
	}
	if err := m.install(certPEM, keyPEM); err != nil {
		return nil, err
	}
	c, _ := ParseCertificates(certPEM)
	d := Describe(c[0], len(c))
	return &d, nil
}
