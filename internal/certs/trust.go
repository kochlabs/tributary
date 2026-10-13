package certs

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"sync/atomic"
	"time"
)

// TrustStore holds the system roots plus administrator-added CAs. Outbound
// TLS (identity providers, later LDAPS) verifies servers against it using
// Go's standard verification.
type TrustStore struct {
	pool   atomic.Pointer[x509.CertPool]
	client atomic.Pointer[http.Client]
}

func NewTrustStore() *TrustStore {
	t := &TrustStore{}
	t.Set(nil)
	return t
}

// Set replaces the added CAs (the system roots are always included) and
// rebuilds the HTTP client so new connections use them.
func (t *TrustStore) Set(cas []*x509.Certificate) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, c := range cas {
		pool.AddCert(c)
	}
	t.pool.Store(pool)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	t.client.Store(&http.Client{Transport: tr, Timeout: 30 * time.Second})
}

func (t *TrustStore) Pool() *x509.CertPool { return t.pool.Load() }

// Client returns the HTTP client for the current trust settings.
func (t *TrustStore) Client() *http.Client { return t.client.Load() }
