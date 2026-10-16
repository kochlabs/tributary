package certs

import "testing"

// Prints what this host would put in a new certificate (run with -v).
func TestDefaultIdentityHost(t *testing.T) {
	id := DefaultIdentity()
	t.Logf("CN=%s DNS=%v IP=%v", id.CommonName, id.DNSNames, id.IPAddresses)
	for _, ip := range id.IPAddresses {
		if len(ip) > 4 && ip[:4] == "fe80" {
			t.Errorf("link-local address included: %s", ip)
		}
	}
	if err := id.validate(); err != nil {
		t.Fatal(err)
	}
}
