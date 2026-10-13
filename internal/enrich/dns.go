package enrich

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Tributary's own DNS lookups (reverse DNS, GeoIP downloads, RIPEstat) can use
// administrator-chosen resolvers instead of the system's. The OS resolver
// configuration is left untouched.
var dnsServers atomic.Pointer[[]string]

func init() {
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = dialDNS
}

// SetDNSServers sets resolvers as "ip" or "ip:port"; empty restores the
// system resolvers. Callers validate with ParseDNSServer first.
func SetDNSServers(servers []string) {
	var list []string
	for _, s := range servers {
		if hp, err := ParseDNSServer(s); err == nil {
			list = append(list, hp)
		}
	}
	dnsServers.Store(&list)
}

// ParseDNSServer normalises "192.0.2.53", "192.0.2.53:5353", "2001:db8::53"
// or "[2001:db8::53]:53" to host:port.
func ParseDNSServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.String(), nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.AddrPortFrom(a, 53).String(), nil
	}
	return "", errors.New("DNS server must be an IP address, optionally with :port")
}

func dialDNS(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	p := dnsServers.Load()
	if p == nil || len(*p) == 0 {
		return d.DialContext(ctx, network, address)
	}
	var lastErr error
	for _, srv := range *p {
		c, err := d.DialContext(ctx, network, srv)
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// SystemDNSServers lists the nameservers from /etc/resolv.conf.
func SystemDNSServers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fs := strings.Fields(sc.Text()); len(fs) >= 2 && fs[0] == "nameserver" {
			out = append(out, fs[1])
		}
	}
	return out
}
