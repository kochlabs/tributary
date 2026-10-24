// Package inventory reads devices, addresses, services and prefixes from an
// inventory (a CMDB or source of truth such as NetBox), read-only, so names
// and context are maintained in one place. See docs/design/INVENTORY.md.
package inventory

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Object is a device or virtual machine.
type Object struct {
	Source string   `json:"source"` // the inventory source's name
	Kind   string   `json:"kind"`   // device | vm
	ID     int64    `json:"id"`
	Name   string   `json:"name"`
	Role   string   `json:"role,omitempty"`
	Site   string   `json:"site,omitempty"`
	Tenant string   `json:"tenant,omitempty"`
	Status string   `json:"status,omitempty"`
	URL    string   `json:"url,omitempty"` // the object in the inventory's UI
	Tags   []string `json:"tags,omitempty"`
}

// Key identifies an object within one source.
func (o Object) Key() string { return o.Kind + ":" + strconv.FormatInt(o.ID, 10) }

// Addr is an IP address assigned to an object.
type Addr struct {
	IP      string `json:"ip"`
	Object  string `json:"object"` // Object.Key
	DNSName string `json:"dnsName,omitempty"`
}

// MAC is a MAC address assigned to an object (lower-case, colon-separated).
type MAC struct {
	MAC    string `json:"mac"`
	Object string `json:"object"`
}

// Service is a documented service on an object.
type Service struct {
	Object      string `json:"object"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"` // tcp | udp | sctp
	Ports       []int  `json:"ports"`
	Description string `json:"description,omitempty"`
}

// Prefix is an IP prefix and its tags.
type Prefix struct {
	Prefix      string   `json:"prefix"`
	Tags        []string `json:"tags,omitempty"`
	Description string   `json:"description,omitempty"`
}

// Snapshot is everything one source holds, as of one sync.
type Snapshot struct {
	Objects  []Object  `json:"objects"`
	Addrs    []Addr    `json:"addrs"`
	MACs     []MAC     `json:"macs"`
	Services []Service `json:"services"`
	Prefixes []Prefix  `json:"prefixes"`
}

// Counts summarises a snapshot.
type Counts struct {
	Objects  int `json:"objects"`
	Addrs    int `json:"addrs"`
	MACs     int `json:"macs"`
	Services int `json:"services"`
	Prefixes int `json:"prefixes"`
}

func (s *Snapshot) Counts() Counts {
	return Counts{len(s.Objects), len(s.Addrs), len(s.MACs), len(s.Services), len(s.Prefixes)}
}

// Source is an inventory backend. Sync returns a complete snapshot.
type Source interface {
	Sync(ctx context.Context) (*Snapshot, error)
}

// Record is what the inventory says about one address or device.
type Record struct {
	Object
	Services []Service `json:"services,omitempty"`
}

// Index answers lookups across sources' snapshots; earlier snapshots (higher
// priority) win. It is immutable once built.
type Index struct {
	byMAC    map[string]*Record
	byIP     map[netip.Addr]*Record
	byName   map[string]*Record
	dnsName  map[netip.Addr]string
	prefixes []Prefix
}

// NewIndex builds an index from snapshots in priority order, each labelled
// with its source's name.
func NewIndex(snaps []*Snapshot, names []string) *Index {
	x := &Index{byMAC: map[string]*Record{}, byIP: map[netip.Addr]*Record{}, byName: map[string]*Record{}, dnsName: map[netip.Addr]string{}}
	for i, s := range snaps {
		if s == nil {
			continue
		}
		recs := map[string]*Record{}
		for _, o := range s.Objects {
			o.Source = names[i]
			recs[o.Key()] = &Record{Object: o}
		}
		for _, sv := range s.Services {
			if r := recs[sv.Object]; r != nil {
				r.Services = append(r.Services, sv)
			}
		}
		for _, m := range s.MACs {
			mac := strings.ToLower(m.MAC)
			if r := recs[m.Object]; r != nil && x.byMAC[mac] == nil {
				x.byMAC[mac] = r
			}
		}
		for _, a := range s.Addrs {
			ip, err := netip.ParseAddr(a.IP)
			if err != nil {
				continue
			}
			ip = ip.Unmap()
			if r := recs[a.Object]; r != nil && x.byIP[ip] == nil {
				x.byIP[ip] = r
			}
			if a.DNSName != "" && x.dnsName[ip] == "" {
				x.dnsName[ip] = a.DNSName
			}
		}
		for _, r := range recs {
			if k := strings.ToLower(r.Name); k != "" && x.byName[k] == nil {
				x.byName[k] = r
			}
		}
		x.prefixes = append(x.prefixes, s.Prefixes...)
	}
	return x
}

// ByMAC finds the object a MAC is assigned to ("aa:bb:..", any case).
func (x *Index) ByMAC(mac string) *Record {
	if x == nil {
		return nil
	}
	return x.byMAC[strings.ToLower(mac)]
}

// ByIP finds the object an address is assigned to.
func (x *Index) ByIP(ip netip.Addr) *Record {
	if x == nil {
		return nil
	}
	return x.byIP[ip.Unmap()]
}

// ByName finds an object by name, or by the name in a DNS name ("host.lan").
func (x *Index) ByName(name string) *Record {
	if x == nil || name == "" {
		return nil
	}
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if r := x.byName[n]; r != nil {
		return r
	}
	short, _, _ := strings.Cut(n, ".")
	return x.byName[short]
}

// Name is the inventory's name for an address: its object's name, else the
// address's DNS name.
func (x *Index) Name(ip netip.Addr) string {
	if r := x.ByIP(ip); r != nil && r.Name != "" {
		return r.Name
	}
	if x == nil {
		return ""
	}
	return x.dnsName[ip.Unmap()]
}

// ServiceName is the documented service on an address's object for a
// protocol ("tcp") and port, or "".
func (x *Index) ServiceName(ip netip.Addr, proto string, port int) string {
	r := x.ByIP(ip)
	if r == nil {
		return ""
	}
	for _, s := range r.Services {
		if strings.EqualFold(s.Protocol, proto) && slices.Contains(s.Ports, port) {
			return s.Name
		}
	}
	return ""
}

// TaggedPrefixes lists the prefixes carrying tag (by name or slug).
func (x *Index) TaggedPrefixes(tag string) []netip.Prefix {
	if x == nil || tag == "" {
		return nil
	}
	var out []netip.Prefix
	for _, p := range x.prefixes {
		if !slices.ContainsFunc(p.Tags, func(t string) bool { return strings.EqualFold(t, tag) }) {
			continue
		}
		if pp, err := netip.ParsePrefix(p.Prefix); err == nil && !slices.Contains(out, pp.Masked()) {
			out = append(out, pp.Masked())
		}
	}
	return out
}
