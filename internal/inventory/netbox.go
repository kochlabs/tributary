package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// NetBox reads a NetBox 4.2+ instance through its REST API.
type NetBox struct {
	URL    string // e.g. https://netbox.example.com
	Token  string // read-only API token: "nbt_<key>.<token>" (v2) or a v1 key
	Site   string // optional scope, by slug
	Tenant string
	Tag    string
	Client func() *http.Client
	Agent  string
}

const maxNetBoxObjects = 200000

// errToken is a refused token: reported as is, without the API path.
var errToken = errors.New("NetBox refused the token: check it, and that it can read")

// nbRef is a nested object reference ({"id", "name", "slug"}).
type nbRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type nbChoice struct {
	Value string `json:"value"`
}

type nbObject struct {
	ID         int64    `json:"id"`
	Name       string   `json:"name"`
	DisplayURL string   `json:"display_url"`
	Role       *nbRef   `json:"role"`
	Site       *nbRef   `json:"site"`
	Tenant     *nbRef   `json:"tenant"`
	Status     nbChoice `json:"status"`
	Tags       []nbRef  `json:"tags"`
}

// nbAssigned is an interface an address or MAC is assigned to.
type nbAssigned struct {
	Device         *nbRef `json:"device"`
	VirtualMachine *nbRef `json:"virtual_machine"`
}

func (a *nbAssigned) key() string {
	switch {
	case a == nil:
		return ""
	case a.Device != nil:
		return "device:" + strconv.FormatInt(a.Device.ID, 10)
	case a.VirtualMachine != nil:
		return "vm:" + strconv.FormatInt(a.VirtualMachine.ID, 10)
	}
	return ""
}

func slugs(tags []nbRef) []string {
	var out []string
	for _, t := range tags {
		out = append(out, t.Slug)
	}
	return out
}

// Sync reads devices, VMs, MACs, addresses, services and prefixes. Objects
// are limited to the scope (site, tenant, tag); the rest are kept when they
// belong to an object in scope (prefixes: when they match the scope).
func (n *NetBox) Sync(ctx context.Context) (*Snapshot, error) {
	scope := url.Values{}
	if n.Site != "" {
		scope.Set("site", n.Site)
	}
	if n.Tenant != "" {
		scope.Set("tenant", n.Tenant)
	}
	if n.Tag != "" {
		scope.Set("tag", n.Tag)
	}
	snap := &Snapshot{}
	inScope := map[string]bool{}
	for _, k := range []struct{ path, kind string }{{"dcim/devices/", "device"}, {"virtualization/virtual-machines/", "vm"}} {
		err := each(ctx, n, k.path, scope, func(raw json.RawMessage) error {
			var o nbObject
			if err := json.Unmarshal(raw, &o); err != nil {
				return err
			}
			obj := Object{Kind: k.kind, ID: o.ID, Name: o.Name, URL: o.DisplayURL, Status: o.Status.Value, Tags: slugs(o.Tags)}
			if o.Role != nil {
				obj.Role = o.Role.Name
			}
			if o.Site != nil {
				obj.Site = o.Site.Name
			}
			if o.Tenant != nil {
				obj.Tenant = o.Tenant.Name
			}
			snap.Objects = append(snap.Objects, obj)
			inScope[obj.Key()] = true
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	err := each(ctx, n, "dcim/mac-addresses/", nil, func(raw json.RawMessage) error {
		var m struct {
			MAC      string      `json:"mac_address"`
			Assigned *nbAssigned `json:"assigned_object"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		if k := m.Assigned.key(); inScope[k] {
			snap.MACs = append(snap.MACs, MAC{MAC: strings.ToLower(m.MAC), Object: k})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = each(ctx, n, "ipam/ip-addresses/", nil, func(raw json.RawMessage) error {
		var a struct {
			Address  string      `json:"address"`
			DNSName  string      `json:"dns_name"`
			Assigned *nbAssigned `json:"assigned_object"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		ip, _, _ := strings.Cut(a.Address, "/")
		if k := a.Assigned.key(); inScope[k] {
			snap.Addrs = append(snap.Addrs, Addr{IP: ip, Object: k, DNSName: a.DNSName})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = each(ctx, n, "ipam/services/", nil, func(raw json.RawMessage) error {
		var s struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Protocol    nbChoice `json:"protocol"`
			Ports       []int    `json:"ports"`
			ParentType  string   `json:"parent_object_type"`
			ParentID    int64    `json:"parent_object_id"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		kind := map[string]string{"dcim.device": "device", "virtualization.virtualmachine": "vm"}[s.ParentType]
		if k := kind + ":" + strconv.FormatInt(s.ParentID, 10); kind != "" && inScope[k] {
			snap.Services = append(snap.Services, Service{Object: k, Name: s.Name, Protocol: s.Protocol.Value, Ports: s.Ports, Description: s.Description})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	pscope := url.Values{}
	if n.Tenant != "" {
		pscope.Set("tenant", n.Tenant)
	}
	err = each(ctx, n, "ipam/prefixes/", pscope, func(raw json.RawMessage) error {
		var p struct {
			Prefix      string  `json:"prefix"`
			Description string  `json:"description"`
			Tags        []nbRef `json:"tags"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
		snap.Prefixes = append(snap.Prefixes, Prefix{Prefix: p.Prefix, Tags: slugs(p.Tags), Description: p.Description})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return snap, nil
}

// TokenWritable reports whether the configured token can write: NetBox lists
// a token's own record (matched by its key) to it, read-only tokens included.
func (n *NetBox) TokenWritable(ctx context.Context) (bool, error) {
	writable := false
	key := n.Token
	if strings.HasPrefix(key, "nbt_") {
		key, _, _ = strings.Cut(strings.TrimPrefix(key, "nbt_"), ".")
	}
	err := each(ctx, n, "users/tokens/", nil, func(raw json.RawMessage) error {
		var t struct {
			Key          string `json:"key"`
			WriteEnabled bool   `json:"write_enabled"`
		}
		if err := json.Unmarshal(raw, &t); err != nil {
			return err
		}
		if t.Key != "" && (t.Key == key || t.Key == n.Token) {
			writable = t.WriteEnabled
		}
		return nil
	})
	return writable, err
}

// each pages through a list endpoint, calling fn for every result.
func each(ctx context.Context, n *NetBox, path string, q url.Values, fn func(json.RawMessage) error) error {
	if q == nil {
		q = url.Values{}
	}
	q.Set("limit", "1000")
	next := strings.TrimRight(n.URL, "/") + "/api/" + path + "?" + q.Encode()
	seen := 0
	for next != "" {
		var page struct {
			Next    *string           `json:"next"`
			Results []json.RawMessage `json:"results"`
		}
		if err := n.get(ctx, next, &page); err != nil {
			if errors.Is(err, errToken) {
				return err
			}
			return fmt.Errorf("%s: %w", path, err)
		}
		for _, r := range page.Results {
			if err := fn(r); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		}
		seen += len(page.Results)
		if seen > maxNetBoxObjects {
			return fmt.Errorf("%s: more than %d objects; narrow the scope", path, maxNetBoxObjects)
		}
		next = ""
		if page.Next != nil {
			next = *page.Next
		}
	}
	return nil
}

func (n *NetBox) get(ctx context.Context, u string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	auth := "Token " + n.Token
	if strings.HasPrefix(n.Token, "nbt_") {
		auth = "Bearer " + n.Token
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", n.Agent)
	resp, err := n.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return errToken
	case resp.StatusCode != http.StatusOK:
		msg := strings.TrimSpace(string(body))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("NetBox replied %s: %s", resp.Status, msg)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("not a NetBox API response (check the URL): %w", err)
	}
	return nil
}
