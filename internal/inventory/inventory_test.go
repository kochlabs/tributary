package inventory

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kochlabs/tributary/internal/config"
)

// fakeNetBox serves a small inventory, two results per page, and records
// the Authorization header it saw.
func fakeNetBox(t *testing.T, auth *string) *httptest.Server {
	data := map[string][]any{
		"dcim/devices/": {
			map[string]any{"id": 1, "name": "Fozzie", "display_url": "https://nb/dcim/devices/1/", "role": map[string]any{"name": "Media server"},
				"site": map[string]any{"name": "Home"}, "status": map[string]any{"value": "active"}, "tags": []any{map[string]any{"slug": "home"}}},
			map[string]any{"id": 2, "name": "UXG-Fiber", "role": map[string]any{"name": "Gateway"}, "status": map[string]any{"value": "active"}},
			map[string]any{"id": 3, "name": "Statler", "status": map[string]any{"value": "active"}},
		},
		"virtualization/virtual-machines/": {
			map[string]any{"id": 7, "name": "kl-svc-netflow-1", "status": map[string]any{"value": "active"}},
		},
		"dcim/mac-addresses/": {
			map[string]any{"mac_address": "00:8A:76:EC:3A:B4", "assigned_object": map[string]any{"device": map[string]any{"id": 1}}},
			map[string]any{"mac_address": "BC:24:11:6C:15:34", "assigned_object": map[string]any{"virtual_machine": map[string]any{"id": 7}}},
			map[string]any{"mac_address": "00:00:00:00:00:99", "assigned_object": map[string]any{"device": map[string]any{"id": 99}}}, // out of scope
		},
		"ipam/ip-addresses/": {
			map[string]any{"address": "192.168.80.51/24", "dns_name": "fozzie.lan", "assigned_object": map[string]any{"device": map[string]any{"id": 1}}},
			map[string]any{"address": "192.168.20.1/24", "assigned_object": map[string]any{"device": map[string]any{"id": 2}}},
			map[string]any{"address": "192.168.20.230/24", "assigned_object": map[string]any{"virtual_machine": map[string]any{"id": 7}}},
			map[string]any{"address": "192.168.80.9/24", "dns_name": "printer.lan", "assigned_object": nil},
		},
		"ipam/services/": {
			map[string]any{"name": "Plex", "protocol": map[string]any{"value": "tcp"}, "ports": []int{32400}, "parent_object_type": "dcim.device", "parent_object_id": 1},
		},
		"ipam/prefixes/": {
			map[string]any{"prefix": "2603:7083:8640:9600::/56", "tags": []any{map[string]any{"slug": "tributary-local"}}},
			map[string]any{"prefix": "192.168.80.0/24"},
		},
		"users/tokens/": {
			map[string]any{"key": "abc123", "write_enabled": false},
			map[string]any{"key": "other", "write_enabled": true},
		},
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*auth = r.Header.Get("Authorization")
		path := strings.TrimPrefix(r.URL.Path, "/api/")
		items, ok := data[path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if path == "dcim/devices/" && r.URL.Query().Get("site") == "elsewhere" {
			items = nil
		}
		offset := 0
		if o := r.URL.Query().Get("offset"); o != "" {
			json.Unmarshal([]byte(o), &offset)
		}
		end := min(offset+2, len(items))
		page := map[string]any{"count": len(items), "results": items[offset:end], "next": nil}
		if end < len(items) {
			page["next"] = srv.URL + r.URL.Path + "?limit=2&offset=" + itoa(end)
		}
		json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestNetBoxSyncAndIndex(t *testing.T) {
	var auth string
	srv := fakeNetBox(t, &auth)
	nb := &NetBox{URL: srv.URL, Token: "nbt_abc123.secret", Client: srv.Client, Agent: "test"}
	snap, err := nb.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer nbt_abc123.secret" {
		t.Fatalf("v2 token sent as %q", auth)
	}
	if c := snap.Counts(); c.Objects != 4 || c.MACs != 2 || c.Addrs != 3 || c.Services != 1 || c.Prefixes != 2 {
		t.Fatalf("counts %+v (unassigned addresses and out-of-scope MACs are dropped)", c)
	}
	x := NewIndex([]*Snapshot{snap}, []string{"NetBox"})
	if r := x.ByMAC("00:8a:76:ec:3a:b4"); r == nil || r.Name != "Fozzie" || r.Role != "Media server" || r.Source != "NetBox" || r.URL == "" {
		t.Fatalf("by MAC: %+v", r)
	}
	if r := x.ByIP(netip.MustParseAddr("::ffff:192.168.20.230")); r == nil || r.Name != "kl-svc-netflow-1" || r.Kind != "vm" {
		t.Fatalf("by IP: %+v", r)
	}
	if x.Name(netip.MustParseAddr("192.168.80.51")) != "Fozzie" || x.ByName("fozzie.lan") == nil {
		t.Fatal("names")
	}
	if got := x.ServiceName(netip.MustParseAddr("192.168.80.51"), "TCP", 32400); got != "Plex" {
		t.Fatalf("service: %q", got)
	}
	if x.ServiceName(netip.MustParseAddr("192.168.80.51"), "udp", 32400) != "" {
		t.Fatal("service matched the wrong protocol")
	}
	if p := x.TaggedPrefixes("tributary-local"); len(p) != 1 || p[0].String() != "2603:7083:8640:9600::/56" {
		t.Fatalf("tagged prefixes: %v", p)
	}
	if w, err := nb.TokenWritable(context.Background()); err != nil || w {
		t.Fatalf("writable: %v %v", w, err)
	}
	// v1 tokens use the Token scheme; an empty scope result is fine.
	nb1 := &NetBox{URL: srv.URL, Token: "0123abcd", Site: "elsewhere", Client: srv.Client}
	snap1, err := nb1.Sync(context.Background())
	if err != nil || auth != "Token 0123abcd" || len(snap1.Objects) != 1 {
		t.Fatalf("v1 / scope: %q %d %v", auth, len(snap1.Objects), err)
	}
	// Higher-priority sources win.
	other := &Snapshot{Objects: []Object{{Kind: "device", ID: 1, Name: "Not Fozzie"}}, Addrs: []Addr{{IP: "192.168.80.51", Object: "device:1"}}}
	if NewIndex([]*Snapshot{other, snap}, []string{"A", "B"}).Name(netip.MustParseAddr("192.168.80.51")) != "Not Fozzie" {
		t.Fatal("priority")
	}
	var nilIndex *Index
	if nilIndex.ByIP(netip.MustParseAddr("1.2.3.4")) != nil || nilIndex.Name(netip.MustParseAddr("1.2.3.4")) != "" {
		t.Fatal("nil index")
	}
}

func TestManager(t *testing.T) {
	var auth string
	srv := fakeNetBox(t, &auth)
	cfg, err := config.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	if _, err := cfg.SaveInventorySource(config.InventorySource{Name: "NetBox", URL: srv.URL}); err == nil {
		t.Fatal("saved without a token")
	}
	src, err := cfg.SaveInventorySource(config.InventorySource{Name: "NetBox", URL: srv.URL + "/", Token: "nbt_abc123.secret", Enabled: true, LocalTag: "tributary-local"})
	if err != nil || !src.HasToken || src.Token != "" || src.URL != srv.URL {
		t.Fatalf("save: %+v %v", src, err)
	}
	changed := 0
	m := &Manager{Cfg: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Client: srv.Client, Agent: "test", OnChange: func() { changed++ }}
	m.init()
	res, err := m.Test(context.Background(), config.InventorySource{URL: srv.URL, Token: "nbt_abc123.secret"})
	if err != nil || res.Counts.Objects != 4 || res.Writable || len(res.Sample) != 4 {
		t.Fatalf("test: %+v %v", res, err)
	}
	m.syncDue(context.Background(), 0, true)
	if m.Index().Name(netip.MustParseAddr("192.168.80.51")) != "Fozzie" || changed == 0 {
		t.Fatal("not synced")
	}
	got, _ := cfg.InventorySource(src.ID)
	if got.LastSuccess == 0 || !strings.Contains(got.Counts, `"objects":4`) {
		t.Fatalf("status: %+v", got)
	}
	// The snapshot survives a restart, without contacting NetBox.
	m2 := &Manager{Cfg: cfg, Log: m.Log, Client: func() *http.Client { t.Fatal("contacted NetBox"); return nil }}
	if err := m2.Reload(); err != nil || m2.Index().Name(netip.MustParseAddr("192.168.80.51")) != "Fozzie" {
		t.Fatal("cached snapshot not used")
	}
	// Disabled sources drop out of the index.
	src.Enabled = false
	cfg.SaveInventorySource(src)
	m2.Reload()
	if m2.Index().Name(netip.MustParseAddr("192.168.80.51")) != "" {
		t.Fatal("disabled source still used")
	}
	// A failed sync keeps the last snapshot and records the error.
	src.Enabled, src.URL = true, srv.URL+"/missing"
	src.Token = "nbt_abc123.secret"
	cfg.SaveInventorySource(src)
	m.syncDue(context.Background(), 0, true)
	got, _ = cfg.InventorySource(src.ID)
	if got.LastError == "" {
		t.Fatal("no error recorded")
	}
}
