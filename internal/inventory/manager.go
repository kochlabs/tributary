package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/kochlabs/tributary/internal/config"
)

// Manager keeps enabled sources synced and the index current. Lookups use
// cached snapshots only; they never wait on an inventory.
type Manager struct {
	Cfg    *config.DB
	Log    *slog.Logger
	Client func() *http.Client
	Agent  string
	// OnChange runs after the index changes (e.g. to update local networks).
	OnChange func()

	cur  atomic.Pointer[Index]
	kick chan int64
}

func (m *Manager) init() {
	if m.kick == nil {
		m.kick = make(chan int64, 16)
	}
}

// Index is the current index (nil-safe to query).
func (m *Manager) Index() *Index {
	if m == nil {
		return nil
	}
	return m.cur.Load()
}

// LocalPrefixes are the prefixes enabled sources mark as local (by their
// local tag), for the local networks.
func (m *Manager) LocalPrefixes() []netip.Prefix {
	if m == nil {
		return nil
	}
	list, err := m.Cfg.InventorySources()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, s := range list {
		if s.Enabled && s.LocalTag != "" {
			for _, p := range m.Index().TaggedPrefixes(s.LocalTag) {
				if !slices.Contains(out, p) {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// Backend returns the client for a source (with its token).
func (m *Manager) Backend(s config.InventorySource) *NetBox {
	return &NetBox{URL: s.URL, Token: s.Token, Site: s.ScopeSite, Tenant: s.ScopeTenant, Tag: s.ScopeTag, Client: m.Client, Agent: m.Agent}
}

// Reload rebuilds the index from the enabled sources' cached snapshots.
func (m *Manager) Reload() error {
	if m == nil {
		return nil
	}
	list, err := m.Cfg.InventorySources()
	if err != nil {
		return err
	}
	var snaps []*Snapshot
	var names []string
	for _, s := range list {
		if !s.Enabled {
			continue
		}
		data, err := m.Cfg.InventorySnapshot(s.ID)
		if err != nil || data == "" {
			continue
		}
		var snap Snapshot
		if err := json.Unmarshal([]byte(data), &snap); err != nil {
			m.Log.Warn("inventory: unreadable snapshot", "source", s.Name, "err", err)
			continue
		}
		snaps, names = append(snaps, &snap), append(names, s.Name)
	}
	m.cur.Store(NewIndex(snaps, names))
	if m.OnChange != nil {
		m.OnChange()
	}
	return nil
}

// SyncSoon asks for a source to be synced now (0 = every enabled source).
func (m *Manager) SyncSoon(id int64) {
	if m == nil {
		return
	}
	m.init()
	select {
	case m.kick <- id:
	default:
	}
}

// Run syncs sources when due until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.init()
	if err := m.Reload(); err != nil {
		m.Log.Warn("inventory: loading", "err", err)
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	m.syncDue(ctx, 0, false)
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-m.kick:
			m.syncDue(ctx, id, true)
		case <-t.C:
			m.syncDue(ctx, 0, false)
		}
	}
}

func (m *Manager) syncDue(ctx context.Context, id int64, force bool) {
	list, err := m.Cfg.InventorySourcesSecrets()
	if err != nil {
		m.Log.Warn("inventory: reading sources", "err", err)
		return
	}
	changed := false
	for _, s := range list {
		if !s.Enabled || (id != 0 && s.ID != id) {
			continue
		}
		due := time.Since(time.UnixMilli(s.LastAttempt)) >= time.Duration(s.IntervalMin)*time.Minute
		if !force && !due {
			continue
		}
		snap, err := m.Backend(s).Sync(ctx)
		var data, counts []byte
		if err == nil {
			data, _ = json.Marshal(snap)
			counts, _ = json.Marshal(snap.Counts())
		}
		if serr := m.Cfg.SaveInventorySync(s.ID, time.Now(), string(data), string(counts), err); serr != nil {
			m.Log.Warn("inventory: saving sync", "source", s.Name, "err", serr)
		}
		if err != nil {
			m.Log.Warn("inventory sync failed", "source", s.Name, "err", err)
			continue
		}
		m.Log.Info("inventory synced", "source", s.Name, "objects", len(snap.Objects), "addresses", len(snap.Addrs))
		changed = true
	}
	if changed {
		_ = m.Reload()
	}
}

// TestResult is what a test sync found, for the source form.
type TestResult struct {
	Counts   Counts   `json:"counts"`
	Sample   []string `json:"sample"`            // a few object names
	Writable bool     `json:"writable"`          // the token can write: warn
	Warning  string   `json:"warning,omitempty"` // e.g. no MACs (NetBox < 4.2)
}

// Test syncs a source without keeping the result.
func (m *Manager) Test(ctx context.Context, s config.InventorySource) (TestResult, error) {
	if m == nil {
		return TestResult{}, errors.New("inventory sources are not available")
	}
	nb := m.Backend(s)
	snap, err := nb.Sync(ctx)
	if err != nil {
		return TestResult{}, err
	}
	res := TestResult{Counts: snap.Counts()}
	for _, o := range snap.Objects {
		if len(res.Sample) == 5 {
			break
		}
		res.Sample = append(res.Sample, o.Name)
	}
	if w, err := nb.TokenWritable(ctx); err == nil {
		res.Writable = w
	}
	if len(snap.Objects) > 0 && len(snap.MACs) == 0 {
		res.Warning = "no MAC addresses found: devices match by IP only (MAC addresses are objects from NetBox 4.2)"
	}
	if len(snap.Objects) == 0 {
		res.Warning = fmt.Sprintf("no devices found%s", map[bool]string{true: " in the scope", false: ""}[s.ScopeSite+s.ScopeTenant+s.ScopeTag != ""])
	}
	return res, nil
}
