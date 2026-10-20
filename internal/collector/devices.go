package collector

import (
	"net/netip"
	"sync"
	"time"

	"github.com/kochlabs/tributary/internal/flow"
)

// DeviceTracker identifies the local device behind each flow by MAC address.
//
// Routers typically report MACs as seen on the receiving interface, so only
// flows *from* a local address carry the device's own MAC (downloads carry
// the upstream router's). The tracker learns IP→MAC from those flows and
// attributes flows *to* a local address through the learned table, which also
// groups a device's rotating IPv6 privacy addresses under one MAC.
type DeviceTracker struct {
	isLocal func(netip.Addr) bool

	mu      sync.RWMutex
	byIP    map[netip.Addr]IPBinding
	v4ByMAC map[uint64]map[netip.Addr]int64 // to spot routers
	dirty   map[netip.Addr]bool
}

// IPBinding records which MAC last used an address, and when (unix ms).
type IPBinding struct {
	MAC  uint64
	Seen int64
}

const (
	bindingTTL        = 7 * 24 * time.Hour // ignore stale bindings
	rewriteInterval   = time.Minute        // persist a binding at most this often
	routerThresholdV4 = 16                 // IPv4 sources behind one MAC = a router
)

func NewDeviceTracker(isLocal func(netip.Addr) bool, saved map[netip.Addr]IPBinding) *DeviceTracker {
	t := &DeviceTracker{isLocal: isLocal, byIP: map[netip.Addr]IPBinding{}, v4ByMAC: map[uint64]map[netip.Addr]int64{}, dirty: map[netip.Addr]bool{}}
	for ip, b := range saved {
		t.byIP[ip] = b
		t.noteV4(ip, b)
	}
	return t
}

// usable rejects unknown, broadcast and multicast addresses.
func usable(mac uint64) bool {
	return mac != 0 && mac != 0xffffffffffff && mac&(0x01<<40) == 0
}

func (t *DeviceTracker) noteV4(ip netip.Addr, b IPBinding) {
	if !ip.Is4() {
		return
	}
	m := t.v4ByMAC[b.MAC]
	if m == nil {
		m = map[netip.Addr]int64{}
		t.v4ByMAC[b.MAC] = m
	}
	m[ip] = b.Seen
}

// isRouter reports whether many IPv4 addresses recently came from one MAC,
// i.e. it is a router forwarding another subnet rather than an end device.
func (t *DeviceTracker) isRouter(mac uint64, now int64) bool {
	n := 0
	for _, seen := range t.v4ByMAC[mac] {
		if now-seen < int64(24*time.Hour/time.Millisecond) {
			n++
		}
	}
	return n > routerThresholdV4
}

// Assign sets r.DeviceMAC and learns from the flow.
func (t *DeviceTracker) Assign(r *flow.Record) {
	now := r.TimeReceived.UnixMilli()
	src := r.SrcAddr.Unmap()
	if usable(r.SrcMAC) && t.isLocal(src) {
		t.mu.Lock()
		b, ok := t.byIP[src]
		if !ok || b.MAC != r.SrcMAC || now-b.Seen > int64(rewriteInterval/time.Millisecond) {
			nb := IPBinding{MAC: r.SrcMAC, Seen: now}
			t.byIP[src] = nb
			t.noteV4(src, nb)
			t.dirty[src] = true
		}
		router := t.isRouter(r.SrcMAC, now)
		t.mu.Unlock()
		if !router {
			r.DeviceMAC = r.SrcMAC
		}
		return
	}
	dst := r.DstAddr.Unmap()
	if !t.isLocal(dst) {
		return
	}
	t.mu.RLock()
	b, ok := t.byIP[dst]
	router := ok && t.isRouter(b.MAC, now)
	t.mu.RUnlock()
	if ok && !router && now-b.Seen < int64(bindingTTL/time.Millisecond) {
		r.DeviceMAC = b.MAC
	}
}

// Dirty returns and clears bindings changed since the last call, for
// persistence.
func (t *DeviceTracker) Dirty() map[netip.Addr]IPBinding {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[netip.Addr]IPBinding, len(t.dirty))
	for ip := range t.dirty {
		out[ip] = t.byIP[ip]
	}
	clear(t.dirty)
	return out
}

// Bindings returns a snapshot of all current IP→MAC bindings.
func (t *DeviceTracker) Bindings() map[netip.Addr]IPBinding {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[netip.Addr]IPBinding, len(t.byIP))
	for ip, b := range t.byIP {
		out[ip] = b
	}
	return out
}
