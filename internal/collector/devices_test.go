package collector

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/kochlabs/tributary/internal/flow"
)

func local(a netip.Addr) bool {
	return a.IsPrivate() || netip.MustParsePrefix("2603:7083:8640:9600::/56").Contains(a)
}

const (
	laptop  = 0x24e50fd8b387
	ispMAC  = 0x0a0000000143
	gateway = 0x942a6ff84d6d
)

func rec(src, dst string, srcMAC uint64, at time.Time) *flow.Record {
	return &flow.Record{SrcAddr: netip.MustParseAddr(src), DstAddr: netip.MustParseAddr(dst), SrcMAC: srcMAC, DstMAC: gateway, TimeReceived: at}
}

func TestDeviceAttribution(t *testing.T) {
	now := time.Now()
	tr := NewDeviceTracker(local, nil)

	// A download before any upload: no binding yet, so no device.
	down := rec("142.250.1.1", "2603:7083:8640:9600:aaaa::1", ispMAC, now)
	tr.Assign(down)
	if down.DeviceMAC != 0 {
		t.Fatalf("attributed before learning: %x", down.DeviceMAC)
	}
	// Upload from the laptop's privacy address teaches the binding...
	up := rec("2603:7083:8640:9600:aaaa::1", "142.250.1.1", laptop, now)
	tr.Assign(up)
	if up.DeviceMAC != laptop {
		t.Fatalf("upload not attributed: %x", up.DeviceMAC)
	}
	// ...so later downloads to it are the laptop's, never the ISP router's.
	down2 := rec("142.250.1.1", "2603:7083:8640:9600:aaaa::1", ispMAC, now.Add(time.Second))
	tr.Assign(down2)
	if down2.DeviceMAC != laptop {
		t.Fatalf("download not attributed: %x", down2.DeviceMAC)
	}
	// Remote sources are never learned (their MAC is the upstream router).
	if _, ok := tr.Bindings()[netip.MustParseAddr("142.250.1.1")]; ok {
		t.Fatal("learned a remote address")
	}
	// DHCP hands the address to another device: the newest owner wins.
	tr.Assign(rec("192.168.80.50", "1.1.1.1", laptop, now))
	tr.Assign(rec("192.168.80.50", "1.1.1.1", 0x00113270000a, now.Add(time.Minute)))
	d := rec("1.1.1.1", "192.168.80.50", ispMAC, now.Add(2*time.Minute))
	tr.Assign(d)
	if d.DeviceMAC != 0x00113270000a {
		t.Fatalf("reassignment not followed: %x", d.DeviceMAC)
	}
	if n := len(tr.Dirty()); n == 0 || len(tr.Dirty()) != 0 {
		t.Fatal("dirty set not reported once")
	}
}

func TestRouterMACNotADevice(t *testing.T) {
	now := time.Now()
	tr := NewDeviceTracker(local, nil)
	const l3switch = 0x0011aabbccdd
	// Many IPv4 sources behind one MAC: a router forwarding another subnet.
	for i := 1; i <= 20; i++ {
		tr.Assign(rec(fmt.Sprintf("10.9.0.%d", i), "8.8.8.8", l3switch, now))
	}
	r := rec("10.9.0.21", "8.8.8.8", l3switch, now)
	tr.Assign(r)
	if r.DeviceMAC != 0 {
		t.Fatal("router MAC used as a device")
	}
}
