package api

import (
	"context"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/kochlabs/tributary/internal/config"
	"github.com/kochlabs/tributary/internal/enrich"
	"github.com/kochlabs/tributary/internal/inventory"
	"github.com/kochlabs/tributary/internal/store"
)

// deviceName picks the best available name for a MAC: the inventory's (by
// MAC, then by its current IPv4 address), the administrator's, reverse DNS
// of its current IPv4 address, then vendor and the last bytes of the MAC.
func (s *Server) deviceName(ctx context.Context, mac uint64, names map[netip.Addr]string) (name, source string) {
	if r := s.inventoryDevice(mac); r != nil && r.Name != "" {
		return r.Name, "inventory"
	}
	if n := s.Config.DeviceName(mac); n != "" {
		return n, "name"
	}
	if ip, err := netip.ParseAddr(s.Config.RecentIPv4(mac)); err == nil {
		if names == nil {
			names = s.hostNames(ctx, []netip.Addr{ip}, 500*time.Millisecond)
		}
		if h := names[ip]; h != "" {
			return strings.SplitN(h, ".", 2)[0], "dns"
		}
	}
	m := enrich.FormatMAC(mac)
	if mac&(0x02<<40) != 0 {
		// Randomised MACs (phones, laptops) have no vendor; rename them.
		return "Private device " + m[12:], "mac"
	}
	if v := enrich.Vendor(mac); v != "" {
		return shortVendor(v) + " " + m[9:], "vendor"
	}
	return m, "mac"
}

// inventoryDevice is the inventory's record for a MAC, matched by MAC or,
// failing that, by the device's current IPv4 address.
func (s *Server) inventoryDevice(mac uint64) *inventory.Record {
	idx := s.Inventory.Index()
	if r := idx.ByMAC(enrich.FormatMAC(mac)); r != nil {
		return r
	}
	if ip, err := netip.ParseAddr(s.Config.RecentIPv4(mac)); err == nil {
		return idx.ByIP(ip)
	}
	return nil
}

// hostNames names addresses: the inventory's name first, reverse DNS (within
// timeout) for the rest.
func (s *Server) hostNames(ctx context.Context, addrs []netip.Addr, timeout time.Duration) map[netip.Addr]string {
	idx := s.Inventory.Index()
	out := map[netip.Addr]string{}
	var rest []netip.Addr
	for _, a := range addrs {
		if n := idx.Name(a); n != "" {
			out[a] = n
		} else {
			rest = append(rest, a)
		}
	}
	if len(rest) > 0 {
		for a, n := range s.RDNS.Names(ctx, rest, timeout) {
			out[a] = n
		}
	}
	return out
}

// shortVendor trims corporate suffixes: "Synology Incorporated" -> "Synology".
func shortVendor(v string) string {
	for _, suf := range []string{" Incorporated", " Inc.", " Inc", ", Inc.", " Co., Ltd.", " Co.,Ltd.", " Co., Ltd", " Corporation", " Corp.", " GmbH", " Ltd.", " Ltd", " LLC", " Limited", " Technologies", " Technology", " Server Solutions"} {
		v = strings.TrimSuffix(v, suf)
	}
	return strings.TrimSuffix(strings.TrimSpace(v), ",")
}

// deviceDetails labels "device" dimension rows.
func (s *Server) deviceDetails(ctx context.Context, rows []store.TopRow) {
	var v4 []netip.Addr
	macs := make([]uint64, len(rows))
	for i, r := range rows {
		if m, ok := enrich.ParseMAC(r.Key); ok && strings.Count(r.Key, ":") == 5 {
			macs[i] = m
			if ip, err := netip.ParseAddr(s.Config.RecentIPv4(m)); err == nil {
				v4 = append(v4, ip)
			}
		}
	}
	names := s.hostNames(ctx, v4, 800*time.Millisecond)
	for i := range rows {
		if macs[i] == 0 {
			// Exporter reported no MAC: the row is the device's IP.
			if ip, err := netip.ParseAddr(rows[i].Key); err == nil {
				lbl, _ := s.endpoint(ip, s.hostNames(ctx, []netip.Addr{ip}, 300*time.Millisecond)[ip], true)
				rows[i].Label, rows[i].Detail = lbl, ip.String()+" · no MAC reported"
			} else if rows[i].Key == "" {
				rows[i].Label = "Unknown"
			}
			continue
		}
		name, _ := s.deviceName(ctx, macs[i], names)
		rows[i].Label = name
		detail := []string{rows[i].Key}
		if v := enrich.Vendor(macs[i]); v != "" {
			detail = append(detail, v)
		}
		if ip := s.Config.RecentIPv4(macs[i]); ip != "" {
			detail = append(detail, ip)
		}
		rows[i].Detail = strings.Join(detail, " · ")
	}
}

type deviceView struct {
	MAC        string            `json:"mac"`
	Name       string            `json:"name"`
	CustomName string            `json:"customName"`
	NameSource string            `json:"nameSource"`
	Vendor     string            `json:"vendor"`
	Randomized bool              `json:"randomized"`
	FirstSeen  int64             `json:"firstSeen"`
	LastSeen   int64             `json:"lastSeen"`
	IPv4       []string          `json:"ipv4"`
	IPv6       []string          `json:"ipv6"`
	Bytes      uint64            `json:"bytes"`
	Flows      uint64            `json:"flows"`
	IPs        []config.DeviceIP `json:"ips"`
	// Inventory is the inventory's record (role, site, link), if any.
	Inventory *inventory.Record `json:"inventory,omitempty"`
}

// devicesList returns every known device with its traffic in the requested
// time window.
func (s *Server) devicesList(w http.ResponseWriter, r *http.Request) {
	q, err := parseQuery(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := queryCtx(r)
	defer cancel()
	list, err := s.Config.Devices()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	traffic, err := s.Store.DeviceTraffic(ctx, q.From, q.To)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	var v4 []netip.Addr
	for _, d := range list {
		for _, ip := range d.IPs {
			if a, err := netip.ParseAddr(ip.IP); err == nil && a.Is4() {
				v4 = append(v4, a)
				break
			}
		}
	}
	names := s.hostNames(ctx, v4, time.Second)
	out := make([]deviceView, 0, len(list))
	for _, d := range list {
		name, src := s.deviceName(ctx, d.MAC, names)
		v := deviceView{MAC: enrich.FormatMAC(d.MAC), Name: name, CustomName: d.Name, NameSource: src, Vendor: enrich.Vendor(d.MAC),
			Randomized: d.MAC&(0x02<<40) != 0, FirstSeen: d.FirstSeen, LastSeen: d.LastSeen, IPv4: []string{}, IPv6: []string{},
			Bytes: traffic[d.MAC][0], Flows: traffic[d.MAC][1], IPs: d.IPs, Inventory: s.inventoryDevice(d.MAC)}
		for _, ip := range d.IPs {
			if strings.Contains(ip.IP, ":") {
				v.IPv6 = append(v.IPv6, ip.IP)
			} else {
				v.IPv4 = append(v.IPv4, ip.IP)
			}
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deviceRename(w http.ResponseWriter, r *http.Request) {
	mac, ok := enrich.ParseMAC(r.PathValue("mac"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid MAC address")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Config.SetDeviceName(mac, req.Name); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "device.rename", enrich.FormatMAC(mac)+" = "+req.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
