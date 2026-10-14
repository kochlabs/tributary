package api

import (
	"context"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"nfa/internal/config"
	"nfa/internal/enrich"
	"nfa/internal/store"
)

// deviceName picks the best available name for a MAC: the administrator's
// name, then reverse DNS of its current IPv4 address, then vendor and the
// last bytes of the MAC.
func (s *Server) deviceName(ctx context.Context, mac uint64, names map[netip.Addr]string) (name, source string) {
	if n := s.Config.DeviceName(mac); n != "" {
		return n, "name"
	}
	if ip, err := netip.ParseAddr(s.Config.RecentIPv4(mac)); err == nil {
		if names == nil {
			names = s.RDNS.Names(ctx, []netip.Addr{ip}, 500*time.Millisecond)
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
	names := s.RDNS.Names(ctx, v4, 800*time.Millisecond)
	for i := range rows {
		if macs[i] == 0 {
			// Exporter reported no MAC: the row is the device's IP.
			if ip, err := netip.ParseAddr(rows[i].Key); err == nil {
				lbl, _ := s.endpoint(ip, s.RDNS.Names(ctx, []netip.Addr{ip}, 300*time.Millisecond)[ip], true)
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
	names := s.RDNS.Names(ctx, v4, time.Second)
	out := make([]deviceView, 0, len(list))
	for _, d := range list {
		name, src := s.deviceName(ctx, d.MAC, names)
		v := deviceView{MAC: enrich.FormatMAC(d.MAC), Name: name, CustomName: d.Name, NameSource: src, Vendor: enrich.Vendor(d.MAC),
			Randomized: d.MAC&(0x02<<40) != 0, FirstSeen: d.FirstSeen, LastSeen: d.LastSeen, IPv4: []string{}, IPv6: []string{},
			Bytes: traffic[d.MAC][0], Flows: traffic[d.MAC][1], IPs: d.IPs}
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
