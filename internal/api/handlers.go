package api

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kochlabs/tributary/internal/config"
	"github.com/kochlabs/tributary/internal/enrich"
	"github.com/kochlabs/tributary/internal/names"
	"github.com/kochlabs/tributary/internal/store"
	"github.com/kochlabs/tributary/internal/system"
)

// ---- auth ----

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if _, err := s.Store.Stats(ctx); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) publicInfo(w http.ResponseWriter, r *http.Request) {
	locales := uiLocales(s.UI)
	writeJSON(w, http.StatusOK, map[string]any{"name": s.Config.Settings().ApplianceName, "version": s.Version, "source": s.SourceURL, "sso": s.ssoOptions(),
		"languages": append([]string{}, locales...), "language": pickLocale(r, locales)})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		_ = s.Config.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, userFrom(r))
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.Config.Authenticate(u.Username, req.Current); err != nil {
		writeErr(w, http.StatusBadRequest, "current password is incorrect")
		return
	}
	if err := s.Config.UpdateUser(u.Username, nil, nil, &req.New); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Password changes revoke all sessions; issue a fresh one for this browser.
	tok, err := s.Config.CreateSession(u.Username, time.Duration(s.Config.Settings().SessionHours)*time.Hour)
	if err == nil {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode,
			MaxAge: s.Config.Settings().SessionHours * 3600})
	}
	s.Config.Audit(u.Username, "password.change", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- query parameters ----

var rangeUnits = map[byte]time.Duration{'m': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour}

func parseQueryParams(r *http.Request) (store.Query, error) {
	v := r.URL.Query()
	q := store.Query{Metric: v.Get("metric"), GroupBy: v.Get("groupBy")}
	if q.Metric == "" {
		q.Metric = "bps"
	}
	if q.Metric != "bps" && q.Metric != "pps" && q.Metric != "fps" {
		return q, errors.New("metric must be bps, pps or fps")
	}
	now := time.Now()
	if rg := v.Get("range"); rg != "" {
		if len(rg) < 2 {
			return q, errors.New("invalid range")
		}
		unit, ok := rangeUnits[rg[len(rg)-1]]
		n, err := strconv.Atoi(rg[:len(rg)-1])
		if !ok || err != nil || n <= 0 {
			return q, errors.New("invalid range")
		}
		q.From, q.To = now.Add(-time.Duration(n)*unit), now
	} else {
		from, err1 := strconv.ParseInt(v.Get("from"), 10, 64)
		to, err2 := strconv.ParseInt(v.Get("to"), 10, 64)
		if err1 != nil || err2 != nil {
			return q, errors.New("range or from/to (unix ms) required")
		}
		q.From, q.To = time.UnixMilli(from), time.UnixMilli(to)
	}
	if !q.To.After(q.From) {
		return q, errors.New("'to' must be after 'from'")
	}
	if q.To.Sub(q.From) > 400*24*time.Hour {
		return q, errors.New("time range is limited to 400 days")
	}
	if l := v.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 {
			return q, errors.New("invalid limit")
		}
		q.Limit = n
	}
	params := map[string]string{}
	for k := range store.FilterFields {
		if val := v.Get(k); val != "" {
			params[k] = val
		}
	}
	f, err := store.ParseFilter(params)
	if err != nil {
		return q, err
	}
	q.Filter = f
	return q, nil
}

func queryCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 60*time.Second)
}

// ---- labels ----

func (s *Server) exporterLabel(addr string) string {
	if ip, err := netip.ParseAddr(addr); err == nil {
		if n := s.Inventory.Index().Name(ip); n != "" {
			return n
		}
	}
	if n := s.Config.ExporterName(addr); n != "" {
		return n
	}
	return addr
}

func (s *Server) ifaceLabel(exporter string, idx uint32) string {
	if n := s.Config.InterfaceName(exporter, idx); n != "" {
		return n
	}
	return "ifIndex " + strconv.FormatUint(uint64(idx), 10)
}

func (s *Server) label(dim, key string) string {
	if key == "__other__" {
		return "Other"
	}
	u := func() uint64 { n, _ := strconv.ParseUint(key, 10, 64); return n }
	switch dim {
	case "exporter":
		return s.exporterLabel(key)
	case "in_if", "out_if":
		e, i, _ := strings.Cut(key, "|")
		idx, _ := strconv.ParseUint(i, 10, 32)
		return s.exporterLabel(e) + " · " + s.ifaceLabel(e, uint32(idx))
	case "app":
		return names.App(key)
	case "proto":
		return names.Proto(uint8(u()))
	case "src_port", "dst_port":
		if svc := names.Service(uint16(u())); svc != "" {
			return key + " (" + svc + ")"
		}
	case "src_as", "dst_as", "remote_as":
		n := uint32(u())
		switch {
		case n == 0 && dim == "remote_as":
			return "Internal / unknown"
		case n == 0:
			return "Unknown / private"
		case n >= 64512 && n <= 65534 || n >= 4200000000:
			return "Private AS" + key
		}
		if name := s.Geo.ASName(n); name != "" {
			return name
		}
		return "AS" + key
	case "direction":
		return map[string]string{"download": "Download (remote → local)", "upload": "Upload (local → remote)", "internal": "Internal (local ↔ local)", "transit": "Transit (remote ↔ remote)"}[key]
	case "threat":
		return s.threatFeedName(key)
	case "remote_country":
		if key == "" {
			return "Internal / unknown"
		}
		if n := s.Geo.CountryName(key); n != "" {
			return n
		}
	case "src_country", "dst_country", "country":
		if key == "" {
			return "Unknown / private"
		}
		if n := s.Geo.CountryName(key); n != "" {
			return n
		}
	case "dscp":
		return names.DSCP(uint8(u()))
	case "etype":
		return names.EType(uint16(u()))
	case "flow_type":
		return names.FlowType(uint8(u()))
	case "vlan":
		if u() == 0 {
			return "untagged"
		}
		return "VLAN " + key
	}
	return key
}

// ---- analytics ----

func (s *Server) meta(w http.ResponseWriter, r *http.Request) {
	dims := []string{"local_host", "remote_host", "remote_as", "remote_country", "direction"}
	for k := range store.Dimensions {
		dims = append(dims, k)
	}
	sort.Strings(dims)
	filters := make([]string, 0, len(store.FilterFields))
	for k := range store.FilterFields {
		filters = append(filters, k)
	}
	sort.Strings(filters)
	writeJSON(w, http.StatusOK, map[string]any{"dimensions": dims, "filters": filters, "version": s.Version, "name": s.Config.Settings().ApplianceName})
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parseQuery(w, r)
	if !ok {
		return
	}
	ctx, cancel := queryCtx(r)
	defer cancel()
	sum, err := s.Store.Summary(ctx, q)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) timeseries(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parseQuery(w, r)
	if !ok {
		return
	}
	if q.Limit == 0 {
		q.Limit = 8
	}
	q.Limit = min(q.Limit, 20)
	ctx, cancel := queryCtx(r)
	defer cancel()
	ts, err := s.Store.TimeSeries(ctx, q)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	for i := range ts.Series {
		if q.GroupBy == "" {
			ts.Series[i].Label = "Total"
		} else {
			ts.Series[i].Label = s.label(q.GroupBy, ts.Series[i].Key)
		}
	}
	writeJSON(w, http.StatusOK, ts)
}

func (s *Server) top(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parseQuery(w, r)
	if !ok {
		return
	}
	q.GroupBy = r.URL.Query().Get("dimension")
	ctx, cancel := queryCtx(r)
	defer cancel()
	res, err := s.Store.TopN(ctx, q)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	if res.Rows == nil {
		res.Rows = []store.TopRow{}
	}
	for i := range res.Rows {
		res.Rows[i].Label = s.label(q.GroupBy, res.Rows[i].Key)
	}
	s.details(r.Context(), q.GroupBy, res.Rows)
	writeJSON(w, http.StatusOK, res)
}

// flowPage reads one page of flow records; on failure it writes the error
// and returns nil.
func (s *Server) flowPage(w http.ResponseWriter, r *http.Request) *store.FlowPage {
	q, ok := s.parseQuery(w, r)
	if !ok {
		return nil
	}
	v := r.URL.Query()
	offset, _ := strconv.Atoi(v.Get("offset"))
	ctx, cancel := queryCtx(r)
	defer cancel()
	page, err := s.Store.Flows(ctx, q, v.Get("sort"), v.Get("desc") != "false", offset)
	if err != nil {
		s.dbErr(w, err)
		return nil
	}
	return page
}

func (s *Server) flows(w http.ResponseWriter, r *http.Request) {
	page := s.flowPage(w, r)
	if page == nil {
		return
	}
	var addrs []netip.Addr
	for _, f := range page.Rows {
		for _, a := range []string{f.SrcAddr, f.DstAddr} {
			if ip, err := netip.ParseAddr(a); err == nil {
				addrs = append(addrs, ip)
			}
		}
	}
	names := s.hostNames(r.Context(), addrs, time.Second)
	for i := range page.Rows {
		f := &page.Rows[i]
		if ip, err := netip.ParseAddr(f.SrcAddr); err == nil {
			f.SrcHost = names[ip]
		}
		if ip, err := netip.ParseAddr(f.DstAddr); err == nil {
			f.DstHost = names[ip]
		}
		f.SrcASName, f.DstASName = s.Geo.ASName(f.SrcAS), s.Geo.ASName(f.DstAS)
		f.ExporterName = s.Config.ExporterName(f.Exporter)
		f.SrcThreat, f.DstThreat = s.threatFeedName(f.SrcThreat), s.threatFeedName(f.DstThreat)
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) flowsCSV(w http.ResponseWriter, r *http.Request) {
	r.URL.RawQuery += "&limit=5000"
	page := s.flowPage(w, r)
	if page == nil {
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="flows-%s.csv"`, time.Now().Format("20060102-150405")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time_received", "flow_start", "flow_end", "exporter", "in_if", "out_if", "src_addr", "src_port", "dst_addr", "dst_port",
		"protocol", "tcp_flags", "dscp", "src_as", "dst_as", "vlan", "next_hop", "bytes", "packets", "sampling", "flow_type"})
	ts := func(ms int64) string { return time.UnixMilli(ms).UTC().Format(time.RFC3339) }
	for _, f := range page.Rows {
		_ = cw.Write([]string{ts(f.TimeReceived), ts(f.TimeStart), ts(f.TimeEnd), f.Exporter, u64(f.InIf), u64(f.OutIf), f.SrcAddr, u64(f.SrcPort),
			f.DstAddr, u64(f.DstPort), names.Proto(f.Proto), names.TCPFlags(f.TCPFlags), u64(f.ToS >> 2), u64(f.SrcAS), u64(f.DstAS), u64(f.VLAN),
			f.NextHop, u64(f.Bytes), u64(f.Packets), u64(f.Sampling), names.FlowType(f.FlowType)})
	}
	cw.Flush()
}

func u64[T uint8 | uint16 | uint32 | uint64](v T) string { return strconv.FormatUint(uint64(v), 10) }

func (s *Server) dbErr(w http.ResponseWriter, err error) {
	var msg = err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		writeErr(w, http.StatusGatewayTimeout, "query timed out — narrow the time range or add filters")
	case strings.HasPrefix(msg, "unknown dimension"):
		writeErr(w, http.StatusBadRequest, msg)
	default:
		s.Log.Error("query failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "query failed: "+msg)
	}
}

// ---- exporters ----

type exporterView struct {
	config.Exporter
	Live any `json:"live"`
	// SNMP summarises polling for the exporter (nil when off).
	SNMP   *exporterSNMP `json:"snmp,omitempty"`
	Bytes  uint64        `json:"bytes"`
	Flows  uint64        `json:"flows"`
	Status string        `json:"status"` // active | idle | stale
}

type exporterSNMP struct {
	Version   string `json:"version"`
	SysName   string `json:"sysName"`
	SysDescr  string `json:"sysDescr"`
	LastPoll  int64  `json:"lastPoll"`
	LastError string `json:"lastError,omitempty"`
}

func (s *Server) exporters(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parseQuery(w, r)
	if !ok {
		return
	}
	ctx, cancel := queryCtx(r)
	defer cancel()
	traffic, err := s.Store.ExporterTraffic(ctx, q.From, q.To)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	live := map[string]any{}
	lastSeen := map[string]int64{}
	for _, e := range s.Collector.Exporters() {
		live[e.Addr] = e
		lastSeen[e.Addr] = e.LastSeen
	}
	out := []exporterView{}
	now := time.Now().UnixMilli()
	for _, e := range s.Config.Exporters() {
		v := exporterView{Exporter: e, Live: live[e.Addr], Bytes: traffic[e.Addr].Bytes, Flows: traffic[e.Addr].Flows}
		if c, st, err := s.Config.SNMP(e.Addr); err == nil && c.Version != "" {
			v.SNMP = &exporterSNMP{Version: c.Version, SysName: st.SysName, SysDescr: st.SysDescr, LastPoll: st.LastPoll, LastError: st.LastError}
		}
		last := max(lastSeen[e.Addr], traffic[e.Addr].LastSeen)
		switch {
		case now-last < 2*60*1000:
			v.Status = "active"
		case now-last < 60*60*1000:
			v.Status = "idle"
		default:
			v.Status = "stale"
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := netip.MustParseAddr(out[i].Addr), netip.MustParseAddr(out[j].Addr)
		return a.Less(b)
	})
	writeJSON(w, http.StatusOK, out)
}

func validAddr(w http.ResponseWriter, s string) (string, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid exporter address")
		return "", false
	}
	return a.Unmap().String(), true
}

func (s *Server) updateExporter(w http.ResponseWriter, r *http.Request) {
	addr, ok := validAddr(w, r.PathValue("addr"))
	if !ok {
		return
	}
	var e config.Exporter
	if err := readJSON(r, &e); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	e.Addr = addr
	if e.Sampling > 1<<20 {
		writeErr(w, http.StatusBadRequest, "sampling rate too large")
		return
	}
	if err := s.Config.UpdateExporter(e); err != nil {
		if errors.Is(err, config.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "exporter not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "exporter.update", addr)
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) deleteExporter(w http.ResponseWriter, r *http.Request) {
	addr, ok := validAddr(w, r.PathValue("addr"))
	if !ok {
		return
	}
	if err := s.Config.DeleteExporter(addr); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "exporter.delete", addr)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type ifaceView struct {
	config.Interface
	InBytes  uint64 `json:"inBytes"`
	OutBytes uint64 `json:"outBytes"`
}

func (s *Server) interfaces(w http.ResponseWriter, r *http.Request) {
	addr, ok := validAddr(w, r.PathValue("addr"))
	if !ok {
		return
	}
	q, ok := s.parseQuery(w, r)
	if !ok {
		return
	}
	ctx, cancel := queryCtx(r)
	defer cancel()
	seen, err := s.Store.Interfaces(ctx, addr, q.From, q.To)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	cfg, err := s.Config.Interfaces(addr)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	byIdx := map[uint32]*ifaceView{}
	for _, c := range cfg {
		byIdx[c.Index] = &ifaceView{Interface: c}
	}
	for _, t := range seen {
		v := byIdx[t.Index]
		if v == nil {
			v = &ifaceView{Interface: config.Interface{Exporter: addr, Index: t.Index}}
			byIdx[t.Index] = v
		}
		v.InBytes, v.OutBytes = t.InBytes, t.OutBytes
	}
	out := make([]ifaceView, 0, len(byIdx))
	for _, v := range byIdx {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateInterface(w http.ResponseWriter, r *http.Request) {
	addr, ok := validAddr(w, r.PathValue("addr"))
	if !ok {
		return
	}
	idx, err := strconv.ParseUint(r.PathValue("idx"), 10, 32)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid interface index")
		return
	}
	var i config.Interface
	if err := readJSON(r, &i); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	i.Exporter, i.Index = addr, uint32(idx)
	if err := s.Config.SaveInterface(i); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "interface.update", fmt.Sprintf("%s ifIndex %d", addr, idx))
	writeJSON(w, http.StatusOK, i)
}

// ---- system ----

func readProc(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func hostStats() map[string]any {
	out := map[string]any{}
	if f := strings.Fields(readProc("/proc/loadavg")); len(f) >= 3 {
		out["load"] = f[:3]
	}
	mem := map[string]uint64{}
	for _, line := range strings.Split(readProc("/proc/meminfo"), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		mem[k] = n * 1024
	}
	out["memTotal"], out["memAvailable"] = mem["MemTotal"], mem["MemAvailable"]
	if f := strings.Fields(readProc("/proc/uptime")); len(f) > 0 {
		up, _ := strconv.ParseFloat(f[0], 64)
		out["uptime"] = up
	}
	out["hostname"], _ = os.Hostname()
	out["cpus"] = runtime.NumCPU()
	return out
}

func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	db, dbErr := s.Store.Stats(ctx)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	lastErr, _ := s.Writer.LastError.Load().(string)
	resp := map[string]any{
		"version":         s.Version,
		"started":         s.started.UnixMilli(),
		"collector":       s.Collector.Status(),
		"rejectedSources": s.Collector.RejectedSources(),
		"writer": map[string]any{
			"rowsWritten": s.Writer.RowsWritten.Load(), "batches": s.Writer.Batches.Load(), "errors": s.Writer.Errors.Load(),
			"dropped": s.Writer.Dropped.Load(), "queue": s.Writer.QueueLen(), "queueCap": s.Writer.QueueCap(),
			"lastFlush": s.Writer.LastFlush.Load(), "lastError": lastErr,
		},
		"process":  map[string]any{"heapAlloc": ms.HeapAlloc, "sys": ms.Sys, "goroutines": runtime.NumGoroutine(), "gcCycles": ms.NumGC},
		"host":     hostStats(),
		"geo":      s.Geo.Status(),
		"database": db,
	}
	if dbErr != nil {
		resp["databaseError"] = dbErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- settings ----

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Config.Settings())
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var ns config.Settings
	if err := readJSON(r, &ns); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ns.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	old := s.Config.Settings()
	if err := s.Config.SaveSettings(ns); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "settings.update", "")
	if s.ApplySettings != nil {
		if err := s.ApplySettings(r.Context(), old, ns); err != nil {
			writeErr(w, http.StatusConflict, "settings saved but could not be fully applied: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, ns)
}

// ---- users ----

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Config.Users()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		FullName string `json:"fullName"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Config.CreateUser(config.User{Username: req.Username, Role: req.Role, FullName: req.FullName}, req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "user.create", req.Username+" ("+req.Role+")")
	writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Role     *string `json:"role"`
		FullName *string `json:"fullName"`
		Password *string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	name := r.PathValue("name")
	if err := s.Config.UpdateUser(name, req.Role, req.FullName, req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "user.update", name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == userFrom(r).Username {
		writeErr(w, http.StatusBadRequest, "you cannot delete your own account")
		return
	}
	if err := s.Config.DeleteUser(name); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, config.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "user.delete", name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.Config.AuditLog(500)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// details adds a secondary label to top-N rows: AS organisation names, and
// hostname / country / network for addresses.
func (s *Server) details(ctx context.Context, dim string, rows []store.TopRow) {
	switch dim {
	case "device":
		s.deviceDetails(ctx, rows)
	case "src_as", "dst_as", "remote_as":
		for i := range rows {
			if rows[i].Key != "0" && rows[i].Label != "AS"+rows[i].Key {
				rows[i].Detail = "AS" + rows[i].Key
			}
		}
	case "src_country", "dst_country", "country", "remote_country":
		for i := range rows {
			rows[i].Detail = rows[i].Key
		}
	case "threat":
		for i := range rows {
			if rows[i].Key == "" {
				rows[i].Label = "Not listed"
			}
		}
	case "src_addr", "dst_addr", "host", "local_host", "remote_host", "threat_host":
		addrs := make([]netip.Addr, 0, len(rows))
		for _, r := range rows {
			if ip, err := netip.ParseAddr(r.Key); err == nil {
				addrs = append(addrs, ip)
			}
		}
		names := s.hostNames(ctx, addrs, 800*time.Millisecond)
		for i := range rows {
			if ip, err := netip.ParseAddr(rows[i].Key); err == nil {
				rows[i].Label, rows[i].Detail = s.endpoint(ip, names[ip], true)
			}
		}
	case "conversation":
		var addrs []netip.Addr
		pairs := make([][2]netip.Addr, len(rows))
		for i, r := range rows {
			a, b, ok := strings.Cut(r.Key, " ⇄ ")
			if !ok {
				continue
			}
			pa, err1 := netip.ParseAddr(a)
			pb, err2 := netip.ParseAddr(b)
			if err1 == nil && err2 == nil {
				pairs[i] = [2]netip.Addr{pa, pb}
				addrs = append(addrs, pa, pb)
			}
		}
		names := s.hostNames(ctx, addrs, 800*time.Millisecond)
		for i := range rows {
			if !pairs[i][0].IsValid() {
				continue
			}
			for _, ip := range pairs[i] {
				rows[i].Ends = append(rows[i].Ends, s.conversationEnd(ip, names[ip]))
			}
			rows[i].Label = rows[i].Ends[0].Name + " ⇄ " + rows[i].Ends[1].Name
			rows[i].Detail = rows[i].Key
		}
	}
}

// conversationEnd describes one side of a conversation: hostname first, else
// the remote network's organisation, with the address and context below.
func (s *Server) conversationEnd(ip netip.Addr, host string) store.Endpoint {
	e := store.Endpoint{Addr: ip.String(), Name: host, Local: s.Geo.IsLocal(ip)}
	if e.Local {
		if e.Name == "" {
			e.Name = e.Addr
		} else {
			e.Detail = e.Addr
		}
		return e
	}
	g := s.Geo.Lookup(ip)
	ctx := []string{}
	if e.Name == "" && g.ASName != "" {
		e.Name = g.ASName
	} else if g.ASName != "" {
		ctx = append(ctx, g.ASName)
	}
	if e.Name == "" {
		e.Name = e.Addr
	} else {
		ctx = append([]string{e.Addr}, ctx...)
	}
	if g.Country != "" {
		ctx = append(ctx, g.Country)
	}
	e.Detail = strings.Join(ctx, " · ")
	return e
}

// endpoint names an address for display: its hostname if known, else (for
// remote addresses) its network's organisation, else the address itself.
// With withDetail, the second value carries the address and context.
func (s *Server) endpoint(ip netip.Addr, host string, withDetail bool) (string, string) {
	addr := ip.String()
	if s.Geo.IsLocal(ip) {
		if host != "" {
			return host, addr + " · local"
		}
		return addr, "local"
	}
	g := s.Geo.Lookup(ip)
	var ctx []string
	if g.Country != "" {
		ctx = append(ctx, g.Country)
	}
	if g.ASN != 0 {
		ctx = append(ctx, fmt.Sprintf("AS%d %s", g.ASN, g.ASName))
	}
	switch {
	case host != "":
		return host, strings.Join(append([]string{addr}, ctx...), " · ")
	case !withDetail && g.ASName != "":
		return g.ASName + " (" + addr + ")", ""
	}
	return addr, strings.Join(ctx, " · ")
}

func (s *Server) geoStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"geo": s.Geo.Status(), "vendors": s.Vendors.Status(), "rdnsEnabled": s.RDNS.Enabled.Load(), "rdnsCache": s.RDNS.CacheSize(),
		"systemDnsServers": enrich.SystemDNSServers()})
}

func (s *Server) geoUpdate(w http.ResponseWriter, r *http.Request) {
	s.Config.Audit(userFrom(r).Username, "geoip.update", "")
	go func() { _ = s.Geo.Update(context.Background()) }()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "update started"})
}

func (s *Server) ouiUpdate(w http.ResponseWriter, r *http.Request) {
	s.Config.Audit(userFrom(r).Username, "oui.update", "")
	go func() { _ = s.Vendors.Update(context.Background()) }()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "update started"})
}

func (s *Server) enrichmentGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Config.Enrichment().View())
}

// enrichmentPut stores the database sources and switches to them. Secrets
// left empty keep their stored values.
func (s *Server) enrichmentPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		config.Enrichment
		ClearGeoASNURL bool `json:"clearGeoAsnUrl"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Config.SaveEnrichment(req.Enrichment, req.ClearGeoASNURL); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	e := s.Config.Enrichment()
	s.Config.Audit(userFrom(r).Username, "enrichment.update", "geo="+e.GeoSource+" vendors="+e.OUISource)
	if s.Geo.SetSource(e) {
		go s.Geo.Refresh(context.Background())
	}
	if s.Vendors.SetSource(e) {
		go s.Vendors.Refresh(context.Background())
	}
	writeJSON(w, http.StatusOK, e.View())
}

func (s *Server) localSuggestions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := queryCtx(r)
	defer cancel()
	res, err := s.Store.SuggestLocalNetworks(ctx)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ---- system administration (via the privileged helper) ----

func (s *Server) adminErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, system.ErrBusy):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, system.ErrNotInstalled):
		writeErr(w, http.StatusServiceUnavailable, err.Error())
	default:
		writeErr(w, http.StatusBadRequest, err.Error())
	}
}

// finish waits briefly for quick actions so the UI gets the outcome directly;
// slow ones return 202 with the request id to poll.
func (s *Server) finish(w http.ResponseWriter, id string, wait time.Duration) {
	res, err := s.System.WaitResult(id, wait)
	switch {
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
	case res.Pending:
		writeJSON(w, http.StatusAccepted, res)
	case !res.OK:
		writeErr(w, http.StatusUnprocessableEntity, res.Message)
	default:
		writeJSON(w, http.StatusOK, res)
	}
}

func (s *Server) adminResult(w http.ResponseWriter, r *http.Request) {
	res, err := s.System.Result(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) updatesStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.System.UpdateStatus()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) updatesLog(w http.ResponseWriter, r *http.Request) {
	off, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	text, next, err := s.System.Log(off)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"text": text, "offset": next})
}

func (s *Server) updatesRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.System.RequestUpdate(req.Action)
	if err != nil {
		s.adminErr(w, err)
		return
	}
	s.Config.Audit(userFrom(r).Username, "system."+req.Action, "")
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id})
}

func (s *Server) timeStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.System.TimeStatus(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": st, "installed": s.System.Installed()})
}

func (s *Server) timeZones(w http.ResponseWriter, r *http.Request) {
	z, err := s.System.Timezones(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, z)
}

func (s *Server) timeSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Timezone string   `json:"timezone"`
		NTP      bool     `json:"ntp"`
		Servers  []string `json:"servers"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.System.SetTime(req.Timezone, req.NTP, req.Servers)
	if err != nil {
		s.adminErr(w, err)
		return
	}
	s.Config.Audit(userFrom(r).Username, "system.time", fmt.Sprintf("tz=%s ntp=%v servers=%s", req.Timezone, req.NTP, strings.Join(req.Servers, ",")))
	s.finish(w, id, 20*time.Second)
}

func (s *Server) servicesList(w http.ResponseWriter, r *http.Request) {
	list, err := s.System.Services(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": list, "installed": s.System.Installed()})
}

func (s *Server) serviceAction(w http.ResponseWriter, r *http.Request) {
	unit, op := r.PathValue("unit"), r.PathValue("op")
	id, err := s.System.ServiceAction(unit, op)
	if err != nil {
		s.adminErr(w, err)
		return
	}
	s.Config.Audit(userFrom(r).Username, "service."+op, unit)
	s.finish(w, id, 30*time.Second)
}

func (s *Server) storageEstimate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := queryCtx(r)
	defer cancel()
	est, err := s.Store.StorageEstimate(ctx)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, est)
}

// paths returns a Sankey diagram of traffic across 2–3 dimensions.
func (s *Server) paths(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parseQuery(w, r)
	if !ok {
		return
	}
	dims := strings.Split(r.URL.Query().Get("dims"), ",")
	if err := store.ValidPathDimensions(dims); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	ctx, cancel := queryCtx(r)
	defer cancel()
	res, err := s.Store.Paths(ctx, q, dims, limit)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	// Label each column's nodes the way the top-N table does.
	for col, dim := range dims {
		var idx []int
		var rows []store.TopRow
		for i, n := range res.Nodes {
			if n.Column == col && n.Key != store.OtherKey {
				idx = append(idx, i)
				rows = append(rows, store.TopRow{Key: n.Key, Label: s.label(dim, n.Key)})
			}
		}
		s.details(r.Context(), dim, rows)
		for j, i := range idx {
			res.Nodes[i].Label, res.Nodes[i].Detail = rows[j].Label, rows[j].Detail
		}
	}
	writeJSON(w, http.StatusOK, res)
}
