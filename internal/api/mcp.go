package api

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kochlabs/tributary/internal/config"
	"github.com/kochlabs/tributary/internal/enrich"
	"github.com/kochlabs/tributary/internal/store"
)

// The MCP endpoint lets AI assistants query flow data. It is read-only, off
// until an administrator turns it on, and authenticated with API tokens; the
// tools run the same handlers as the web UI, as the token's user, so results
// and permissions match what that user sees.

const (
	mcpPath           = "/mcp"
	mcpCallsPerMinute = 120
	mcpMaxResult      = 512 << 10 // bytes of JSON per tool result
)

const mcpInstructions = `Tributary collects NetFlow, IPFIX and sFlow records from routers, switches and firewalls ("exporters") and stores them for analysis. Byte and packet counts are corrected for sampling. "Local" addresses are private ranges plus the networks configured as local; "remote" ones are everything else, enriched with country and AS (organization). Rates are averages over the requested time range. Remote addresses on threat feeds (lists of known-bad addresses) are tagged: the threat dimension names the feed, threat_host the listed address, and the filter threat=* finds all such traffic. Start with summary or top to get an overview, use filters to narrow down, and search_flows for individual records.`

// mcpWindow is the time range and filters most tools take.
type mcpWindow struct {
	Range   string            `json:"range,omitempty"`
	From    string            `json:"from,omitempty"`
	To      string            `json:"to,omitempty"`
	Filters map[string]string `json:"filters,omitempty"`
}

type mcpTopIn struct {
	mcpWindow
	Dimension string `json:"dimension"`
	Metric    string `json:"metric,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

type mcpSeriesIn struct {
	mcpWindow
	GroupBy string `json:"group_by,omitempty"`
	Metric  string `json:"metric,omitempty"`
	Limit   int    `json:"limit,omitempty"`
}

type mcpPathsIn struct {
	mcpWindow
	Dimensions []string `json:"dimensions"`
	Metric     string   `json:"metric,omitempty"`
	Limit      int      `json:"limit,omitempty"`
}

type mcpFlowsIn struct {
	mcpWindow
	Sort  string `json:"sort,omitempty"`
	Limit int    `json:"limit,omitempty"`
}

type mcpInterfacesIn struct {
	mcpWindow
	Exporter string `json:"exporter"`
}

type mcpDevicesIn struct {
	mcpWindow
	Limit int `json:"limit,omitempty"`
}

type mcpLookupIn struct {
	mcpWindow
	Address string `json:"address"`
}

type mcpNoInput struct{}

// mcpUser is the user an MCP request acts as, set by the token verifier.
func mcpUser(req *mcp.CallToolRequest) *config.User {
	if req.Extra == nil || req.Extra.TokenInfo == nil {
		return nil
	}
	u, _ := req.Extra.TokenInfo.Extra["user"].(*config.User)
	return u
}

// mcpHandler serves the MCP endpoint (Streamable HTTP, stateless).
func (s *Server) mcpHandler() http.Handler {
	srv := mcp.NewServer(&mcp.Implementation{Name: "tributary", Title: "Tributary", Version: s.Version},
		&mcp.ServerOptions{Instructions: mcpInstructions})
	s.addMCPTools(srv)
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	limiter := &mcpLimiter{calls: map[int64][]time.Time{}}
	authed := auth.RequireBearerToken(s.verifyAPIToken, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ti := auth.TokenInfoFromContext(r.Context())
			if id, _ := ti.Extra["tokenID"].(int64); !limiter.allow(id) {
				w.Header().Set("Retry-After", "60")
				writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("more than %d requests a minute with this token", mcpCallsPerMinute))
				return
			}
			h.ServeHTTP(w, r)
		}))
	protect := http.NewCrossOriginProtection()
	return protect.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Config.Settings().MCPEnabled {
			writeErr(w, http.StatusNotFound, "MCP is turned off on this appliance (Configuration → Settings)")
			return
		}
		authed.ServeHTTP(w, r)
	}))
}

func (s *Server) verifyAPIToken(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	u, t, err := s.Config.APITokenUser(token)
	if err != nil {
		return nil, auth.ErrInvalidToken
	}
	ti := &auth.TokenInfo{UserID: u.Username, Extra: map[string]any{"user": u, "tokenID": t.ID}}
	if t.ExpiresAt != 0 {
		ti.Expiration = time.UnixMilli(t.ExpiresAt)
	}
	return ti, nil
}

// mcpLimiter allows mcpCallsPerMinute requests per token in any minute.
type mcpLimiter struct {
	mu    sync.Mutex
	calls map[int64][]time.Time
}

func (l *mcpLimiter) allow(token int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	recent := slices.DeleteFunc(l.calls[token], func(t time.Time) bool { return now.Sub(t) > time.Minute })
	if len(recent) >= mcpCallsPerMinute {
		l.calls[token] = recent
		return false
	}
	l.calls[token] = append(recent, now)
	return true
}

// ---- tools ----

func (s *Server) addMCPTools(srv *mcp.Server) {
	dims := store.DimensionNames()
	filters := sortedKeys(store.FilterFields)
	pathDims := slices.DeleteFunc(slices.Clone(dims), func(d string) bool { return !store.PathDimension(d) })
	window := func(props map[string]*jsonschema.Schema) {
		props["range"].Description = "Time range ending now: a number with m, h or d, such as 15m, 6h or 7d. Default 1h."
		props["from"].Description = "Start of a fixed time range (RFC 3339), instead of range."
		props["to"].Description = "End of a fixed time range (RFC 3339), with from."
		props["filters"].Description = "Only flows matching all of these, by field: " + strings.Join(filters, ", ") +
			`. Values are addresses or CIDR prefixes, ports or port ranges (8000-8100), protocol names, AS numbers, two-letter country codes or app as proto/port (tcp/443); a comma means any of them, a leading ! means not. direction is download or upload; device is a MAC address. Example: {"host": "10.0.0.5", "app": "tcp/443"}.`
	}
	metric := func(props map[string]*jsonschema.Schema) {
		props["metric"].Description = "bps (bits per second, the default), pps (packets) or fps (flows)."
		props["metric"].Enum = []any{"bps", "pps", "fps"}
	}
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true}

	addTool(s, srv, "summary", "Traffic totals and rates for a time range: download and upload, bytes, packets, flows, peaks, and how many local and remote hosts were active.",
		window, func(ctx context.Context, u *config.User, in mcpWindow) (any, error) {
			return s.mcpGet(ctx, u, s.summary, "/api/summary", in, nil, nil)
		}, readOnly)

	addTool(s, srv, "top", "The top values of one dimension by traffic, with their share of the total: e.g. which hosts, applications, organizations or interfaces carried the most.",
		func(p map[string]*jsonschema.Schema) {
			window(p)
			metric(p)
			p["dimension"].Description = "What to rank. conversation pairs a local device with a remote host; remote_as is the remote organization; app is protocol/port."
			p["dimension"].Enum = toAny(dims)
			p["limit"].Description = "Rows to return, 1 to 50 (default 10)."
		}, func(ctx context.Context, u *config.User, in mcpTopIn) (any, error) {
			if in.Dimension == "" {
				return nil, errors.New("dimension is required")
			}
			return s.mcpGet(ctx, u, s.top, "/api/top", in.mcpWindow, url.Values{"dimension": {in.Dimension}, "metric": {in.Metric}, "limit": {clamp(in.Limit, 10, 50)}}, nil)
		}, readOnly)

	addTool(s, srv, "traffic_over_time", "Traffic as a time series for a range, optionally split by a dimension (the top values plus Other). Use it to find when something happened.",
		func(p map[string]*jsonschema.Schema) {
			window(p)
			metric(p)
			p["group_by"].Description = "Split the series by this dimension; empty for the total only."
			p["group_by"].Enum = append([]any{""}, toAny(dims)...)
			p["limit"].Description = "Series to return when grouping, 1 to 10 (default 5)."
		}, func(ctx context.Context, u *config.User, in mcpSeriesIn) (any, error) {
			return s.mcpGet(ctx, u, s.timeseries, "/api/timeseries", in.mcpWindow, url.Values{"groupBy": {in.GroupBy}, "metric": {in.Metric}, "limit": {clamp(in.Limit, 5, 10)}}, nil)
		}, readOnly)

	addTool(s, srv, "traffic_paths", "How traffic flows across two or three dimensions, such as device → application → remote organization, or input interface → output interface on one exporter (filter by exporter).",
		func(p map[string]*jsonschema.Schema) {
			window(p)
			metric(p)
			p["dimensions"].Description = "Two or three dimensions, in order."
			p["dimensions"].Type, p["dimensions"].Types = "array", nil // required: never null
			p["dimensions"].Items.Enum = toAny(pathDims)
			p["limit"].Description = "Nodes per column, 2 to 10 (default 8)."
		}, func(ctx context.Context, u *config.User, in mcpPathsIn) (any, error) {
			return s.mcpGet(ctx, u, s.paths, "/api/paths", in.mcpWindow, url.Values{"dims": {strings.Join(in.Dimensions, ",")}, "metric": {in.Metric}, "limit": {clamp(in.Limit, 8, 10)}}, nil)
		}, readOnly)

	addTool(s, srv, "search_flows", "Individual flow records, newest or largest first, with addresses, ports, protocol, interfaces, AS, country, hostnames and byte counts. Narrow it down with filters.",
		func(p map[string]*jsonschema.Schema) {
			window(p)
			p["sort"].Description = "time (the default, newest first), bytes or packets (largest first)."
			p["sort"].Enum = []any{"time", "bytes", "packets"}
			p["limit"].Description = "Records to return, 1 to 100 (default 25)."
		}, func(ctx context.Context, u *config.User, in mcpFlowsIn) (any, error) {
			return s.mcpGet(ctx, u, s.flows, "/api/flows", in.mcpWindow, url.Values{"sort": {in.Sort}, "limit": {clamp(in.Limit, 25, 100)}}, nil)
		}, readOnly)

	addTool(s, srv, "exporters", "The routers, switches and firewalls sending flows: names, protocol, sampling, live rates, volume, loss and when they were last heard from.",
		window, func(ctx context.Context, u *config.User, in mcpWindow) (any, error) {
			return s.mcpGet(ctx, u, s.exporters, "/api/exporters", in, nil, nil)
		}, readOnly)

	addTool(s, srv, "interfaces", "An exporter's interfaces with names, speeds, traffic in each direction and utilization.",
		func(p map[string]*jsonschema.Schema) {
			window(p)
			p["exporter"].Description = "The exporter's address, as listed by the exporters tool."
		}, func(ctx context.Context, u *config.User, in mcpInterfacesIn) (any, error) {
			if _, err := netip.ParseAddr(in.Exporter); err != nil {
				return nil, errors.New("exporter must be an exporter's IP address")
			}
			return s.mcpGet(ctx, u, s.interfaces, "/api/exporters/"+in.Exporter+"/interfaces", in.mcpWindow, nil, map[string]string{"addr": in.Exporter})
		}, readOnly)

	addTool(s, srv, "devices", "Local devices identified by MAC address, with their names, vendors, addresses and traffic; the busiest first.",
		func(p map[string]*jsonschema.Schema) {
			window(p)
			p["limit"].Description = "Devices to return, 1 to 100 (default 25)."
		}, func(ctx context.Context, u *config.User, in mcpDevicesIn) (any, error) {
			res, err := s.mcpGet(ctx, u, s.devicesList, "/api/devices", in.mcpWindow, nil, nil)
			if err != nil {
				return nil, err
			}
			list, _ := res.([]any)
			bytesOf := func(d any) float64 { m, _ := d.(map[string]any); b, _ := m["bytes"].(float64); return b }
			slices.SortStableFunc(list, func(a, b any) int { return cmp.Compare(bytesOf(b), bytesOf(a)) })
			n, _ := strconv.Atoi(clamp(in.Limit, 25, 100))
			return map[string]any{"total": len(list), "devices": list[:min(n, len(list))]}, nil
		}, readOnly)

	addTool(s, srv, "lookup_address", "Everything known about one IP address: whether it is local, its hostname, country and AS, the threat feeds listing it, its traffic totals, and its top conversations and applications in the time range.",
		func(p map[string]*jsonschema.Schema) {
			window(p)
			p["address"].Description = "An IPv4 or IPv6 address."
		}, func(ctx context.Context, u *config.User, in mcpLookupIn) (any, error) {
			return s.mcpLookup(ctx, u, in)
		}, readOnly)

	addTool(s, srv, "threat_feeds", "The enabled threat feeds (lists of known-bad addresses that flows are matched against), in matching order: entries, last update and errors, plus how many listed hosts and flows each matched in the last 24 hours. Use the threat filter and dimensions for details.",
		nil, func(ctx context.Context, u *config.User, _ mcpNoInput) (any, error) {
			return s.mcpGet(ctx, u, s.threatStatus, "/api/threats", mcpWindow{}, nil, nil)
		}, readOnly)

	addTool(s, srv, "appliance_health", "The appliance's own state: collector listeners and counters, database health and disk space, and current notices (problems needing attention).",
		nil, func(ctx context.Context, u *config.User, _ mcpNoInput) (any, error) {
			sys, err := s.mcpGet(ctx, u, s.system, "/api/system", mcpWindow{}, nil, nil)
			if err != nil {
				return nil, err
			}
			notices, err := s.mcpGet(ctx, u, s.noticesList, "/api/notices", mcpWindow{}, nil, nil)
			if err != nil {
				return nil, err
			}
			return map[string]any{"system": sys, "notices": notices}, nil
		}, readOnly)
}

// addTool registers a tool whose input schema is derived from In and then
// described by describe; every call is audited.
func addTool[In any](s *Server, srv *mcp.Server, name, description string, describe func(map[string]*jsonschema.Schema),
	run func(context.Context, *config.User, In) (any, error), ann *mcp.ToolAnnotations) {
	schema, err := jsonschema.For[In](nil)
	if err != nil {
		panic(err)
	}
	if describe != nil {
		describe(schema.Properties)
	}
	mcp.AddTool(srv, &mcp.Tool{Name: name, Description: description, InputSchema: schema, Annotations: ann},
		func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
			u := mcpUser(req)
			if u == nil {
				return nil, nil, errors.New("not authenticated")
			}
			args, _ := json.Marshal(in)
			if len(args) > 300 {
				args = append(args[:297], "..."...)
			}
			s.Config.Audit(u.Username, "mcp."+name, string(args))
			out, err := run(ctx, u, in)
			if err != nil {
				return nil, nil, err
			}
			return nil, out, nil
		})
}

// mcpGet runs a web UI handler as u and returns its decoded JSON.
func (s *Server) mcpGet(ctx context.Context, u *config.User, h http.HandlerFunc, path string, w mcpWindow, extra url.Values, pathValues map[string]string) (any, error) {
	q, err := w.values()
	if err != nil {
		return nil, err
	}
	for k, vs := range extra {
		for _, v := range vs {
			if v != "" {
				q.Add(k, v)
			}
		}
	}
	r, err := http.NewRequestWithContext(context.WithValue(ctx, ctxKey{}, u), http.MethodGet, path+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	for k, v := range pathValues {
		r.SetPathValue(k, v)
	}
	rec := &captureWriter{header: http.Header{}, status: http.StatusOK}
	h(rec, r)
	if rec.status >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(rec.body.Bytes(), &e) == nil && e.Error != "" {
			return nil, errors.New(e.Error)
		}
		return nil, fmt.Errorf("request failed (%d)", rec.status)
	}
	if rec.body.Len() > mcpMaxResult {
		return nil, errors.New("the result is too large: narrow the time range, add filters or ask for fewer rows")
	}
	var out any
	if err := json.Unmarshal(rec.body.Bytes(), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// values turns a window into the query parameters the handlers read.
func (w mcpWindow) values() (url.Values, error) {
	q := url.Values{}
	switch {
	case w.From != "" || w.To != "":
		from, err1 := time.Parse(time.RFC3339, w.From)
		to, err2 := time.Parse(time.RFC3339, w.To)
		if err1 != nil || err2 != nil {
			return nil, errors.New("from and to must both be RFC 3339 times, such as 2026-10-22T14:00:00Z")
		}
		q.Set("from", strconv.FormatInt(from.UnixMilli(), 10))
		q.Set("to", strconv.FormatInt(to.UnixMilli(), 10))
	case w.Range != "":
		q.Set("range", w.Range)
	default:
		q.Set("range", "1h")
	}
	for k, v := range w.Filters {
		if _, ok := store.FilterFields[k]; !ok {
			return nil, fmt.Errorf("unknown filter %q; filters are %s", k, strings.Join(sortedKeys(store.FilterFields), ", "))
		}
		q.Set(k, v)
	}
	return q, nil
}

func (s *Server) mcpLookup(ctx context.Context, u *config.User, in mcpLookupIn) (any, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(in.Address))
	if err != nil {
		return nil, errors.New("address must be an IPv4 or IPv6 address")
	}
	a = a.Unmap()
	w := in.mcpWindow
	w.Filters = map[string]string{"host": a.String()}
	out := map[string]any{"address": a.String(), "local": s.Geo.IsLocal(a)}
	if geo := s.Geo.Lookup(a); geo != (enrich.Info{}) {
		out["geo"] = geo
	}
	if name := s.RDNS.Names(ctx, []netip.Addr{a}, 2*time.Second)[a]; name != "" {
		out["hostname"] = name
	}
	if s.Threats != nil {
		if feeds := s.Threats.Feeds(a); len(feeds) > 0 {
			out["threatFeeds"] = feeds
		}
	}
	for key, req := range map[string]struct {
		h     http.HandlerFunc
		path  string
		extra url.Values
	}{
		"summary":       {s.summary, "/api/summary", nil},
		"conversations": {s.top, "/api/top", url.Values{"dimension": {"conversation"}, "limit": {"10"}}},
		"applications":  {s.top, "/api/top", url.Values{"dimension": {"app"}, "limit": {"10"}}},
	} {
		res, err := s.mcpGet(ctx, u, req.h, req.path, w, req.extra, nil)
		if err != nil {
			return nil, err
		}
		out[key] = res
	}
	return out, nil
}

// captureWriter collects a handler's response.
type captureWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (c *captureWriter) Header() http.Header         { return c.header }
func (c *captureWriter) Write(b []byte) (int, error) { return c.body.Write(b) }
func (c *captureWriter) WriteHeader(code int)        { c.status = code }

func clamp(n, def, max int) string {
	if n <= 0 {
		n = def
	}
	return strconv.Itoa(min(n, max))
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
