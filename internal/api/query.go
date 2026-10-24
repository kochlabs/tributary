package api

import (
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/kochlabs/tributary/internal/names"
	"github.com/kochlabs/tributary/internal/query"
	"github.com/kochlabs/tributary/internal/store"
)

// The query language (docs/design/QUERY-LANGUAGE.md): endpoints that take
// filters also take q, and the two are combined with AND. Warnings go in a
// header, so every endpoint carries them without changing its body.

// warningsHeader carries a query's warnings as a JSON array.
const warningsHeader = "X-Query-Warnings"

// queryNames resolves names in queries the way Tributary names hosts:
// inventory, names set here (devices, exporters), reverse DNS.
type queryNames struct{ s *Server }

func (n queryNames) HostAddrs(pattern string) []netip.Addr {
	match := func(name string) bool { return names.Match(name, pattern) }
	out := n.s.Inventory.Index().AddrsMatching(match)
	for _, e := range n.s.Config.Exporters() {
		if a, err := netip.ParseAddr(e.Addr); err == nil && match(e.Name) {
			out = append(out, a)
		}
	}
	if devs, err := n.s.Config.Devices(); err == nil {
		for _, d := range devs {
			if !match(d.Name) {
				continue
			}
			for _, ip := range d.IPs {
				if a, err := netip.ParseAddr(ip.IP); err == nil {
					out = append(out, a)
				}
			}
		}
	}
	if n.s.RDNS != nil {
		out = append(out, n.s.RDNS.AddrsMatching(match)...)
	}
	for i, a := range out {
		out[i] = a.Unmap()
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out)
}

func (n queryNames) DeviceMACs(pattern string) []uint64 {
	match := func(name string) bool { return names.Match(name, pattern) }
	var out []uint64
	if devs, err := n.s.Config.Devices(); err == nil {
		for _, d := range devs {
			if match(d.Name) {
				out = append(out, d.MAC)
			}
		}
	}
	for _, m := range n.s.Inventory.Index().MACsMatching(match) {
		if mac, ok := query.ParseMAC(m); ok {
			out = append(out, mac)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// compileQuery parses and compiles a query against this appliance's names.
func (s *Server) compileQuery(q string) (*store.Filter, []query.Warning, string, error) {
	n, err := query.Parse(q)
	if err != nil {
		return nil, nil, "", err
	}
	f, warns, err := store.CompileQuery(n, queryNames{s})
	if err != nil {
		return nil, nil, "", err
	}
	return f, warns, query.Format(n), nil
}

// parseQuery reads the time range, filters and query of a request. On a bad
// request it writes the error and returns false.
func (s *Server) parseQuery(w http.ResponseWriter, r *http.Request) (store.Query, bool) {
	q, err := parseQueryParams(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return q, false
	}
	if text := r.URL.Query().Get("q"); text != "" {
		f, warns, _, err := s.compileQuery(text)
		if err != nil {
			writeQueryErr(w, text, err)
			return q, false
		}
		q.Filter = q.Filter.And(f)
		if len(warns) > 0 {
			b, _ := json.Marshal(warns)
			w.Header().Set(warningsHeader, string(b))
		}
	}
	return q, true
}

// writeQueryErr writes a query error with its position and hint. Positions
// count UTF-16 units, as browsers index text.
func writeQueryErr(w http.ResponseWriter, text string, err error) {
	var qe *query.Error
	if errors.As(err, &qe) {
		e := *qe
		e.Span = utf16Span(text, e.Span)
		writeJSON(w, http.StatusBadRequest, e)
		return
	}
	writeErr(w, http.StatusBadRequest, err.Error())
}

// utf16Span converts a span in bytes of text to UTF-16 units.
func utf16Span(text string, s query.Span) query.Span {
	units := func(b string) int { return len(utf16.Encode([]rune(b))) }
	end := min(s.Pos+s.Len, len(text))
	start := min(s.Pos, end)
	return query.Span{Pos: units(text[:start]), Len: units(text[start:end])}
}

// queryCheck validates a query as it is typed: its canonical form and
// warnings, or the error. An invalid query is a successful check, so the
// error comes back with status 200.
func (s *Server) queryCheck(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("q")
	_, warns, canonical, err := s.compileQuery(text)
	var qe *query.Error
	if errors.As(err, &qe) {
		e := *qe
		e.Span = utf16Span(text, e.Span)
		writeJSON(w, http.StatusOK, map[string]any{"error": e})
		return
	} else if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if warns == nil {
		warns = []query.Warning{}
	}
	for i := range warns {
		warns[i].Span = utf16Span(text, warns[i].Span)
	}
	writeJSON(w, http.StatusOK, map[string]any{"query": canonical, "warnings": warns})
}

// suggestion is one completion: the text shown, the text inserted.
type suggestion struct {
	Label  string `json:"label"`
	Apply  string `json:"apply"`
	Detail string `json:"detail,omitempty"`
	Kind   string `json:"kind"` // field | value | keyword
}

// maxSuggestions caps one answer.
const maxSuggestions = 50

// querySuggest completes the query at the cursor: field names, or values
// for the field there. pos and the returned from/to count UTF-16 units.
func (s *Server) querySuggest(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("q")
	pos, _ := strconv.Atoi(r.URL.Query().Get("pos"))
	c := query.Complete(text, byteOffset(text, pos))
	var out []suggestion
	switch c.Kind {
	case query.CompleteField:
		if c.AfterTerm {
			for _, kw := range []string{"AND", "OR", "NOT"} {
				out = append(out, suggestion{Label: kw, Apply: kw + " ", Kind: "keyword"})
			}
		}
		for _, f := range store.QueryFieldNames() {
			out = append(out, suggestion{Label: f, Apply: f + ":", Kind: "field"})
		}
	case query.CompleteValue:
		out = s.valueSuggestions(c.Field)
	}
	// Keep what starts with the typed text, then what contains it (in the
	// label or the detail: "germ" finds DE).
	prefix := strings.ToLower(strings.TrimPrefix(c.Prefix, `"`))
	var first, rest []suggestion
	for _, o := range out {
		l := strings.ToLower(o.Label)
		switch {
		case strings.HasPrefix(l, prefix):
			first = append(first, o)
		case prefix != "" && (strings.Contains(l, prefix) || strings.Contains(strings.ToLower(o.Detail), prefix)):
			rest = append(rest, o)
		}
	}
	out = append(first, rest...)
	if len(out) > maxSuggestions {
		out = out[:maxSuggestions]
	}
	if out == nil {
		out = []suggestion{}
	}
	span := utf16Span(text, query.Span{Pos: c.From, Len: c.To - c.From})
	writeJSON(w, http.StatusOK, map[string]any{"from": span.Pos, "to": span.Pos + span.Len, "options": out})
}

// byteOffset converts a UTF-16 offset into text to bytes.
func byteOffset(text string, units int) int {
	n := 0
	for i, r := range text {
		if n >= units {
			return i
		}
		n += utf16.RuneLen(r)
	}
	return len(text)
}

func (s *Server) valueSuggestions(field string) []suggestion {
	var out []suggestion
	add := func(label, detail string) {
		out = append(out, suggestion{Label: label, Apply: query.Quote(label, false) + " ", Detail: detail, Kind: "value"})
	}
	hostNames := func() {
		seen := map[string]bool{}
		addName := func(n, detail string) {
			if n != "" && !seen[strings.ToLower(n)] {
				seen[strings.ToLower(n)] = true
				add(n, detail)
			}
		}
		if devs, err := s.Config.Devices(); err == nil {
			for _, d := range devs {
				addName(d.Name, "device")
			}
		}
		for _, e := range s.Config.Exporters() {
			addName(e.Name, "exporter")
		}
		for _, n := range s.Inventory.Index().Names() {
			addName(n, "inventory")
		}
	}
	switch field := strings.ToLower(field); field {
	case "host", "src", "dst", "local", "remote", "nexthop", "ip", "addr", "ip.addr", "ip.src", "ip.dst", "peer":
		hostNames()
	case "exporter":
		for _, e := range s.Config.Exporters() {
			if e.Name != "" {
				add(e.Name, e.Addr)
			} else {
				add(e.Addr, "")
			}
		}
	case "device":
		if devs, err := s.Config.Devices(); err == nil {
			for _, d := range devs {
				if d.Name != "" {
					add(d.Name, "")
				}
			}
		}
	case "threat":
		if feeds, err := s.Config.ThreatFeeds(); err == nil {
			for _, f := range feeds {
				if f.Enabled {
					add(f.Name, "")
				}
			}
		}
		add("*", "any feed")
		out[len(out)-1].Apply = "* "
	case "proto":
		for _, p := range store.ProtoNames() {
			add(p, "")
		}
	case "port", "src_port", "dst_port", "sport", "dport", "tcp.port", "udp.port":
		for _, p := range names.WellKnownPorts() {
			add(strconv.Itoa(int(p)), names.Service(p))
		}
	case "app":
		for _, p := range names.WellKnownPorts() {
			add("tcp/"+strconv.Itoa(int(p)), names.Service(p))
			add("udp/"+strconv.Itoa(int(p)), names.Service(p))
		}
	case "country", "src_country", "dst_country", "remote_country":
		if s.Geo != nil {
			cs := s.Geo.Countries()
			codes := slices.Sorted(maps.Keys(cs))
			for _, c := range codes {
				add(c, cs[c])
			}
		}
	case "direction":
		for _, d := range []string{"download", "upload", "internal", "transit"} {
			add(d, "")
		}
	case "flags":
		for _, f := range []string{"syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr"} {
			add(f, "")
		}
	case "etype":
		add("ipv4", "")
		add("ipv6", "")
	}
	return out
}
