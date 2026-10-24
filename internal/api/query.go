package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"slices"
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
