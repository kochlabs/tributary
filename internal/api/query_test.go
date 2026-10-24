package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kochlabs/tributary/internal/config"
)

func TestParseQueryParam(t *testing.T) {
	cfg, err := config.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	cfg.SeenExporter("10.0.0.1")
	cfg.UpdateExporter(config.Exporter{Addr: "10.0.0.1", Name: "core-router"})
	s := &Server{Config: cfg}

	get := func(url string) (*httptest.ResponseRecorder, bool) {
		w := httptest.NewRecorder()
		_, ok := s.parseQuery(w, httptest.NewRequest("GET", url, nil))
		return w, ok
	}
	// A name resolves; an unknown one is a warning, not an error.
	if w, ok := get("/api/flows?range=1h&q=exporter:core-router"); !ok || w.Header().Get(warningsHeader) != "" {
		t.Fatalf("named exporter: %v %s %s", ok, w.Body, w.Header())
	}
	w, ok := get("/api/flows?range=1h&q=host:nass+OR+port:22&proto=tcp")
	if !ok || !strings.Contains(w.Header().Get(warningsHeader), "no host named nass") {
		t.Fatalf("warning: %v %s", ok, w.Header())
	}
	// An error says where.
	w, ok = get("/api/flows?range=1h&q=dst_prot:443")
	var e struct {
		Error, Hint string
		Pos, Len    int
	}
	json.Unmarshal(w.Body.Bytes(), &e)
	if ok || w.Code != 400 || e.Error != "unknown field dst_prot" || e.Hint != "did you mean dst_port?" || e.Pos != 0 || e.Len != 8 {
		t.Fatalf("error: %v %d %s", ok, w.Code, w.Body)
	}

	// Positions count UTF-16 units, as the browser does.
	w = httptest.NewRecorder()
	s.queryCheck(w, httptest.NewRequest("GET", "/api/query/check?q=device:%22Caf%C3%A9+TV%22+bogus:1", nil))
	var chk struct{ Error struct{ Pos, Len int } }
	json.Unmarshal(w.Body.Bytes(), &chk)
	if w.Code != 200 || chk.Error.Pos != 17 || chk.Error.Len != 5 { // 18 in bytes: é is two
		t.Fatalf("utf-16 position: %s", w.Body)
	}

	// check gives the canonical form.
	w = httptest.NewRecorder()
	s.queryCheck(w, httptest.NewRequest("GET", "/api/query/check?q=dst_port:(80+443)+not+country:us", nil))
	var res struct {
		Query    string
		Warnings []any
	}
	json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 200 || res.Query != "dst_port:(80 OR 443) OR NOT country:us" || res.Warnings == nil {
		t.Fatalf("check: %d %s", w.Code, w.Body)
	}
}

func TestQuerySuggest(t *testing.T) {
	cfg, err := config.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	cfg.SeenExporter("10.0.0.1")
	cfg.UpdateExporter(config.Exporter{Addr: "10.0.0.1", Name: "core router"})
	s := &Server{Config: cfg}
	suggest := func(q string) (from, to int, labels []string, applies []string) {
		pos := strings.Index(q, "|")
		q = strings.Replace(q, "|", "", 1)
		w := httptest.NewRecorder()
		s.querySuggest(w, httptest.NewRequest("GET", "/api/query/suggest?q="+url.QueryEscape(q)+"&pos="+strconv.Itoa(pos), nil))
		var res struct {
			From, To int
			Options  []suggestion
		}
		json.Unmarshal(w.Body.Bytes(), &res)
		for _, o := range res.Options {
			labels, applies = append(labels, o.Label), append(applies, o.Apply)
		}
		return res.From, res.To, labels, applies
	}
	if _, _, labels, applies := suggest("dst_p|"); len(labels) != 1 || labels[0] != "dst_port" || applies[0] != "dst_port:" {
		t.Fatalf("field: %v %v", labels, applies)
	}
	if from, to, labels, applies := suggest("exporter:co|"); from != 9 || to != 11 || len(labels) != 1 || applies[0] != `"core router" ` {
		t.Fatalf("value: %d-%d %v %v", from, to, labels, applies)
	}
	if _, _, labels, _ := suggest("dst_port:ss|"); len(labels) == 0 || labels[0] != "22" {
		t.Fatalf("a service's name finds its port: %v", labels)
	}
	if _, _, labels, _ := suggest("host:nas |"); labels[0] != "AND" {
		t.Fatalf("after a term: %v", labels)
	}
	if from, _, _, _ := suggest(`device:"Café" exporter:|`); from != 23 {
		t.Fatalf("UTF-16 positions: %d", from)
	}
}
