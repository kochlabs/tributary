package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/kochlabs/tributary/internal/config"
)

func TestNoticesFilteredByRole(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("GET", "/api/notices", nil)
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, &config.User{Username: "u", Role: "admin"}))
	w := httptest.NewRecorder()
	s.noticesList(w, r)
	if w.Code != 503 {
		t.Fatalf("before the first check: %d", w.Code)
	}
	list := []Notice{
		{ID: "disk", Level: "warning", Action: &NoticeAction{Label: "Retention settings", Route: "/admin/settings", admin: true}},
		{ID: "updates", Level: "info", adminOnly: true, Action: &NoticeAction{Label: "View updates", Route: "/admin/updates", admin: true}},
		{ID: "silent", Level: "warning", Action: &NoticeAction{Label: "Exporters", Route: "/exporters"}},
	}
	s.notices.Store(&list)
	get := func(role string) []Notice {
		r := httptest.NewRequest("GET", "/api/notices", nil)
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, &config.User{Username: "u", Role: role}))
		w := httptest.NewRecorder()
		s.noticesList(w, r)
		var out []Notice
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := get("admin"); len(got) != 3 || got[0].Action == nil {
		t.Fatalf("admin: %+v", got)
	}
	v := get("viewer")
	if len(v) != 2 || v[0].ID != "disk" || v[0].Action != nil || v[1].Action == nil {
		t.Fatalf("viewer: %+v", v)
	}
	// The stored list must not be modified by filtering.
	if list[0].Action == nil {
		t.Fatal("filtering changed the stored notice")
	}
}

func TestDiskUsageDedupes(t *testing.T) {
	d := diskUsage([]string{"/", "/", t.TempDir(), "/nonexistent-path"})
	if len(d) == 0 || d[0].total == 0 || d[0].free > d[0].total {
		t.Fatalf("%+v", d)
	}
	for i := range d {
		for j := i + 1; j < len(d); j++ {
			if d[i].total == d[j].total && d[i].free == d[j].free && d[i].path == d[j].path {
				t.Fatalf("duplicate %+v", d)
			}
		}
	}
	if humanBytes(1536) != "1.5 KiB" || humanBytes(5<<30) != "5.0 GiB" {
		t.Fatal(humanBytes(1536), humanBytes(5<<30))
	}
}
