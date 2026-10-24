package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kochlabs/tributary/internal/config"
)

// A model that first writes an invalid query is told the error, and its
// correction is checked and returned in canonical form.
func TestAIGenerate(t *testing.T) {
	var prompts []string
	answers := []string{
		`{"query":"dst_prot:22","range":"7d","explanation":"SSH"}`,
		`{"query":"dst_port:22 and not remote_country:us","range":"7d","explanation":"SSH from abroad"}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" {
			var b struct {
				Messages []struct{ Role, Content string }
			}
			json.NewDecoder(r.Body).Decode(&b)
			prompts = append(prompts, b.Messages[0].Content+"\n---\n"+b.Messages[len(b.Messages)-1].Content)
			json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": answers[min(len(prompts)-1, 1)]}}}})
		}
	}))
	defer srv.Close()
	cfg, err := config.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	cfg.SeenExporter("10.0.0.1")
	cfg.UpdateExporter(config.Exporter{Addr: "10.0.0.1", Name: "core router"})
	s := &Server{Config: cfg, Version: "test"}

	set := config.AISettings{Enabled: true, Provider: "openai", URL: srv.URL + "/v1", Model: "m", SendNames: true}
	res, err := s.aiGenerate(context.Background(), set, "ssh from abroad last week")
	if err != nil || res.Error != nil || res.Query != "dst_port:22 AND NOT remote_country:us" || res.Range != "7d" {
		t.Fatalf("%+v %v", res, err)
	}
	if len(prompts) != 2 || !strings.Contains(prompts[1], "unknown field dst_prot (did you mean dst_port?)") {
		t.Fatalf("correction not asked for: %q", prompts)
	}
	if !strings.Contains(prompts[0], `"core router"`) {
		t.Fatal("names not sent")
	}
	set.SendNames = false
	prompts = nil
	s.aiGenerate(context.Background(), set, "x")
	if strings.Contains(prompts[0], "core router") {
		t.Fatal("names sent although turned off")
	}
}
