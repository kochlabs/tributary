package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnthropic(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "from-the-environment")
	var got map[string]any
	var gotKey, gotBeta string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/gw/v1/models":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{
				map[string]any{"id": "claude-x", "display_name": "Claude X", "type": "model", "lifecycle": "active", "capabilities": map[string]any{"structured_outputs": map[string]any{"supported": true}}},
				map[string]any{"id": "old", "display_name": "Old", "type": "model", "lifecycle": "retired"},
			}, "has_more": false})
		case "/gw/v1/messages":
			gotBeta = r.Header.Get("anthropic-beta")
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), "messages\":[") { // the endpoint probe
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]any{"type": "invalid_request_error", "message": "messages: field required"}})
				return
			}
			json.Unmarshal(b, &got)
			json.NewEncoder(w).Encode(map[string]any{"id": "m", "type": "message", "role": "assistant", "model": "claude-x", "stop_reason": "end_turn",
				"content": []any{map[string]any{"type": "text", "text": `{"query":"dst_port:22","range":"","explanation":"SSH"}`}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	p, _ := New(Config{Provider: "anthropic", URL: srv.URL + "/gw/", APIKey: "configured", Client: srv.Client()})
	models, err := p.Models(context.Background())
	if err != nil || len(models) != 1 || models[0].ID != "claude-x" || models[0].Name != "Claude X" {
		t.Fatalf("models: %+v %v", models, err)
	}
	if gotKey != "configured" {
		t.Fatalf("sent key %q: only the configured key may be used", gotKey)
	}
	reply, err := p.Complete(context.Background(), "claude-x", "sys", []Message{{"user", "ssh"}, {"assistant", "x"}, {"user", "again"}}, map[string]any{"type": "object"})
	if err != nil || !strings.Contains(reply, "dst_port:22") {
		t.Fatalf("complete: %q %v", reply, err)
	}
	oc, _ := got["output_config"].(map[string]any)
	if oc == nil || oc["format"] == nil || len(got["messages"].([]any)) != 3 {
		t.Fatalf("request: %v", got)
	}
	if gotBeta != "" || got["fallbacks"] != nil {
		t.Fatalf("fallbacks sent to a gateway: %q %v", gotBeta, got["fallbacks"])
	}
}

func TestOpenAI(t *testing.T) {
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/models":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "b"}, map[string]any{"id": "a"}}})
		case "/v1/chat/completions":
			var b map[string]any
			json.NewDecoder(r.Body).Decode(&b)
			bodies = append(bodies, b)
			if b["response_format"] != nil { // a server without JSON schemas
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "response_format not supported"}})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": "<think>hmm {not this}</think>\n```json\n{\"query\":\"proto:udp\"}\n```"}}}})
		}
	}))
	defer srv.Close()
	p, _ := New(Config{Provider: "openai", URL: srv.URL + "/v1", APIKey: "k", Client: srv.Client()})
	if m, err := p.Models(context.Background()); err != nil || len(m) != 2 || m[0].ID != "a" {
		t.Fatalf("models: %v %v", m, err)
	}
	reply, err := p.Complete(context.Background(), "a", "sys", []Message{{"user", "udp"}}, map[string]any{"type": "object"})
	if err != nil || len(bodies) != 2 {
		t.Fatalf("complete: %v (%d requests)", err, len(bodies))
	}
	var ans struct{ Query string }
	if err := ParseJSON(reply, &ans); err != nil || ans.Query != "proto:udp" {
		t.Fatalf("parse: %+v %v", ans, err)
	}
	bad, _ := New(Config{Provider: "openai", URL: srv.URL + "/v1", APIKey: "wrong", Client: srv.Client()})
	if _, err := bad.Models(context.Background()); err == nil || err.Error() != "the API key was rejected" {
		t.Fatalf("bad key: %v", err)
	}
}

// A gateway's root answers the OpenAI-style model list but not the Messages
// API: the error says which URL to use.
func TestAnthropicWrongEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/messages" {
			w.Header().Set("Content-Type", "text/plain")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()
	p, _ := New(Config{Provider: "anthropic", URL: srv.URL, Client: srv.Client()})
	_, err := p.Complete(context.Background(), "m", "s", []Message{{"user", "x"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "https://gateway/anthropic") {
		t.Fatalf("%v", err)
	}
	// Caught when listing models, before a model is even chosen.
	if _, err := p.Models(context.Background()); err == nil || !strings.Contains(err.Error(), "https://gateway/anthropic") {
		t.Fatalf("models: %v", err)
	}
}
