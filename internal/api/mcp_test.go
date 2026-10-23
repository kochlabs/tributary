package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kochlabs/tributary/internal/config"
)

// bearer adds an Authorization header to every request.
type bearer struct {
	token string
	next  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(r)
}

func mcpSession(t *testing.T, endpoint, token string) (*mcp.ClientSession, error) {
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	return c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: endpoint,
		HTTPClient: &http.Client{Transport: bearer{token, http.DefaultTransport}}}, nil)
}

func rawPost(t *testing.T, url string, header map[string]string) int {
	req, _ := http.NewRequest("POST", url, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestMCPEndpoint(t *testing.T) {
	cfg, err := config.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Config: cfg, Version: "test"}
	app := httptest.NewServer(s.Handler())
	defer app.Close()
	endpoint := app.URL + "/mcp"
	cfg.CreateUser(config.User{Username: "viewer", Role: "viewer"}, "Viewer-pass-1")
	cfg.CreateUser(config.User{Username: "admin", Role: "admin"}, "Admin-pass-12")

	// Administrators manage tokens, for any user; viewers can't.
	v := newClient(t, app.URL)
	v.post("/api/auth/login", map[string]string{"username": "viewer", "password": "Viewer-pass-1"})
	if code, _, _ := v.do("GET", "/api/tokens", nil); code != http.StatusForbidden {
		t.Fatalf("viewer listed tokens: %d", code)
	}
	if code, _, _ := v.do("POST", "/api/tokens", map[string]any{"username": "viewer", "name": "x"}); code != http.StatusForbidden {
		t.Fatalf("viewer created a token: %d", code)
	}
	c := newClient(t, app.URL)
	c.post("/api/auth/login", map[string]string{"username": "admin", "password": "Admin-pass-12"})
	if code, _, _ := c.do("POST", "/api/tokens", map[string]any{"username": "nobody", "name": "x"}); code != http.StatusBadRequest {
		t.Fatalf("token for a missing user: %d", code)
	}
	code, out, raw := c.do("POST", "/api/tokens", map[string]any{"username": "viewer", "name": "claude", "days": 30})
	token, _ := out["token"].(string)
	if code != 200 || !strings.HasPrefix(token, config.APITokenPrefix) {
		t.Fatalf("create token: %d %s", code, raw)
	}
	if code, out, list := c.do("GET", "/api/tokens", nil); code != 200 || len(out["tokens"].([]any)) != 1 || strings.Contains(list, token) {
		t.Fatalf("list (must not include the secret): %d %s", code, list)
	}

	// Off by default.
	if code := rawPost(t, endpoint, map[string]string{"Authorization": "Bearer " + token}); code != http.StatusNotFound {
		t.Fatalf("while off: %d", code)
	}
	st := cfg.Settings()
	st.MCPEnabled = true
	cfg.SaveSettings(st)
	if code := rawPost(t, endpoint, nil); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	if code := rawPost(t, endpoint, map[string]string{"Authorization": "Bearer trb_wrong"}); code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", code)
	}
	if code := rawPost(t, endpoint, map[string]string{"Authorization": "Bearer " + token, "Sec-Fetch-Site": "cross-site"}); code != http.StatusForbidden {
		t.Fatalf("cross-site browser request: %d", code)
	}

	sess, err := mcpSession(t, endpoint, token)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if sess.InitializeResult().ServerInfo.Name != "tributary" || sess.InitializeResult().Instructions == "" {
		t.Fatalf("init: %+v", sess.InitializeResult())
	}
	tools, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
		if tl.Annotations == nil || !tl.Annotations.ReadOnlyHint {
			t.Fatalf("%s is not marked read-only", tl.Name)
		}
	}
	if len(names) != 11 {
		t.Fatalf("tools: %v", names)
	}
	// Input errors come back as tool errors the assistant can read.
	for args, want := range map[string]map[string]any{
		"unknown filter": {"dimension": "app", "filters": map[string]any{"hostname": "x"}},
		"RFC 3339":       {"dimension": "app", "from": "yesterday", "to": "now"},
	} {
		res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "top", Arguments: want})
		if err != nil || !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, args) {
			t.Fatalf("%s: %v %+v", args, err, res)
		}
	}
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "interfaces", Arguments: map[string]any{"exporter": "router"}})
	if err != nil || !res.IsError {
		t.Fatalf("bad exporter: %v %+v", err, res)
	}
	// Calls are audited as the token's user.
	entries, _ := cfg.AuditLog(20)
	found := false
	for _, e := range entries {
		found = found || (e.Username == "viewer" && e.Action == "mcp.top")
	}
	if !found {
		t.Fatal("tool call not audited")
	}

	// A revoked token stops working.
	list, _ := cfg.APITokens("viewer")
	if code, _, _ := c.do("DELETE", "/api/tokens/"+strconv.FormatInt(list[0].ID, 10), nil); code != 200 {
		t.Fatal("revoke")
	}
	if code := rawPost(t, endpoint, map[string]string{"Authorization": "Bearer " + token}); code != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d", code)
	}

	// Rate limit per token.
	token2, _, _ := cfg.CreateAPIToken("viewer", "busy", 0)
	limited := false
	for i := 0; i <= mcpCallsPerMinute && !limited; i++ {
		limited = rawPost(t, endpoint, map[string]string{"Authorization": "Bearer " + token2}) == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("no rate limit")
	}
}
