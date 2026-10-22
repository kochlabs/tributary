package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestMCPLive calls every tool against a running appliance with flow data
// when NFA_TEST_MCP is set to "<endpoint>|<token>" (the certificate isn't
// verified).
func TestMCPLive(t *testing.T) {
	spec := os.Getenv("NFA_TEST_MCP")
	if spec == "" {
		t.Skip("NFA_TEST_MCP not set")
	}
	endpoint, token, _ := strings.Cut(spec, "|")
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	c := mcp.NewClient(&mcp.Implementation{Name: "live-test", Version: "1"}, nil)
	sess, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: endpoint,
		HTTPClient: &http.Client{Transport: bearer{token, tr}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	calls := []struct {
		tool string
		args map[string]any
	}{
		{"summary", map[string]any{"range": "6h"}},
		{"top", map[string]any{"dimension": "remote_as", "range": "6h", "limit": 5}},
		{"top", map[string]any{"dimension": "conversation", "range": "1h", "filters": map[string]any{"app": "tcp/443"}}},
		{"traffic_over_time", map[string]any{"range": "6h", "group_by": "app", "limit": 3}},
		{"traffic_paths", map[string]any{"range": "6h", "dimensions": []any{"device", "app", "remote_as"}}},
		{"search_flows", map[string]any{"range": "15m", "sort": "bytes", "limit": 5}},
		{"exporters", map[string]any{"range": "1h"}},
		{"interfaces", map[string]any{"exporter": "127.0.1.1", "range": "1h"}},
		{"devices", map[string]any{"range": "1h"}},
		{"lookup_address", map[string]any{"address": "10.10.0.10", "range": "1h"}},
		{"appliance_health", nil},
	}
	for _, call := range calls {
		res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: call.tool, Arguments: call.args})
		if err != nil {
			t.Fatalf("%s: %v", call.tool, err)
		}
		if res.IsError {
			t.Fatalf("%s: %s", call.tool, res.Content[0].(*mcp.TextContent).Text)
		}
		b, _ := json.Marshal(res.StructuredContent)
		if len(b) < 20 {
			t.Fatalf("%s: almost empty result %s", call.tool, b)
		}
		t.Logf("%-18s %6d bytes  %.120s", call.tool, len(b), b)
	}
}
