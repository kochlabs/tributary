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
	call := func(tool string, args map[string]any) map[string]any {
		res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		if res.IsError {
			t.Fatalf("%s: %s", tool, res.Content[0].(*mcp.TextContent).Text)
		}
		b, _ := json.Marshal(res.StructuredContent)
		t.Logf("%-18s %6d bytes  %.120s", tool, len(b), b)
		var out map[string]any
		json.Unmarshal(b, &out)
		return out
	}

	// An exporter and a busy local host from the appliance's own data.
	exporter, host := "", ""
	if res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "exporters", Arguments: map[string]any{"range": "24h"}}); err == nil && !res.IsError {
		if list, ok := res.StructuredContent.([]any); ok && len(list) > 0 {
			exporter, _ = list[0].(map[string]any)["addr"].(string)
		}
	}
	if top := call("top", map[string]any{"dimension": "local_host", "range": "24h", "limit": 1}); top != nil {
		if rows, ok := top["rows"].([]any); ok && len(rows) > 0 {
			host, _ = rows[0].(map[string]any)["key"].(string)
		}
	}
	if exporter == "" || host == "" {
		t.Fatalf("no data to test with (exporter %q, host %q)", exporter, host)
	}

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
		{"interfaces", map[string]any{"exporter": exporter, "range": "1h"}},
		{"devices", map[string]any{"range": "1h"}},
		{"lookup_address", map[string]any{"address": host, "range": "1h"}},
		{"top", map[string]any{"dimension": "threat", "range": "6h"}},
		{"threat_feeds", nil},
		{"appliance_health", nil},
	}
	for _, c := range calls {
		if out := call(c.tool, c.args); len(out) == 0 && c.tool != "exporters" && c.tool != "interfaces" {
			t.Fatalf("%s: empty result", c.tool)
		}
	}
}
