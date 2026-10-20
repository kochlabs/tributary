package snmp

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/kochlabs/tributary/internal/config"
)

// Runs against a real agent: NFA_TEST_SNMP=127.0.0.1:16161 with community
// "testcomm" and v3 user nmsuser (SHA-256 "authpass123", AES "privpass123").
func TestQueryLive(t *testing.T) {
	agent := os.Getenv("NFA_TEST_SNMP")
	if agent == "" {
		t.Skip("set NFA_TEST_SNMP to run against an SNMP agent")
	}
	host, port, _ := strings.Cut(agent, ":")
	var p int
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	ctx := context.Background()
	for name, s := range map[string]config.SNMPConfig{
		"v2c": {Version: "2c", Host: host, Port: p, Community: "testcomm"},
		"v3":  {Version: "3", Host: host, Port: p, User: "nmsuser", AuthProto: "SHA256", AuthPass: "authpass123", PrivProto: "AES", PrivPass: "privpass123"},
	} {
		res, err := Query(ctx, "192.0.2.1", s)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Logf("%s: sysName=%q sysDescr=%q interfaces=%+v", name, res.SysName, res.SysDescr, res.Interfaces)
		if res.SysName != "test-router-01" || len(res.Interfaces) < 2 {
			t.Fatalf("%s: %+v", name, res)
		}
		found := false
		for _, i := range res.Interfaces {
			if i.Name == "lo" && i.Speed == 10_000_000 {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: lo with 10 Mbit/s not found", name)
		}
	}
	if _, err := Query(ctx, "x", config.SNMPConfig{Version: "2c", Host: host, Port: p, Community: "wrong"}); err == nil || !strings.Contains(err.Error(), "no response") {
		t.Errorf("wrong community: %v", err)
	}
	if _, err := Query(ctx, "x", config.SNMPConfig{Version: "3", Host: host, Port: p, User: "nmsuser", AuthProto: "SHA256", AuthPass: "wrongpass1", PrivProto: "AES", PrivPass: "privpass123"}); err == nil {
		t.Error("wrong v3 passphrase accepted")
	} else {
		t.Logf("wrong v3 passphrase: %v", err)
	}
}
