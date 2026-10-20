package config

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestSNMPInterfacePrecedence(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const e = "192.0.2.1"
	db.LearnInterface(e, 1, "eth0", "learned from NetFlow")
	if n := db.InterfaceName(e, 1); n != "eth0" {
		t.Fatalf("learned: %q", n)
	}
	if err := db.SaveSNMP(e, SNMPConfig{Version: "2c", Community: "public"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveSNMPPoll(e, "rtr1", "RouterOS", []SNMPInterface{{Index: 1, Name: "ether1", Alias: "WAN", Speed: 1e9}, {Index: 7, Name: "bridge"}}, nil); err != nil {
		t.Fatal(err)
	}
	if n := db.InterfaceName(e, 1); n != "ether1" {
		t.Fatalf("SNMP should replace a learned name: %q", n)
	}
	if n := db.InterfaceName(e, 7); n != "bridge" {
		t.Fatalf("SNMP-only interface: %q", n)
	}
	ifs, _ := db.Interfaces(e)
	if len(ifs) != 2 || ifs[0].SNMPAlias != "WAN" || ifs[0].SNMPSpeed != 1e9 || !ifs[0].Learned || ifs[1].Index != 7 {
		t.Fatalf("interfaces: %+v", ifs)
	}
	// Setting only the speed keeps the learned name (still replaceable by SNMP).
	db.LearnInterface(e, 3, "eth3", "")
	if err := db.SaveInterface(Interface{Exporter: e, Index: 3, Speed: 1e9}); err != nil {
		t.Fatal(err)
	}
	if ifs, _ := db.Interfaces(e); ifs[1].Index != 3 || ifs[1].Name != "eth3" || !ifs[1].Learned || ifs[1].Speed != 1e9 {
		t.Fatalf("speed-only edit: %+v", ifs[1])
	}
	// An administrator's name wins over SNMP.
	if err := db.SaveInterface(Interface{Exporter: e, Index: 1, Name: "Uplink"}); err != nil {
		t.Fatal(err)
	}
	if n := db.InterfaceName(e, 1); n != "Uplink" {
		t.Fatalf("manual: %q", n)
	}
	// A failed poll keeps the previous data.
	db.SaveSNMPPoll(e, "", "", nil, errors.New("timeout"))
	if _, st, _ := db.SNMP(e); st.LastError != "timeout" || st.SysName != "rtr1" || st.Interfaces != 2 {
		t.Fatalf("status after failure: %+v", st)
	}
	// Turning SNMP off forgets its data.
	if err := db.SaveSNMP(e, SNMPConfig{}); err != nil {
		t.Fatal(err)
	}
	if n := db.InterfaceName(e, 7); n != "" {
		t.Fatalf("SNMP name kept after turning SNMP off: %q", n)
	}
}

func TestSNMPSecrets(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const e = "192.0.2.2"
	for _, bad := range []SNMPConfig{
		{Version: "2c"},
		{Version: "3"},
		{Version: "3", User: "u", PrivProto: "AES", PrivPass: "longenough"},
		{Version: "3", User: "u", AuthProto: "SHA", AuthPass: "short"},
		{Version: "1", Community: "x"},
		{Version: "2c", Community: "x", Port: 70000},
	} {
		if db.SaveSNMP(e, bad) == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if err := db.SaveSNMP(e, SNMPConfig{Version: "3", User: "nms", AuthProto: "SHA256", AuthPass: "authpass1", PrivProto: "AES", PrivPass: "privpass1"}); err != nil {
		t.Fatal(err)
	}
	var raw string
	db.db.QueryRow("SELECT config FROM exporter_snmp WHERE addr = ?", e).Scan(&raw)
	if strings.Contains(raw, "authpass1") || strings.Contains(raw, "privpass1") {
		t.Fatal("passphrases stored in clear")
	}
	// Empty passphrases keep the stored ones.
	if err := db.SaveSNMP(e, SNMPConfig{Version: "3", User: "nms", AuthProto: "SHA256", PrivProto: "AES"}); err != nil {
		t.Fatal(err)
	}
	s, st, _ := db.SNMP(e)
	if s.AuthPass != "authpass1" || s.PrivPass != "privpass1" {
		t.Fatalf("kept secrets: %+v", s)
	}
	if v := s.View(st); v.AuthPass != "" || !v.HasAuthPass || !v.HasPrivPass {
		t.Fatalf("view: %+v", v)
	}
	// Switching to v2c drops the v3 secrets.
	db.SaveSNMP(e, SNMPConfig{Version: "2c", Community: "c0mm"})
	if s, _, _ := db.SNMP(e); s.AuthPass != "" || s.User != "" || s.Community != "c0mm" {
		t.Fatalf("after switch: %+v", s)
	}
}
