package config

import "testing"

func TestSyslogValidate(t *testing.T) {
	s := Syslog{Enabled: true, Targets: []SyslogTarget{{Address: " logs.example.com ", Transport: "tls"}, {Address: "", Transport: "udp"}, {Address: "[2001:db8::5]:1514", Transport: "tcp"}}}
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	if len(s.Targets) != 2 || s.Targets[0].HostPort() != "logs.example.com:6514" || s.Targets[1].HostPort() != "[2001:db8::5]:1514" || s.Format != "rfc5424" {
		t.Fatalf("%+v %s", s, s.Targets[0].HostPort())
	}
	if (Syslog{Targets: []SyslogTarget{{Address: "h", Transport: "udp"}}}).Targets[0].HostPort() != "h:514" {
		t.Fatal("udp default port")
	}
	for _, bad := range []Syslog{
		{Enabled: true},
		{Targets: []SyslogTarget{{Address: "h", Transport: "sctp"}}},
		{Targets: []SyslogTarget{{Address: "h:99999", Transport: "udp"}}},
		{Facility: 24},
		{Format: "cef"},
	} {
		if bad.validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
