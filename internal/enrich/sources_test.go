package enrich

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
)

func TestParseOUIFormats(t *testing.T) {
	manuf := "# comment\n00:00:0C\tCisco\tCisco Systems, Inc\n00:1B:C5:00:00:00/36\tConverging\tConverging Systems Inc.\n70:B3:D5:F0:00:00/28\tShort\n"
	ieee := "Registry,Assignment,Organization Name,Organization Address\n" +
		"MA-L,3C22FB,\"Apple, Inc.\",\"1 Infinite Loop Cupertino CA US 95014 \"\n" +
		"MA-M,C85CE27,SYNERGY SYSTEMS AND SOLUTIONS,\"A1526 Faridabad IN\"\n" +
		"MA-S,8C1F64F5A,Example Sensors,Somewhere\n"
	tbl := newOUITable()
	if err := parseOUI(strings.NewReader(manuf), tbl); err != nil {
		t.Fatal(err)
	}
	if err := parseOUI(strings.NewReader(ieee), tbl); err != nil {
		t.Fatal(err)
	}
	ouiCur.Store(tbl)
	defer ouiCur.Store(nil)
	for mac, want := range map[uint64]string{
		0x00000C123456: "Cisco Systems, Inc",
		0x001BC5000ABC: "Converging Systems Inc.",
		0x70B3D5F12345: "Short",
		0x3C22FB010203: "Apple, Inc.",
		0xC85CE2712345: "SYNERGY SYSTEMS AND SOLUTIONS",
		0x8C1F64F5A123: "Example Sensors",
		0x8C1F64F5B123: "",
	} {
		if got := Vendor(mac); got != want {
			t.Errorf("Vendor(%012x) = %q, want %q", mac, got, want)
		}
	}
}

func TestVendorEmptyUntilLoaded(t *testing.T) {
	ouiCur.Store(nil)
	if v := Vendor(0x3C22FB010203); v != "" {
		t.Fatalf("vendor data without a loaded table: %q", v)
	}
	if v := Vendor(0x3E22FB010203); v != "Private (randomized) address" {
		t.Fatalf("randomized: %q", v)
	}
}

func TestUnpack(t *testing.T) {
	payload := []byte("database bytes")
	gz := func(b []byte) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write(b)
		zw.Close()
		return buf.Bytes()
	}
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, f := range []struct{ name, body string }{{"GeoLite2-ASN_20261010/LICENSE.txt", "license"}, {"GeoLite2-ASN_20261010/GeoLite2-ASN.mmdb", string(payload)}} {
		tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(f.body))
	}
	tw.Close()
	for name, in := range map[string][]byte{"raw": payload, "gzip": gz(payload), "tar.gz": gz(tarBuf.Bytes())} {
		r, err := unpack(bytes.NewReader(in), ".mmdb")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, _ := io.ReadAll(r)
		if !bytes.Equal(got, payload) {
			t.Errorf("%s: got %q", name, got)
		}
	}
}

func TestAttribution(t *testing.T) {
	for typ, want := range map[string]string{
		"DBIP-Country-Lite":                     "IP Geolocation by DB-IP",
		"DBIP-ASN-Lite (compat=GeoLite2-ASN)":   "IP Geolocation by DB-IP",
		"GeoLite2-ASN":                          "This product includes GeoLite2 data created by MaxMind",
		"GeoIP2-Country":                        "",
		"DBIP-Location-ISP (compat=Enterprise)": "",
	} {
		got := ""
		if a := attributionFor(typ); a != nil {
			got = a.Text
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", typ, got, want)
		}
	}
}

func TestRedact(t *testing.T) {
	u := "https://db-ip.com/account/SECRETKEY/db/ip-to-asn/mmdb?key=abc123"
	err := redact(io.ErrUnexpectedEOF, u)
	if strings.Contains(err.Error(), "SECRETKEY") {
		t.Fatal("key leaked")
	}
	err = redact(&wrapErr{"Get \"" + u + "\": EOF"}, u)
	if strings.Contains(err.Error(), "SECRETKEY") || strings.Contains(err.Error(), "abc123") {
		t.Fatalf("key leaked: %v", err)
	}
}

type wrapErr struct{ s string }

func (e *wrapErr) Error() string { return e.s }
