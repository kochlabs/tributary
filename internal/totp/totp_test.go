package totp

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B test vector for SHA1 (secret "12345678901234567890").
func TestRFC6238(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for _, tc := range []struct {
		unix int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		got, err := Code(secret, tc.unix/Period)
		if err != nil || got != tc.want {
			t.Errorf("t=%d: %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestValidate(t *testing.T) {
	s := NewSecret()
	now := time.Unix(1_800_000_000, 0)
	c, _ := Code(s, Step(now))
	step, ok := Validate(s, c, now, 0)
	if !ok {
		t.Fatal("current code rejected")
	}
	if _, ok := Validate(s, c, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	prev, _ := Code(s, Step(now)-1)
	if _, ok := Validate(s, prev[:3]+" "+prev[3:], now, 0); !ok {
		t.Fatal("previous step (with a space) rejected")
	}
	old, _ := Code(s, Step(now)-3)
	if _, ok := Validate(s, old, now, 0); ok {
		t.Fatal("code from 90 s ago accepted")
	}
	if _, ok := Validate(s, "12345", now, 0); ok {
		t.Fatal("short code accepted")
	}
	u := URI("Tributary", "alice", s)
	if !strings.HasPrefix(u, "otpauth://totp/Tributary:alice?") || !strings.Contains(u, "secret="+s) {
		t.Fatal(u)
	}
	png, err := QRPNG(u)
	if err != nil || !bytes.HasPrefix(png, []byte("\x89PNG")) {
		t.Fatal("QR", err)
	}
}
