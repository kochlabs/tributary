package dirauth

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"net"
	"strings"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"

	"github.com/kochlabs/tributary/internal/config"
)

// radiusServer answers PAP requests for alice/Secret-123 with Class "netadmins",
// and requires (and checks) Message-Authenticator on requests.
func radiusServer(t *testing.T, secret string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &radius.PacketServer{
		SecretSource: radius.StaticSecretSource([]byte(secret)),
		Handler: radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
			if !validRequestMA(r.Packet) {
				return // drop, as a BlastRADIUS-hardened server does
			}
			code := radius.CodeAccessReject
			if rfc2865.UserName_GetString(r.Packet) == "alice" && rfc2865.UserPassword_GetString(r.Packet) == "Secret-123" {
				code = radius.CodeAccessAccept
			}
			resp := r.Response(code)
			if code == radius.CodeAccessAccept {
				rfc2865.Class_Add(resp, []byte("netadmins"))
				rfc2865.FilterID_AddString(resp, "ops")
			}
			signResponse(resp, r.Packet.Authenticator)
			w.Write(resp)
		}),
	}
	go srv.Serve(pc)
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	return pc.LocalAddr().String()
}

func validRequestMA(p *radius.Packet) bool {
	for i, a := range p.Attributes {
		if a.Type != attrMessageAuthenticator {
			continue
		}
		got := append([]byte(nil), a.Attribute...)
		p.Attributes[i].Attribute = make(radius.Attribute, 16)
		wire, _ := p.MarshalBinary()
		p.Attributes[i].Attribute = got
		m := hmac.New(md5.New, p.Secret)
		m.Write(wire)
		return hmac.Equal(m.Sum(nil), got) && i == 0
	}
	return false
}

func signResponse(resp *radius.Packet, reqAuth [16]byte) {
	resp.Attributes = append(radius.Attributes{{Type: attrMessageAuthenticator, Attribute: make(radius.Attribute, 16)}}, resp.Attributes...)
	saved := resp.Authenticator
	resp.Authenticator = reqAuth
	wire, _ := resp.MarshalBinary()
	resp.Authenticator = saved
	m := hmac.New(md5.New, resp.Secret)
	m.Write(wire)
	copy(resp.Attributes[0].Attribute, m.Sum(nil))
}

func TestRADIUS(t *testing.T) {
	addr := radiusServer(t, "shared-s3cret")
	dead, _ := net.ListenPacket("udp", "127.0.0.1:0") // never answers
	defer dead.Close()
	ctx := context.Background()
	cfg := &config.RADIUSConfig{Servers: []string{dead.LocalAddr().String(), addr}, Secret: "shared-s3cret", NASIdentifier: "tributary", TimeoutSec: 2, RoleAttribute: "Class"}

	start := time.Now()
	res, err := RADIUS(ctx, cfg, "alice", "Secret-123")
	if err != nil {
		t.Fatal(err)
	}
	if res.Username != "alice" || len(res.Groups) != 1 || res.Groups[0] != "netadmins" {
		t.Fatalf("%+v", res)
	}
	t.Logf("failed over from the silent server in %s", time.Since(start).Round(time.Millisecond))

	cfg.RoleAttribute = "Filter-Id"
	if res, _ := RADIUS(ctx, cfg, "alice", "Secret-123"); len(res.Groups) != 1 || res.Groups[0] != "ops" {
		t.Fatalf("Filter-Id: %+v", res)
	}
	if _, err := RADIUS(ctx, &config.RADIUSConfig{Servers: []string{addr}, Secret: "shared-s3cret", TimeoutSec: 2}, "alice", "wrong"); err != ErrInvalid {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := RADIUS(ctx, &config.RADIUSConfig{Servers: []string{addr}, Secret: "shared-s3cret", TimeoutSec: 2}, "alice", ""); err != ErrInvalid {
		t.Fatalf("empty password: %v", err)
	}
	// A wrong shared secret: the server drops the request (bad Message-Authenticator).
	_, err = RADIUS(ctx, &config.RADIUSConfig{Servers: []string{addr}, Secret: "wrong-secret", TimeoutSec: 2}, "alice", "Secret-123")
	if err == nil || !strings.Contains(err.Error(), "no response") {
		t.Fatalf("wrong secret: %v", err)
	}
}
