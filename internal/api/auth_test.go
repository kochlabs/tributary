package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"

	"nfa/internal/config"
	"nfa/internal/totp"
)

// A RADIUS server accepting carol/Radius-pass-1 (Class "noc") and dave/Radius-pass-2 (no class).
func fakeRADIUS(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &radius.PacketServer{SecretSource: radius.StaticSecretSource([]byte("radius-secret")), Handler: radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
		user, pass := rfc2865.UserName_GetString(r.Packet), rfc2865.UserPassword_GetString(r.Packet)
		switch {
		case user == "carol" && pass == "Radius-pass-1":
			resp := r.Response(radius.CodeAccessAccept)
			rfc2865.Class_Add(resp, []byte("noc"))
			w.Write(resp)
		case user == "dave" && pass == "Radius-pass-2":
			w.Write(r.Response(radius.CodeAccessAccept))
		case user == "admin" && pass == "Radius-pass-3":
			resp := r.Response(radius.CodeAccessAccept)
			rfc2865.Class_Add(resp, []byte("noc"))
			w.Write(resp)
		default:
			w.Write(r.Response(radius.CodeAccessReject))
		}
	})}
	go srv.Serve(pc)
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	return pc.LocalAddr().String()
}

type client struct {
	t    *testing.T
	base string
	c    *http.Client
}

func (c *client) post(path string, body any) (int, map[string]any) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", c.base+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "nfa")
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (c *client) get(path string) int {
	req, _ := http.NewRequest("GET", c.base+path, nil)
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, c: &http.Client{Jar: jar}}
}

func TestPasswordSignIn(t *testing.T) {
	cfg, err := config.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Config: cfg}
	app := httptest.NewServer(s.Handler())
	defer app.Close()
	cfg.CreateUser(config.User{Username: "admin", Role: "admin"}, "Local-pass-1")
	src, err := cfg.SaveIdentitySource(config.IdentitySource{Type: "radius", Name: "Corp RADIUS", Enabled: true, Priority: 10,
		RADIUS:   &config.RADIUSConfig{Servers: []string{fakeRADIUS(t)}, Secret: "radius-secret", TimeoutSec: 2},
		Mappings: []config.RoleMapping{{Group: "NOC", Role: "viewer"}}})
	if err != nil {
		t.Fatal(err)
	}

	// Local account.
	c := newClient(t, app.URL)
	if code, out := c.post("/api/auth/login", map[string]string{"username": "admin", "password": "Local-pass-1"}); code != 200 || out["username"] != "admin" {
		t.Fatalf("local: %d %v", code, out)
	}
	// A directory account with a mapped group gets an account and a session.
	c = newClient(t, app.URL)
	if code, out := c.post("/api/auth/login", map[string]string{"username": "carol", "password": "Radius-pass-1"}); code != 200 || out["role"] != "viewer" || out["sourceId"] != float64(src) {
		t.Fatalf("radius: %d %v", code, out)
	}
	if c.get("/api/auth/me") != 200 {
		t.Fatal("no session after RADIUS sign-in")
	}
	// No matching group: denied with an explanation, no account created.
	if code, out := newClient(t, app.URL).post("/api/auth/login", map[string]string{"username": "dave", "password": "Radius-pass-2"}); code != 403 || out["error"] == nil {
		t.Fatalf("unmapped: %d %v", code, out)
	}
	if _, ok := cfg.ExternalUserSource("dave"); ok {
		t.Fatal("account created for an unmapped user")
	}
	// The directory can't sign in as a local account, even with valid directory credentials.
	if code, _ := newClient(t, app.URL).post("/api/auth/login", map[string]string{"username": "admin", "password": "Radius-pass-3"}); code != 401 {
		t.Fatalf("directory shadowing a local account: %d", code)
	}
	if code, _ := newClient(t, app.URL).post("/api/auth/login", map[string]string{"username": "carol", "password": "wrong"}); code != 401 {
		t.Fatalf("wrong password: %d", code)
	}

	// MFA for the RADIUS user: setup, then sign-in needs a code.
	setupCode, setup := c.post("/api/auth/mfa/setup", map[string]string{})
	if setupCode != 200 || setup["secret"] == nil || len(setup["qr"].(string)) < 100 {
		t.Fatalf("setup: %d %v", setupCode, setup)
	}
	secret := setup["secret"].(string)
	code0, _ := totp.Code(secret, totp.Step(time.Now()))
	if code, out := c.post("/api/auth/mfa/setup/confirm", map[string]string{"code": code0}); code != 200 || len(out["recoveryCodes"].([]any)) != 10 {
		t.Fatalf("confirm: %d %v", code, out)
	}
	c2 := newClient(t, app.URL)
	code, out := c2.post("/api/auth/login", map[string]string{"username": "carol", "password": "Radius-pass-1"})
	if code != 200 || out["mfaRequired"] != true || c2.get("/api/auth/me") != 401 {
		t.Fatalf("login with MFA: %d %v", code, out)
	}
	tok := out["token"].(string)
	if code, _ := c2.post("/api/auth/mfa", map[string]string{"token": tok, "code": "000000"}); code != 401 {
		t.Fatalf("wrong code: %d", code)
	}
	next, _ := totp.Code(secret, totp.Step(time.Now())+1)
	if code, out := c2.post("/api/auth/mfa", map[string]string{"token": tok, "code": next}); code != 200 || c2.get("/api/auth/me") != 200 {
		t.Fatalf("right code: %d %v", code, out)
	}
	// The token is single-use.
	if code, _ := c2.post("/api/auth/mfa", map[string]string{"token": tok, "code": next}); code != 401 {
		t.Fatalf("token reuse: %d", code)
	}

	// Policy: administrators must enrol before they get a session.
	st := cfg.Settings()
	st.RequireMFAAdmins = true
	cfg.SaveSettings(st)
	c3 := newClient(t, app.URL)
	code, out = c3.post("/api/auth/login", map[string]string{"username": "admin", "password": "Local-pass-1"})
	if code != 200 || out["mfaSetupRequired"] != true || c3.get("/api/auth/me") != 401 {
		t.Fatalf("enrol required: %d %v", code, out)
	}
	etok := out["token"].(string)
	_, es := c3.post("/api/auth/mfa/enroll", map[string]string{"token": etok})
	ec, _ := totp.Code(es["secret"].(string), totp.Step(time.Now()))
	if code, out := c3.post("/api/auth/mfa/enroll", map[string]string{"token": etok, "code": ec}); code != 200 || c3.get("/api/auth/me") != 200 || out["recoveryCodes"] == nil {
		t.Fatalf("enrol: %d %v", code, out)
	}
	if !cfg.MFAEnabled("admin") {
		t.Fatal("MFA not on after enrolment")
	}
	// Admin can't switch it off while the policy is on; an admin reset works.
	if code, _ := c3.post("/api/auth/mfa/disable", map[string]string{"code": ec}); code != 400 {
		t.Fatalf("disable under policy: %d", code)
	}
	if code, _ := c3.post("/api/users/carol/mfa/reset", map[string]string{}); code != 200 || cfg.MFAEnabled("carol") {
		t.Fatalf("admin reset: %d", code)
	}
	if c2.get("/api/auth/me") != 401 {
		t.Fatal("reset should sign the user out")
	}
}
