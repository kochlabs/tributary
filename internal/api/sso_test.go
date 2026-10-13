package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"nfa/internal/config"
)

// fakeIdP is a minimal OpenID provider: discovery, JWKS, authorize (which
// immediately redirects back), a token endpoint that enforces PKCE, and
// userinfo. Tests tweak the claims it issues.
type fakeIdP struct {
	t        *testing.T
	srv      *httptest.Server
	key      *rsa.PrivateKey
	mu       sync.Mutex
	codes    map[string]authReq
	claims   map[string]any // extra claims for the next ID token
	badNonce bool
}

type authReq struct{ nonce, challenge, redirect string }

func newFakeIdP(t *testing.T) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{t: t, key: key, codes: map[string]authReq{}}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"userinfo_endpoint": f.srv.URL + "/userinfo", "jwks_uri": f.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "PKCE required", 400)
			return
		}
		code := "code-" + q.Get("state")
		f.mu.Lock()
		f.codes[code] = authReq{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		id, secret, _ := r.BasicAuth()
		if id == "" {
			id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		if id != "tributary" || secret != "s3cret" {
			http.Error(w, `{"error":"invalid_client"}`, 401)
			return
		}
		f.mu.Lock()
		req, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != req.challenge || r.PostForm.Get("redirect_uri") != req.redirect {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		nonce := req.nonce
		if f.badNonce {
			nonce = "forged"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": f.sign(nonce)})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"sub": "u1"})
	})
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) sign(nonce string) string {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		f.t.Fatal(err)
	}
	c := map[string]any{"iss": f.srv.URL, "aud": "tributary", "sub": "u1", "nonce": nonce,
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(), "name": "Ada Lovelace"}
	for k, v := range f.claims {
		c[k] = v
	}
	tok, err := jwt.Signed(sig).Claims(c).Serialize()
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

type harness struct {
	t   *testing.T
	cfg *config.DB
	app *httptest.Server
	idp *fakeIdP
	src int64
}

func newHarness(t *testing.T) *harness {
	cfg, err := config.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cfg.Close() })
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Config: cfg}
	h := &harness{t: t, cfg: cfg, app: httptest.NewServer(s.Handler()), idp: newFakeIdP(t)}
	t.Cleanup(h.app.Close)
	h.src, err = cfg.SaveIdentitySource(config.IdentitySource{
		Type: "oidc", Name: "Fake IdP", Enabled: true, Priority: 10,
		OIDC:     &config.OIDCConfig{Issuer: h.idp.srv.URL, ClientID: "tributary", ClientSecret: "s3cret", Scopes: []string{"openid", "profile"}},
		Mappings: []config.RoleMapping{{Group: "tributary-admins", Role: "admin"}, {Group: "tributary-viewers", Role: "viewer"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// signIn runs the browser side of the flow and returns where the appliance
// finally sent the browser, plus whether a session cookie was issued.
func (h *harness) signIn(start string) (string, bool) {
	jar, _ := cookiejar.New(nil)
	var final string
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), h.app.URL) && !strings.HasPrefix(req.URL.Path, "/api/") {
			final = req.URL.RequestURI()
			return http.ErrUseLastResponse
		}
		return nil
	}}
	resp, err := client.Get(h.app.URL + start)
	if err != nil {
		h.t.Fatal(err)
	}
	resp.Body.Close()
	u, _ := url.Parse(h.app.URL)
	for _, c := range jar.Cookies(u) {
		if c.Name == cookieName && c.Value != "" {
			return final, true
		}
	}
	return final, false
}

func TestSSOAdminSignIn(t *testing.T) {
	h := newHarness(t)
	h.idp.claims = map[string]any{"preferred_username": "ada", "groups": []string{"staff", "tributary-admins"}}
	dest, session := h.signIn("/api/auth/sso/1/start?next=/flows")
	if dest != "/flows" || !session {
		t.Fatalf("got dest %q session %v", dest, session)
	}
	users, _ := h.cfg.Users()
	if len(users) != 1 || users[0].Username != "ada" || users[0].Role != "admin" || users[0].SourceID != h.src || users[0].FullName != "Ada Lovelace" {
		t.Fatalf("user: %+v", users)
	}
	// Roles are re-evaluated at every sign-in.
	h.idp.claims["groups"] = []string{"tributary-viewers"}
	if _, ok := h.signIn("/api/auth/sso/1/start"); !ok {
		t.Fatal("second sign-in failed")
	}
	users, _ = h.cfg.Users()
	if users[0].Role != "viewer" {
		t.Fatalf("role not re-evaluated: %s", users[0].Role)
	}
	// SSO accounts can never sign in with a password.
	if _, err := h.cfg.Authenticate("ada", ""); err == nil {
		t.Fatal("external account accepted a local password login")
	}
}

func TestSSODeniedWithoutMapping(t *testing.T) {
	h := newHarness(t)
	h.idp.claims = map[string]any{"preferred_username": "eve", "groups": []string{"staff"}}
	dest, session := h.signIn("/api/auth/sso/1/start")
	if session || !strings.Contains(dest, "sso_error") {
		t.Fatalf("expected denial, got dest %q session %v", dest, session)
	}
	if users, _ := h.cfg.Users(); len(users) != 0 {
		t.Fatalf("user created for denied sign-in: %+v", users)
	}
}

func TestSSOCannotTakeOverLocalAccount(t *testing.T) {
	h := newHarness(t)
	if err := h.cfg.CreateUser(config.User{Username: "admin", Role: "admin"}, "local-password"); err != nil {
		t.Fatal(err)
	}
	h.idp.claims = map[string]any{"preferred_username": "admin", "groups": []string{"tributary-admins"}}
	dest, session := h.signIn("/api/auth/sso/1/start")
	if session || !strings.Contains(dest, "sso_error") {
		t.Fatalf("local account taken over: dest %q session %v", dest, session)
	}
}

func TestSSORejectsForgedNonce(t *testing.T) {
	h := newHarness(t)
	h.idp.claims = map[string]any{"preferred_username": "ada", "groups": []string{"tributary-admins"}}
	h.idp.badNonce = true
	if dest, session := h.signIn("/api/auth/sso/1/start"); session || !strings.Contains(dest, "sso_error") {
		t.Fatalf("forged nonce accepted: %q %v", dest, session)
	}
}

func TestSSOCallbackWithoutBrowserState(t *testing.T) {
	h := newHarness(t)
	// A callback URL replayed in another browser has no state cookie.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(h.app.URL + "/api/auth/sso/1/callback?code=x&state=abc")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "sso_error") {
		t.Fatalf("callback without state accepted: %s", loc)
	}
}

func TestSSOSecretEncryptedAtRest(t *testing.T) {
	h := newHarness(t)
	list, _ := h.cfg.IdentitySources()
	if list[0].OIDC.ClientSecret != "" || !list[0].HasSecret {
		t.Fatalf("secret exposed in listing: %+v", list[0].OIDC)
	}
	full, _ := h.cfg.IdentitySource(h.src, true)
	if full.OIDC.ClientSecret != "s3cret" {
		t.Fatalf("secret round-trip failed: %q", full.OIDC.ClientSecret)
	}
	// Updating without a secret keeps the stored one.
	full.OIDC.ClientSecret = ""
	full.Name = "Renamed"
	if _, err := h.cfg.SaveIdentitySource(*full); err != nil {
		t.Fatal(err)
	}
	again, _ := h.cfg.IdentitySource(h.src, true)
	if again.OIDC.ClientSecret != "s3cret" || again.Name != "Renamed" {
		t.Fatalf("secret lost on update: %+v", again.OIDC)
	}
}
