package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"html"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"

	"nfa/internal/config"
)

// testIdP is an in-process SAML identity provider that signs in one user.
type testIdP struct {
	idp     *saml.IdentityProvider
	srv     *httptest.Server
	session saml.Session
	plain   bool // don't encrypt assertions
}

func (p *testIdP) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	s := p.session
	s.ID, s.CreateTime, s.ExpireTime = "sess", time.Now(), time.Now().Add(time.Hour)
	return &s
}

// GetServiceProvider reads the appliance's metadata from its published URL,
// as a provider administrator importing it would.
func (p *testIdP) GetServiceProvider(r *http.Request, id string) (*saml.EntityDescriptor, error) {
	resp, err := http.Get(id)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	ed, err := samlsp.ParseMetadata(b)
	if err == nil && p.plain {
		for i := range ed.SPSSODescriptors {
			ed.SPSSODescriptors[i].KeyDescriptors = nil
		}
	}
	return ed, err
}

func newTestIdP(t *testing.T) *testIdP {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	p := &testIdP{session: saml.Session{NameID: "alice@example.com", UserName: "alice", UserCommonName: "Alice Example",
		CustomAttributes: []saml.Attribute{{Name: "http://schemas.xmlsoap.org/claims/Group", Values: []saml.AttributeValue{{Type: "xs:string", Value: "Net-Admins"}}}}}}
	mux := http.NewServeMux()
	mux.HandleFunc("/metadata", func(w http.ResponseWriter, r *http.Request) { p.idp.ServeMetadata(w, r) })
	mux.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) { p.idp.ServeSSO(w, r) })
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	base, _ := url.Parse(p.srv.URL)
	p.idp = &saml.IdentityProvider{Key: key, Signer: key, Certificate: cert, Logger: discardLogger{},
		MetadataURL: *base.JoinPath("/metadata"), SSOURL: *base.JoinPath("/sso"),
		ServiceProviderProvider: p, SessionProvider: p, SignatureMethod: dsig.RSASHA256SignatureMethod}
	return p
}

type discardLogger struct{}

func (discardLogger) Printf(string, ...any) {}
func (discardLogger) Print(...any)          {}
func (discardLogger) Println(...any)        {}
func (discardLogger) Fatal(...any)          {}
func (discardLogger) Fatalf(string, ...any) {}
func (discardLogger) Fatalln(...any)        {}
func (discardLogger) Panic(...any)          {}
func (discardLogger) Panicf(string, ...any) {}
func (discardLogger) Panicln(...any)        {}

var formField = regexp.MustCompile(`name="(SAMLResponse|RelayState)" value="([^"]*)"`)

// samlLogin runs the browser side: start at the appliance, follow the
// redirect to the provider, and return the form the provider would post back.
func samlLogin(t *testing.T, c *client, id int64) (acs string, form url.Values) {
	t.Helper()
	noFollow := *c.c
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noFollow.Get(c.base + "/api/auth/sso/" + strconv.FormatInt(id, 10) + "/start?next=/exporters")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.Contains(loc, "SAMLRequest=") {
		t.Fatalf("start: %d %s", resp.StatusCode, loc)
	}
	if !strings.Contains(loc, "&Signature=") || !strings.Contains(loc, "SigAlg=") {
		t.Fatalf("request not signed: %s", loc)
	}
	resp, err = noFollow.Get(loc)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("idp: %d %s", resp.StatusCode, page)
	}
	form = url.Values{}
	for _, m := range formField.FindAllStringSubmatch(string(page), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	if form.Get("SAMLResponse") == "" {
		t.Fatalf("no SAMLResponse in %s", page)
	}
	acsRe := regexp.MustCompile(`action="([^"]+)"`).FindStringSubmatch(string(page))
	return html.UnescapeString(acsRe[1]), form
}

// postACS posts the provider's form as the browser would (no JSON, no
// X-Requested-With) and returns where the appliance redirects.
func postACS(t *testing.T, c *client, acs string, form url.Values) string {
	t.Helper()
	noFollow := *c.c
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noFollow.PostForm(acs, form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Fatalf("acs: %d", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

func TestSAMLSignIn(t *testing.T) {
	cfg, err := config.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	s := &Server{Log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})), Config: cfg}
	app := httptest.NewServer(s.Handler())
	defer app.Close()
	idp := newTestIdP(t)

	cfg.CreateUser(config.User{Username: "admin", Role: "admin"}, "Local-pass-1")
	adm := newClient(t, app.URL)
	if code, _ := adm.post("/api/auth/login", map[string]string{"username": "admin", "password": "Local-pass-1"}); code != 200 {
		t.Fatal("admin login")
	}
	// The editor's test loads the provider metadata.
	if code, out := adm.post("/api/identity-sources/test", map[string]any{"type": "saml", "saml": map[string]any{"metadataUrl": idp.srv.URL + "/metadata"}}); code != 200 || out["ok"] != true || out["ssoUrl"] != idp.srv.URL+"/sso" {
		t.Fatalf("test: %d %v", code, out)
	}
	code, out := adm.post("/api/identity-sources", map[string]any{"type": "saml", "name": "Test IdP", "enabled": true, "priority": 5,
		"saml":     map[string]any{"metadataUrl": idp.srv.URL + "/metadata", "groupsAttr": "http://schemas.xmlsoap.org/claims/Group", "nameAttr": "cn", "signRequests": true, "spKey": "attacker"},
		"mappings": []map[string]string{{"group": "net-admins", "role": "admin"}}})
	if code != 200 {
		t.Fatalf("save: %d %v", code, out)
	}
	id := int64(out["id"].(float64))
	info := out["saml"].(map[string]any)
	if info["acsUrl"] != app.URL+"/api/auth/sso/"+strconv.FormatInt(id, 10)+"/acs" {
		t.Fatalf("info: %v", info)
	}
	if stored, _ := cfg.IdentitySource(id, true); !strings.HasPrefix(stored.SAML.SPKey, "-----BEGIN PRIVATE KEY") || stored.SAML.MetadataXML == "" {
		t.Fatal("key pair or metadata not stored")
	}
	// Public metadata: POST ACS only.
	resp, _ := http.Get(info["metadataUrl"].(string))
	md, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(md), info["acsUrl"].(string)) || strings.Contains(string(md), "HTTP-Artifact") {
		t.Fatalf("metadata: %s", md)
	}

	// Sign-in: an encrypted, signed assertion; the group maps case-insensitively.
	c := newClient(t, app.URL)
	acs, form := samlLogin(t, c, id)
	if loc := postACS(t, c, acs, form); loc != "/exporters" {
		t.Fatalf("redirect: %s", loc)
	}
	if c.get("/api/auth/me") != 200 {
		t.Fatal("no session after SAML sign-in")
	}
	u, _ := cfg.SessionUserByName("alice@example.com")
	if u == nil || u.Role != "admin" || u.FullName != "Alice Example" || u.SourceID != id {
		t.Fatalf("user: %+v", u)
	}

	// Replaying the same response fails: the request ID is used up.
	if loc := postACS(t, c, acs, form); !strings.HasPrefix(loc, "/login?sso_error=") {
		t.Fatalf("replay accepted: %s", loc)
	}
	// A response captured from another browser fails (no matching cookie).
	_, form2 := samlLogin(t, newClient(t, app.URL), id)
	if loc := postACS(t, newClient(t, app.URL), acs, form2); !strings.HasPrefix(loc, "/login?sso_error=") {
		t.Fatalf("other browser accepted: %s", loc)
	}
	// Unencrypted assertions are accepted too, but changing one breaks its
	// signature.
	idp.plain = true
	c3 := newClient(t, app.URL)
	acs3, form3 := samlLogin(t, c3, id)
	raw, _ := base64.StdEncoding.DecodeString(form3.Get("SAMLResponse"))
	if !strings.Contains(string(raw), ">alice@example.com<") {
		t.Fatalf("expected a plaintext assertion: %s", raw)
	}
	tampered := strings.ReplaceAll(string(raw), ">alice@example.com<", ">admin<")
	form3.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(tampered)))
	if loc := postACS(t, c3, acs3, form3); !strings.HasPrefix(loc, "/login?sso_error=") {
		t.Fatalf("tampered accepted: %s", loc)
	}
	c3 = newClient(t, app.URL)
	acs3, form3 = samlLogin(t, c3, id)
	if loc := postACS(t, c3, acs3, form3); loc != "/exporters" {
		t.Fatalf("plaintext assertion: %s", loc)
	}
	// Stripping the signatures doesn't help either.
	c3 = newClient(t, app.URL)
	acs3, form3 = samlLogin(t, c3, id)
	raw, _ = base64.StdEncoding.DecodeString(form3.Get("SAMLResponse"))
	unsigned := regexp.MustCompile(`(?s)<ds:Signature.*?</ds:Signature>`).ReplaceAllString(string(raw), "")
	if unsigned == string(raw) {
		t.Fatal("no signature found to strip")
	}
	form3.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(unsigned)))
	if loc := postACS(t, c3, acs3, form3); !strings.HasPrefix(loc, "/login?sso_error=") {
		t.Fatalf("unsigned accepted: %s", loc)
	}
	idp.plain = false

	// No mapped group and no default role: denied, no account.
	idp.session.NameID, idp.session.CustomAttributes = "bob@example.com", nil
	c4 := newClient(t, app.URL)
	acs4, form4 := samlLogin(t, c4, id)
	if loc := postACS(t, c4, acs4, form4); !strings.Contains(loc, "sso_error=") {
		t.Fatalf("unmapped accepted: %s", loc)
	}
	if _, ok := cfg.ExternalUserSource("bob@example.com"); ok {
		t.Fatal("account created for an unmapped user")
	}

	// The username can come from an attribute (matched by FriendlyName).
	src, _ := cfg.IdentitySource(id, false)
	src.SAML.UsernameAttr, src.DefaultRole = "uid", "viewer"
	if _, err := cfg.SaveIdentitySource(*src); err != nil {
		t.Fatal(err)
	}
	idp.session.UserName = "bob"
	c5 := newClient(t, app.URL)
	acs5, form5 := samlLogin(t, c5, id)
	if loc := postACS(t, c5, acs5, form5); loc != "/exporters" {
		t.Fatalf("attribute username: %s", loc)
	}
	if u, _ := cfg.SessionUserByName("bob"); u == nil || u.Role != "viewer" {
		t.Fatalf("bob: %+v", u)
	}
	// The key pair survives edits.
	if after, _ := cfg.IdentitySource(id, true); !strings.HasPrefix(after.SAML.SPKey, "-----BEGIN PRIVATE KEY") {
		t.Fatal("key lost on update")
	}
}
