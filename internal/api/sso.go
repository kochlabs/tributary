package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/kochlabs/tributary/internal/config"
	"github.com/kochlabs/tributary/internal/dirauth"
)

// Single sign-on. OpenID Connect uses the Authorization Code flow with PKCE,
// state and nonce; SAML is in saml.go. The pending login is kept server-side
// and bound to the browser with a short-lived cookie, so a stolen or forged
// callback is useless.

const (
	ssoCookie  = "nfa_sso"
	ssoTimeout = 10 * time.Minute
)

type ssoPending struct {
	sourceID  int64
	nonce     string
	verifier  string
	requestID string // SAML AuthnRequest ID
	next      string
	expires   time.Time
}

type ssoState struct {
	mu      sync.Mutex
	pending map[string]ssoPending // by state
}

func (st *ssoState) put(state string, p ssoPending) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	for k, v := range st.pending {
		if now.After(v.expires) {
			delete(st.pending, k)
		}
	}
	if len(st.pending) >= 1000 {
		return errors.New("too many sign-ins in progress; try again shortly")
	}
	st.pending[state] = p
	return nil
}

func (st *ssoState) take(state string) (ssoPending, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	p, ok := st.pending[state]
	delete(st.pending, state)
	if !ok || time.Now().After(p.expires) {
		return ssoPending{}, false
	}
	return p, true
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// redirectURI is the callback the provider must have registered. It follows
// the address the browser used to reach the appliance.
func (s *Server) redirectURI(r *http.Request, id int64) string {
	scheme := "https"
	if !s.SecureCookies {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/api/auth/sso/%d/callback", scheme, r.Host, id)
}

// httpCtx makes go-oidc and oauth2 use the appliance trust store, so
// providers with certificates from a private CA (added under Trusted CAs)
// verify normally.
func (s *Server) httpCtx(ctx context.Context) context.Context {
	if s.Trust == nil {
		return ctx
	}
	c := s.Trust.Client()
	return context.WithValue(oidc.ClientContext(ctx, c), oauth2.HTTPClient, c)
}

func (s *Server) oauthConfig(ctx context.Context, r *http.Request, src *config.IdentitySource) (*oidc.Provider, *oauth2.Config, error) {
	ctx, cancel := context.WithTimeout(s.httpCtx(ctx), 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, src.OIDC.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("could not load the provider's metadata: %w", err)
	}
	return p, &oauth2.Config{
		ClientID:     src.OIDC.ClientID,
		ClientSecret: src.OIDC.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  s.redirectURI(r, src.ID),
		Scopes:       src.OIDC.Scopes,
	}, nil
}

// ssoFail sends the browser back to the sign-in page with a message.
func ssoFail(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/login?sso_error="+url.QueryEscape(msg), http.StatusFound)
}

func safeNext(next string) string {
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") && !strings.HasPrefix(next, "/\\") && !strings.HasPrefix(next, "/api/") {
		return next
	}
	return "/dashboard"
}

func (s *Server) ssoStart(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	src, err := s.Config.IdentitySource(id, true)
	if err == nil && src.Enabled && src.SAML != nil {
		s.samlStart(w, r, src)
		return
	}
	if err != nil || !src.Enabled || src.OIDC == nil {
		ssoFail(w, r, "That sign-in option is not available.")
		return
	}
	_, oc, err := s.oauthConfig(r.Context(), r, src)
	if err != nil {
		s.Log.Warn("sso start failed", "source", src.Name, "err", err)
		ssoFail(w, r, "Could not reach "+src.Name+". Try again or sign in with a local account.")
		return
	}
	state, nonce, verifier := randomString(16), randomString(16), oauth2.GenerateVerifier()
	if err := s.sso.put(state, ssoPending{sourceID: id, nonce: nonce, verifier: verifier, next: safeNext(r.URL.Query().Get("next")), expires: time.Now().Add(ssoTimeout)}); err != nil {
		ssoFail(w, r, err.Error())
		return
	}
	// Lax, not Strict: the provider redirects back cross-site.
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: state, Path: "/api/auth/sso/", HttpOnly: true, Secure: s.SecureCookies,
		SameSite: http.SameSiteLaxMode, MaxAge: int(ssoTimeout.Seconds())})
	http.Redirect(w, r, oc.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (s *Server) ssoCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: "", Path: "/api/auth/sso/", MaxAge: -1, HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteLaxMode})
	if e := q.Get("error"); e != "" {
		msg := "Sign-in was cancelled or refused by the provider."
		if d := q.Get("error_description"); d != "" && len(d) < 200 {
			msg = "The provider refused sign-in: " + d
		}
		ssoFail(w, r, msg)
		return
	}
	c, err := r.Cookie(ssoCookie)
	state := q.Get("state")
	if err != nil || state == "" || c.Value != state {
		ssoFail(w, r, "The sign-in session expired or was started in another browser. Please try again.")
		return
	}
	pend, ok := s.sso.take(state)
	if !ok || pend.sourceID != id {
		ssoFail(w, r, "The sign-in session expired. Please try again.")
		return
	}
	src, err := s.Config.IdentitySource(id, true)
	if err != nil || !src.Enabled || src.OIDC == nil {
		ssoFail(w, r, "That sign-in option is not available.")
		return
	}
	ctx, cancel := context.WithTimeout(s.httpCtx(r.Context()), 15*time.Second)
	defer cancel()
	prov, oc, err := s.oauthConfig(ctx, r, src)
	if err != nil {
		ssoFail(w, r, "Could not reach "+src.Name+".")
		return
	}
	tok, err := oc.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(pend.verifier))
	if err != nil {
		s.Log.Warn("sso code exchange failed", "source", src.Name, "err", err)
		ssoFail(w, r, "Sign-in failed: the provider rejected the request. Check the client ID, secret and redirect URI.")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		ssoFail(w, r, "Sign-in failed: the provider returned no ID token.")
		return
	}
	idt, err := prov.Verifier(&oidc.Config{ClientID: src.OIDC.ClientID}).Verify(ctx, raw)
	if err != nil {
		s.Log.Warn("sso id token rejected", "source", src.Name, "err", err)
		ssoFail(w, r, "Sign-in failed: the identity token could not be verified.")
		return
	}
	if idt.Nonce != pend.nonce {
		ssoFail(w, r, "Sign-in failed: the identity token did not match this sign-in.")
		return
	}
	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		ssoFail(w, r, "Sign-in failed: unreadable identity token.")
		return
	}
	// Many providers only include groups in the userinfo response.
	if _, ok := claims[src.OIDC.GroupsClaim]; !ok {
		if ui, err := prov.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil {
			extra := map[string]any{}
			if ui.Claims(&extra) == nil {
				for k, v := range extra {
					if _, exists := claims[k]; !exists {
						claims[k] = v
					}
				}
			}
		}
	}
	username, _ := claims[src.OIDC.UsernameClaim].(string)
	if username == "" {
		ssoFail(w, r, fmt.Sprintf("Sign-in failed: the provider did not send the %q claim used as the username.", src.OIDC.UsernameClaim))
		return
	}
	fullName, _ := claims["name"].(string)
	s.ssoFinish(w, r, src, username, fullName, claimStrings(claims[src.OIDC.GroupsClaim]), pend.next)
}

// ssoFinish signs in a user a provider has vouched for: map the role, create
// or update the account, and start a session.
func (s *Server) ssoFinish(w http.ResponseWriter, r *http.Request, src *config.IdentitySource, username, fullName string, groups []string, next string) {
	role := src.ResolveRole(groups)
	ip := clientIP(r)
	if role == "" {
		s.Config.Audit(username, "login.sso.denied", fmt.Sprintf("%s via %s: no role mapping matched", ip, src.Name))
		ssoFail(w, r, "You signed in to "+src.Name+", but your account isn't permitted to use this appliance. Ask an administrator to add your group.")
		return
	}
	u, err := s.Config.UpsertExternalUser(src.ID, username, fullName, role)
	if err != nil {
		s.Config.Audit(username, "login.sso.denied", fmt.Sprintf("%s via %s: %v", ip, src.Name, err))
		if errors.Is(err, config.ErrAccountConflict) {
			ssoFail(w, r, "An account named "+username+" already exists on this appliance and is not linked to "+src.Name+".")
			return
		}
		ssoFail(w, r, "Sign-in failed: "+err.Error())
		return
	}
	ttl := time.Duration(s.Config.Settings().SessionHours) * time.Hour
	sess, err := s.Config.CreateSession(u.Username, ttl)
	if err != nil {
		ssoFail(w, r, "Could not create a session.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sess, Path: "/", HttpOnly: true, Secure: s.SecureCookies,
		SameSite: http.SameSiteStrictMode, MaxAge: int(ttl.Seconds())})
	s.Config.Audit(u.Username, "login.sso", fmt.Sprintf("%s via %s as %s", ip, src.Name, role))
	// 303: the SAML response arrives as a POST.
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// claimStrings accepts a claim that is a list of strings or a single string.
func claimStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// ---- administration ----

func (s *Server) identitySources(w http.ResponseWriter, r *http.Request) {
	list, err := s.Config.IdentitySources()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) identitySourceGet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	src, err := s.Config.IdentitySource(id, false)
	if err != nil {
		writeErr(w, http.StatusNotFound, "identity source not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"source": src, "redirectUri": s.redirectURI(r, id), "saml": s.samlInfo(r, src)})
}

func (s *Server) identitySourceSave(w http.ResponseWriter, r *http.Request) {
	var src config.IdentitySource
	if err := readJSON(r, &src); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if idStr := r.PathValue("id"); idStr != "" {
		src.ID, _ = strconv.ParseInt(idStr, 10, 64)
	} else {
		src.ID = 0
	}
	if src.Type == "saml" {
		if err := s.prepareSAML(r.Context(), &src); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	id, err := s.Config.SaveIdentitySource(src)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, config.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, err.Error())
		return
	}
	action := "identity.update"
	if src.ID == 0 {
		action = "identity.create"
	}
	s.Config.Audit(userFrom(r).Username, action, src.Name)
	out := map[string]any{"id": id, "redirectUri": s.redirectURI(r, id)}
	if saved, err := s.Config.IdentitySource(id, false); err == nil {
		out["saml"] = s.samlInfo(r, saved)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) identitySourceDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	src, err := s.Config.IdentitySource(id, false)
	if err != nil {
		writeErr(w, http.StatusNotFound, "identity source not found")
		return
	}
	if u := userFrom(r); u.SourceID == id {
		writeErr(w, http.StatusBadRequest, "you are signed in through this source; sign in with another account to delete it")
		return
	}
	if err := s.Config.DeleteIdentitySource(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "identity.delete", src.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// identitySourceTest checks a source's settings before saving: OIDC loads
// the discovery document; SAML loads the provider metadata; LDAP binds the service account (and optionally
// looks up a user); RADIUS sends a request with test credentials.
func (s *Server) identitySourceTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type     string               `json:"type"`
		ID       int64                `json:"id"` // reuse the stored secret when the form leaves it empty
		Issuer   string               `json:"issuer"`
		SAML     *config.SAMLConfig   `json:"saml"`
		LDAP     *config.LDAPConfig   `json:"ldap"`
		RADIUS   *config.RADIUSConfig `json:"radius"`
		Username string               `json:"username"`
		Password string               `json:"password"`
		// The form's role mappings, so the test shows the role a user would get.
		Mappings    []config.RoleMapping `json:"mappings"`
		DefaultRole string               `json:"defaultRole"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	switch req.Type {
	case "saml":
		s.samlTest(w, r, req.SAML)
		return
	case "ldap", "radius":
		s.directoryTest(w, r, config.IdentitySource{Type: req.Type, Name: "test", LDAP: req.LDAP, RADIUS: req.RADIUS, Mappings: req.Mappings, DefaultRole: req.DefaultRole},
			req.ID, req.Username, req.Password)
		return
	}
	issuer := strings.TrimSpace(req.Issuer)
	u, err := url.Parse(issuer)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Enter a valid issuer URL."})
		return
	}
	ctx, cancel := context.WithTimeout(s.httpCtx(r.Context()), 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	var meta struct {
		Authorization string   `json:"authorization_endpoint"`
		Token         string   `json:"token_endpoint"`
		UserInfo      string   `json:"userinfo_endpoint"`
		Scopes        []string `json:"scopes_supported"`
		Claims        []string `json:"claims_supported"`
		PKCE          []string `json:"code_challenge_methods_supported"`
	}
	_ = p.Claims(&meta)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Provider metadata loaded.", "authorizationEndpoint": meta.Authorization,
		"tokenEndpoint": meta.Token, "userinfoEndpoint": meta.UserInfo, "scopes": meta.Scopes, "claims": meta.Claims, "pkce": meta.PKCE})
}

func (s *Server) directoryTest(w http.ResponseWriter, r *http.Request, src config.IdentitySource, id int64, username, password string) {
	typ := src.Type
	if err := src.Validate(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	// An empty secret in the form means "keep the stored one".
	if id > 0 {
		if stored, err := s.Config.IdentitySource(id, true); err == nil && stored.Type == typ {
			if typ == "ldap" && src.LDAP.BindPassword == "" {
				src.LDAP.BindPassword = stored.LDAP.BindPassword
			}
			if typ == "radius" && src.RADIUS.Secret == "" {
				src.RADIUS.Secret = stored.RADIUS.Secret
			}
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if typ == "ldap" {
		dn, groups, err := dirauth.TestLDAP(ctx, src.LDAP, s.trustPool(), strings.TrimSpace(username))
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": err.Error()})
			return
		}
		msg := "Connected, and the service account signed in."
		if src.LDAP.Insecure() {
			msg += " Warning: ldap:// without StartTLS sends passwords unencrypted."
		}
		out := map[string]any{"ok": true, "message": msg}
		if username != "" {
			out["dn"], out["groups"], out["role"] = dn, groups, src.ResolveRole(groups)
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	if username == "" || password == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Enter a test username and password: RADIUS can only be tested with a sign-in attempt."})
		return
	}
	res, err := dirauth.RADIUS(ctx, src.RADIUS, username, password)
	switch {
	case errors.Is(err, dirauth.ErrInvalid):
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "The server answered and rejected these credentials, so it is reachable and the shared secret is correct."})
	case err != nil:
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": err.Error()})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Accepted.", "groups": res.Groups, "role": src.ResolveRole(res.Groups)})
	}
}

// ssoOptions lists enabled sources for the sign-in page.
func (s *Server) ssoOptions() []map[string]any {
	list, err := s.Config.IdentitySources()
	if err != nil {
		return nil
	}
	out := []map[string]any{}
	for _, src := range list {
		if src.Enabled && !src.PasswordBased() { // LDAP/RADIUS use the regular sign-in form
			out = append(out, map[string]any{"id": src.ID, "name": src.Name})
		}
	}
	return out
}
