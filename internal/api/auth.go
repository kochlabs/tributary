package api

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"nfa/internal/config"
	"nfa/internal/dirauth"
	"nfa/internal/totp"
)

// Password sign-in: local accounts first, then LDAP/RADIUS identity sources,
// then (when enabled) a second step with an authenticator code.

var (
	errInvalidLogin = errors.New("invalid username or password")
	errNotPermitted = errors.New("your account isn't permitted to use this appliance; ask an administrator to add your group")
)

// passwordLogin checks credentials and returns the account and how it signed
// in ("local" or the identity source's name).
func (s *Server) passwordLogin(ctx context.Context, username, password string) (*config.User, string, error) {
	owner, exists := s.Config.ExternalUserSource(username)
	if !exists || owner == 0 {
		if u, err := s.Config.Authenticate(username, password); err == nil {
			return u, "local", nil
		}
		if exists {
			return nil, "", errInvalidLogin // a local account never falls through to a directory
		}
	}
	list, err := s.Config.IdentitySources()
	if err != nil {
		return nil, "", err
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].Priority < list[j].Priority })
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for _, meta := range list {
		if !meta.Enabled || !meta.PasswordBased() || (exists && meta.ID != owner) {
			continue
		}
		src, err := s.Config.IdentitySource(meta.ID, true)
		if err != nil {
			continue
		}
		var res *dirauth.Result
		switch src.Type {
		case "ldap":
			res, err = dirauth.LDAP(ctx, src.LDAP, s.trustPool(), username, password)
		case "radius":
			res, err = dirauth.RADIUS(ctx, src.RADIUS, username, password)
		}
		if errors.Is(err, dirauth.ErrInvalid) {
			continue
		}
		if err != nil {
			s.Log.Warn("identity source unavailable for sign-in", "source", src.Name, "err", err)
			continue
		}
		role := src.ResolveRole(res.Groups)
		if role == "" {
			s.Config.Audit(res.Username, "login.denied", fmt.Sprintf("via %s: no role mapping matched (groups: %v)", src.Name, res.Groups))
			return nil, "", errNotPermitted
		}
		u, err := s.Config.UpsertExternalUser(src.ID, res.Username, res.FullName, role)
		if err != nil {
			s.Config.Audit(res.Username, "login.denied", fmt.Sprintf("via %s: %v", src.Name, err))
			if errors.Is(err, config.ErrAccountConflict) {
				return nil, "", fmt.Errorf("an account named %s already exists on this appliance and isn't linked to %s", res.Username, src.Name)
			}
			return nil, "", err
		}
		return u, src.Name, nil
	}
	return nil, "", errInvalidLogin
}

// trustPool is the system roots plus the trusted CAs (nil before they load).
func (s *Server) trustPool() *x509.CertPool {
	if s.Trust == nil {
		return nil
	}
	return s.Trust.Pool()
}

// ---- pending second step ----

type mfaPending struct {
	username string
	kind     string // verify | enroll
	via      string
	ip       string
	expires  time.Time
	attempts int
}

type mfaState struct {
	mu sync.Mutex
	m  map[string]*mfaPending
}

const mfaPendingTTL = 5 * time.Minute

func (st *mfaState) put(p mfaPending) string {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.m == nil {
		st.m = map[string]*mfaPending{}
	}
	now := time.Now()
	for k, v := range st.m {
		if now.After(v.expires) {
			delete(st.m, k)
		}
	}
	tok := randomString(32)
	p.expires = now.Add(mfaPendingTTL)
	st.m[tok] = &p
	return tok
}

// get returns the pending sign-in for token, counting an attempt; after five
// attempts or five minutes the token is gone and the user starts over.
func (st *mfaState) get(token, kind string) (*mfaPending, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	p, ok := st.m[token]
	if !ok || p.kind != kind || time.Now().After(p.expires) {
		delete(st.m, token)
		return nil, false
	}
	p.attempts++
	if p.attempts > 5 {
		delete(st.m, token)
		return nil, false
	}
	return p, true
}

func (st *mfaState) drop(token string) {
	st.mu.Lock()
	delete(st.m, token)
	st.mu.Unlock()
}

// startSession signs the user in on this browser.
func (s *Server) startSession(w http.ResponseWriter, username string) error {
	ttl := time.Duration(s.Config.Settings().SessionHours) * time.Hour
	tok, err := s.Config.CreateSession(username, ttl)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: s.SecureCookies,
		SameSite: http.SameSiteStrictMode, MaxAge: int(ttl.Seconds())})
	return nil
}

// login is the first step of password sign-in.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.limiter.blocked(ip) {
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts, try again in a few minutes")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	u, via, err := s.passwordLogin(r.Context(), req.Username, req.Password)
	if err != nil {
		s.limiter.fail(ip)
		if errors.Is(err, errInvalidLogin) {
			s.Config.Audit(req.Username, "login.failed", ip)
			writeErr(w, http.StatusUnauthorized, errInvalidLogin.Error())
			return
		}
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	s.limiter.reset(ip)
	if s.Config.MFAEnabled(u.Username) {
		tok := s.mfa.put(mfaPending{username: u.Username, kind: "verify", via: via, ip: ip})
		writeJSON(w, http.StatusOK, map[string]any{"mfaRequired": true, "token": tok})
		return
	}
	if u.Role == "admin" && s.Config.Settings().RequireMFAAdmins {
		tok := s.mfa.put(mfaPending{username: u.Username, kind: "enroll", via: via, ip: ip})
		writeJSON(w, http.StatusOK, map[string]any{"mfaSetupRequired": true, "token": tok})
		return
	}
	if err := s.startSession(w, u.Username); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	s.Config.Audit(u.Username, "login", loginDetail(ip, via, ""))
	writeJSON(w, http.StatusOK, u)
}

func loginDetail(ip, via, mfa string) string {
	d := ip
	if via != "" && via != "local" {
		d += " via " + via
	}
	if mfa != "" {
		d += " (" + mfa + ")"
	}
	return d
}

// mfaVerify is the second step: an authenticator or recovery code.
func (s *Server) mfaVerify(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.limiter.blocked(ip) {
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts, try again in a few minutes")
		return
	}
	var req struct {
		Token string `json:"token"`
		Code  string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p, ok := s.mfa.get(req.Token, "verify")
	if !ok {
		writeErr(w, http.StatusUnauthorized, "the sign-in expired; enter your password again")
		return
	}
	recovery, err := s.Config.VerifyMFA(p.username, req.Code)
	if err != nil {
		s.limiter.fail(ip)
		s.Config.Audit(p.username, "login.mfa.failed", ip)
		writeErr(w, http.StatusUnauthorized, config.ErrBadCode.Error())
		return
	}
	s.mfa.drop(req.Token)
	s.limiter.reset(ip)
	if err := s.startSession(w, p.username); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	how := "authenticator code"
	if recovery {
		how = fmt.Sprintf("recovery code, %d left", s.Config.RecoveryCodesLeft(p.username))
	}
	s.Config.Audit(p.username, "login", loginDetail(ip, p.via, how))
	u, _ := s.Config.SessionUserByName(p.username)
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "recoveryUsed": recovery, "recoveryLeft": s.Config.RecoveryCodesLeft(p.username)})
}

type mfaSetup struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	QR     string `json:"qr"` // data: URL of a PNG
}

func (s *Server) beginMFA(username string) (*mfaSetup, error) {
	secret, err := s.Config.BeginMFA(username)
	if err != nil {
		return nil, err
	}
	issuer := s.Config.Settings().ApplianceName
	uri := totp.URI(issuer, username, secret)
	png, err := totp.QRPNG(uri)
	if err != nil {
		return nil, err
	}
	return &mfaSetup{Secret: secret, URI: uri, QR: "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)}, nil
}

// mfaEnroll starts setup during sign-in when the policy requires it.
func (s *Server) mfaEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
		Code  string `json:"code"` // set to finish
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p, ok := s.mfa.get(req.Token, "enroll")
	if !ok {
		writeErr(w, http.StatusUnauthorized, "the sign-in expired; enter your password again")
		return
	}
	if req.Code == "" {
		setup, err := s.beginMFA(p.username)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, setup)
		return
	}
	codes, err := s.Config.EnableMFA(p.username, req.Code)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mfa.drop(req.Token)
	if err := s.startSession(w, p.username); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	s.Config.Audit(p.username, "mfa.enable", "during sign-in")
	s.Config.Audit(p.username, "login", loginDetail(p.ip, p.via, "authenticator code"))
	u, _ := s.Config.SessionUserByName(p.username)
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "recoveryCodes": codes})
}

// canUseMFA: password-based accounts only; SSO users rely on their provider.
func (s *Server) canUseMFA(u *config.User) bool {
	if u.SourceID == 0 {
		return true
	}
	src, err := s.Config.IdentitySource(u.SourceID, false)
	return err == nil && src.PasswordBased()
}

func (s *Server) mfaStatus(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	writeJSON(w, http.StatusOK, map[string]any{"available": s.canUseMFA(u), "enabled": s.Config.MFAEnabled(u.Username),
		"recoveryLeft": s.Config.RecoveryCodesLeft(u.Username), "required": u.Role == "admin" && s.Config.Settings().RequireMFAAdmins})
}

func (s *Server) mfaSetupStart(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if !s.canUseMFA(u) {
		writeErr(w, http.StatusBadRequest, "single sign-on accounts use their identity provider's two-factor authentication")
		return
	}
	setup, err := s.beginMFA(u.Username)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, setup)
}

func (s *Server) mfaSetupFinish(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	codes, err := s.Config.EnableMFA(u.Username, req.Code)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Config.Audit(u.Username, "mfa.enable", "")
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

func (s *Server) mfaDisable(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if u.Role == "admin" && s.Config.Settings().RequireMFAAdmins {
		writeErr(w, http.StatusBadRequest, "two-factor authentication is required for administrators")
		return
	}
	if _, err := s.Config.VerifyMFA(u.Username, req.Code); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Config.DisableMFA(u.Username); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Config.Audit(u.Username, "mfa.disable", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// mfaReset lets an administrator turn off MFA for someone who lost their
// device; their sessions end.
func (s *Server) mfaReset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("username")
	if err := s.Config.DisableMFA(name); err != nil {
		writeErr(w, http.StatusNotFound, "no such user")
		return
	}
	_ = s.Config.DeleteUserSessions(name)
	s.Config.Audit(userFrom(r).Username, "mfa.reset", name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
