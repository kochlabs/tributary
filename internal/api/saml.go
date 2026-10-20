package api

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"

	"nfa/internal/config"
)

// SAML 2.0 sign-in (Web Browser SSO profile). The appliance is the service
// provider: it sends signed AuthnRequests with the HTTP-Redirect binding and
// accepts HTTP-POST responses at its assertion consumer service (ACS).
// Only responses to a request this browser started are accepted (no
// IdP-initiated sign-in), each request ID is usable once, and assertions
// must be signed by the provider and addressed to this appliance.

const samlMaxResponse = 1 << 20

// samlURLs returns the appliance's metadata URL (also the default entity ID)
// and ACS URL for a source, for the address the browser used.
func (s *Server) samlURLs(r *http.Request, id int64) (metadata, acs url.URL) {
	scheme := "https"
	if !s.SecureCookies {
		scheme = "http"
	}
	base := url.URL{Scheme: scheme, Host: r.Host}
	metadata, acs = base, base
	metadata.Path = fmt.Sprintf("/api/auth/sso/%d/metadata", id)
	acs.Path = fmt.Sprintf("/api/auth/sso/%d/acs", id)
	return metadata, acs
}

func (s *Server) samlEntityID(r *http.Request, src *config.IdentitySource) string {
	if src.SAML.EntityID != "" {
		return src.SAML.EntityID
	}
	m, _ := s.samlURLs(r, src.ID)
	return m.String()
}

// samlSP builds the service provider for a source. Without the private key
// (withKey false) it can only describe itself (metadata).
func (s *Server) samlSP(r *http.Request, src *config.IdentitySource, withKey bool) (*saml.ServiceProvider, error) {
	block, _ := pem.Decode([]byte(src.SAML.SPCert))
	if block == nil {
		return nil, errors.New("the source has no service provider certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	metaURL, acsURL := s.samlURLs(r, src.ID)
	sp := &saml.ServiceProvider{
		EntityID:          s.samlEntityID(r, src),
		Certificate:       cert,
		MetadataURL:       metaURL,
		AcsURL:            acsURL,
		AuthnNameIDFormat: saml.UnspecifiedNameIDFormat,
		HTTPClient:        s.trustClient(),
	}
	if src.SAML.SignRequests {
		sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	}
	// The SAML profile requires an audience restriction naming this service
	// provider; the library would accept an assertion without one.
	sp.ValidateAudienceRestriction = func(a *saml.Assertion) error {
		if a.Conditions == nil {
			return errors.New("assertion has no Conditions")
		}
		for _, ar := range a.Conditions.AudienceRestrictions {
			if ar.Audience.Value == sp.EntityID {
				return nil
			}
		}
		return fmt.Errorf("assertion is not addressed to %q", sp.EntityID)
	}
	if src.SAML.MetadataXML != "" {
		if sp.IDPMetadata, err = samlsp.ParseMetadata([]byte(src.SAML.MetadataXML)); err != nil {
			return nil, fmt.Errorf("the stored provider metadata is invalid: %w", err)
		}
	}
	if withKey {
		kb, _ := pem.Decode([]byte(src.SAML.SPKey))
		if kb == nil {
			return nil, errors.New("the source's private key is missing")
		}
		key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("unsupported private key")
		}
		sp.Key = signer
	}
	return sp, nil
}

func (s *Server) trustClient() *http.Client {
	if s.Trust == nil {
		return &http.Client{Timeout: 15 * time.Second}
	}
	return s.Trust.Client()
}

// fetchSAMLMetadata downloads and checks a provider's metadata.
func (s *Server) fetchSAMLMetadata(ctx context.Context, rawURL string) (string, *saml.EntityDescriptor, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := s.trustClient().Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("could not fetch the metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("could not fetch the metadata: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, samlMaxResponse+1))
	if err != nil {
		return "", nil, fmt.Errorf("could not fetch the metadata: %w", err)
	}
	if len(b) > samlMaxResponse {
		return "", nil, errors.New("the metadata is too large")
	}
	ed, err := parseIdPMetadata(b)
	if err != nil {
		return "", nil, err
	}
	return string(b), ed, nil
}

// parseIdPMetadata parses provider metadata and checks it can be used.
func parseIdPMetadata(b []byte) (*saml.EntityDescriptor, error) {
	ed, err := samlsp.ParseMetadata(b)
	if err != nil {
		return nil, fmt.Errorf("the metadata is not valid SAML metadata: %w", err)
	}
	if len(ed.IDPSSODescriptors) == 0 {
		return nil, errors.New("the metadata describes no identity provider (IDPSSODescriptor)")
	}
	if idpSSO(ed) == "" {
		return nil, errors.New("the identity provider offers no single sign-on service with the HTTP-Redirect binding")
	}
	if len(idpSigningCerts(ed)) == 0 {
		return nil, errors.New("the metadata contains no signing certificate")
	}
	return ed, nil
}

func idpSSO(ed *saml.EntityDescriptor) string {
	for _, d := range ed.IDPSSODescriptors {
		for _, s := range d.SingleSignOnServices {
			if s.Binding == saml.HTTPRedirectBinding {
				return s.Location
			}
		}
	}
	return ""
}

func idpSigningCerts(ed *saml.EntityDescriptor) []*x509.Certificate {
	var out []*x509.Certificate
	for _, d := range ed.IDPSSODescriptors {
		for _, kd := range d.KeyDescriptors {
			if kd.Use != "" && kd.Use != "signing" {
				continue
			}
			for _, xc := range kd.KeyInfo.X509Data.X509Certificates {
				raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(xc.Data), ""))
				if err != nil {
					continue
				}
				if c, err := x509.ParseCertificate(raw); err == nil {
					out = append(out, c)
				}
			}
		}
	}
	return out
}

// prepareSAML fills in a SAML source's metadata before it is saved: fetched
// from its URL, or the pasted XML checked.
func (s *Server) prepareSAML(ctx context.Context, src *config.IdentitySource) error {
	c := src.SAML
	if c == nil {
		return nil
	}
	c.MetadataURL = strings.TrimSpace(c.MetadataURL)
	if c.MetadataURL == "" {
		if strings.TrimSpace(c.MetadataXML) == "" {
			return errors.New("the identity provider's metadata is required: enter its URL or paste the XML")
		}
		_, err := parseIdPMetadata([]byte(c.MetadataXML))
		c.MetadataFetched = 0
		return err
	}
	xmlText, _, err := s.fetchSAMLMetadata(ctx, c.MetadataURL)
	if err != nil {
		// Keep the stored copy if the provider is briefly unreachable while
		// other settings are edited.
		if src.ID != 0 {
			if stored, serr := s.Config.IdentitySource(src.ID, false); serr == nil && stored.SAML != nil &&
				stored.SAML.MetadataURL == c.MetadataURL && stored.SAML.MetadataXML != "" {
				c.MetadataXML, c.MetadataFetched = stored.SAML.MetadataXML, stored.SAML.MetadataFetched
				return nil
			}
		}
		return err
	}
	c.MetadataXML, c.MetadataFetched = xmlText, time.Now().UnixMilli()
	return nil
}

// refreshSAMLMetadata re-fetches a source's metadata when it is older than a
// day, so provider certificate rollovers are picked up. Failures keep the
// stored copy.
func (s *Server) refreshSAMLMetadata(ctx context.Context, src *config.IdentitySource) {
	c := src.SAML
	if c.MetadataURL == "" || time.Since(time.UnixMilli(c.MetadataFetched)) < config.MetadataMaxAge {
		return
	}
	xmlText, _, err := s.fetchSAMLMetadata(ctx, c.MetadataURL)
	if err != nil {
		s.Log.Warn("saml metadata refresh failed; using the stored copy", "source", src.Name, "err", err)
		return
	}
	now := time.Now()
	if err := s.Config.SaveSAMLMetadata(src.ID, xmlText, now); err != nil {
		s.Log.Warn("saml metadata save failed", "source", src.Name, "err", err)
	}
	c.MetadataXML, c.MetadataFetched = xmlText, now.UnixMilli()
}

func (s *Server) samlStart(w http.ResponseWriter, r *http.Request, src *config.IdentitySource) {
	s.refreshSAMLMetadata(r.Context(), src)
	sp, err := s.samlSP(r, src, true)
	if err != nil {
		s.Log.Warn("saml start failed", "source", src.Name, "err", err)
		ssoFail(w, r, "Sign-in with "+src.Name+" is not set up correctly.")
		return
	}
	req, err := sp.MakeAuthenticationRequest(idpSSO(sp.IDPMetadata), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		s.Log.Warn("saml request failed", "source", src.Name, "err", err)
		ssoFail(w, r, "Sign-in with "+src.Name+" is not set up correctly.")
		return
	}
	relay := randomString(16)
	u, err := req.Redirect(relay, sp)
	if err != nil {
		s.Log.Warn("saml request failed", "source", src.Name, "err", err)
		ssoFail(w, r, "Sign-in with "+src.Name+" is not set up correctly.")
		return
	}
	if err := s.sso.put(relay, ssoPending{sourceID: src.ID, requestID: req.ID, next: safeNext(r.URL.Query().Get("next")), expires: time.Now().Add(ssoTimeout)}); err != nil {
		ssoFail(w, r, err.Error())
		return
	}
	// The response comes back as a cross-site POST, which only carries
	// SameSite=None cookies.
	http.SetCookie(w, s.samlCookie(relay, int(ssoTimeout.Seconds())))
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) samlCookie(value string, maxAge int) *http.Cookie {
	c := &http.Cookie{Name: ssoCookie, Value: value, Path: "/api/auth/sso/", HttpOnly: true, Secure: s.SecureCookies, MaxAge: maxAge,
		SameSite: http.SameSiteNoneMode}
	if !s.SecureCookies {
		c.SameSite = http.SameSiteLaxMode // browsers reject SameSite=None without Secure
	}
	return c
}

// samlACS receives the provider's response (HTTP-POST binding).
func (s *Server) samlACS(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	http.SetCookie(w, s.samlCookie("", -1))
	r.Body = http.MaxBytesReader(w, r.Body, 2*samlMaxResponse)
	if err := r.ParseForm(); err != nil {
		ssoFail(w, r, "Sign-in failed: the provider's response could not be read.")
		return
	}
	relay := r.PostForm.Get("RelayState")
	c, err := r.Cookie(ssoCookie)
	if err != nil || relay == "" || c.Value != relay {
		ssoFail(w, r, "The sign-in session expired or was started in another browser. Please try again.")
		return
	}
	pend, ok := s.sso.take(relay)
	if !ok || pend.sourceID != id || pend.requestID == "" {
		ssoFail(w, r, "The sign-in session expired. Please try again.")
		return
	}
	src, err := s.Config.IdentitySource(id, true)
	if err != nil || !src.Enabled || src.SAML == nil {
		ssoFail(w, r, "That sign-in option is not available.")
		return
	}
	sp, err := s.samlSP(r, src, true)
	if err != nil {
		s.Log.Warn("saml acs failed", "source", src.Name, "err", err)
		ssoFail(w, r, "Sign-in with "+src.Name+" is not set up correctly.")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLResponse"))
	if err != nil || len(raw) == 0 {
		ssoFail(w, r, "Sign-in failed: the provider's response could not be read.")
		return
	}
	a, err := parseSAMLResponse(sp, raw, pend.requestID)
	if err != nil {
		var bad saml.ErrBadStatus
		var inv *saml.InvalidResponseError
		detail := err
		if errors.As(err, &inv) && inv.PrivateErr != nil {
			detail = inv.PrivateErr
			errors.As(inv.PrivateErr, &bad)
		}
		s.Log.Warn("saml response rejected", "source", src.Name, "err", detail)
		s.Config.Audit("-", "login.sso.denied", fmt.Sprintf("%s via %s: response rejected", clientIP(r), src.Name))
		if bad.Status != "" {
			ssoFail(w, r, src.Name+" refused the sign-in ("+strings.TrimPrefix(bad.Status, "urn:oasis:names:tc:SAML:2.0:status:")+").")
			return
		}
		ssoFail(w, r, "Sign-in failed: the response from "+src.Name+" could not be verified.")
		return
	}
	username, fullName, groups := samlIdentity(a, src.SAML)
	if username == "" {
		what := "a NameID"
		if src.SAML.UsernameAttr != "" {
			what = fmt.Sprintf("the %q attribute", src.SAML.UsernameAttr)
		}
		ssoFail(w, r, "Sign-in failed: the provider did not send "+what+" to use as the username.")
		return
	}
	s.ssoFinish(w, r, src, username, fullName, groups, pend.next)
}

// parseSAMLResponse verifies a response with the library and adds the checks
// it leaves out: the assertion must carry a bearer confirmation bound to our
// request, and malformed (but signed) input must not crash the handler.
func parseSAMLResponse(sp *saml.ServiceProvider, raw []byte, requestID string) (a *saml.Assertion, err error) {
	defer func() {
		if p := recover(); p != nil {
			a, err = nil, fmt.Errorf("malformed response: %v", p)
		}
	}()
	acs := sp.AcsURL
	a, err = sp.ParseXMLResponse(raw, []string{requestID}, acs)
	if err != nil {
		return nil, err
	}
	if a.Subject == nil {
		return nil, errors.New("assertion has no Subject")
	}
	bound := false
	for _, sc := range a.Subject.SubjectConfirmations {
		if sc.Method == "urn:oasis:names:tc:SAML:2.0:cm:bearer" && sc.SubjectConfirmationData != nil &&
			sc.SubjectConfirmationData.InResponseTo == requestID && sc.SubjectConfirmationData.Recipient == acs.String() {
			bound = true
		}
	}
	if !bound {
		return nil, errors.New("assertion has no bearer SubjectConfirmation for this request")
	}
	return a, nil
}

// samlIdentity reads the username, display name and groups from an
// assertion. Attributes match by Name or FriendlyName.
func samlIdentity(a *saml.Assertion, c *config.SAMLConfig) (username, fullName string, groups []string) {
	values := func(name string) []string {
		if name == "" {
			return nil
		}
		var out []string
		for _, st := range a.AttributeStatements {
			for _, at := range st.Attributes {
				if at.Name == name || (at.FriendlyName != "" && at.FriendlyName == name) {
					for _, v := range at.Values {
						if t := strings.TrimSpace(v.Value); t != "" {
							out = append(out, t)
						}
					}
				}
			}
		}
		return out
	}
	if c.UsernameAttr != "" {
		if v := values(c.UsernameAttr); len(v) > 0 {
			username = v[0]
		}
	} else if a.Subject != nil && a.Subject.NameID != nil {
		username = strings.TrimSpace(a.Subject.NameID.Value)
	}
	if v := values(c.NameAttr); len(v) > 0 {
		fullName = v[0]
	}
	return username, fullName, values(c.GroupsAttr)
}

// samlMetadata publishes the appliance's service provider metadata for a
// source, for the identity provider administrator to import.
func (s *Server) samlMetadata(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	src, err := s.Config.IdentitySource(id, false)
	if err != nil || src.SAML == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	sp, err := s.samlSP(r, src, false)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	md := sp.Metadata()
	for i := range md.SPSSODescriptors {
		// Only the HTTP-POST binding is accepted at the ACS.
		var acs []saml.IndexedEndpoint
		for _, e := range md.SPSSODescriptors[i].AssertionConsumerServices {
			if e.Binding == saml.HTTPPostBinding {
				acs = append(acs, e)
			}
		}
		md.SPSSODescriptors[i].AssertionConsumerServices = acs
	}
	b, err := xml.MarshalIndent(md, "", "  ")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	if r.URL.Query().Has("download") {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="tributary-saml-%d.xml"`, id))
	}
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(b)
}

// samlInfo describes the appliance side of a SAML source for the editor.
func (s *Server) samlInfo(r *http.Request, src *config.IdentitySource) map[string]any {
	if src == nil || src.SAML == nil {
		return nil
	}
	meta, acs := s.samlURLs(r, src.ID)
	out := map[string]any{"entityId": s.samlEntityID(r, src), "acsUrl": acs.String(), "metadataUrl": meta.String()}
	if b, _ := pem.Decode([]byte(src.SAML.SPCert)); b != nil {
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			out["certExpires"] = c.NotAfter.UnixMilli()
		}
	}
	return out
}

// samlTest loads a provider's metadata (from the URL or pasted XML) and
// describes it.
func (s *Server) samlTest(w http.ResponseWriter, r *http.Request, c *config.SAMLConfig) {
	if c == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Enter the provider's metadata URL or XML."})
		return
	}
	var ed *saml.EntityDescriptor
	var err error
	switch {
	case strings.TrimSpace(c.MetadataURL) != "":
		_, ed, err = s.fetchSAMLMetadata(r.Context(), strings.TrimSpace(c.MetadataURL))
	case strings.TrimSpace(c.MetadataXML) != "":
		ed, err = parseIdPMetadata([]byte(c.MetadataXML))
	default:
		err = errors.New("enter the provider's metadata URL or paste its XML")
	}
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	var certs []map[string]any
	msg := "Provider metadata loaded."
	for _, cert := range idpSigningCerts(ed) {
		certs = append(certs, map[string]any{"subject": cert.Subject.String(), "notAfter": cert.NotAfter.UnixMilli()})
		if time.Now().After(cert.NotAfter) {
			msg += " Note: a signing certificate has expired (most providers still use it; check that it's current)."
		}
	}
	wantsSigned := false
	for _, d := range ed.IDPSSODescriptors {
		if d.WantAuthnRequestsSigned != nil && *d.WantAuthnRequestsSigned {
			wantsSigned = true
		}
	}
	if wantsSigned && !c.SignRequests {
		msg += " The provider requires signed requests: turn on request signing."
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg, "idpEntityId": ed.EntityID, "ssoUrl": idpSSO(ed),
		"signingCerts": certs, "wantsSignedRequests": wantsSigned})
}
