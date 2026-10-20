package api

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kochlabs/tributary/internal/certs"
	"github.com/kochlabs/tributary/internal/config"
)

func (s *Server) certStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.Certs.Status()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": st, "defaults": certs.DefaultIdentity()})
}

func (s *Server) certDownload(w http.ResponseWriter, r *http.Request) {
	b, err := s.Certs.CertificatePEM()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="tributary-certificate.pem"`)
	_, _ = w.Write(b)
}

func (s *Server) certUpload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"privateKey"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	d, err := s.Certs.Upload([]byte(req.Certificate), []byte(req.PrivateKey))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "certificate.upload", fmt.Sprintf("%s, issuer %s, expires %s", d.Subject, d.Issuer, time.UnixMilli(d.NotAfter).Format("2006-01-02")))
	writeJSON(w, http.StatusOK, d)
}

type certRequest struct {
	Identity certs.Identity `json:"identity"`
	KeyType  string         `json:"keyType"`
	Days     int            `json:"days"`
}

func (s *Server) certCSR(w http.ResponseWriter, r *http.Request) {
	var req certRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	info, err := s.Certs.GenerateCSR(req.Identity, req.KeyType)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "certificate.csr", info.CommonName+" ("+info.Key+")")
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) certCSRDiscard(w http.ResponseWriter, r *http.Request) {
	s.Certs.DiscardCSR()
	s.Config.Audit(userFrom(r).Username, "certificate.csr.discard", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) certSelfSigned(w http.ResponseWriter, r *http.Request) {
	var req certRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	d, err := s.Certs.RegenerateSelfSigned(req.Identity, req.KeyType, req.Days)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "certificate.self-signed", d.Subject)
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) certRestore(w http.ResponseWriter, r *http.Request) {
	d, err := s.Certs.Restore()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "certificate.restore", d.Subject)
	writeJSON(w, http.StatusOK, d)
}

// ---- trusted CAs ----

// trustedView is a stored CA with its parsed details (which carry the
// fingerprint, so the stored copy's is not repeated).
type trustedView struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"createdAt"`
	certs.Details
}

// ReloadTrust pushes the stored CAs into the outbound trust store.
func (s *Server) ReloadTrust() error {
	list, err := s.Config.TrustedCAs()
	if err != nil {
		return err
	}
	var cas []*x509.Certificate
	for _, t := range list {
		if c, err := certs.ParseCertificates([]byte(t.PEM)); err == nil {
			cas = append(cas, c...)
		}
	}
	s.Trust.Set(cas)
	return nil
}

func (s *Server) trustedList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Config.TrustedCAs()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := []trustedView{}
	for _, t := range list {
		v := trustedView{ID: t.ID, Name: t.Name, CreatedAt: t.CreatedAt}
		if c, err := certs.ParseCertificates([]byte(t.PEM)); err == nil {
			v.Details = certs.Describe(c[0], 1)
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// trustedAdd accepts one or more CA certificates (e.g. a root and its
// intermediates) in PEM form.
func (s *Server) trustedAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		PEM  string `json:"pem"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	list, err := certs.ParseCertificates([]byte(req.PEM))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, c := range list {
		if !c.IsCA {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("%q is not a CA certificate (basic constraints CA:FALSE); add the issuing CA instead", c.Subject.CommonName))
			return
		}
	}
	var added []string
	for _, c := range list {
		name := strings.TrimSpace(req.Name)
		if name == "" || len(list) > 1 {
			name = c.Subject.CommonName
			if name == "" {
				name = c.Subject.String()
			}
		}
		if len(name) > 128 {
			name = name[:128]
		}
		d := certs.Describe(c, 1)
		one := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
		if _, err := s.Config.AddTrustedCA(name, one, d.SHA256); err != nil {
			if errors.Is(err, config.ErrDuplicateCA) && len(list) > 1 {
				continue // skip ones already present when adding a bundle
			}
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		added = append(added, name)
	}
	if err := s.ReloadTrust(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "trusted-ca.add", strings.Join(added, ", "))
	writeJSON(w, http.StatusOK, map[string]any{"added": added})
}

func (s *Server) trustedDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.Config.DeleteTrustedCA(id); err != nil {
		writeErr(w, http.StatusNotFound, "trusted CA not found")
		return
	}
	_ = s.ReloadTrust()
	s.Config.Audit(userFrom(r).Username, "trusted-ca.delete", strconv.FormatInt(id, 10))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
