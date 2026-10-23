package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kochlabs/tributary/internal/config"
	"github.com/kochlabs/tributary/internal/mail"
)

// Email (Configuration → Email): the SMTP server the appliance sends mail
// through.

func (s *Server) emailGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Config.Email())
}

func (s *Server) emailPut(w http.ResponseWriter, r *http.Request) {
	var e config.Email
	if err := readJSON(r, &e); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.Config.SaveEmail(e)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	state := "off"
	if out.Enabled {
		state = "on"
	}
	s.Config.Audit(userFrom(r).Username, "email.update", fmt.Sprintf("email %s, %s:%d (%s)", state, out.Host, out.Port, out.Security))
	writeJSON(w, http.StatusOK, out)
}

// emailTest sends a test message with the given (possibly unsaved) settings.
func (s *Server) emailTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Config config.Email `json:"config"`
		To     string       `json:"to"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	e := req.Config
	e.Enabled = true // validate fully even while sending is off
	if err := config.ValidateEmail(&e); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	to, err := mail.Recipients(req.To)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Config.FillEmailSecrets(&e); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	u := userFrom(r).Username
	name := s.Config.Settings().ApplianceName
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err = mail.Send(ctx, e, s.trustPool(), mail.Message{
		To:      to,
		Subject: name + ": test message",
		Text: fmt.Sprintf("This is a test message from %s (%s), sent by %s at %s.\n\nEmail from the appliance is working.\n",
			name, s.baseURL(r), u, time.Now().Format("2006-01-02 15:04 MST")),
	})
	detail := strings.Join(to, ", ")
	if err != nil {
		s.Config.Audit(u, "email.test", detail+": failed: "+err.Error())
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.Config.Audit(u, "email.test", detail)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
