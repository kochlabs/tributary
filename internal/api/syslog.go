package api

import (
	"context"
	"net/http"
	"time"

	"github.com/kochlabs/tributary/internal/config"
)

func (s *Server) syslogGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"config": s.Config.Syslog(), "status": s.Syslog.Status()})
}

func (s *Server) syslogPut(w http.ResponseWriter, r *http.Request) {
	var c config.Syslog
	if err := readJSON(r, &c); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	c, err := s.Config.SaveSyslog(c)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Syslog.SetConfig(c)
	state := "off"
	if c.Enabled {
		state = "on"
	}
	// Audited after applying, so turning forwarding on is itself forwarded.
	s.Config.Audit(userFrom(r).Username, "syslog.update", "forwarding "+state)
	writeJSON(w, http.StatusOK, map[string]any{"config": c, "status": s.Syslog.Status()})
}

// syslogTest sends a test message with the given (possibly unsaved) settings.
func (s *Server) syslogTest(w http.ResponseWriter, r *http.Request) {
	var c config.Syslog
	if err := readJSON(r, &c); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	c.Enabled = len(c.Targets) > 0 // validate the servers even if forwarding is still off
	if err := config.ValidateSyslog(&c); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	type result struct {
		Address string `json:"address"`
		OK      bool   `json:"ok"`
		Error   string `json:"error,omitempty"`
	}
	out := []result{}
	for i, err := range s.Syslog.Test(ctx, c, userFrom(r).Username) {
		res := result{Address: c.Targets[i].HostPort() + " (" + c.Targets[i].Transport + ")", OK: err == nil}
		if err != nil {
			res.Error = err.Error()
		}
		out = append(out, res)
	}
	writeJSON(w, http.StatusOK, out)
}
