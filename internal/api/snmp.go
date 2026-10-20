package api

import (
	"context"
	"net/http"
	"time"

	"nfa/internal/config"
)

func (s *Server) snmpGet(w http.ResponseWriter, r *http.Request) {
	addr, ok := validAddr(w, r.PathValue("addr"))
	if !ok {
		return
	}
	c, st, err := s.Config.SNMP(addr)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c.View(st))
}

func (s *Server) snmpPut(w http.ResponseWriter, r *http.Request) {
	addr, ok := validAddr(w, r.PathValue("addr"))
	if !ok {
		return
	}
	var c config.SNMPConfig
	if err := readJSON(r, &c); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Config.SaveSNMP(addr, c); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	detail := addr + " off"
	if c.Version != "" {
		detail = addr + " v" + c.Version
		s.SNMP.PollSoon(addr)
	}
	s.Config.Audit(userFrom(r).Username, "snmp.update", detail)
	saved, st, _ := s.Config.SNMP(addr)
	writeJSON(w, http.StatusOK, saved.View(st))
}

// snmpPoll polls an exporter now and returns the outcome.
func (s *Server) snmpPoll(w http.ResponseWriter, r *http.Request) {
	addr, ok := validAddr(w, r.PathValue("addr"))
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	pollErr := s.SNMP.Poll(ctx, addr)
	c, st, err := s.Config.SNMP(addr)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pollErr != nil && st.LastError == "" {
		st.LastError = pollErr.Error()
	}
	writeJSON(w, http.StatusOK, c.View(st))
}
