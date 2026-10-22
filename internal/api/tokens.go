package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/kochlabs/tributary/internal/config"
)

// API tokens for MCP clients, managed by administrators (Access → API
// Tokens). A token acts as its owner, with the owner's role: a token for a
// viewer account can only view.

func (s *Server) tokensList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Config.APITokens("")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": list, "mcpEnabled": s.Config.Settings().MCPEnabled, "endpoint": s.mcpURL(r)})
}

func (s *Server) tokenCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Name     string `json:"name"`
		Days     int    `json:"days"` // 0 = no expiry
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Days < 0 || req.Days > 3650 {
		writeErr(w, http.StatusBadRequest, "expiry must be between 1 and 3650 days, or none")
		return
	}
	if _, err := s.Config.SessionUserByName(req.Username); err != nil {
		writeErr(w, http.StatusBadRequest, "no such user")
		return
	}
	secret, t, err := s.Config.CreateAPIToken(req.Username, req.Name, time.Duration(req.Days)*24*time.Hour)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, config.ErrTooManyTokens) || errors.Is(err, config.ErrTokenName) {
			code = http.StatusBadRequest
		}
		writeErr(w, code, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "token.create", fmt.Sprintf("%s for %s (%s…)", t.Name, t.Username, t.Prefix))
	writeJSON(w, http.StatusOK, map[string]any{"token": secret, "info": t})
}

func (s *Server) tokenDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t, err := s.Config.DeleteAPIToken(id, "")
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such token")
		return
	}
	s.Config.Audit(userFrom(r).Username, "token.revoke", fmt.Sprintf("%s of %s (%s…)", t.Name, t.Username, t.Prefix))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// mcpURL is the MCP endpoint as this browser reaches the appliance.
func (s *Server) mcpURL(r *http.Request) string {
	scheme := "https"
	if !s.SecureCookies {
		scheme = "http"
	}
	return scheme + "://" + r.Host + mcpPath
}
