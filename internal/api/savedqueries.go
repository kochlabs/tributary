package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/kochlabs/tributary/internal/config"
)

// Saved queries: anyone signed in saves their own and sees shared ones;
// only the owner or an administrator changes or deletes one.

func (s *Server) savedQueriesList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Config.SavedQueries(userFrom(r).Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// mayChange tells whether the request's user may change q.
func mayChange(r *http.Request, q config.SavedQuery) bool {
	u := userFrom(r)
	return u.Username == q.Owner || u.Role == "admin"
}

func (s *Server) savedQuerySave(w http.ResponseWriter, r *http.Request) {
	var q config.SavedQuery
	if err := readJSON(r, &q); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	q.ID, q.Owner = 0, userFrom(r).Username
	action := "query.create"
	if p := r.PathValue("id"); p != "" {
		q.ID, _ = strconv.ParseInt(p, 10, 64)
		old, err := s.Config.SavedQuery(q.ID)
		if err != nil || !mayChange(r, old) && !old.Shared {
			writeErr(w, http.StatusNotFound, "no such saved query")
			return
		}
		if !mayChange(r, old) {
			writeErr(w, http.StatusForbidden, "only its owner or an administrator can change this query")
			return
		}
		action = "query.update"
	}
	_, _, canonical, err := s.compileQuery(q.Query)
	if err != nil {
		writeQueryErr(w, q.Query, err)
		return
	}
	q.Query = canonical
	saved, err := s.Config.SaveSavedQuery(q)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	detail := saved.Name
	if saved.Shared {
		detail += " (shared)"
	}
	s.Config.Audit(userFrom(r).Username, action, detail)
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) savedQueryDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	q, err := s.Config.SavedQuery(id)
	if err != nil || !mayChange(r, q) && !q.Shared {
		writeErr(w, http.StatusNotFound, "no such saved query")
		return
	}
	if !mayChange(r, q) {
		writeErr(w, http.StatusForbidden, "only its owner or an administrator can delete this query")
		return
	}
	if err := s.Config.DeleteSavedQuery(id); err != nil && !errors.Is(err, config.ErrNotFound) {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "query.delete", q.Name+" ("+q.Owner+")")
	w.WriteHeader(http.StatusNoContent)
}
