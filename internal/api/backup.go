package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	"nfa/internal/backup"
)

// uploadPath accepts a raw backup file instead of JSON (still CSRF-safe: it
// requires the X-Requested-With header, which forces a CORS preflight).
const uploadPath = "/api/restore/upload"

func (s *Server) backupsList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Backups.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	flows, _ := s.Backups.FlowsSize(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"backups": list, "job": s.Backups.Job(),
		"freeBytes": backup.FreeSpace(s.DataDir), "flowsBytes": flows, "minPassphrase": backup.MinPassphrase})
}

func (s *Server) backupCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase   string `json:"passphrase"`
		IncludeFlows bool   `json:"includeFlows"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Backups.StartBackup(req.Passphrase, req.IncludeFlows); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	detail := "configuration"
	if req.IncludeFlows {
		detail += " and flow history"
	}
	s.Config.Audit(userFrom(r).Username, "backup.create", detail)
	writeJSON(w, http.StatusAccepted, s.Backups.Job())
}

func (s *Server) backupDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	p, err := s.Backups.Path(name)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such backup")
		return
	}
	f, err := os.Open(p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer f.Close()
	fi, _ := f.Stat()
	// Large backups take longer than the server's default write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(6 * time.Hour))
	s.Config.Audit(userFrom(r).Username, "backup.download", name)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

func (s *Server) backupDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Backups.Delete(name); err != nil {
		writeErr(w, http.StatusNotFound, "no such backup")
		return
	}
	s.Config.Audit(userFrom(r).Username, "backup.delete", name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) restoreUpload(w http.ResponseWriter, r *http.Request) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(6 * time.Hour))
	const margin = 200 << 20
	free := int64(backup.FreeSpace(s.DataDir))
	if free <= margin {
		writeErr(w, http.StatusInsufficientStorage, "not enough free disk space to receive a backup")
		return
	}
	n, err := s.Backups.Upload(r.Body, free-margin)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"size": n})
}

func (s *Server) restoreInspect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	man, err := s.Backups.Inspect(req.Passphrase)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, man)
}

func (s *Server) restoreApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase   string `json:"passphrase"`
		RestoreFlows bool   `json:"restoreFlows"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.Restart == nil {
		writeErr(w, http.StatusInternalServerError, "restore is not available")
		return
	}
	man, err := s.Backups.Inspect(req.Passphrase)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Backups.StartRestore(req.Passphrase, req.RestoreFlows, s.Restart); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	detail := "backup of " + man.Hostname + " from " + time.UnixMilli(man.Created).UTC().Format(time.RFC3339)
	if req.RestoreFlows {
		detail += " (with flow history)"
	}
	s.Config.Audit(userFrom(r).Username, "restore.apply", detail)
	writeJSON(w, http.StatusAccepted, s.Backups.Job())
}
