package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/kochlabs/tributary/internal/config"
)

// Inventory sources (Configuration → Inventory Sources): read-only
// connections to NetBox and the like, used for names and context.

func (s *Server) inventorySources(w http.ResponseWriter, r *http.Request) {
	list, err := s.Config.InventorySources()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) inventorySourceSave(w http.ResponseWriter, r *http.Request) {
	var src config.InventorySource
	if err := readJSON(r, &src); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	src.ID = 0
	action := "inventory.create"
	if p := r.PathValue("id"); p != "" {
		src.ID, _ = strconv.ParseInt(p, 10, 64)
		action = "inventory.update"
	}
	saved, err := s.Config.SaveInventorySource(src)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, config.ErrNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, action, fmt.Sprintf("%s (%s)", saved.Name, saved.URL))
	_ = s.Inventory.Reload()
	if saved.Enabled {
		s.Inventory.SyncSoon(saved.ID)
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) inventorySourceDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	src, err := s.Config.InventorySource(id)
	if err == nil {
		err = s.Config.DeleteInventorySource(id)
	}
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such inventory source")
		return
	}
	_ = s.Inventory.Reload()
	s.Config.Audit(userFrom(r).Username, "inventory.delete", src.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// inventorySourceTest syncs a source as entered (the stored token when the
// form leaves it empty) without keeping the result.
func (s *Server) inventorySourceTest(w http.ResponseWriter, r *http.Request) {
	var src config.InventorySource
	if err := readJSON(r, &src); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := config.ValidateInventorySource(&src); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Config.FillInventoryToken(&src); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if src.Token == "" {
		writeErr(w, http.StatusBadRequest, "enter an API token")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	res, err := s.Inventory.Test(ctx, src)
	s.Config.Audit(userFrom(r).Username, "inventory.test", src.URL)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": res})
}

func (s *Server) inventorySourceSync(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if _, err := s.Config.InventorySource(id); err != nil {
		writeErr(w, http.StatusNotFound, "no such inventory source")
		return
	}
	s.Inventory.SyncSoon(id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
