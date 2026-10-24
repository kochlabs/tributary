package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/kochlabs/tributary/internal/config"
	"github.com/kochlabs/tributary/internal/notify"
)

// Notification channels (Configuration → Notifications): destinations for
// webhooks and Telegram. Reports (and later rules) choose their channels.

func (s *Server) channelsList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Config.Channels()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"channels": list, "publicUrl": s.Config.Settings().PublicURL})
}

func (s *Server) channelSave(w http.ResponseWriter, r *http.Request) {
	var ch config.Channel
	if err := readJSON(r, &ch); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ch.ID = 0
	action := "notify.channel.create"
	if p := r.PathValue("id"); p != "" {
		ch.ID, _ = strconv.ParseInt(p, 10, 64)
		action = "notify.channel.update"
		if ch.Type == "webhook" {
			ch.Secret = "" // a webhook's secret changes only by regenerating it
		}
	}
	saved, err := s.Config.SaveChannel(ch)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, config.ErrNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, action, fmt.Sprintf("%s (%s)", saved.Name, saved.Type))
	writeJSON(w, http.StatusOK, saved) // a new webhook's secret, once
}

func (s *Server) channelDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ch, err := s.Config.Channel(id)
	if err == nil {
		err = s.Config.DeleteChannel(id)
	}
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such channel")
		return
	}
	s.Config.Audit(userFrom(r).Username, "notify.channel.delete", ch.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) channelRegenerate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ch, err := s.Config.Channel(id)
	if err != nil || ch.Type != "webhook" {
		writeErr(w, http.StatusNotFound, "no such webhook")
		return
	}
	sec, err := s.Config.RegenerateWebhookSecret(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "notify.channel.secret", ch.Name)
	writeJSON(w, http.StatusOK, map[string]string{"secret": sec})
}

// channelTest sends a test event through a channel as entered (a saved
// channel's secret when the form leaves it empty).
func (s *Server) channelTest(w http.ResponseWriter, r *http.Request) {
	var ch config.Channel
	if err := readJSON(r, &ch); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if ch.ID != 0 && ch.Secret == "" {
		if stored, err := s.Config.ChannelSecret(ch.ID); err == nil && stored.Type == ch.Type {
			ch.Secret = stored.Secret
		}
	}
	if ch.Type == "webhook" && ch.Secret == "" {
		ch.Secret = config.NewWebhookSecret() // unsaved: sign with a throwaway secret
	}
	if err := config.ValidateChannel(&ch); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if ch.Type == "telegram" && ch.Secret == "" {
		writeErr(w, http.StatusBadRequest, "enter the bot token")
		return
	}
	u := userFrom(r).Username
	name := s.Config.Settings().ApplianceName
	ev := notify.Event{ID: notify.NewID(), Type: "test", Level: "info", Appliance: name, Timestamp: time.Now(),
		Title: "Test notification", Message: fmt.Sprintf("Sent by %s from %s. Notifications are working.", u, name), URL: s.publicLink("/admin/notifications")}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err := s.Notify.Send(ctx, ch, ev)
	s.Config.Audit(u, "notify.channel.test", ch.Name+map[bool]string{true: "", false: ": failed"}[err == nil])
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) channelDeliveries(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	list, err := s.Config.Deliveries(id, 50)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}
