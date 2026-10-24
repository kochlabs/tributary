// Package notify delivers events (report runs, later rule findings) to
// notification channels: signed webhooks (Standard Webhooks) and Telegram.
// The source of an event chooses its channels; deliveries are queued in the
// configuration database and retried.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kochlabs/tributary/internal/config"
)

// Event is something to tell people about.
type Event struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"` // report.completed | report.failed | test (later finding.*)
	Timestamp time.Time      `json:"timestamp"`
	Appliance string         `json:"appliance"`
	Level     string         `json:"level"` // info | warning | danger
	Title     string         `json:"title"`
	Message   string         `json:"message"`
	URL       string         `json:"url,omitempty"` // a page in Tributary, when its address is set
	Data      map[string]any `json:"data,omitempty"`
	// Attachment is a file sent along where the channel can (Telegram); the
	// webhook payload names it in data instead.
	Attachment     string `json:"-"`
	AttachmentName string `json:"-"`
}

// NewID makes an event ID.
func NewID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "evt_" + hex.EncodeToString(b)
}

// Dispatcher queues events for channels and delivers them.
type Dispatcher struct {
	Cfg    *config.DB
	Log    *slog.Logger
	Client func() *http.Client
	Agent  string
	// TelegramAPI is the Bot API base (tests point it elsewhere).
	TelegramAPI string

	kick chan struct{}
}

func (d *Dispatcher) init() {
	if d.kick == nil {
		d.kick = make(chan struct{}, 1)
	}
	if d.TelegramAPI == "" {
		d.TelegramAPI = "https://api.telegram.org"
	}
}

// Publish queues ev for the given channels (disabled or deleted ones are
// skipped).
func (d *Dispatcher) Publish(ev Event, channels []int64) {
	if d == nil || len(channels) == 0 {
		return
	}
	d.init()
	if ev.ID == "" {
		ev.ID = NewID()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return
	}
	queued := false
	for _, id := range channels {
		ch, err := d.Cfg.Channel(id)
		if err != nil || !ch.Enabled {
			continue
		}
		del := config.Delivery{ChannelID: ch.ID, EventID: ev.ID, EventType: ev.Type, Payload: string(payload)}
		if ch.Type == "telegram" {
			del.Attachment = ev.Attachment
		}
		if err := d.Cfg.EnqueueDelivery(del); err != nil {
			d.Log.Warn("notify: queueing", "channel", ch.Name, "err", err)
			continue
		}
		queued = true
	}
	if queued {
		select {
		case d.kick <- struct{}{}:
		default:
		}
	}
}

// retryAfter is the wait before attempt n+1 (n attempts made so far).
var retryAfter = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour}

// giveUp is how long a delivery, and a failing channel, are retried.
const giveUp = 24 * time.Hour

// Run delivers queued events until ctx ends.
func (d *Dispatcher) Run(ctx context.Context) {
	d.init()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	prune := time.NewTicker(6 * time.Hour)
	defer prune.Stop()
	for {
		d.deliverDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-d.kick:
		case <-t.C:
		case <-prune.C:
			_ = d.Cfg.PruneDeliveries(7 * 24 * time.Hour)
		}
	}
}

func (d *Dispatcher) deliverDue(ctx context.Context) {
	due, err := d.Cfg.DueDeliveries(time.Now(), 100)
	if err != nil {
		return
	}
	for _, del := range due {
		ch, err := d.Cfg.ChannelSecret(del.ChannelID)
		if err != nil {
			continue
		}
		var ev Event
		_ = json.Unmarshal([]byte(del.Payload), &ev)
		ev.Attachment = del.Attachment
		sendErr := d.Send(ctx, ch, ev)
		now := time.Now()
		var next time.Time
		if sendErr != nil {
			n := min(del.Attempts, len(retryAfter)-1)
			if next = now.Add(retryAfter[n]); next.Sub(time.UnixMilli(del.CreatedAt)) > giveUp {
				next = time.Time{}
			}
			d.Log.Warn("notification failed", "channel", ch.Name, "event", del.EventType, "err", sendErr)
		}
		_ = d.Cfg.DeliveryResult(del, now, sendErr, next)
		// A channel failing for a day is turned off (a notice says so).
		if sendErr != nil && ch.FailingSince > 0 && now.Sub(time.UnixMilli(ch.FailingSince)) > giveUp {
			_ = d.Cfg.DisableChannel(ch.ID)
			d.Log.Warn("notification channel disabled after failing for a day", "channel", ch.Name)
		}
	}
}

// Send delivers one event to one channel now.
func (d *Dispatcher) Send(ctx context.Context, ch config.Channel, ev Event) error {
	if d == nil {
		return errors.New("notifications are not available")
	}
	d.init()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	switch ch.Type {
	case "webhook":
		return d.sendWebhook(ctx, ch, ev)
	case "telegram":
		return d.sendTelegram(ctx, ch, ev)
	}
	return fmt.Errorf("unknown channel type %q", ch.Type)
}

// Sign returns the Standard Webhooks signature header value for a message.
func Sign(secret, id string, ts time.Time, body []byte) (string, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		return "", errors.New("the signing secret is not valid")
	}
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s.%d.", id, ts.Unix())
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (d *Dispatcher) sendWebhook(ctx context.Context, ch config.Channel, ev Event) error {
	if ev.Attachment != "" {
		if ev.Data == nil {
			ev.Data = map[string]any{}
		}
		ev.Data["attachment"] = ev.AttachmentName
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	now := time.Now()
	sig, err := Sign(ch.Secret, ev.ID, now, body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	h := req.Header
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", d.Agent)
	h.Set("webhook-id", ev.ID)
	h.Set("webhook-timestamp", strconv.FormatInt(now.Unix(), 10))
	h.Set("webhook-signature", sig)
	resp, err := d.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(reply))
		if msg != "" {
			msg = ": " + msg
		}
		return fmt.Errorf("the webhook replied %s%s", resp.Status, msg)
	}
	return nil
}

var levelMark = map[string]string{"info": "ℹ️", "warning": "⚠️", "danger": "🔴"}

// telegramText renders an event as Telegram HTML.
func telegramText(ev Event) string {
	var b strings.Builder
	if m := levelMark[ev.Level]; m != "" {
		b.WriteString(m + " ")
	}
	b.WriteString("<b>" + html.EscapeString(ev.Title) + "</b>")
	if ev.Message != "" {
		b.WriteString("\n" + html.EscapeString(ev.Message))
	}
	if ev.URL != "" {
		b.WriteString(fmt.Sprintf("\n<a href=\"%s\">Open in %s</a>", html.EscapeString(ev.URL), html.EscapeString(ev.Appliance)))
	}
	if ev.Appliance != "" && ev.URL == "" {
		b.WriteString("\n<i>" + html.EscapeString(ev.Appliance) + "</i>")
	}
	return b.String()
}

func (d *Dispatcher) sendTelegram(ctx context.Context, ch config.Channel, ev Event) error {
	token := ch.Secret
	// The token is part of the API URL: keep it out of errors and logs.
	scrub := func(err error) error {
		if err == nil || token == "" {
			return err
		}
		return errors.New(strings.ReplaceAll(err.Error(), token, "<token>"))
	}
	base := strings.TrimRight(d.TelegramAPI, "/") + "/bot" + token
	text := telegramText(ev)
	var req *http.Request
	var err error
	if ev.Attachment != "" {
		if f, ferr := os.Open(ev.Attachment); ferr == nil {
			defer f.Close()
			var buf bytes.Buffer
			mw := multipart.NewWriter(&buf)
			_ = mw.WriteField("chat_id", ch.ChatID)
			caption := text
			if len([]rune(caption)) > 1000 { // Telegram's caption limit is 1024
				caption = string([]rune(caption)[:1000]) + "…"
			}
			_ = mw.WriteField("caption", caption)
			_ = mw.WriteField("parse_mode", "HTML")
			name := ev.AttachmentName
			if name == "" {
				name = filepath.Base(ev.Attachment)
			}
			fw, _ := mw.CreateFormFile("document", name)
			if _, err := io.Copy(fw, f); err != nil {
				return err
			}
			mw.Close()
			req, err = http.NewRequestWithContext(ctx, http.MethodPost, base+"/sendDocument", &buf)
			if err != nil {
				return scrub(err)
			}
			req.Header.Set("Content-Type", mw.FormDataContentType())
		}
		// A file pruned since the event was queued: send the text alone.
	}
	if req == nil {
		body, _ := json.Marshal(map[string]any{"chat_id": ch.ChatID, "text": text, "parse_mode": "HTML", "link_preview_options": map[string]bool{"is_disabled": true}})
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, base+"/sendMessage", bytes.NewReader(body))
		if err != nil {
			return scrub(err)
		}
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", d.Agent)
	resp, err := d.Client().Do(req)
	if err != nil {
		return scrub(err)
	}
	defer resp.Body.Close()
	var reply struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&reply)
	if !reply.OK {
		if reply.Description == "" {
			reply.Description = resp.Status
		}
		return scrub(fmt.Errorf("Telegram: %s", reply.Description))
	}
	return nil
}
