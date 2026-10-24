package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kochlabs/tributary/internal/config"
)

// The Standard Webhooks reference example.
func TestSignSpecVector(t *testing.T) {
	sig, err := Sign("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", "msg_p5jXN8AQM9LWM0D4loKWxJek", time.Unix(1614265330, 0), []byte(`{"test": 2432232314}`))
	if err != nil || sig != "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" {
		t.Fatalf("signature %q %v", sig, err)
	}
}

func newDispatcher(t *testing.T) (*Dispatcher, *config.DB) {
	cfg, err := config.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cfg.Close() })
	return &Dispatcher{Cfg: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Client: func() *http.Client { return http.DefaultClient }, Agent: "Tributary/test"}, cfg
}

func TestWebhookDelivery(t *testing.T) {
	var mu sync.Mutex
	var got []*http.Request
	var bodies [][]byte
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		got, bodies = append(got, r), append(bodies, b)
		if fail {
			http.Error(w, "busy", http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	d, cfg := newDispatcher(t)
	ch, err := cfg.SaveChannel(config.Channel{Name: "SIEM", Type: "webhook", URL: srv.URL, Enabled: true})
	if err != nil || !strings.HasPrefix(ch.Secret, "whsec_") {
		t.Fatalf("save: %+v %v", ch, err)
	}
	secret := ch.Secret
	if again, _ := cfg.Channel(ch.ID); again.Secret != "" || !again.HasSecret {
		t.Fatal("the secret is returned after creation")
	}

	// Events go to the channels their source chose; disabled and deleted
	// channels are skipped.
	off, _ := cfg.SaveChannel(config.Channel{Name: "Off", Type: "webhook", URL: srv.URL})
	d.Publish(Event{Type: "report.failed", Level: "warning", Title: "nowhere"}, nil)
	d.Publish(Event{Type: "report.completed", Level: "info", Title: "Weekly", Data: map[string]any{"free": "1 GB"}}, []int64{ch.ID, off.ID, 999})
	due, _ := cfg.DueDeliveries(time.Now(), 10)
	if len(due) != 1 || due[0].ChannelID != ch.ID {
		t.Fatalf("queued %+v", due)
	}

	// A failure is retried later, with the error recorded.
	d.deliverDue(context.Background())
	dels, _ := cfg.Deliveries(ch.ID, 10)
	if len(dels) != 1 || dels[0].Status != "pending" || dels[0].Attempts != 1 || !strings.Contains(dels[0].LastError, "503") || dels[0].NextAttempt <= time.Now().UnixMilli() {
		t.Fatalf("after failure: %+v", dels)
	}
	if c, _ := cfg.Channel(ch.ID); c.LastError == "" || c.FailingSince == 0 {
		t.Fatalf("channel status: %+v", c)
	}

	// Due again: delivered, signed per Standard Webhooks.
	mu.Lock()
	fail = false
	mu.Unlock()
	cfg.DeliveryResult(dels[0], time.Now(), errTest, time.Now().Add(-time.Second)) // make it due now
	d.deliverDue(context.Background())
	dels, _ = cfg.Deliveries(ch.ID, 10)
	if dels[0].Status != "delivered" {
		t.Fatalf("not delivered: %+v", dels[0])
	}
	r, body := got[len(got)-1], bodies[len(bodies)-1]
	ts := r.Header.Get("webhook-timestamp")
	id := r.Header.Get("webhook-id")
	tsec, _ := strconv.ParseInt(ts, 10, 64)
	want, _ := Sign(secret, id, time.Unix(tsec, 0), body)
	if r.Header.Get("webhook-signature") != want || !strings.HasPrefix(id, "evt_") {
		t.Fatalf("signature %q, want %q", r.Header.Get("webhook-signature"), want)
	}
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil || ev.Title != "Weekly" || ev.Type != "report.completed" || ev.Data["free"] != "1 GB" {
		t.Fatalf("payload %s", body)
	}
	if c, _ := cfg.Channel(ch.ID); c.LastSuccess == 0 || c.LastError != "" || c.FailingSince != 0 {
		t.Fatalf("channel status after success: %+v", c)
	}

	// Regenerating the secret changes the signature key.
	newSec, err := cfg.RegenerateWebhookSecret(ch.ID)
	if err != nil || newSec == secret {
		t.Fatal("regenerate")
	}
}

var errTest = io.ErrUnexpectedEOF

func TestTelegram(t *testing.T) {
	const token = "123456:ABC-secret-token"
	var paths []string
	var texts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/sendDocument") {
			r.ParseMultipartForm(1 << 20)
			texts = append(texts, r.FormValue("caption"))
			f, h, err := r.FormFile("document")
			if err != nil || h.Filename != "Weekly-2026-10-19.pdf" {
				t.Errorf("document: %v %v", h, err)
			} else {
				f.Close()
			}
		} else {
			var m map[string]any
			json.NewDecoder(r.Body).Decode(&m)
			texts = append(texts, m["text"].(string))
			if m["chat_id"] != "-100123" {
				json.NewEncoder(w).Encode(map[string]any{"ok": false, "description": "Bad Request: chat not found"})
				return
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()
	d, cfg := newDispatcher(t)
	d.TelegramAPI = srv.URL
	ch, err := cfg.SaveChannel(config.Channel{Name: "Me", Type: "telegram", Secret: token, ChatID: "-100123", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	ch, _ = cfg.ChannelSecret(ch.ID)
	err = d.Send(context.Background(), ch, Event{Type: "test", Level: "info", Title: "Test <message>", Message: "a & b", Appliance: "Tributary"})
	if err != nil || paths[0] != "/bot"+token+"/sendMessage" || !strings.Contains(texts[0], "<b>Test &lt;message&gt;</b>") || !strings.Contains(texts[0], "a &amp; b") {
		t.Fatalf("message: %v %v %q", err, paths, texts)
	}
	// Reports go as documents.
	pdf := filepath.Join(t.TempDir(), "r.pdf")
	os.WriteFile(pdf, []byte("%PDF-1.3 test"), 0o600)
	if err := d.Send(context.Background(), ch, Event{Type: "report.completed", Title: "Weekly", Attachment: pdf, AttachmentName: "Weekly-2026-10-19.pdf"}); err != nil || !strings.HasSuffix(paths[1], "/sendDocument") {
		t.Fatalf("document: %v %v", err, paths)
	}
	// Telegram's error is reported; the token never is.
	ch.ChatID = "nope"
	err = d.Send(context.Background(), ch, Event{Type: "test", Title: "x"})
	if err == nil || !strings.Contains(err.Error(), "chat not found") || strings.Contains(err.Error(), token) {
		t.Fatalf("error: %v", err)
	}
	d.TelegramAPI = "http://127.0.0.1:1"
	err = d.Send(context.Background(), ch, Event{Type: "test", Title: "x"})
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "<token>") {
		t.Fatalf("connection error leaks the token: %v", err)
	}
}

func TestChannelValidation(t *testing.T) {
	_, cfg := newDispatcher(t)
	for _, bad := range []config.Channel{
		{Name: "", Type: "webhook", URL: "https://x"},
		{Name: "a", Type: "webhook", URL: "ftp://x"},
		{Name: "a", Type: "webhook", URL: "http://169.254.169.254/latest"},
		{Name: "a", Type: "telegram", Secret: "t"},   // no chat
		{Name: "a", Type: "telegram", ChatID: "1"},   // no token
		{Name: "a", Type: "slack", URL: "https://x"}, // unknown type
	} {
		if _, err := cfg.SaveChannel(bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	// Switching type drops the old secret: a webhook secret isn't a bot token.
	ch, _ := cfg.SaveChannel(config.Channel{Name: "a", Type: "webhook", URL: "https://example.com/hook"})
	ch.Type, ch.ChatID, ch.Secret = "telegram", "1", ""
	if _, err := cfg.SaveChannel(ch); err == nil {
		t.Fatal("kept the webhook secret as a bot token")
	}
}
