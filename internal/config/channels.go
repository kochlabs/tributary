package config

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Notification channels are destinations (webhooks, chat services). What
// goes to a channel is chosen where events come from: a rule or a report
// picks its channels. Deliveries are queued here and retried, so restarts
// and outages lose nothing.

const channelSchema = `
CREATE TABLE IF NOT EXISTS notify_channels (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	name         TEXT NOT NULL UNIQUE,
	type         TEXT NOT NULL,
	enabled      INTEGER NOT NULL DEFAULT 1,
	url          TEXT NOT NULL DEFAULT '',
	secret       TEXT NOT NULL DEFAULT '',
	chat_id      TEXT NOT NULL DEFAULT '',
	last_success INTEGER NOT NULL DEFAULT 0,
	last_error   TEXT NOT NULL DEFAULT '',
	failing_since INTEGER NOT NULL DEFAULT 0,
	created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS notify_deliveries (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	channel_id   INTEGER NOT NULL REFERENCES notify_channels(id) ON DELETE CASCADE,
	event_id     TEXT NOT NULL,
	event_type   TEXT NOT NULL,
	payload      TEXT NOT NULL,
	attachment   TEXT NOT NULL DEFAULT '',
	status       TEXT NOT NULL DEFAULT 'pending',
	attempts     INTEGER NOT NULL DEFAULT 0,
	next_attempt INTEGER NOT NULL,
	last_error   TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	done_at      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS notify_deliveries_due ON notify_deliveries(status, next_attempt);
CREATE INDEX IF NOT EXISTS notify_deliveries_channel ON notify_deliveries(channel_id, created_at);
-- When a host was last reported to a threat feed's channels.
CREATE TABLE IF NOT EXISTS threat_alerts (
	feed_id   INTEGER NOT NULL,
	host      TEXT NOT NULL,
	last_sent INTEGER NOT NULL,
	PRIMARY KEY (feed_id, host)
);
`

type Channel struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"` // webhook | telegram
	Enabled bool   `json:"enabled"`
	// URL is the webhook's address.
	URL string `json:"url"`
	// Secret is write-only: the webhook signing secret (generated, shown
	// once) or the Telegram bot token.
	Secret    string `json:"secret,omitempty"`
	HasSecret bool   `json:"hasSecret"`
	ChatID    string `json:"chatId"` // telegram

	LastSuccess  int64  `json:"lastSuccess"`
	LastError    string `json:"lastError"`
	FailingSince int64  `json:"failingSince"`
	CreatedAt    int64  `json:"createdAt"`
}

type Delivery struct {
	ID          int64  `json:"id"`
	ChannelID   int64  `json:"channelId"`
	EventID     string `json:"eventId"`
	EventType   string `json:"eventType"`
	Payload     string `json:"-"`
	Attachment  string `json:"-"`      // file path sent along (Telegram), if any
	Status      string `json:"status"` // pending | delivered | failed
	Attempts    int    `json:"attempts"`
	NextAttempt int64  `json:"nextAttempt"`
	LastError   string `json:"lastError,omitempty"`
	CreatedAt   int64  `json:"createdAt"`
	DoneAt      int64  `json:"doneAt"`
}

var ErrChannelExists = errors.New("a channel with that name already exists")

func (c *DB) migrateChannels() error {
	_, err := c.db.Exec(channelSchema)
	return err
}

// NewWebhookSecret makes a Standard Webhooks signing secret ("whsec_" and
// 32 random bytes, base64).
func NewWebhookSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "whsec_" + base64.StdEncoding.EncodeToString(b)
}

// ValidateChannel checks and normalises ch.
func ValidateChannel(ch *Channel) error {
	ch.Name = strings.TrimSpace(ch.Name)
	ch.URL = strings.TrimSpace(ch.URL)
	ch.ChatID = strings.TrimSpace(ch.ChatID)
	ch.Secret = strings.TrimSpace(ch.Secret)
	if ch.Name == "" || len(ch.Name) > 64 {
		return errors.New("name is required (up to 64 characters)")
	}
	switch ch.Type {
	case "webhook":
		u, err := url.Parse(ch.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return errors.New("enter the webhook's address (http:// or https://)")
		}
		if h := u.Hostname(); h == "169.254.169.254" || h == "metadata.google.internal" {
			return errors.New("that address is a cloud metadata service")
		}
		ch.ChatID = ""
	case "telegram":
		ch.URL = ""
		if ch.ChatID == "" || strings.ContainsAny(ch.ChatID, " /?&#") {
			return errors.New("enter the chat ID (a number, or @channelname)")
		}
	default:
		return fmt.Errorf("unknown channel type %q", ch.Type)
	}
	return nil
}

const channelCols = "id, name, type, enabled, url, secret, chat_id, last_success, last_error, failing_since, created_at"

func scanChannel(row interface{ Scan(...any) error }) (Channel, error) {
	var ch Channel
	var en int
	err := row.Scan(&ch.ID, &ch.Name, &ch.Type, &en, &ch.URL, &ch.Secret, &ch.ChatID, &ch.LastSuccess, &ch.LastError, &ch.FailingSince, &ch.CreatedAt)
	ch.Enabled = en == 1
	return ch, err
}

// Channels lists channels, secrets omitted.
func (c *DB) Channels() ([]Channel, error) {
	rows, err := c.db.Query("SELECT " + channelCols + " FROM notify_channels ORDER BY name COLLATE NOCASE")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		ch, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		ch.HasSecret, ch.Secret = ch.Secret != "", ""
		out = append(out, ch)
	}
	return out, rows.Err()
}

// ChannelSecret returns a channel with its secret decrypted, for sending.
func (c *DB) ChannelSecret(id int64) (Channel, error) {
	ch, err := scanChannel(c.db.QueryRow("SELECT "+channelCols+" FROM notify_channels WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return ch, ErrNotFound
	}
	if err != nil {
		return ch, err
	}
	ch.HasSecret = ch.Secret != ""
	ch.Secret, err = c.decrypt(ch.Secret)
	return ch, err
}

func (c *DB) Channel(id int64) (Channel, error) {
	ch, err := c.ChannelSecret(id)
	ch.Secret = ""
	return ch, err
}

// SaveChannel creates (ID 0) or updates a channel. A new webhook gets a
// generated signing secret, returned once in the result; an empty secret on
// update keeps the stored one.
func (c *DB) SaveChannel(ch Channel) (Channel, error) {
	if err := ValidateChannel(&ch); err != nil {
		return ch, err
	}
	newSecret := ""
	enc := ""
	switch {
	case ch.Type == "webhook" && ch.ID == 0:
		newSecret = NewWebhookSecret()
		ch.Secret = newSecret
	case ch.Secret == "" && ch.ID != 0:
		var oldType string
		if err := c.db.QueryRow("SELECT secret, type FROM notify_channels WHERE id = ?", ch.ID).Scan(&enc, &oldType); err != nil {
			return ch, ErrNotFound
		}
		if oldType != ch.Type {
			enc = ""
		}
	}
	if ch.Secret != "" {
		var err error
		if enc, err = c.encrypt(ch.Secret); err != nil {
			return ch, err
		}
	}
	if enc == "" {
		if ch.Type == "telegram" {
			return ch, errors.New("enter the bot token")
		}
		return ch, errors.New("the channel has no secret")
	}
	b := 0
	if ch.Enabled {
		b = 1
	}
	var err error
	if ch.ID == 0 {
		var res sql.Result
		res, err = c.db.Exec(`INSERT INTO notify_channels(name, type, enabled, url, secret, chat_id, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
			ch.Name, ch.Type, b, ch.URL, enc, ch.ChatID, time.Now().UnixMilli())
		if err == nil {
			ch.ID, err = res.LastInsertId()
		}
	} else {
		// Re-enabling starts the failure clock over.
		_, err = c.db.Exec(`UPDATE notify_channels SET name = ?, type = ?, enabled = ?, url = ?, secret = ?, chat_id = ?,
			failing_since = CASE WHEN ? = 1 THEN 0 ELSE failing_since END WHERE id = ?`,
			ch.Name, ch.Type, b, ch.URL, enc, ch.ChatID, b, ch.ID)
	}
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ch, ErrChannelExists
		}
		return ch, err
	}
	out, err := c.Channel(ch.ID)
	out.Secret = newSecret
	return out, err
}

// RegenerateWebhookSecret replaces a webhook's signing secret, returning it.
func (c *DB) RegenerateWebhookSecret(id int64) (string, error) {
	sec := NewWebhookSecret()
	enc, err := c.encrypt(sec)
	if err != nil {
		return "", err
	}
	res, err := c.db.Exec("UPDATE notify_channels SET secret = ? WHERE id = ? AND type = 'webhook'", enc, id)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	return sec, nil
}

func (c *DB) DeleteChannel(id int64) error {
	res, err := c.db.Exec("DELETE FROM notify_channels WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, _ = c.db.Exec("DELETE FROM notify_deliveries WHERE channel_id = ?", id)
	return nil
}

// EnqueueDelivery queues an event for a channel.
func (c *DB) EnqueueDelivery(d Delivery) error {
	now := time.Now().UnixMilli()
	_, err := c.db.Exec(`INSERT INTO notify_deliveries(channel_id, event_id, event_type, payload, attachment, next_attempt, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		d.ChannelID, d.EventID, d.EventType, d.Payload, d.Attachment, now, now)
	return err
}

// DueDeliveries lists pending deliveries due at t, oldest first.
func (c *DB) DueDeliveries(t time.Time, limit int) ([]Delivery, error) {
	rows, err := c.db.Query(`SELECT id, channel_id, event_id, event_type, payload, attachment, status, attempts, next_attempt, last_error, created_at, done_at
		FROM notify_deliveries WHERE status = 'pending' AND next_attempt <= ? ORDER BY id LIMIT ?`, t.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	return scanDeliveries(rows)
}

// Deliveries lists a channel's recent deliveries, newest first.
func (c *DB) Deliveries(channelID int64, limit int) ([]Delivery, error) {
	rows, err := c.db.Query(`SELECT id, channel_id, event_id, event_type, payload, attachment, status, attempts, next_attempt, last_error, created_at, done_at
		FROM notify_deliveries WHERE channel_id = ? ORDER BY id DESC LIMIT ?`, channelID, limit)
	if err != nil {
		return nil, err
	}
	return scanDeliveries(rows)
}

func scanDeliveries(rows *sql.Rows) ([]Delivery, error) {
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.ChannelID, &d.EventID, &d.EventType, &d.Payload, &d.Attachment, &d.Status, &d.Attempts, &d.NextAttempt,
			&d.LastError, &d.CreatedAt, &d.DoneAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeliveryResult records an attempt: delivered, retried at next, or failed
// for good (next zero). The channel's status follows.
func (c *DB) DeliveryResult(d Delivery, at time.Time, sendErr error, next time.Time) error {
	ms := at.UnixMilli()
	switch {
	case sendErr == nil:
		if _, err := c.db.Exec("UPDATE notify_deliveries SET status = 'delivered', attempts = attempts + 1, last_error = '', done_at = ? WHERE id = ?", ms, d.ID); err != nil {
			return err
		}
		_, err := c.db.Exec("UPDATE notify_channels SET last_success = ?, last_error = '', failing_since = 0 WHERE id = ?", ms, d.ChannelID)
		return err
	case next.IsZero():
		if _, err := c.db.Exec("UPDATE notify_deliveries SET status = 'failed', attempts = attempts + 1, last_error = ?, done_at = ? WHERE id = ?", firstLineOf(sendErr.Error()), ms, d.ID); err != nil {
			return err
		}
	default:
		if _, err := c.db.Exec("UPDATE notify_deliveries SET attempts = attempts + 1, last_error = ?, next_attempt = ? WHERE id = ?", firstLineOf(sendErr.Error()), next.UnixMilli(), d.ID); err != nil {
			return err
		}
	}
	_, err := c.db.Exec("UPDATE notify_channels SET last_error = ?, failing_since = CASE WHEN failing_since = 0 THEN ? ELSE failing_since END WHERE id = ?",
		firstLineOf(sendErr.Error()), ms, d.ChannelID)
	return err
}

// DisableChannel turns a channel off (after failing for too long) and drops
// its pending deliveries.
func (c *DB) DisableChannel(id int64) error {
	if _, err := c.db.Exec("UPDATE notify_channels SET enabled = 0 WHERE id = ?", id); err != nil {
		return err
	}
	_, err := c.db.Exec("UPDATE notify_deliveries SET status = 'failed', last_error = 'channel disabled', done_at = ? WHERE channel_id = ? AND status = 'pending'", time.Now().UnixMilli(), id)
	return err
}

// PruneDeliveries drops finished deliveries older than d, keeping the last
// 50 per channel.
func (c *DB) PruneDeliveries(d time.Duration) error {
	_, err := c.db.Exec(`DELETE FROM notify_deliveries WHERE status <> 'pending' AND done_at < ? AND id NOT IN (
		SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY channel_id ORDER BY id DESC) AS n FROM notify_deliveries) WHERE n <= 50)`,
		time.Now().Add(-d).UnixMilli())
	return err
}

// CleanChannelIDs sorts and de-duplicates the channels a source sends to.
func CleanChannelIDs(ids []int64) ([]int64, error) {
	if ids == nil {
		return []int64{}, nil
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if len(ids) > 20 {
		return nil, errors.New("at most 20 channels")
	}
	return ids, nil
}

// NoticeRouting sends appliance notices at or above Level to Channels.
type NoticeRouting struct {
	Level    string  `json:"level"` // info | warning | danger
	Channels []int64 `json:"channels"`
}

func (c *DB) NoticeRouting() NoticeRouting {
	r := NoticeRouting{Level: "warning", Channels: []int64{}}
	var v string
	if c.db.QueryRow("SELECT value FROM settings WHERE key = 'notice_routing'").Scan(&v) == nil {
		_ = json.Unmarshal([]byte(v), &r)
	}
	return r
}

func (c *DB) SaveNoticeRouting(r NoticeRouting) error {
	switch r.Level {
	case "info", "warning", "danger":
	default:
		return errors.New("level must be info, warning or danger")
	}
	var err error
	if r.Channels, err = CleanChannelIDs(r.Channels); err != nil {
		return err
	}
	return c.putSetting("notice_routing", r)
}

// SentNotice is a notice that was sent to channels, until it clears.
type SentNotice struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Title    string `json:"title"`
	LastSeen int64  `json:"lastSeen"` // ms
}

func (c *DB) SentNotices() []SentNotice {
	out := []SentNotice{}
	var v string
	if c.db.QueryRow("SELECT value FROM settings WHERE key = 'notices_sent'").Scan(&v) == nil {
		_ = json.Unmarshal([]byte(v), &out)
	}
	return out
}

func (c *DB) SaveSentNotices(list []SentNotice) error { return c.putSetting("notices_sent", list) }

func (c *DB) putSetting(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.db.Exec("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, string(b))
	return err
}

// ThreatAlertDue reports whether host's matches on a feed may be sent again
// (never sent, or not since every), and if so records them as sent at now.
func (c *DB) ThreatAlertDue(feedID int64, host string, now time.Time, every time.Duration) (bool, error) {
	res, err := c.db.Exec(`INSERT INTO threat_alerts(feed_id, host, last_sent) VALUES(?, ?, ?)
		ON CONFLICT(feed_id, host) DO UPDATE SET last_sent = excluded.last_sent WHERE last_sent < ?`,
		feedID, host, now.UnixMilli(), now.Add(-every).UnixMilli())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// PruneThreatAlerts forgets alerts sent before t.
func (c *DB) PruneThreatAlerts(t time.Time) error {
	_, err := c.db.Exec("DELETE FROM threat_alerts WHERE last_sent < ?", t.UnixMilli())
	return err
}
