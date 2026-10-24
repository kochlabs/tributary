package config

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Threat feeds are lists of known-bad addresses that flows are matched
// against. The table is seeded once with well-known free feeds; after that
// it is the administrator's: feeds can be edited, disabled or deleted, and
// their own added.

const threatFeedSchema = `
CREATE TABLE IF NOT EXISTS threat_feeds (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	name           TEXT NOT NULL UNIQUE,
	url            TEXT NOT NULL,
	format         TEXT NOT NULL DEFAULT 'text',
	field          TEXT NOT NULL DEFAULT '',
	column_no      INTEGER NOT NULL DEFAULT 1,
	delimiter      TEXT NOT NULL DEFAULT ',',
	enabled        INTEGER NOT NULL DEFAULT 1,
	notify         INTEGER NOT NULL DEFAULT 1,
	interval_hours INTEGER NOT NULL DEFAULT 12,
	last_attempt   INTEGER NOT NULL DEFAULT 0,
	last_success   INTEGER NOT NULL DEFAULT 0,
	last_error     TEXT NOT NULL DEFAULT '',
	entries        INTEGER NOT NULL DEFAULT 0,
	created_at     INTEGER NOT NULL,
	position       INTEGER NOT NULL DEFAULT 0,
	channels       TEXT NOT NULL DEFAULT '[]'
);
`

// ThreatFeed is one list of bad addresses.
type ThreatFeed struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// URL is http(s)://… or an absolute path to a file on the appliance.
	URL string `json:"url"`
	// Format: text (an address or CIDR at the start of each line, comments
	// with # or ;), csv (a column) or json (a field of each object, in a JSON
	// array or one object per line).
	Format    string `json:"format"`
	Field     string `json:"field"`     // json
	Column    int    `json:"column"`    // csv, 1-based
	Delimiter string `json:"delimiter"` // csv
	Enabled   bool   `json:"enabled"`
	// Notify raises notices for matches; off for informational lists (such
	// as Tor exit nodes) that are worth seeing but not worth a warning.
	Notify        bool `json:"notify"`
	IntervalHours int  `json:"intervalHours"`
	// Channels are notification channels that matches are sent to (IDs).
	Channels []int64 `json:"channels"`

	LastAttempt int64  `json:"lastAttempt"`
	LastSuccess int64  `json:"lastSuccess"`
	LastError   string `json:"lastError"`
	Entries     int    `json:"entries"`
	CreatedAt   int64  `json:"createdAt"`
}

// DefaultThreatFeeds are offered on first start (and by "add defaults").
var DefaultThreatFeeds = []ThreatFeed{
	{Name: "Spamhaus DROP (IPv4)", URL: "https://www.spamhaus.org/drop/drop_v4.json", Format: "json", Field: "cidr", Enabled: true, Notify: true, IntervalHours: 12},
	{Name: "Spamhaus DROP (IPv6)", URL: "https://www.spamhaus.org/drop/drop_v6.json", Format: "json", Field: "cidr", Enabled: true, Notify: true, IntervalHours: 12},
	{Name: "abuse.ch Feodo Tracker", URL: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", Format: "text", Enabled: true, Notify: true, IntervalHours: 6},
	{Name: "FireHOL Level 1", URL: "https://iplists.firehol.org/files/firehol_level1.netset", Format: "text", Enabled: true, Notify: true, IntervalHours: 12},
	{Name: "Emerging Threats compromised", URL: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", Format: "text", Enabled: true, Notify: true, IntervalHours: 12},
	{Name: "CINS Army", URL: "https://cinsscore.com/list/ci-badguys.txt", Format: "text", Enabled: false, Notify: true, IntervalHours: 12},
	{Name: "Tor exit nodes", URL: "https://check.torproject.org/torbulkexitlist", Format: "text", Enabled: false, Notify: false, IntervalHours: 6},
}

var ErrFeedExists = errors.New("a feed with that name already exists")

func (c *DB) migrateThreatFeeds() error {
	if _, err := c.db.Exec(threatFeedSchema); err != nil {
		return err
	}
	var n int
	if err := c.db.QueryRow("SELECT count(*) FROM pragma_table_info('threat_feeds') WHERE name = 'position'").Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := c.db.Exec("ALTER TABLE threat_feeds ADD COLUMN position INTEGER NOT NULL DEFAULT 0"); err != nil {
			return err
		}
		if _, err := c.db.Exec("UPDATE threat_feeds SET position = id"); err != nil {
			return err
		}
	}
	if err := c.db.QueryRow("SELECT count(*) FROM pragma_table_info('threat_feeds') WHERE name = 'channels'").Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := c.db.Exec("ALTER TABLE threat_feeds ADD COLUMN channels TEXT NOT NULL DEFAULT '[]'"); err != nil {
			return err
		}
	}
	// Seed once: feeds an administrator deletes stay deleted.
	var seeded string
	if c.db.QueryRow("SELECT value FROM settings WHERE key = 'threat_feeds_seeded'").Scan(&seeded) == nil {
		return nil
	}
	if _, err := c.AddDefaultThreatFeeds(); err != nil {
		return err
	}
	_, err := c.db.Exec("INSERT INTO settings(key, value) VALUES('threat_feeds_seeded', '1')")
	return err
}

// AddDefaultThreatFeeds adds the default feeds that aren't present (by URL).
func (c *DB) AddDefaultThreatFeeds() (int, error) {
	n := 0
	for _, f := range DefaultThreatFeeds {
		var exists int
		if err := c.db.QueryRow("SELECT count(*) FROM threat_feeds WHERE url = ? OR name = ?", f.URL, f.Name).Scan(&exists); err != nil {
			return n, err
		}
		if exists > 0 {
			continue
		}
		if _, err := c.SaveThreatFeed(f); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (f *ThreatFeed) normalize() error {
	f.Name = strings.TrimSpace(f.Name)
	f.URL = strings.TrimSpace(f.URL)
	f.Field = strings.TrimSpace(f.Field)
	if f.Name == "" || len(f.Name) > 64 {
		return errors.New("name is required (up to 64 characters)")
	}
	if strings.ContainsAny(f.Name, ",!*") { // the filter syntax uses them
		return errors.New("the name can't contain , ! or *")
	}
	if strings.Trim(f.Name, "0123456789") == "" { // flows store feed IDs; filters accept either
		return errors.New("the name can't be only digits")
	}
	if strings.HasPrefix(f.URL, "/") {
		if filepath.Clean(f.URL) != f.URL {
			return errors.New("the file path must be absolute and clean")
		}
	} else if u, err := url.Parse(f.URL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("the source must be an http(s) URL or an absolute file path on the appliance")
	}
	switch f.Format {
	case "", "text":
		f.Format = "text"
	case "csv":
		if f.Column < 1 || f.Column > 100 {
			return errors.New("the CSV column must be between 1 and 100")
		}
		if f.Delimiter == "" {
			f.Delimiter = ","
		}
		if len([]rune(f.Delimiter)) != 1 && f.Delimiter != `\t` {
			return errors.New("the CSV delimiter must be one character (or \\t)")
		}
	case "json":
		if f.Field == "" {
			return errors.New("enter the JSON field that holds the address")
		}
	default:
		return errors.New("format must be text, csv or json")
	}
	if f.Column == 0 {
		f.Column = 1
	}
	if f.Delimiter == "" {
		f.Delimiter = ","
	}
	if f.IntervalHours == 0 {
		f.IntervalHours = 12
	}
	if f.IntervalHours < 1 || f.IntervalHours > 24*30 {
		return errors.New("update every 1 hour to 30 days")
	}
	var err error
	f.Channels, err = CleanChannelIDs(f.Channels)
	return err
}

// ValidateThreatFeed checks a feed as saving would.
func ValidateThreatFeed(f *ThreatFeed) error { return f.normalize() }

const threatFeedCols = "id, name, url, format, field, column_no, delimiter, enabled, notify, interval_hours, last_attempt, last_success, last_error, entries, created_at, channels"

func scanThreatFeed(row interface{ Scan(...any) error }) (ThreatFeed, error) {
	var f ThreatFeed
	var en, no int
	var chans string
	err := row.Scan(&f.ID, &f.Name, &f.URL, &f.Format, &f.Field, &f.Column, &f.Delimiter, &en, &no, &f.IntervalHours,
		&f.LastAttempt, &f.LastSuccess, &f.LastError, &f.Entries, &f.CreatedAt, &chans)
	f.Enabled, f.Notify = en == 1, no == 1
	f.Channels = []int64{}
	_ = json.Unmarshal([]byte(chans), &f.Channels)
	return f, err
}

// ThreatFeeds lists the feeds in the order they are matched.
func (c *DB) ThreatFeeds() ([]ThreatFeed, error) {
	rows, err := c.db.Query("SELECT " + threatFeedCols + " FROM threat_feeds ORDER BY position, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ThreatFeed{}
	for rows.Next() {
		f, err := scanThreatFeed(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (c *DB) ThreatFeed(id int64) (ThreatFeed, error) {
	f, err := scanThreatFeed(c.db.QueryRow("SELECT "+threatFeedCols+" FROM threat_feeds WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	return f, err
}

// SaveThreatFeed creates (ID 0) or updates a feed's settings; its status
// fields are left alone.
func (c *DB) SaveThreatFeed(f ThreatFeed) (int64, error) {
	if err := f.normalize(); err != nil {
		return 0, err
	}
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	chans, _ := json.Marshal(f.Channels)
	var err error
	if f.ID == 0 {
		var res sql.Result
		// New feeds go last.
		res, err = c.db.Exec(`INSERT INTO threat_feeds(name, url, format, field, column_no, delimiter, enabled, notify, interval_hours, channels, created_at, position)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT coalesce(max(position), 0) + 1 FROM threat_feeds))`, f.Name, f.URL, f.Format, f.Field, f.Column, f.Delimiter, b(f.Enabled), b(f.Notify), f.IntervalHours, string(chans), time.Now().UnixMilli())
		if err == nil {
			f.ID, err = res.LastInsertId()
		}
	} else {
		var res sql.Result
		// A changed source starts over: its old status doesn't apply.
		res, err = c.db.Exec(`UPDATE threat_feeds SET name = ?, format = ?, field = ?, column_no = ?, delimiter = ?, enabled = ?, notify = ?, interval_hours = ?, channels = ?,
				last_attempt = CASE WHEN url = ? THEN last_attempt ELSE 0 END, last_success = CASE WHEN url = ? THEN last_success ELSE 0 END,
				last_error = CASE WHEN url = ? THEN last_error ELSE '' END, entries = CASE WHEN url = ? THEN entries ELSE 0 END, url = ?
			WHERE id = ?`, f.Name, f.Format, f.Field, f.Column, f.Delimiter, b(f.Enabled), b(f.Notify), f.IntervalHours, string(chans), f.URL, f.URL, f.URL, f.URL, f.URL, f.ID)
		if err == nil {
			if n, _ := res.RowsAffected(); n == 0 {
				return 0, ErrNotFound
			}
		}
	}
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return 0, ErrFeedExists
	}
	return f.ID, err
}

// MoveThreatFeed moves a feed one place up or down in the matching order.
func (c *DB) MoveThreatFeed(id int64, up bool) error {
	feeds, err := c.ThreatFeeds()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(feeds, func(f ThreatFeed) bool { return f.ID == id })
	if i < 0 {
		return ErrNotFound
	}
	j := i + 1
	if up {
		j = i - 1
	}
	if j < 0 || j >= len(feeds) {
		return nil // already first or last
	}
	feeds[i], feeds[j] = feeds[j], feeds[i]
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for pos, f := range feeds {
		if _, err := tx.Exec("UPDATE threat_feeds SET position = ? WHERE id = ?", pos+1, f.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (c *DB) DeleteThreatFeed(id int64) error {
	res, err := c.db.Exec("DELETE FROM threat_feeds WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SaveThreatFeedResult records a download attempt: entries on success, or
// the error (keeping the last good list in use).
func (c *DB) SaveThreatFeedResult(id int64, at time.Time, entries int, fetchErr error) error {
	var err error
	if fetchErr != nil {
		_, err = c.db.Exec("UPDATE threat_feeds SET last_attempt = ?, last_error = ? WHERE id = ?", at.UnixMilli(), firstLineOf(fetchErr.Error()), id)
	} else {
		_, err = c.db.Exec("UPDATE threat_feeds SET last_attempt = ?, last_success = ?, last_error = '', entries = ? WHERE id = ?", at.UnixMilli(), at.UnixMilli(), entries, id)
	}
	return err
}

func firstLineOf(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// String is used in logs.
func (f ThreatFeed) String() string { return fmt.Sprintf("%s (%s)", f.Name, f.URL) }
