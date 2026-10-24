package config

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Inventory sources are read-only connections to a CMDB or source of truth
// (NetBox first). Each source's last snapshot is cached here as JSON, so
// lookups work while the inventory is unreachable and after a restart.

const inventorySchema = `
CREATE TABLE IF NOT EXISTS inventory_sources (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	name          TEXT NOT NULL UNIQUE,
	type          TEXT NOT NULL,
	enabled       INTEGER NOT NULL DEFAULT 1,
	priority      INTEGER NOT NULL DEFAULT 10,
	url           TEXT NOT NULL,
	token         TEXT NOT NULL DEFAULT '',
	scope_site    TEXT NOT NULL DEFAULT '',
	scope_tenant  TEXT NOT NULL DEFAULT '',
	scope_tag     TEXT NOT NULL DEFAULT '',
	interval_min  INTEGER NOT NULL DEFAULT 15,
	local_tag     TEXT NOT NULL DEFAULT '',
	last_attempt  INTEGER NOT NULL DEFAULT 0,
	last_success  INTEGER NOT NULL DEFAULT 0,
	last_error    TEXT NOT NULL DEFAULT '',
	counts        TEXT NOT NULL DEFAULT '{}',
	created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS inventory_snapshots (
	source_id INTEGER PRIMARY KEY REFERENCES inventory_sources(id) ON DELETE CASCADE,
	data      TEXT NOT NULL,
	synced_at INTEGER NOT NULL
);
`

type InventorySource struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"` // netbox
	Enabled  bool   `json:"enabled"`
	Priority int    `json:"priority"` // lower first; the first source matching wins
	URL      string `json:"url"`
	// Token is write-only: empty keeps the stored one.
	Token    string `json:"token,omitempty"`
	HasToken bool   `json:"hasToken"`
	// Scope limits objects to a site, tenant or tag (slugs).
	ScopeSite   string `json:"scopeSite"`
	ScopeTenant string `json:"scopeTenant"`
	ScopeTag    string `json:"scopeTag"`
	IntervalMin int    `json:"intervalMin"`
	// LocalTag, when set, adds prefixes with this tag to the local networks.
	LocalTag string `json:"localTag"`

	LastAttempt int64  `json:"lastAttempt"`
	LastSuccess int64  `json:"lastSuccess"`
	LastError   string `json:"lastError"`
	Counts      string `json:"counts"` // JSON, from the last sync
	CreatedAt   int64  `json:"createdAt"`
}

var ErrInventoryExists = errors.New("an inventory source with that name already exists")

func (c *DB) migrateInventory() error {
	_, err := c.db.Exec(inventorySchema)
	return err
}

// ValidateInventorySource checks and normalises s.
func ValidateInventorySource(s *InventorySource) error {
	s.Name = strings.TrimSpace(s.Name)
	s.URL = strings.TrimRight(strings.TrimSpace(s.URL), "/")
	s.ScopeSite, s.ScopeTenant, s.ScopeTag = strings.TrimSpace(s.ScopeSite), strings.TrimSpace(s.ScopeTenant), strings.TrimSpace(s.ScopeTag)
	s.LocalTag = strings.TrimSpace(s.LocalTag)
	if s.Name == "" || len(s.Name) > 64 {
		return errors.New("name is required (up to 64 characters)")
	}
	if s.Type == "" {
		s.Type = "netbox"
	}
	if s.Type != "netbox" {
		return fmt.Errorf("unknown inventory type %q", s.Type)
	}
	if u, err := url.Parse(s.URL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" {
		return errors.New("enter the inventory's address, e.g. https://netbox.example.com")
	}
	if s.IntervalMin == 0 {
		s.IntervalMin = 15
	}
	if s.IntervalMin < 5 || s.IntervalMin > 24*60 {
		return errors.New("sync every 5 minutes to 24 hours")
	}
	if s.Priority < 0 || s.Priority > 1000 {
		return errors.New("priority must be between 0 and 1000")
	}
	for _, v := range []string{s.ScopeSite, s.ScopeTenant, s.ScopeTag, s.LocalTag} {
		if strings.ContainsAny(v, " /?&#") {
			return fmt.Errorf("%q is not a slug", v)
		}
	}
	return nil
}

const inventoryCols = "id, name, type, enabled, priority, url, token, scope_site, scope_tenant, scope_tag, interval_min, local_tag, last_attempt, last_success, last_error, counts, created_at"

func scanInventory(row interface{ Scan(...any) error }) (InventorySource, error) {
	var s InventorySource
	var en int
	err := row.Scan(&s.ID, &s.Name, &s.Type, &en, &s.Priority, &s.URL, &s.Token, &s.ScopeSite, &s.ScopeTenant, &s.ScopeTag,
		&s.IntervalMin, &s.LocalTag, &s.LastAttempt, &s.LastSuccess, &s.LastError, &s.Counts, &s.CreatedAt)
	s.Enabled = en == 1
	return s, err
}

// InventorySources lists sources by priority, tokens omitted.
func (c *DB) InventorySources() ([]InventorySource, error) {
	list, err := c.inventorySources()
	for i := range list {
		list[i].HasToken, list[i].Token = list[i].Token != "", ""
	}
	return list, err
}

func (c *DB) inventorySources() ([]InventorySource, error) {
	rows, err := c.db.Query("SELECT " + inventoryCols + " FROM inventory_sources ORDER BY priority, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []InventorySource{}
	for rows.Next() {
		s, err := scanInventory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// InventorySourcesSecrets lists sources with tokens decrypted, for syncing.
func (c *DB) InventorySourcesSecrets() ([]InventorySource, error) {
	list, err := c.inventorySources()
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].Token, err = c.decrypt(list[i].Token); err != nil {
			return nil, fmt.Errorf("decrypting the token of %s: %w", list[i].Name, err)
		}
	}
	return list, nil
}

func (c *DB) InventorySource(id int64) (InventorySource, error) {
	s, err := scanInventory(c.db.QueryRow("SELECT "+inventoryCols+" FROM inventory_sources WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	s.HasToken, s.Token = s.Token != "", ""
	return s, err
}

// FillInventoryToken completes a form's source with the stored token when
// the form left it empty and the address is unchanged (for testing).
func (c *DB) FillInventoryToken(s *InventorySource) error {
	if s.Token != "" || s.ID == 0 {
		return nil
	}
	var enc, u string
	if err := c.db.QueryRow("SELECT token, url FROM inventory_sources WHERE id = ?", s.ID).Scan(&enc, &u); err != nil {
		return nil
	}
	if strings.TrimRight(u, "/") != s.URL {
		return nil
	}
	tok, err := c.decrypt(enc)
	s.Token = tok
	return err
}

// SaveInventorySource creates (ID 0) or updates a source. An empty token
// keeps the stored one unless the address changed.
func (c *DB) SaveInventorySource(s InventorySource) (InventorySource, error) {
	if err := ValidateInventorySource(&s); err != nil {
		return s, err
	}
	enc := ""
	if s.Token != "" {
		var err error
		if enc, err = c.encrypt(strings.TrimSpace(s.Token)); err != nil {
			return s, err
		}
	} else if s.ID != 0 {
		var oldURL string
		if err := c.db.QueryRow("SELECT token, url FROM inventory_sources WHERE id = ?", s.ID).Scan(&enc, &oldURL); err != nil {
			return s, ErrNotFound
		}
		if strings.TrimRight(oldURL, "/") != s.URL {
			enc = ""
		}
	}
	if enc == "" {
		return s, errors.New("enter an API token")
	}
	b := 0
	if s.Enabled {
		b = 1
	}
	var err error
	if s.ID == 0 {
		var res sql.Result
		res, err = c.db.Exec(`INSERT INTO inventory_sources(name, type, enabled, priority, url, token, scope_site, scope_tenant, scope_tag, interval_min, local_tag, created_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, s.Name, s.Type, b, s.Priority, s.URL, enc, s.ScopeSite, s.ScopeTenant, s.ScopeTag, s.IntervalMin, s.LocalTag, time.Now().UnixMilli())
		if err == nil {
			s.ID, err = res.LastInsertId()
		}
	} else {
		// A different address or scope starts over: the old snapshot doesn't apply.
		_, err = c.db.Exec(`UPDATE inventory_sources SET name = ?, type = ?, enabled = ?, priority = ?, url = ?, token = ?, scope_site = ?, scope_tenant = ?,
			scope_tag = ?, interval_min = ?, local_tag = ? WHERE id = ?`,
			s.Name, s.Type, b, s.Priority, s.URL, enc, s.ScopeSite, s.ScopeTenant, s.ScopeTag, s.IntervalMin, s.LocalTag, s.ID)
	}
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return s, ErrInventoryExists
		}
		return s, err
	}
	return c.InventorySource(s.ID)
}

func (c *DB) DeleteInventorySource(id int64) error {
	res, err := c.db.Exec("DELETE FROM inventory_sources WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, _ = c.db.Exec("DELETE FROM inventory_snapshots WHERE source_id = ?", id)
	return nil
}

// SaveInventorySync records a sync attempt; on success it stores the
// snapshot (JSON) and its counts.
func (c *DB) SaveInventorySync(id int64, at time.Time, data, counts string, syncErr error) error {
	if syncErr != nil {
		_, err := c.db.Exec("UPDATE inventory_sources SET last_attempt = ?, last_error = ? WHERE id = ?", at.UnixMilli(), firstLineOf(syncErr.Error()), id)
		return err
	}
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO inventory_snapshots(source_id, data, synced_at) VALUES(?, ?, ?) ON CONFLICT(source_id) DO UPDATE SET data = excluded.data, synced_at = excluded.synced_at",
		id, data, at.UnixMilli()); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE inventory_sources SET last_attempt = ?, last_success = ?, last_error = '', counts = ? WHERE id = ?", at.UnixMilli(), at.UnixMilli(), counts, id); err != nil {
		return err
	}
	return tx.Commit()
}

// InventorySnapshot returns a source's cached snapshot (JSON), "" if none.
func (c *DB) InventorySnapshot(id int64) (string, error) {
	var data string
	err := c.db.QueryRow("SELECT data FROM inventory_snapshots WHERE source_id = ?", id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return data, err
}
