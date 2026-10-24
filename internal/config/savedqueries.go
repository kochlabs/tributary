package config

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Saved queries (docs/design/QUERY-LANGUAGE.md): named queries, private to
// their owner unless shared. Only the owner or an administrator changes one.
const savedQuerySchema = `
CREATE TABLE IF NOT EXISTS saved_queries (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	query      TEXT NOT NULL,
	owner      TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
	shared     INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	UNIQUE (owner, name)
);
`

// MaxSavedQueries is how many queries one user may save.
const MaxSavedQueries = 200

var (
	ErrSavedQueryExists = errors.New("you already have a saved query with that name")
	ErrTooManyQueries   = errors.New("too many saved queries: delete one first")
)

type SavedQuery struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Query     string `json:"query"`
	Owner     string `json:"owner"`
	Shared    bool   `json:"shared"`
	CreatedAt int64  `json:"createdAt"`
	UpdatedAt int64  `json:"updatedAt"`
}

func (c *DB) migrateSavedQueries() error {
	_, err := c.db.Exec(savedQuerySchema)
	return err
}

func (q *SavedQuery) normalize() error {
	q.Name = strings.TrimSpace(q.Name)
	q.Query = strings.TrimSpace(q.Query)
	if q.Name == "" || len([]rune(q.Name)) > 80 {
		return errors.New("name is required (up to 80 characters)")
	}
	if q.Query == "" {
		return errors.New("the query is empty")
	}
	if len(q.Query) > 2000 {
		return errors.New("the query is too long")
	}
	return nil
}

const savedQueryCols = "id, name, query, owner, shared, created_at, updated_at"

func scanSavedQuery(row interface{ Scan(...any) error }) (SavedQuery, error) {
	var q SavedQuery
	var shared int
	err := row.Scan(&q.ID, &q.Name, &q.Query, &q.Owner, &shared, &q.CreatedAt, &q.UpdatedAt)
	q.Shared = shared == 1
	return q, err
}

// SavedQueries lists the queries user can see: their own and shared ones,
// their own first, then by name.
func (c *DB) SavedQueries(user string) ([]SavedQuery, error) {
	rows, err := c.db.Query("SELECT "+savedQueryCols+" FROM saved_queries WHERE owner = ? OR shared = 1 ORDER BY owner <> ?, name COLLATE NOCASE", user, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SavedQuery{}
	for rows.Next() {
		q, err := scanSavedQuery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

func (c *DB) SavedQuery(id int64) (SavedQuery, error) {
	q, err := scanSavedQuery(c.db.QueryRow("SELECT "+savedQueryCols+" FROM saved_queries WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return q, ErrNotFound
	}
	return q, err
}

// SaveSavedQuery creates (ID 0, owned by q.Owner) or updates a saved query;
// the owner never changes. Who may update is the caller's check.
func (c *DB) SaveSavedQuery(q SavedQuery) (SavedQuery, error) {
	if err := q.normalize(); err != nil {
		return q, err
	}
	now := time.Now().UnixMilli()
	b := 0
	if q.Shared {
		b = 1
	}
	if q.ID == 0 {
		var n int
		if err := c.db.QueryRow("SELECT count(*) FROM saved_queries WHERE owner = ?", q.Owner).Scan(&n); err != nil {
			return q, err
		}
		if n >= MaxSavedQueries {
			return q, ErrTooManyQueries
		}
		res, err := c.db.Exec("INSERT INTO saved_queries(name, query, owner, shared, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)",
			q.Name, q.Query, q.Owner, b, now, now)
		if err != nil {
			return q, uniqueErr(err)
		}
		q.ID, _ = res.LastInsertId()
	} else {
		res, err := c.db.Exec("UPDATE saved_queries SET name = ?, query = ?, shared = ?, updated_at = ? WHERE id = ?", q.Name, q.Query, b, now, q.ID)
		if err != nil {
			return q, uniqueErr(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return q, ErrNotFound
		}
	}
	return c.SavedQuery(q.ID)
}

func uniqueErr(err error) error {
	if strings.Contains(err.Error(), "UNIQUE") {
		return ErrSavedQueryExists
	}
	return err
}

func (c *DB) DeleteSavedQuery(id int64) error {
	res, err := c.db.Exec("DELETE FROM saved_queries WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
