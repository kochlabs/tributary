package config

import (
	"errors"
	"strings"
	"time"
)

const trustedSchema = `
CREATE TABLE IF NOT EXISTS trusted_cas (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	pem        TEXT NOT NULL,
	sha256     TEXT NOT NULL UNIQUE,
	created_at INTEGER NOT NULL
);
`

// TrustedCA is a CA certificate an administrator added for outbound TLS.
type TrustedCA struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	PEM       string `json:"-"`
	SHA256    string `json:"sha256"`
	CreatedAt int64  `json:"createdAt"`
}

var ErrDuplicateCA = errors.New("this CA certificate is already trusted")

func (c *DB) TrustedCAs() ([]TrustedCA, error) {
	rows, err := c.db.Query("SELECT id, name, pem, sha256, created_at FROM trusted_cas ORDER BY name, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrustedCA{}
	for rows.Next() {
		var t TrustedCA
		if err := rows.Scan(&t.ID, &t.Name, &t.PEM, &t.SHA256, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (c *DB) AddTrustedCA(name, pem, sha256 string) (int64, error) {
	res, err := c.db.Exec("INSERT INTO trusted_cas(name, pem, sha256, created_at) VALUES(?, ?, ?, ?)", name, pem, sha256, time.Now().UnixMilli())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, ErrDuplicateCA
		}
		return 0, err
	}
	return res.LastInsertId()
}

func (c *DB) DeleteTrustedCA(id int64) error {
	res, err := c.db.Exec("DELETE FROM trusted_cas WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
