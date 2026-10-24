package store

import (
	"context"
	"strings"
	"sync/atomic"
)

// Flows store the ID of the threat feed listing an address (src_threat,
// dst_threat), so renaming a feed relabels its past matches. The threat
// filter accepts a feed's name too: names are resolved to IDs here.

var threatFeedIDs atomic.Pointer[map[string]string] // lower-case name → ID

func init() { SetThreatFeeds(nil) }

// SetThreatFeeds sets the feed names the threat filter resolves (ID → name).
func SetThreatFeeds(names map[string]string) {
	m := make(map[string]string, len(names))
	for id, name := range names {
		m[strings.ToLower(name)] = id
	}
	threatFeedIDs.Store(&m)
}

// threatValue maps a filter value to what flows store: a feed's ID for its
// name, else the value itself (an ID, or a name stored before IDs were).
func threatValue(v string) string {
	if id, ok := (*threatFeedIDs.Load())[strings.ToLower(v)]; ok {
		return id
	}
	return v
}

// MigrateThreatNames rewrites matches stored by feed name (before flows
// stored IDs) to the feeds' IDs. names maps ID → name; names of feeds that
// no longer exist stay as they are. It is a no-op once done.
func (s *Store) MigrateThreatNames(ctx context.Context, names map[string]string) error {
	var ids, labels []string
	for id, name := range names {
		ids, labels = append(ids, id), append(labels, name)
	}
	if len(ids) == 0 {
		return nil
	}
	var n uint64
	if err := s.conn.QueryRow(ctx, "SELECT count() FROM netflow.flows WHERE src_threat IN ? OR dst_threat IN ?", labels, labels).Scan(&n); err != nil || n == 0 {
		return err
	}
	return s.conn.Exec(ctx, `ALTER TABLE netflow.flows UPDATE
		src_threat = transform(src_threat, ?, ?, src_threat), dst_threat = transform(dst_threat, ?, ?, dst_threat)
		WHERE src_threat IN ? OR dst_threat IN ?`, labels, ids, labels, ids, labels, labels)
}
