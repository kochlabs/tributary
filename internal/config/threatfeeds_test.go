package config

import (
	"slices"
	"testing"
	"time"
)

func TestThreatFeedOrder(t *testing.T) {
	db := openTestDB(t)
	names := func() []string {
		feeds, err := db.ThreatFeeds()
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, f := range feeds {
			out = append(out, f.Name)
		}
		return out
	}
	seeded := names()
	if len(seeded) != len(DefaultThreatFeeds) || seeded[0] != DefaultThreatFeeds[0].Name {
		t.Fatalf("seeded %v", seeded)
	}
	id, err := db.SaveThreatFeed(ThreatFeed{Name: "Mine", URL: "https://example.com/list.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(); got[len(got)-1] != "Mine" {
		t.Fatalf("new feed not last: %v", got)
	}
	if err := db.MoveThreatFeed(id, true); err != nil {
		t.Fatal(err)
	}
	if got := names(); got[len(got)-2] != "Mine" {
		t.Fatalf("move up: %v", got)
	}
	if err := db.MoveThreatFeed(id, false); err != nil {
		t.Fatal(err)
	}
	if err := db.MoveThreatFeed(id, false); err != nil { // already last: no-op
		t.Fatal(err)
	}
	if got := names(); !slices.Equal(got, append(slices.Clone(seeded), "Mine")) {
		t.Fatalf("move down: %v", got)
	}
	if err := db.MoveThreatFeed(999, true); err != ErrNotFound {
		t.Fatalf("missing feed: %v", err)
	}
	// Deleting leaves a gap; moving still works and new feeds still go last.
	feeds, _ := db.ThreatFeeds()
	if err := db.DeleteThreatFeed(feeds[1].ID); err != nil {
		t.Fatal(err)
	}
	if err := db.MoveThreatFeed(feeds[2].ID, true); err != nil {
		t.Fatal(err)
	}
	if got := names(); got[0] != feeds[2].Name || got[1] != feeds[0].Name {
		t.Fatalf("after delete: %v", got)
	}
}

func TestThreatAlertDue(t *testing.T) {
	c := openTestDB(t)
	now := time.Now()
	due := func(at time.Time) bool {
		ok, err := c.ThreatAlertDue(1, "192.168.1.10", at, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !due(now) || due(now.Add(time.Hour)) || !due(now.Add(25*time.Hour)) {
		t.Fatal("once a day per host and feed")
	}
	if ok, _ := c.ThreatAlertDue(2, "192.168.1.10", now.Add(time.Hour), 24*time.Hour); !ok {
		t.Fatal("feeds are separate")
	}
}

func TestThreatFeedChannels(t *testing.T) {
	db := openTestDB(t)
	id, err := db.SaveThreatFeed(ThreatFeed{Name: "x", URL: "https://example.com/x.txt", Channels: []int64{3, 1, 3}})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := db.ThreatFeed(id)
	if !slices.Equal(f.Channels, []int64{1, 3}) {
		t.Fatalf("channels %v", f.Channels)
	}
}
