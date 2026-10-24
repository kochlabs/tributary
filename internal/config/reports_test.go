package config

import (
	"testing"
	"time"
)

func TestReportRangeAndSchedule(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no tz data")
	}
	// Wednesday 21 Oct 2026, 10:30 local.
	now := time.Date(2026, 10, 21, 10, 30, 0, 0, loc)
	f := func(t time.Time) string { return t.In(loc).Format("Mon 2006-01-02 15:04") }
	for _, c := range []struct{ period, from, to string }{
		{"yesterday", "Tue 2026-10-20 00:00", "Wed 2026-10-21 00:00"},
		{"last_week", "Mon 2026-10-12 00:00", "Mon 2026-10-19 00:00"},
		{"last_month", "Tue 2026-09-01 00:00", "Thu 2026-10-01 00:00"},
		{"last_24h", "Tue 2026-10-20 10:30", "Wed 2026-10-21 10:30"},
		{"last_7d", "Wed 2026-10-14 10:30", "Wed 2026-10-21 10:30"},
	} {
		from, to := ReportRange(c.period, now, loc)
		if f(from) != c.from || f(to) != c.to {
			t.Errorf("%s: %s – %s", c.period, f(from), f(to))
		}
	}
	// Across the end of daylight saving time (1 Nov 2026), a week is 169 hours.
	from, to := ReportRange("last_week", time.Date(2026, 11, 4, 9, 0, 0, 0, loc), loc)
	if to.Sub(from) != 169*time.Hour {
		t.Errorf("DST week is %v", to.Sub(from))
	}

	for _, c := range []struct {
		r    Report
		want string
	}{
		{Report{Schedule: "daily", Hour: 7}, "Thu 2026-10-22 07:00"},
		{Report{Schedule: "daily", Hour: 11}, "Wed 2026-10-21 11:00"},
		{Report{Schedule: "weekly", Hour: 7, Weekday: 1}, "Mon 2026-10-26 07:00"},
		{Report{Schedule: "weekly", Hour: 11, Weekday: 3}, "Wed 2026-10-21 11:00"},
		{Report{Schedule: "weekly", Hour: 9, Weekday: 3}, "Wed 2026-10-28 09:00"},
		{Report{Schedule: "monthly", Hour: 6, Monthday: 1}, "Sun 2026-11-01 06:00"},
		{Report{Schedule: "monthly", Hour: 12, Monthday: 21}, "Wed 2026-10-21 12:00"},
	} {
		if got := f(NextReportRun(c.r, now, loc)); got != c.want {
			t.Errorf("%+v: %s, want %s", c.r, got, c.want)
		}
	}
	if !NextReportRun(Report{Schedule: "off"}, now, loc).IsZero() {
		t.Error("off is scheduled")
	}
}

func TestReports(t *testing.T) {
	db := openTestDB(t)
	now := time.Date(2026, 10, 21, 10, 30, 0, 0, time.UTC)
	for _, bad := range []Report{
		{Name: "", Template: "summary", Period: "last_7d"},
		{Name: "x", Template: "nope", Period: "last_7d"},
		{Name: "x", Template: "summary", Period: "fortnight"},
		{Name: "x", Template: "summary", Period: "last_7d", Sections: []string{"bogus"}},
		{Name: "x", Template: "summary", Period: "last_7d", Recipients: "not an address"},
		{Name: "x", Template: "summary", Period: "last_7d", Schedule: "monthly", Monthday: 31},
	} {
		if _, err := db.SaveReport(bad, now, time.UTC); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	r, err := db.SaveReport(Report{Name: "Weekly", Template: "security", Period: "last_week", Schedule: "weekly", Hour: 7, Weekday: 1,
		Sections: []string{"threats", "kpis", "threats"}, Recipients: "a@example.com; Bob <b@example.com>\na@example.com"}, now, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Sections) != 2 || r.Sections[0] != "kpis" || r.Recipients != "a@example.com, b@example.com" || len(r.RecipientList()) != 2 {
		t.Fatalf("normalised %+v", r)
	}
	if r.NextRun != time.Date(2026, 10, 26, 7, 0, 0, 0, time.UTC).UnixMilli() {
		t.Fatalf("next run %v", time.UnixMilli(r.NextRun))
	}
	if _, err := db.SaveReport(Report{Name: "Weekly", Template: "summary", Period: "last_7d"}, now, time.UTC); err != ErrReportExists {
		t.Fatalf("duplicate: %v", err)
	}
	due, _ := db.DueReports(time.UnixMilli(r.NextRun))
	if len(due) != 1 {
		t.Fatalf("due %v", due)
	}
	// Runs beyond keep are dropped, oldest first.
	r.Keep = 2
	if r, err = db.SaveReport(r, now, time.UTC); err != nil {
		t.Fatal(err)
	}
	var dropped []string
	for i := range 4 {
		_, files, err := db.AddReportRun(ReportRun{ReportID: r.ID, StartedAt: int64(i), Status: "ok", File: string(rune('a' + i))}, r.Keep)
		if err != nil {
			t.Fatal(err)
		}
		dropped = append(dropped, files...)
	}
	runs, _ := db.ReportRuns(r.ID, 0)
	if len(runs) != 2 || runs[0].File != "d" || len(dropped) != 2 || dropped[0] != "a" {
		t.Fatalf("runs %v dropped %v", runs, dropped)
	}
	files, err := db.DeleteReport(r.ID)
	if err != nil || len(files) != 2 {
		t.Fatalf("delete: %v %v", files, err)
	}
	if runs, _ := db.ReportRuns(r.ID, 0); len(runs) != 0 {
		t.Fatal("runs left")
	}
}

func TestConvertReportFilters(t *testing.T) {
	db := openTestDB(t)
	r, err := db.SaveReport(Report{Name: "Old", Template: "summary", Period: "last_7d", Filters: map[string]string{"host": "10.0.0.5"}, Query: "proto:tcp"}, time.Now(), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	conv := func(f map[string]string) string { return "host:" + f["host"] }
	if err := db.ConvertReportFilters(conv); err != nil {
		t.Fatal(err)
	}
	got, _ := db.Report(r.ID)
	if got.Query != "(host:10.0.0.5) AND (proto:tcp)" || len(got.Filters) != 0 {
		t.Fatalf("%q %v", got.Query, got.Filters)
	}
	// Once: nothing left to convert.
	if err := db.ConvertReportFilters(func(map[string]string) string { t.Fatal("converted twice"); return "" }); err != nil {
		t.Fatal(err)
	}
}
