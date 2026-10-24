package config

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"time"
)

// Reports are saved PDF report definitions, optionally run on a schedule;
// each run is kept as a file and listed in report_runs.

const reportSchema = `
CREATE TABLE IF NOT EXISTS reports (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL UNIQUE,
	template    TEXT NOT NULL,
	sections    TEXT NOT NULL DEFAULT '[]',
	period      TEXT NOT NULL,
	filters     TEXT NOT NULL DEFAULT '{}',
	schedule    TEXT NOT NULL DEFAULT 'off',
	hour        INTEGER NOT NULL DEFAULT 7,
	weekday     INTEGER NOT NULL DEFAULT 1,
	monthday    INTEGER NOT NULL DEFAULT 1,
	recipients  TEXT NOT NULL DEFAULT '',
	channels    TEXT NOT NULL DEFAULT '[]',
	keep        INTEGER NOT NULL DEFAULT 12,
	created_by  TEXT NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL,
	updated_at  INTEGER NOT NULL,
	next_run    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS report_runs (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	report_id  INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
	started_at INTEGER NOT NULL,
	range_from INTEGER NOT NULL,
	range_to   INTEGER NOT NULL,
	trigger    TEXT NOT NULL,
	status     TEXT NOT NULL,
	error      TEXT NOT NULL DEFAULT '',
	file       TEXT NOT NULL DEFAULT '',
	size       INTEGER NOT NULL DEFAULT 0,
	emailed    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS report_runs_report ON report_runs(report_id, started_at);
`

// Report templates and the sections they can include, in page order.
var (
	ReportTemplates = map[string][]string{
		"summary":  {"kpis", "traffic", "services", "devices", "apps", "countries", "threats", "exporters"},
		"security": {"kpis", "threats", "exposure", "new_devices", "countries"},
	}
	reportSections = []string{"kpis", "traffic", "services", "devices", "apps", "countries", "threats", "exposure", "new_devices", "exporters"}
	// Periods: the previous calendar day, week (Monday to Sunday) or month,
	// or a rolling window ending at the run.
	reportPeriods = []string{"yesterday", "last_week", "last_month", "last_24h", "last_7d", "last_30d"}
)

// ReportSections lists every section in page order.
func ReportSections() []string { return slices.Clone(reportSections) }

type Report struct {
	ID       int64             `json:"id"`
	Name     string            `json:"name"`
	Template string            `json:"template"`
	Sections []string          `json:"sections"`
	Period   string            `json:"period"`
	Filters  map[string]string `json:"filters"`
	// Schedule: off | daily | weekly | monthly, at Hour (local time) on
	// Weekday (0 = Sunday) or Monthday (1–28).
	Schedule   string `json:"schedule"`
	Hour       int    `json:"hour"`
	Weekday    int    `json:"weekday"`
	Monthday   int    `json:"monthday"`
	Recipients string `json:"recipients"` // comma- or newline-separated addresses
	// Channels are notification channels runs are sent to (IDs).
	Channels  []int64 `json:"channels"`
	Keep      int     `json:"keep"` // runs kept on the appliance
	CreatedBy string  `json:"createdBy"`
	CreatedAt int64   `json:"createdAt"`
	UpdatedAt int64   `json:"updatedAt"`
	NextRun   int64   `json:"nextRun"` // ms; 0 = not scheduled
}

type ReportRun struct {
	ID        int64  `json:"id"`
	ReportID  int64  `json:"reportId"`
	StartedAt int64  `json:"startedAt"`
	From      int64  `json:"from"`
	To        int64  `json:"to"`
	Trigger   string `json:"trigger"` // schedule | manual
	Status    string `json:"status"`  // ok | failed
	Error     string `json:"error,omitempty"`
	File      string `json:"-"`
	Size      int64  `json:"size"`
	Emailed   string `json:"emailed,omitempty"` // recipients it was sent to
}

var ErrReportExists = errors.New("a report with that name already exists")

func (c *DB) migrateReports() error {
	if _, err := c.db.Exec(reportSchema); err != nil {
		return err
	}
	var n int
	if err := c.db.QueryRow("SELECT count(*) FROM pragma_table_info('reports') WHERE name = 'channels'").Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		_, err := c.db.Exec("ALTER TABLE reports ADD COLUMN channels TEXT NOT NULL DEFAULT '[]'")
		return err
	}
	return nil
}

// ValidateReport checks and normalises r.
func ValidateReport(r *Report) error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" || len(r.Name) > 80 {
		return errors.New("name is required (up to 80 characters)")
	}
	defaults, ok := ReportTemplates[r.Template]
	if !ok {
		return fmt.Errorf("unknown template %q", r.Template)
	}
	if len(r.Sections) == 0 {
		r.Sections = slices.Clone(defaults)
	}
	var secs []string
	for _, s := range reportSections { // page order, no duplicates
		if slices.Contains(r.Sections, s) {
			secs = append(secs, s)
		}
	}
	for _, s := range r.Sections {
		if !slices.Contains(reportSections, s) {
			return fmt.Errorf("unknown section %q", s)
		}
	}
	r.Sections = secs
	if !slices.Contains(reportPeriods, r.Period) {
		return fmt.Errorf("unknown period %q", r.Period)
	}
	if r.Filters == nil {
		r.Filters = map[string]string{}
	}
	if len(r.Filters) > 20 {
		return errors.New("too many filters")
	}
	switch r.Schedule {
	case "", "off":
		r.Schedule = "off"
	case "daily", "weekly", "monthly":
	default:
		return fmt.Errorf("unknown schedule %q", r.Schedule)
	}
	if r.Hour < 0 || r.Hour > 23 || r.Weekday < 0 || r.Weekday > 6 {
		return errors.New("invalid schedule time")
	}
	if r.Monthday == 0 {
		r.Monthday = 1
	}
	if r.Monthday < 1 || r.Monthday > 28 {
		return errors.New("the day of the month must be between 1 and 28")
	}
	var to []string
	for _, f := range strings.FieldsFunc(r.Recipients, func(c rune) bool { return c == ',' || c == ';' || c == '\n' }) {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		a, err := mail.ParseAddress(f)
		if err != nil {
			return fmt.Errorf("%q is not a valid email address", f)
		}
		if !slices.Contains(to, a.Address) {
			to = append(to, a.Address)
		}
	}
	if len(to) > 50 {
		return errors.New("at most 50 recipients")
	}
	r.Recipients = strings.Join(to, ", ")
	var err error
	if r.Channels, err = CleanChannelIDs(r.Channels); err != nil {
		return err
	}
	if r.Keep == 0 {
		r.Keep = 12
	}
	if r.Keep < 1 || r.Keep > 100 {
		return errors.New("keep between 1 and 100 runs")
	}
	return nil
}

// ReportRange is the time range a report covers when run at t, in loc.
func ReportRange(period string, t time.Time, loc *time.Location) (from, to time.Time) {
	t = t.In(loc)
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
	switch period {
	case "yesterday":
		return day.AddDate(0, 0, -1), day
	case "last_week": // Monday to Monday
		monday := day.AddDate(0, 0, -((int(day.Weekday()) + 6) % 7))
		return monday.AddDate(0, 0, -7), monday
	case "last_month":
		first := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, loc)
		return first.AddDate(0, -1, 0), first
	case "last_24h":
		return t.Add(-24 * time.Hour), t
	case "last_30d":
		return t.AddDate(0, 0, -30), t
	}
	return t.AddDate(0, 0, -7), t // last_7d
}

// NextReportRun is the first scheduled time after t, in loc (zero if off).
func NextReportRun(r Report, t time.Time, loc *time.Location) time.Time {
	t = t.In(loc)
	at := func(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, r.Hour, 0, 0, 0, loc) }
	switch r.Schedule {
	case "daily":
		n := at(t.Year(), t.Month(), t.Day())
		if !n.After(t) {
			n = at(t.Year(), t.Month(), t.Day()+1)
		}
		return n
	case "weekly":
		for i := 0; i <= 7; i++ {
			n := at(t.Year(), t.Month(), t.Day()+i)
			if int(n.Weekday()) == r.Weekday && n.After(t) {
				return n
			}
		}
	case "monthly":
		n := at(t.Year(), t.Month(), r.Monthday)
		if !n.After(t) {
			n = at(t.Year(), t.Month()+1, r.Monthday)
		}
		return n
	}
	return time.Time{}
}

const reportCols = "id, name, template, sections, period, filters, schedule, hour, weekday, monthday, recipients, channels, keep, created_by, created_at, updated_at, next_run"

func scanReport(row interface{ Scan(...any) error }) (Report, error) {
	var r Report
	var secs, filters, chans string
	err := row.Scan(&r.ID, &r.Name, &r.Template, &secs, &r.Period, &filters, &r.Schedule, &r.Hour, &r.Weekday, &r.Monthday,
		&r.Recipients, &chans, &r.Keep, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt, &r.NextRun)
	if err != nil {
		return r, err
	}
	_ = json.Unmarshal([]byte(secs), &r.Sections)
	_ = json.Unmarshal([]byte(filters), &r.Filters)
	_ = json.Unmarshal([]byte(chans), &r.Channels)
	if r.Channels == nil {
		r.Channels = []int64{}
	}
	if r.Sections == nil {
		r.Sections = []string{}
	}
	if r.Filters == nil {
		r.Filters = map[string]string{}
	}
	return r, nil
}

func (c *DB) Reports() ([]Report, error) {
	rows, err := c.db.Query("SELECT " + reportCols + " FROM reports ORDER BY name COLLATE NOCASE")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Report{}
	for rows.Next() {
		r, err := scanReport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (c *DB) Report(id int64) (Report, error) {
	r, err := scanReport(c.db.QueryRow("SELECT "+reportCols+" FROM reports WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// SaveReport creates (ID 0) or updates a report and schedules its next run
// after now, in loc.
func (c *DB) SaveReport(r Report, now time.Time, loc *time.Location) (Report, error) {
	if err := ValidateReport(&r); err != nil {
		return r, err
	}
	secs, _ := json.Marshal(r.Sections)
	filters, _ := json.Marshal(r.Filters)
	chans, _ := json.Marshal(r.Channels)
	next := int64(0)
	if n := NextReportRun(r, now, loc); !n.IsZero() {
		next = n.UnixMilli()
	}
	ms := now.UnixMilli()
	var err error
	if r.ID == 0 {
		var res sql.Result
		res, err = c.db.Exec(`INSERT INTO reports(name, template, sections, period, filters, schedule, hour, weekday, monthday, recipients, channels, keep, created_by, created_at, updated_at, next_run)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.Name, r.Template, string(secs), r.Period, string(filters), r.Schedule, r.Hour, r.Weekday, r.Monthday, r.Recipients, string(chans), r.Keep, r.CreatedBy, ms, ms, next)
		if err == nil {
			r.ID, err = res.LastInsertId()
		}
	} else {
		var res sql.Result
		res, err = c.db.Exec(`UPDATE reports SET name = ?, template = ?, sections = ?, period = ?, filters = ?, schedule = ?, hour = ?, weekday = ?, monthday = ?,
			recipients = ?, channels = ?, keep = ?, updated_at = ?, next_run = ? WHERE id = ?`,
			r.Name, r.Template, string(secs), r.Period, string(filters), r.Schedule, r.Hour, r.Weekday, r.Monthday, r.Recipients, string(chans), r.Keep, ms, next, r.ID)
		if err == nil {
			if n, _ := res.RowsAffected(); n == 0 {
				return r, ErrNotFound
			}
		}
	}
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return r, ErrReportExists
		}
		return r, err
	}
	return c.Report(r.ID)
}

// SetReportNextRun records when a report runs next (0 = not scheduled).
func (c *DB) SetReportNextRun(id int64, next time.Time) error {
	ms := int64(0)
	if !next.IsZero() {
		ms = next.UnixMilli()
	}
	_, err := c.db.Exec("UPDATE reports SET next_run = ? WHERE id = ?", ms, id)
	return err
}

// DueReports are scheduled reports whose next run is at or before t.
func (c *DB) DueReports(t time.Time) ([]Report, error) {
	all, err := c.Reports()
	if err != nil {
		return nil, err
	}
	var out []Report
	for _, r := range all {
		if r.Schedule != "off" && r.NextRun > 0 && r.NextRun <= t.UnixMilli() {
			out = append(out, r)
		}
	}
	return out, nil
}

// DeleteReport removes a report and its runs, returning the runs' files for
// the caller to delete.
func (c *DB) DeleteReport(id int64) ([]string, error) {
	runs, err := c.ReportRuns(id, 0)
	if err != nil {
		return nil, err
	}
	res, err := c.db.Exec("DELETE FROM reports WHERE id = ?", id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	_, _ = c.db.Exec("DELETE FROM report_runs WHERE report_id = ?", id) // in case foreign keys are off
	var files []string
	for _, r := range runs {
		if r.File != "" {
			files = append(files, r.File)
		}
	}
	return files, nil
}

const runCols = "id, report_id, started_at, range_from, range_to, trigger, status, error, file, size, emailed"

func scanRun(row interface{ Scan(...any) error }) (ReportRun, error) {
	var r ReportRun
	err := row.Scan(&r.ID, &r.ReportID, &r.StartedAt, &r.From, &r.To, &r.Trigger, &r.Status, &r.Error, &r.File, &r.Size, &r.Emailed)
	return r, err
}

// ReportRuns lists a report's runs, newest first (limit 0 = all).
func (c *DB) ReportRuns(reportID int64, limit int) ([]ReportRun, error) {
	q := "SELECT " + runCols + " FROM report_runs WHERE report_id = ? ORDER BY started_at DESC, id DESC"
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := c.db.Query(q, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReportRun{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (c *DB) ReportRun(id int64) (ReportRun, error) {
	r, err := scanRun(c.db.QueryRow("SELECT "+runCols+" FROM report_runs WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// AddReportRun records a run and drops the oldest beyond the report's keep
// count, returning the dropped runs' files for the caller to delete.
func (c *DB) AddReportRun(run ReportRun, keep int) (ReportRun, []string, error) {
	res, err := c.db.Exec(`INSERT INTO report_runs(report_id, started_at, range_from, range_to, trigger, status, error, file, size, emailed)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, run.ReportID, run.StartedAt, run.From, run.To, run.Trigger, run.Status, firstLineOf(run.Error), run.File, run.Size, run.Emailed)
	if err != nil {
		return run, nil, err
	}
	run.ID, _ = res.LastInsertId()
	all, err := c.ReportRuns(run.ReportID, 0)
	if err != nil || len(all) <= keep {
		return run, nil, err
	}
	var files []string
	for _, old := range all[keep:] {
		if _, err := c.db.Exec("DELETE FROM report_runs WHERE id = ?", old.ID); err != nil {
			return run, files, err
		}
		if old.File != "" {
			files = append(files, old.File)
		}
	}
	return run, files, nil
}

// RecipientList parses the stored recipient list.
func (r Report) RecipientList() []string {
	var out []string
	for _, f := range strings.Split(r.Recipients, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
