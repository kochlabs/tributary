package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kochlabs/tributary/internal/config"
	"github.com/kochlabs/tributary/internal/mail"
	"github.com/kochlabs/tributary/internal/notify"
	"github.com/kochlabs/tributary/internal/report"
	"github.com/kochlabs/tributary/internal/store"
)

// Reports (Reports page): saved definitions, rendered to PDF on demand or on
// a schedule; runs are kept under <data>/reports and optionally emailed.

type reportView struct {
	config.Report
	LastRun *config.ReportRun `json:"lastRun,omitempty"`
}

func (s *Server) reportsList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Config.Reports()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]reportView, 0, len(list))
	for _, rep := range list {
		v := reportView{Report: rep}
		if runs, err := s.Config.ReportRuns(rep.ID, 1); err == nil && len(runs) > 0 {
			v.LastRun = &runs[0]
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"reports": out, "emailEnabled": s.Config.Email().Enabled,
		"templates": config.ReportTemplates, "sections": config.ReportSections(), "timezone": time.Now().Format("MST"),
	})
}

func (s *Server) reportSave(w http.ResponseWriter, r *http.Request) {
	var rep config.Report
	if err := readJSON(r, &rep); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rep.ID = 0
	action := "report.create"
	if p := r.PathValue("id"); p != "" {
		rep.ID, _ = strconv.ParseInt(p, 10, 64)
		action = "report.update"
	} else {
		rep.CreatedBy = userFrom(r).Username
	}
	if err := s.validateReportFilters(rep.Filters); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Channels deleted since the editor loaded are dropped.
	rep.Channels = slices.DeleteFunc(rep.Channels, func(id int64) bool {
		_, err := s.Config.Channel(id)
		return err != nil
	})
	saved, err := s.Config.SaveReport(rep, time.Now(), time.Local)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, config.ErrNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, action, fmt.Sprintf("%s (%s, %s)", saved.Name, saved.Template, saved.Schedule))
	writeJSON(w, http.StatusOK, saved)
}

// validateReportFilters rejects unknown keys (which ParseFilter ignores, as
// query strings carry other parameters) and invalid values.
func (s *Server) validateReportFilters(f map[string]string) error {
	for k := range f {
		if _, ok := store.FilterFields[k]; !ok {
			return fmt.Errorf("unknown filter %q", k)
		}
	}
	_, err := store.ParseFilter(f)
	return err
}

func (s *Server) reportDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rep, err := s.Config.Report(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such report")
		return
	}
	files, err := s.Config.DeleteReport(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.removeReportFiles(files)
	s.Config.Audit(userFrom(r).Username, "report.delete", rep.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// reportPreview renders a definition (saved or not) for its period ending
// now, without keeping it.
func (s *Server) reportPreview(w http.ResponseWriter, r *http.Request) {
	var rep config.Report
	if err := readJSON(r, &rep); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if rep.Name == "" {
		rep.Name = templateTitles[rep.Template]
	}
	if err := config.ValidateReport(&rep); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.validateReportFilters(rep.Filters); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := queryCtx(r)
	defer cancel()
	from, to := config.ReportRange(rep.Period, time.Now(), time.Local)
	pdf, err := s.renderReport(ctx, rep, from, to)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	writePDF(w, pdf, reportFileName(rep.Name, from))
}

func (s *Server) renderReport(ctx context.Context, rep config.Report, from, to time.Time) ([]byte, error) {
	data, err := s.buildReport(ctx, rep, from, to)
	if err != nil {
		return nil, err
	}
	return report.Render(data)
}

func writePDF(w http.ResponseWriter, pdf []byte, name string) {
	h := w.Header()
	h.Set("Content-Type", "application/pdf")
	h.Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, name))
	h.Set("Cache-Control", "no-store")
	w.Write(pdf)
}

// reportRun runs a report now: kept and emailed like a scheduled run.
func (s *Server) reportRun(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rep, err := s.Config.Report(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such report")
		return
	}
	var req struct {
		Deliver bool `json:"deliver"` // email it and send it to its channels
	}
	_ = readJSON(r, &req)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	run := s.runReport(ctx, rep, "manual", req.Deliver)
	s.Config.Audit(userFrom(r).Username, "report.run", rep.Name+": "+run.Status)
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) reportRuns(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	runs, err := s.Config.ReportRuns(id, 0)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, runs)
}

func (s *Server) reportRunPDF(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("run"), 10, 64)
	run, err := s.Config.ReportRun(id)
	if err != nil || run.File == "" {
		writeErr(w, http.StatusNotFound, "no such report run")
		return
	}
	pdf, err := os.ReadFile(s.reportPath(run.File))
	if err != nil {
		writeErr(w, http.StatusNotFound, "the report file is missing")
		return
	}
	rep, _ := s.Config.Report(run.ReportID)
	writePDF(w, pdf, reportFileName(rep.Name, time.UnixMilli(run.From)))
}

func (s *Server) reportDir() string { return filepath.Join(s.DataDir, "reports") }

// reportPath resolves a stored run file name inside the reports directory.
func (s *Server) reportPath(name string) string {
	return filepath.Join(s.reportDir(), filepath.Base(name))
}

func (s *Server) removeReportFiles(files []string) {
	for _, f := range files {
		_ = os.Remove(s.reportPath(f))
	}
}

// runReport renders rep for its period ending now, keeps the PDF, and when
// deliver is set emails it to its recipients (if email is set up) and sends
// it to its channels; it records the run. Runs are serialized: they are
// heavy on the database.
func (s *Server) runReport(ctx context.Context, rep config.Report, trigger string, deliver bool) config.ReportRun {
	s.reportMu.Lock()
	defer s.reportMu.Unlock()
	now := time.Now()
	from, to := config.ReportRange(rep.Period, now, time.Local)
	run := config.ReportRun{ReportID: rep.ID, StartedAt: now.UnixMilli(), From: from.UnixMilli(), To: to.UnixMilli(), Trigger: trigger, Status: "ok"}
	name := s.Config.Settings().ApplianceName
	fail := func(err error) config.ReportRun {
		run.Status, run.Error = "failed", err.Error()
		s.Log.Warn("report failed", "report", rep.Name, "err", err)
		if deliver {
			s.Notify.Publish(notify.Event{Type: "report.failed", Level: "warning", Appliance: name, Title: rep.Name + " failed", Message: err.Error(),
				URL: s.publicLink("/reports"), Data: map[string]any{"reportId": rep.ID, "trigger": trigger}}, rep.Channels)
		}
		return s.recordRun(run, rep.Keep)
	}
	pdf, err := s.renderReport(ctx, rep, from, to)
	if err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(s.reportDir(), 0o750); err != nil {
		return fail(err)
	}
	file := fmt.Sprintf("%d-%s.pdf", rep.ID, now.Format("20060102-150405"))
	if err := os.WriteFile(s.reportPath(file), pdf, 0o640); err != nil {
		return fail(err)
	}
	run.File, run.Size = file, int64(len(pdf))
	if rcpts := rep.RecipientList(); deliver && len(rcpts) > 0 {
		if err := s.emailReport(ctx, rep, rcpts, from, to, pdf); err != nil {
			return fail(fmt.Errorf("the report was made but not emailed: %w", err))
		}
		run.Emailed = strings.Join(rcpts, ", ")
	}
	if deliver {
		s.Notify.Publish(notify.Event{Type: "report.completed", Level: "info", Appliance: name, Title: rep.Name, Message: periodLabel(from, to),
			URL: s.publicLink("/reports"), Attachment: s.reportPath(run.File), AttachmentName: reportFileName(rep.Name, from),
			Data: map[string]any{"reportId": rep.ID, "trigger": trigger, "from": from, "to": to, "size": run.Size}}, rep.Channels)
	}
	return s.recordRun(run, rep.Keep)
}

func (s *Server) recordRun(run config.ReportRun, keep int) config.ReportRun {
	saved, dropped, err := s.Config.AddReportRun(run, keep)
	if err != nil {
		s.Log.Warn("recording a report run failed", "err", err)
	}
	s.removeReportFiles(dropped)
	return saved
}

func (s *Server) emailReport(ctx context.Context, rep config.Report, rcpts []string, from, to time.Time, pdf []byte) error {
	cfg, err := s.Config.EmailSecrets()
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		return errors.New("email is turned off (Configuration → Email)")
	}
	name := s.Config.Settings().ApplianceName
	period := periodLabel(from, to)
	return mail.Send(ctx, cfg, s.trustPool(), mail.Message{
		To:          rcpts,
		Subject:     fmt.Sprintf("%s: %s, %s", name, rep.Name, period),
		Text:        fmt.Sprintf("%s for %s is attached.\n\nSent by %s.\n", rep.Name, period, name),
		Attachments: []mail.Attachment{{Name: reportFileName(rep.Name, from), ContentType: "application/pdf", Data: pdf}},
	})
}

// RunReports runs scheduled reports when they are due until ctx ends.
func (s *Server) RunReports(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		due, err := s.Config.DueReports(time.Now())
		if err != nil {
			continue
		}
		for _, rep := range due {
			// Schedule the next run first, so a failing report doesn't retry
			// every minute.
			_ = s.Config.SetReportNextRun(rep.ID, config.NextReportRun(rep, time.Now(), time.Local))
			rctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			s.runReport(rctx, rep, "schedule", true)
			cancel()
		}
	}
}
