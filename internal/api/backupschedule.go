package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"nfa/internal/backup"
	"nfa/internal/config"
	"nfa/internal/offsite"
)

func (s *Server) backupSchedule(w http.ResponseWriter, r *http.Request) {
	sch := s.Config.BackupSchedule()
	out := map[string]any{"schedule": sch, "run": s.Config.BackupRun(), "minPassphrase": backup.MinPassphrase}
	if s.Scheduler != nil {
		running, phase := s.Scheduler.Running()
		out["running"], out["phase"] = running, phase
	}
	if sch.Enabled {
		out["next"] = offsite.Next(sch, time.Now()).UnixMilli()
	}
	if _, key, err := s.Config.BackupSSHKey(); err == nil {
		out["sshKey"] = key
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) backupScheduleSave(w http.ResponseWriter, r *http.Request) {
	var sch config.BackupSchedule
	if err := readJSON(r, &sch); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	saved, err := s.Config.SaveBackupSchedule(sch)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	detail := "off"
	if saved.Enabled {
		detail = fmt.Sprintf("%s at %s to %s, encrypted with a %s", saved.Frequency, saved.Time, saved.Destination.Describe(),
			map[string]string{"passphrase": "passphrase", "publickey": "public key"}[saved.Encryption])
	}
	s.Config.Audit(userFrom(r).Username, "backup.schedule", detail)
	s.backupSchedule(w, r)
}

// backupScheduleTest checks the destination in the form, using stored
// secrets the form leaves empty.
func (s *Server) backupScheduleTest(w http.ResponseWriter, r *http.Request) {
	var sch config.BackupSchedule
	if err := readJSON(r, &sch); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if sch.Destination.Type == "" {
		writeJSON(w, http.StatusOK, offsite.TestResult{Message: "Choose a destination to test."})
		return
	}
	// Only the destination matters here; don't trip over unrelated fields.
	probe := config.BackupSchedule{Destination: sch.Destination}
	if err := config.ValidateBackupDestination(&probe.Destination); err != nil {
		writeJSON(w, http.StatusOK, offsite.TestResult{Message: err.Error()})
		return
	}
	if err := s.Config.FillBackupSecrets(&probe); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	env := offsite.Env{RootCAs: s.trustPool()}
	if k, _, err := s.Config.BackupSSHKey(); err == nil {
		env.SSHKey = k
	}
	writeJSON(w, http.StatusOK, offsite.Test(r.Context(), probe.Destination, env, backup.IsOwn))
}

func (s *Server) backupScheduleRun(w http.ResponseWriter, r *http.Request) {
	if s.Scheduler == nil {
		writeErr(w, http.StatusInternalServerError, "scheduled backups are not available")
		return
	}
	sch := s.Config.BackupSchedule()
	if sch.Encryption == "passphrase" && !sch.HasPassphrase {
		writeErr(w, http.StatusBadRequest, "save the schedule with a passphrase first")
		return
	}
	// The run outlives this request.
	if err := s.Scheduler.RunNow(context.WithoutCancel(r.Context())); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, offsite.ErrRunning) {
			code = http.StatusConflict
		}
		writeErr(w, code, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "backup.run", "to "+sch.Destination.Describe())
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

// backupNotice reports a failed or overdue scheduled backup.
func (s *Server) backupNotice(now time.Time) *Notice {
	sch := s.Config.BackupSchedule()
	if !sch.Enabled {
		return nil
	}
	run := s.Config.BackupRun()
	action := &NoticeAction{Label: "Backup & Restore", Route: "/admin/backup", admin: true}
	if run.Finished > 0 && !run.OK {
		return &Notice{ID: fmt.Sprintf("backup-failed:%d", run.Started), Kind: "backup-failed", Level: "danger", adminOnly: true, Dismissible: true,
			Params: map[string]string{"error": firstLine(run.Error)}, Message: "The last scheduled backup failed: " + firstLine(run.Error), Action: action}
	}
	// Overdue: no success for a whole interval plus grace, counting from when
	// the schedule was set up.
	grace := offsite.Interval(sch) + 6*time.Hour
	since := max(run.LastSuccess, sch.Updated)
	if now.Sub(time.UnixMilli(since)) > grace {
		return &Notice{ID: fmt.Sprintf("backup-overdue:%d", since), Kind: "backup-overdue", Level: "warning", adminOnly: true, Dismissible: true,
			Params: map[string]string{"since": time.UnixMilli(since).UTC().Format(time.RFC3339)}, Message: "No scheduled backup has succeeded recently.", Action: action}
	}
	return nil
}

// backupSSHKeyRegenerate replaces the appliance's SSH key with a new one.
func (s *Server) backupSSHKeyRegenerate(w http.ResponseWriter, r *http.Request) {
	_, old, _ := s.Config.BackupSSHKey()
	info, err := s.Config.RegenerateBackupSSHKey()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "backup.sshkey.regenerate", fmt.Sprintf("%s replaced by %s", old.Fingerprint, info.Fingerprint))
	writeJSON(w, http.StatusOK, info)
}

// backupSSHKeyUpload replaces the appliance's SSH key with the
// administrator's own private key.
func (s *Server) backupSSHKeyUpload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PrivateKey string `json:"privateKey"`
		Passphrase string `json:"passphrase"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, old, _ := s.Config.BackupSSHKey()
	info, err := s.Config.SetBackupSSHKey(req.PrivateKey, req.Passphrase)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Config.Audit(userFrom(r).Username, "backup.sshkey.upload", fmt.Sprintf("%s replaced by %s (%s)", old.Fingerprint, info.Fingerprint, info.Type))
	writeJSON(w, http.StatusOK, info)
}
