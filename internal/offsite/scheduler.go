package offsite

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"nfa/internal/backup"
	"nfa/internal/config"
)

// ErrRunning means a scheduled backup is already in progress.
var ErrRunning = errors.New("a scheduled backup is already running")

// Scheduler makes backups on the configured schedule, copies them to the
// destination and prunes old ones.
type Scheduler struct {
	Cfg     *config.DB
	Backups *backup.Manager
	Log     *slog.Logger
	RootCAs func() *x509.CertPool
	// RetryDelay is the wait before the second copy attempt (doubled before
	// the third); 0 means 30 seconds.
	RetryDelay time.Duration

	running atomic.Bool
	phase   atomic.Pointer[string]
}

// Interval is the time between scheduled backups.
func Interval(s config.BackupSchedule) time.Duration {
	if s.Frequency == "weekly" {
		return 7 * 24 * time.Hour
	}
	return 24 * time.Hour
}

// lastSlot is the most recent scheduled time at or before now.
func lastSlot(s config.BackupSchedule, now time.Time) time.Time {
	var h, m int
	fmt.Sscanf(s.Time, "%d:%d", &h, &m)
	t := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	if t.After(now) {
		t = t.AddDate(0, 0, -1)
	}
	if s.Frequency == "weekly" {
		for int(t.Weekday()) != s.Weekday {
			t = t.AddDate(0, 0, -1)
		}
	}
	return t
}

// Next is the next scheduled time after now.
func Next(s config.BackupSchedule, now time.Time) time.Time {
	t := lastSlot(s, now)
	if s.Frequency == "weekly" {
		return t.AddDate(0, 0, 7)
	}
	return t.AddDate(0, 0, 1)
}

// Due reports whether a scheduled time has passed since the last run and
// since the schedule was saved (saving doesn't trigger an immediate
// backup). A slot missed while the appliance was off runs once at start.
func Due(s config.BackupSchedule, last config.BackupRun, now time.Time) bool {
	if !s.Enabled {
		return false
	}
	slot := lastSlot(s, now)
	return slot.UnixMilli() > last.Started && slot.UnixMilli() > s.Updated
}

// Running reports whether a scheduled backup is in progress, and its phase.
func (s *Scheduler) Running() (bool, string) {
	p := s.phase.Load()
	if p == nil {
		return s.running.Load(), ""
	}
	return s.running.Load(), *p
}

func (s *Scheduler) setPhase(p string) { s.phase.Store(&p) }

// Run checks the schedule every minute until ctx ends.
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		sch := s.Cfg.BackupSchedule()
		if Due(sch, s.Cfg.BackupRun(), time.Now()) && s.running.CompareAndSwap(false, true) {
			err := s.run(ctx)
			s.running.Store(false)
			if errors.Is(err, backup.ErrBusy) {
				s.Log.Info("scheduled backup waiting for another backup or restore to finish")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunNow starts a backup with the scheduled settings in the background.
func (s *Scheduler) RunNow(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return ErrRunning
	}
	go func() {
		defer s.running.Store(false)
		if err := s.run(ctx); errors.Is(err, backup.ErrBusy) {
			_ = s.Cfg.SaveBackupRun(s.failed(s.Cfg.BackupRun(), time.Now(), err))
		}
	}()
	return nil
}

func (s *Scheduler) env() Env {
	env := Env{}
	if s.RootCAs != nil {
		env.RootCAs = s.RootCAs()
	}
	if k, _, err := s.Cfg.BackupSSHKey(); err == nil {
		env.SSHKey = k
	}
	return env
}

func (s *Scheduler) failed(prev config.BackupRun, started time.Time, err error) config.BackupRun {
	return config.BackupRun{Started: started.UnixMilli(), Finished: time.Now().UnixMilli(), Error: err.Error(), LastSuccess: prev.LastSuccess}
}

// run makes one backup, copies and prunes. It records the result, except
// when another backup or restore is running (ErrBusy), so the schedule
// retries a minute later.
func (s *Scheduler) run(ctx context.Context) error {
	defer s.phase.Store(nil)
	started := time.Now()
	prev := s.Cfg.BackupRun()
	sch, err := s.Cfg.BackupScheduleSecrets()
	fail := func(err error) error {
		s.Log.Warn("scheduled backup failed", "err", err)
		_ = s.Cfg.SaveBackupRun(s.failed(prev, started, err))
		s.Cfg.Audit("system", "backup.scheduled.failed", err.Error())
		return err
	}
	if err != nil {
		return fail(err)
	}
	keys := ""
	if sch.Encryption == "publickey" {
		keys = sch.PublicKeys
	}
	rcpts, err := backup.Recipients(sch.Passphrase, keys)
	if err != nil {
		return fail(fmt.Errorf("encryption: %w", err))
	}
	s.setPhase("backup")
	name, err := s.Backups.RunScheduled(rcpts, sch.IncludeFlows)
	if errors.Is(err, backup.ErrBusy) {
		return err
	}
	if err != nil {
		return fail(err)
	}
	path, err := s.Backups.Path(name)
	if err != nil {
		return fail(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fail(err)
	}
	run := config.BackupRun{Started: started.UnixMilli(), Name: name, Size: fi.Size(), LastSuccess: prev.LastSuccess}
	var notes []string
	if sch.Destination.Type != "" {
		s.setPhase("copy")
		if err := s.copy(ctx, sch, path, name, fi.Size()); err != nil {
			run.Finished, run.Error = time.Now().UnixMilli(), fmt.Sprintf("the backup was made on the appliance (%s), but copying it to %s failed: %v", name, sch.Destination.Describe(), err)
			_ = s.Cfg.SaveBackupRun(run)
			s.Cfg.Audit("system", "backup.scheduled.failed", run.Error)
			s.Log.Warn("scheduled backup copy failed", "name", name, "err", err)
			s.pruneLocal(sch, &notes)
			return err
		}
		run.Copied = true
		s.setPhase("prune")
		if gone, err := s.pruneRemote(ctx, sch); err != nil {
			notes = append(notes, "pruning old backups at the destination failed: "+err.Error())
		} else if len(gone) > 0 {
			s.Log.Info("pruned old backups at the destination", "names", gone)
		}
	}
	s.pruneLocal(sch, &notes)
	run.OK, run.Finished, run.LastSuccess = true, time.Now().UnixMilli(), time.Now().UnixMilli()
	run.Error = strings.Join(notes, "; ")
	_ = s.Cfg.SaveBackupRun(run)
	detail := fmt.Sprintf("%s (%d bytes)", name, fi.Size())
	if run.Copied {
		detail += " copied to " + sch.Destination.Describe()
	}
	s.Cfg.Audit("system", "backup.scheduled", detail)
	s.Log.Info("scheduled backup done", "name", name, "copied", run.Copied)
	return nil
}

func (s *Scheduler) pruneLocal(sch config.BackupSchedule, notes *[]string) {
	if gone, err := s.Backups.PruneScheduled(sch.KeepLocal); err != nil {
		*notes = append(*notes, "pruning old backups on the appliance failed: "+err.Error())
	} else if len(gone) > 0 {
		s.Log.Info("pruned old scheduled backups", "names", gone)
	}
}

// copy uploads a backup, retrying transient failures, and checks the size
// that arrived.
func (s *Scheduler) copy(ctx context.Context, sch config.BackupSchedule, path, name string, size int64) error {
	delay := s.RetryDelay
	if delay == 0 {
		delay = 30 * time.Second
	}
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt-1) * delay):
			}
		}
		if err = s.copyOnce(ctx, sch, path, name, size); err == nil {
			return nil
		}
		s.Log.Warn("copying backup failed", "attempt", attempt, "err", err)
	}
	return err
}

func (s *Scheduler) copyOnce(ctx context.Context, sch config.BackupSchedule, path, name string, size int64) error {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Hour)
	defer cancel()
	t, err := Open(ctx, sch.Destination, s.env())
	if err != nil {
		return err
	}
	defer t.Close()
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := t.Put(ctx, filepath.Base(name), f, size); err != nil {
		return err
	}
	list, err := t.List(ctx)
	if err != nil {
		return fmt.Errorf("checking the upload: %w", err)
	}
	for _, o := range list {
		if o.Name == name {
			if o.Size != size {
				return fmt.Errorf("the uploaded file has %d bytes, expected %d", o.Size, size)
			}
			return nil
		}
	}
	return errors.New("the uploaded file is missing from the destination")
}

// pruneRemote deletes this appliance's backups at the destination beyond
// the newest KeepRemote. Other files, including other appliances'
// backups, are never touched.
func (s *Scheduler) pruneRemote(ctx context.Context, sch config.BackupSchedule) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	t, err := Open(ctx, sch.Destination, s.env())
	if err != nil {
		return nil, err
	}
	defer t.Close()
	list, err := t.List(ctx)
	if err != nil {
		return nil, err
	}
	var own []string
	for _, o := range list {
		if backup.IsOwn(o.Name) {
			own = append(own, o.Name)
		}
	}
	// Names end in a sortable timestamp: newest first.
	sort.Sort(sort.Reverse(sort.StringSlice(own)))
	var gone []string
	for i, n := range own {
		if i < sch.KeepRemote {
			continue
		}
		if err := t.Delete(ctx, n); err != nil {
			return gone, err
		}
		gone = append(gone, n)
	}
	return gone, nil
}
