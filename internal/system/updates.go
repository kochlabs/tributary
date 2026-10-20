package system

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Package struct {
	Name     string `json:"name"`
	Suite    string `json:"suite"`
	Version  string `json:"version"`
	From     string `json:"from"`
	Security bool   `json:"security"`
}

type UpdateStatus struct {
	Installed       bool      `json:"installed"` // helper present on this system
	State           string    `json:"state"`     // idle | running | done | failed
	Action          string    `json:"action"`
	StartedAt       *int64    `json:"startedAt"`
	FinishedAt      *int64    `json:"finishedAt"`
	ExitCode        *int      `json:"exitCode"`
	LastCheck       *int64    `json:"lastCheck"`
	LastInstall     *int64    `json:"lastInstall"`
	LastInstallExit *int      `json:"lastInstallExit"`
	Upgradable      []Package `json:"upgradable"`
	RebootRequired  bool      `json:"rebootRequired"`
	OS              string    `json:"os"`
	Kernel          string    `json:"kernel"`
	Pending         string    `json:"pending,omitempty"` // requested, not yet picked up
}

// UpdateStatus reads the helper's published state. Times are converted to unix ms.
func (m *Manager) UpdateStatus() (*UpdateStatus, error) {
	st := &UpdateStatus{State: "idle", Upgradable: []Package{}}
	st.Installed = m.Installed()
	b, err := os.ReadFile(filepath.Join(m.StateDir, "status.json"))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, st); err != nil {
			return nil, fmt.Errorf("status file: %w", err)
		}
	}
	for _, t := range []**int64{&st.StartedAt, &st.FinishedAt, &st.LastCheck, &st.LastInstall} {
		if *t != nil {
			ms := **t * 1000
			*t = &ms
		}
	}
	if st.Upgradable == nil {
		st.Upgradable = []Package{}
	}
	if b, err := os.ReadFile(filepath.Join(m.RequestDir, "request.json")); err == nil {
		var r struct{ Action string }
		_ = json.Unmarshal(b, &r)
		st.Pending = r.Action
	}
	// The helper's snapshot goes stale on reboot (/run is cleared), so read
	// the current state rather than trusting the last check.
	_, err = os.Stat(RebootRequiredFile)
	st.RebootRequired = err == nil
	if k := runningKernel(); k != "" {
		st.Kernel = k
	}
	return st, nil
}

// RebootRequiredFile is created by Debian packages that need a restart.
var RebootRequiredFile = "/run/reboot-required"

func runningKernel() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Log returns the output of the current or last action, starting at offset.
func (m *Manager) Log(offset int64) (string, int64, error) {
	f, err := os.Open(filepath.Join(m.StateDir, "log"))
	if errors.Is(err, os.ErrNotExist) {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if offset < 0 || offset > info.Size() {
		offset = 0 // log was truncated by a new action
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return "", 0, err
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	return string(b), offset + int64(len(b)), err
}

// RequestUpdate asks the helper to check for, install, or finish (reboot)
// updates.
func (m *Manager) RequestUpdate(action string) (string, error) {
	switch action {
	case "check", "upgrade", "reboot":
	default:
		return "", fmt.Errorf("unknown action %q", action)
	}
	st, err := m.UpdateStatus()
	if err != nil {
		return "", err
	}
	if st.State == "running" {
		return "", ErrBusy
	}
	return m.submit(map[string]any{"action": action})
}
