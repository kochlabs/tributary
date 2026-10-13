// Package system connects the web UI to the privileged admin helper
// (deploy/admin/tributary-admin.sh). The service never changes the OS itself:
// it writes a JSON request that a root-owned systemd unit validates and runs,
// and reads the state the helper publishes. Read-only queries (time status,
// unit states) use unprivileged commands directly.
package system

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Manager struct {
	RequestDir   string // writable by the service, watched by tributary-admin.path
	StateDir     string // written by the helper, readable by the service
	HelperPath   string
	ServicesConf string
}

func New() *Manager {
	return &Manager{
		RequestDir:   "/var/lib/nfa/admin-request",
		StateDir:     "/var/lib/tributary-admin",
		HelperPath:   "/usr/lib/tributary/tributary-admin.sh",
		ServicesConf: "/etc/tributary/services.conf",
	}
}

var (
	ErrBusy         = errors.New("another administrative action is pending")
	ErrNotInstalled = errors.New("the admin helper is not installed on this system")
)

func (m *Manager) Installed() bool {
	_, err := os.Stat(m.HelperPath)
	return err == nil
}

func (m *Manager) pending() bool {
	_, err := os.Stat(filepath.Join(m.RequestDir, "request.json"))
	return err == nil
}

// submit writes a request for the helper and returns its id.
func (m *Manager) submit(req map[string]any) (string, error) {
	if !m.Installed() {
		return "", ErrNotInstalled
	}
	if m.pending() {
		return "", ErrBusy
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	req["id"] = id
	data, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	tmp := filepath.Join(m.RequestDir, fmt.Sprintf(".req-%s", id))
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return "", err
	}
	// Rename is atomic: the path unit never sees a half-written request.
	return id, os.Rename(tmp, filepath.Join(m.RequestDir, "request.json"))
}

type Result struct {
	ID      string `json:"id"`
	Action  string `json:"action"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	At      int64  `json:"at"`
	Pending bool   `json:"pending"`
}

// Result reports the outcome of request id: Pending until the helper has
// published a result for it.
func (m *Manager) Result(id string) (*Result, error) {
	b, err := os.ReadFile(filepath.Join(m.StateDir, "result.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var r Result
	if err == nil {
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
	}
	if r.ID != id {
		return &Result{ID: id, Pending: true}, nil
	}
	r.At *= 1000
	return &r, nil
}

// WaitResult polls for a request's result up to timeout.
func (m *Manager) WaitResult(id string, timeout time.Duration) (*Result, error) {
	deadline := time.Now().Add(timeout)
	for {
		r, err := m.Result(id)
		if err != nil || !r.Pending || time.Now().After(deadline) {
			return r, err
		}
		time.Sleep(200 * time.Millisecond)
	}
}
