package system

import (
	"os"
	"path/filepath"
	"testing"
)

// A status saved before a reboot must not keep claiming a restart is needed.
func TestRebootRequiredIsLive(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{StateDir: dir, RequestDir: dir}
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(`{"rebootRequired":true,"kernel":"old"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	flag := filepath.Join(dir, "reboot-required")
	old := RebootRequiredFile
	RebootRequiredFile = flag
	defer func() { RebootRequiredFile = old }()

	st, err := m.UpdateStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.RebootRequired {
		t.Fatal("stale reboot-required reported after the flag file is gone")
	}
	if st.Kernel == "old" {
		t.Fatal("kernel should be the running one")
	}
	os.WriteFile(flag, nil, 0o644)
	if st, _ = m.UpdateStatus(); !st.RebootRequired {
		t.Fatal("reboot-required not reported while the flag file exists")
	}
}
