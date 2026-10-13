package system

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
)

type Service struct {
	Unit        string   `json:"unit"`
	Description string   `json:"description"`
	Active      string   `json:"active"` // active | inactive | failed | activating | ...
	Sub         string   `json:"sub"`    // running | exited | dead | waiting | ...
	OnBoot      string   `json:"onBoot"` // enabled | disabled | static | ...
	Since       int64    `json:"since"`
	MainPID     int      `json:"mainPid"`
	Memory      uint64   `json:"memory"`
	Ops         []string `json:"ops"` // operations permitted from the UI
}

// allowlist parses services.conf: "unit [op ...]" per line.
func (m *Manager) allowlist() ([]string, map[string][]string, error) {
	f, err := os.Open(m.ServicesConf)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	var units []string
	ops := map[string][]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) == 0 || strings.HasPrefix(fs[0], "#") {
			continue
		}
		units = append(units, fs[0])
		ops[fs[0]] = fs[1:]
	}
	return units, ops, sc.Err()
}

// Services lists the appliance-relevant units that exist on this system.
func (m *Manager) Services(ctx context.Context) ([]Service, error) {
	units, ops, err := m.allowlist()
	if err != nil {
		return nil, err
	}
	args := append([]string{"show", "--property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID,MemoryCurrent,ActiveEnterTimestamp", "--timestamp=unix", "--"}, units...)
	out, err := run(ctx, "systemctl", args...)
	if err != nil && out == "" {
		return nil, fmt.Errorf("systemctl: %w", err)
	}
	var list []Service
	for _, block := range strings.Split(strings.TrimSpace(out), "\n\n") {
		kv := keyValues(block)
		if kv["LoadState"] != "loaded" {
			continue // not installed here
		}
		s := Service{Unit: kv["Id"], Description: kv["Description"], Active: kv["ActiveState"], Sub: kv["SubState"],
			OnBoot: kv["UnitFileState"], Ops: ops[kv["Id"]]}
		if s.Ops == nil {
			s.Ops = []string{}
		}
		fmt.Sscan(kv["MainPID"], &s.MainPID)
		fmt.Sscan(kv["MemoryCurrent"], &s.Memory)
		var since int64
		if _, err := fmt.Sscan(strings.TrimPrefix(kv["ActiveEnterTimestamp"], "@"), &since); err == nil {
			s.Since = since * 1000
		}
		list = append(list, s)
	}
	slices.SortFunc(list, func(a, b Service) int { return strings.Compare(a.Unit, b.Unit) })
	return list, nil
}

// ServiceAction asks the helper to perform an allowlisted operation.
func (m *Manager) ServiceAction(unit, op string) (string, error) {
	_, ops, err := m.allowlist()
	if err != nil {
		return "", err
	}
	if !slices.Contains(ops[unit], op) {
		return "", fmt.Errorf("operation %q is not permitted on %q", op, unit)
	}
	return m.submit(map[string]any{"action": "service", "unit": unit, "op": op})
}
