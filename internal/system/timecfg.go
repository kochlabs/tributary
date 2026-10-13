package system

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const timesyncConf = "/etc/systemd/timesyncd.conf.d/tributary.conf"

type TimeStatus struct {
	Timezone     string   `json:"timezone"`
	NTPEnabled   bool     `json:"ntpEnabled"`
	Synchronized bool     `json:"synchronized"`
	Now          int64    `json:"now"`
	Servers      []string `json:"servers"`        // configured on the appliance (ordered)
	Defaults     []string `json:"defaultServers"` // distribution fallback list
	ServerName   string   `json:"serverName"`
	ServerAddr   string   `json:"serverAddress"`
	Stratum      int      `json:"stratum"`
	Offset       string   `json:"offset"`
	Delay        string   `json:"delay"`
	Jitter       string   `json:"jitter"`
	PollInterval string   `json:"pollInterval"`
	LastSync     int64    `json:"lastSync"`
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func keyValues(s string) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			m[k] = v
		}
	}
	return m
}

var timesyncLine = regexp.MustCompile(`^\s*([A-Za-z ]+):\s*(.*)$`)

// TimeStatus reads clock and NTP state via timedatectl (no privileges needed).
func (m *Manager) TimeStatus(ctx context.Context) (*TimeStatus, error) {
	out, err := run(ctx, "timedatectl", "show")
	if err != nil {
		return nil, fmt.Errorf("timedatectl: %w", err)
	}
	kv := keyValues(out)
	st := &TimeStatus{
		Timezone:     kv["Timezone"],
		NTPEnabled:   kv["NTP"] == "yes",
		Synchronized: kv["NTPSynchronized"] == "yes",
		Now:          time.Now().UnixMilli(),
		Servers:      []string{},
		Defaults:     []string{},
	}
	if out, err := run(ctx, "timedatectl", "show-timesync"); err == nil {
		ts := keyValues(out)
		st.Defaults = strings.Fields(ts["FallbackNTPServers"])
		st.ServerName, st.ServerAddr = ts["ServerName"], ts["ServerAddress"]
	}
	st.Servers = configuredServers()
	// The human-readable status has offset, delay, jitter and poll interval.
	if out, err := run(ctx, "timedatectl", "timesync-status"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			mm := timesyncLine.FindStringSubmatch(line)
			if mm == nil {
				continue
			}
			v := strings.TrimSpace(mm[2])
			switch strings.TrimSpace(mm[1]) {
			case "Offset":
				st.Offset = strings.TrimPrefix(v, "+")
			case "Delay":
				st.Delay = v
			case "Jitter":
				st.Jitter = v
			case "Stratum":
				st.Stratum, _ = strconv.Atoi(v)
			case "Poll interval":
				st.PollInterval, _, _ = strings.Cut(v, " (")
			}
		}
	}
	// timesyncd touches this file on every successful synchronisation.
	if fi, err := os.Stat("/var/lib/systemd/timesync/clock"); err == nil && st.NTPEnabled {
		st.LastSync = fi.ModTime().UnixMilli()
	}
	return st, nil
}

func configuredServers() []string {
	b, err := os.ReadFile(timesyncConf)
	if err != nil {
		return []string{}
	}
	for _, line := range bytes.Split(b, []byte("\n")) {
		if v, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("NTP=")); ok {
			return strings.Fields(string(v))
		}
	}
	return []string{}
}

func (m *Manager) Timezones(ctx context.Context) ([]string, error) {
	out, err := run(ctx, "timedatectl", "list-timezones")
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// ValidNTPServer accepts host names and IP addresses (the helper re-checks).
func ValidNTPServer(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return hostnameRe.MatchString(s) && !strings.Contains(s, "..")
}

// SetTime applies the time zone, NTP switch and ordered server list (an
// empty list restores the distribution defaults).
func (m *Manager) SetTime(timezone string, ntp bool, servers []string) (string, error) {
	if len(servers) > 10 {
		return "", errors.New("at most 10 NTP servers")
	}
	for _, s := range servers {
		if !ValidNTPServer(s) {
			return "", fmt.Errorf("invalid NTP server %q", s)
		}
	}
	return m.submit(map[string]any{"action": "time", "timezone": timezone, "ntp": ntp, "servers": servers})
}
