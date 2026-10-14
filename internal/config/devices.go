package config

import (
	"strings"
	"time"
)

const deviceSchema = `
CREATE TABLE IF NOT EXISTS devices (
	mac        INTEGER PRIMARY KEY,
	name       TEXT NOT NULL DEFAULT '',
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS device_ips (
	ip   TEXT PRIMARY KEY,
	mac  INTEGER NOT NULL,
	seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS device_ips_mac ON device_ips(mac);
`

// DeviceIP is a learned binding of a local address to a MAC.
type DeviceIP struct {
	IP   string `json:"ip"`
	MAC  uint64 `json:"-"`
	Seen int64  `json:"seen"`
}

// Device is a local device identified by MAC.
type Device struct {
	MAC       uint64     `json:"-"`
	Name      string     `json:"name"`
	FirstSeen int64      `json:"firstSeen"`
	LastSeen  int64      `json:"lastSeen"`
	IPs       []DeviceIP `json:"ips"`
}

func (c *DB) DeviceIPs() ([]DeviceIP, error) {
	rows, err := c.db.Query("SELECT ip, mac, seen FROM device_ips")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceIP
	for rows.Next() {
		var d DeviceIP
		if err := rows.Scan(&d.IP, &d.MAC, &d.Seen); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SaveDeviceIPs persists learned bindings and keeps device first/last seen
// current. Bindings unseen for 30 days are pruned.
func (c *DB) SaveDeviceIPs(list []DeviceIP) error {
	if len(list) == 0 {
		return nil
	}
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, d := range list {
		if _, err := tx.Exec(`INSERT INTO device_ips(ip, mac, seen) VALUES(?, ?, ?)
			ON CONFLICT(ip) DO UPDATE SET mac = excluded.mac, seen = excluded.seen`, d.IP, d.MAC, d.Seen); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO devices(mac, first_seen, last_seen) VALUES(?, ?, ?)
			ON CONFLICT(mac) DO UPDATE SET last_seen = max(last_seen, excluded.last_seen)`, d.MAC, d.Seen, d.Seen); err != nil {
			return err
		}
	}
	if _, err := tx.Exec("DELETE FROM device_ips WHERE seen < ?", time.Now().Add(-30*24*time.Hour).UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}

// Devices lists known devices with their addresses (newest first).
func (c *DB) Devices() ([]Device, error) {
	rows, err := c.db.Query("SELECT mac, name, first_seen, last_seen FROM devices ORDER BY last_seen DESC")
	if err != nil {
		return nil, err
	}
	byMAC := map[uint64]*Device{}
	var out []*Device
	for rows.Next() {
		d := &Device{IPs: []DeviceIP{}}
		if err := rows.Scan(&d.MAC, &d.Name, &d.FirstSeen, &d.LastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		byMAC[d.MAC] = d
		out = append(out, d)
	}
	rows.Close()
	ips, err := c.db.Query("SELECT ip, mac, seen FROM device_ips ORDER BY seen DESC")
	if err != nil {
		return nil, err
	}
	defer ips.Close()
	for ips.Next() {
		var ip DeviceIP
		if err := ips.Scan(&ip.IP, &ip.MAC, &ip.Seen); err != nil {
			return nil, err
		}
		if d := byMAC[ip.MAC]; d != nil {
			d.IPs = append(d.IPs, ip)
		}
	}
	res := make([]Device, 0, len(out))
	for _, d := range out {
		res = append(res, *d)
	}
	return res, ips.Err()
}

// DeviceName returns the administrator-given name, or "".
func (c *DB) DeviceName(mac uint64) string {
	var n string
	_ = c.db.QueryRow("SELECT name FROM devices WHERE mac = ?", mac).Scan(&n)
	return n
}

func (c *DB) SetDeviceName(mac uint64, name string) error {
	name = strings.TrimSpace(name)
	if len(name) > 64 {
		name = name[:64]
	}
	now := time.Now().UnixMilli()
	_, err := c.db.Exec(`INSERT INTO devices(mac, name, first_seen, last_seen) VALUES(?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET name = excluded.name`, mac, name, now, now)
	return err
}

// RecentIPv4 returns the most recently used IPv4 address of a device, for
// naming it by reverse DNS.
func (c *DB) RecentIPv4(mac uint64) string {
	var ip string
	_ = c.db.QueryRow("SELECT ip FROM device_ips WHERE mac = ? AND ip NOT LIKE '%:%' ORDER BY seen DESC LIMIT 1", mac).Scan(&ip)
	return ip
}
