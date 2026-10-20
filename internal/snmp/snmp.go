// Package snmp polls exporters for interface names, descriptions and speeds
// (IF-MIB) and their system name, so reports and utilization use the
// device's own data even when it doesn't send names in its flow records.
package snmp

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"

	"nfa/internal/config"
)

const (
	oidSysDescr = ".1.3.6.1.2.1.1.1.0"
	oidSysName  = ".1.3.6.1.2.1.1.5.0"
	oidIfDescr  = ".1.3.6.1.2.1.2.2.1.2"     // ifDescr
	oidIfSpeed  = ".1.3.6.1.2.1.2.2.1.5"     // ifSpeed (bit/s, caps at 4294967295)
	oidIfName   = ".1.3.6.1.2.1.31.1.1.1.1"  // ifName
	oidIfHigh   = ".1.3.6.1.2.1.31.1.1.1.15" // ifHighSpeed (Mbit/s)
	oidIfAlias  = ".1.3.6.1.2.1.31.1.1.1.18" // ifAlias
)

// Interval between polls of each exporter.
const Interval = 15 * time.Minute

type Poller struct {
	cfg *config.DB
	log *slog.Logger

	mu      sync.Mutex
	polling map[string]bool
	kick    chan string
}

func New(cfg *config.DB, log *slog.Logger) *Poller {
	return &Poller{cfg: cfg, log: log, polling: map[string]bool{}, kick: make(chan string, 16)}
}

// PollSoon asks for an exporter to be polled now (e.g. after its settings
// changed); it never blocks.
func (p *Poller) PollSoon(addr string) {
	select {
	case p.kick <- addr:
	default:
	}
}

// Run polls each enabled exporter every Interval until ctx ends.
func (p *Poller) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	check := func() {
		addrs, err := p.cfg.SNMPEnabled()
		if err != nil {
			return
		}
		for _, a := range addrs {
			if _, st, err := p.cfg.SNMP(a); err == nil && time.Since(time.UnixMilli(st.LastPoll)) >= Interval {
				p.pollAsync(ctx, a)
			}
		}
	}
	check()
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-p.kick:
			p.pollAsync(ctx, a)
		case <-t.C:
			check()
		}
	}
}

func (p *Poller) pollAsync(ctx context.Context, addr string) {
	p.mu.Lock()
	if p.polling[addr] {
		p.mu.Unlock()
		return
	}
	p.polling[addr] = true
	p.mu.Unlock()
	go func() {
		defer func() {
			p.mu.Lock()
			delete(p.polling, addr)
			p.mu.Unlock()
		}()
		_ = p.Poll(ctx, addr)
	}()
}

// Poll queries one exporter now and stores the result.
func (p *Poller) Poll(ctx context.Context, addr string) error {
	s, _, err := p.cfg.SNMP(addr)
	if err != nil {
		return err
	}
	if s.Version == "" {
		return fmt.Errorf("SNMP is off for %s", addr)
	}
	res, err := Query(ctx, addr, s)
	if err != nil {
		p.log.Warn("SNMP poll failed", "exporter", addr, "err", err)
		_ = p.cfg.SaveSNMPPoll(addr, "", "", nil, err)
		return err
	}
	p.log.Info("SNMP poll", "exporter", addr, "sysName", res.SysName, "interfaces", len(res.Interfaces))
	return p.cfg.SaveSNMPPoll(addr, res.SysName, res.SysDescr, res.Interfaces, nil)
}

type Result struct {
	SysName    string
	SysDescr   string
	Interfaces []config.SNMPInterface
}

// client builds a gosnmp client for the settings.
func client(ctx context.Context, exporter string, s config.SNMPConfig) (*gosnmp.GoSNMP, error) {
	host, port := s.Target(exporter)
	g := &gosnmp.GoSNMP{Target: host, Port: port, Timeout: 3 * time.Second, Retries: 1, MaxRepetitions: 25, Context: ctx}
	switch s.Version {
	case "2c":
		g.Version, g.Community = gosnmp.Version2c, s.Community
	case "3":
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		usm := &gosnmp.UsmSecurityParameters{UserName: s.User}
		g.MsgFlags = gosnmp.NoAuthNoPriv
		if s.AuthProto != "" {
			g.MsgFlags = gosnmp.AuthNoPriv
			usm.AuthenticationProtocol = map[string]gosnmp.SnmpV3AuthProtocol{
				"MD5": gosnmp.MD5, "SHA": gosnmp.SHA, "SHA256": gosnmp.SHA256, "SHA512": gosnmp.SHA512}[s.AuthProto]
			usm.AuthenticationPassphrase = s.AuthPass
		}
		if s.PrivProto != "" {
			g.MsgFlags = gosnmp.AuthPriv
			usm.PrivacyProtocol = map[string]gosnmp.SnmpV3PrivProtocol{
				"DES": gosnmp.DES, "AES": gosnmp.AES, "AES256": gosnmp.AES256}[s.PrivProto]
			usm.PrivacyPassphrase = s.PrivPass
		}
		g.SecurityParameters = usm
	default:
		return nil, fmt.Errorf("unsupported SNMP version %q", s.Version)
	}
	return g, nil
}

// Query reads the system and interface tables from an agent.
func Query(ctx context.Context, exporter string, s config.SNMPConfig) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	g, err := client(ctx, exporter, s)
	if err != nil {
		return nil, err
	}
	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", g.Target, err)
	}
	defer g.Conn.Close()

	res := &Result{}
	sys, err := g.Get([]string{oidSysName, oidSysDescr})
	if err != nil && s.Version == "3" && strings.Contains(err.Error(), "not authentic") {
		return nil, explain(err)
	}
	if err != nil {
		return nil, explain(err)
	}
	if sys.Error != gosnmp.NoError {
		return nil, fmt.Errorf("agent error: %s", sys.Error)
	}
	for _, v := range sys.Variables {
		switch v.Name {
		case oidSysName:
			res.SysName = str(v)
		case oidSysDescr:
			res.SysDescr = firstLine(str(v))
		}
	}

	ifs := map[uint32]*config.SNMPInterface{}
	get := func(idx uint32) *config.SNMPInterface {
		i := ifs[idx]
		if i == nil {
			i = &config.SNMPInterface{Index: idx}
			ifs[idx] = i
		}
		return i
	}
	descr := map[uint32]string{}
	walk := func(root string, f func(idx uint32, v gosnmp.SnmpPDU)) error {
		return g.BulkWalk(root, func(v gosnmp.SnmpPDU) error {
			var idx uint32
			if _, err := fmt.Sscanf(strings.TrimPrefix(v.Name, root+"."), "%d", &idx); err == nil && idx > 0 {
				f(idx, v)
			}
			return nil
		})
	}
	if err := walk(oidIfDescr, func(idx uint32, v gosnmp.SnmpPDU) { descr[idx] = str(v); get(idx) }); err != nil {
		return nil, explain(err)
	}
	// IF-MIB extensions are optional on old agents; ignore their absence.
	_ = walk(oidIfName, func(idx uint32, v gosnmp.SnmpPDU) { get(idx).Name = str(v) })
	_ = walk(oidIfAlias, func(idx uint32, v gosnmp.SnmpPDU) { get(idx).Alias = str(v) })
	high := map[uint32]uint64{}
	_ = walk(oidIfHigh, func(idx uint32, v gosnmp.SnmpPDU) { high[idx] = gosnmp.ToBigInt(v.Value).Uint64() * 1_000_000 })
	low := map[uint32]uint64{}
	_ = walk(oidIfSpeed, func(idx uint32, v gosnmp.SnmpPDU) { low[idx] = gosnmp.ToBigInt(v.Value).Uint64() })

	for idx, i := range ifs {
		if i.Name == "" {
			i.Name = descr[idx]
		}
		// ifSpeed saturates at ~4.3 Gbit/s; ifHighSpeed covers faster links.
		switch {
		case high[idx] > 0 && (low[idx] == 0 || low[idx] >= 4_294_967_295 || high[idx] > low[idx]):
			i.Speed = high[idx]
		default:
			i.Speed = low[idx]
		}
		res.Interfaces = append(res.Interfaces, *i)
	}
	sort.Slice(res.Interfaces, func(a, b int) bool { return res.Interfaces[a].Index < res.Interfaces[b].Index })
	return res, nil
}

func str(v gosnmp.SnmpPDU) string {
	switch b := v.Value.(type) {
	case []byte:
		return strings.TrimSpace(strings.ToValidUTF8(string(b), "?"))
	case string:
		return strings.TrimSpace(b)
	}
	return ""
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return strings.TrimSpace(s)
}

// explain turns gosnmp's errors into something an administrator can act on.
func explain(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "request timeout"):
		return fmt.Errorf("no response (check the address, port, community or credentials, and that SNMP is enabled on the device): %w", err)
	case strings.Contains(msg, "unknown user"), strings.Contains(msg, "UnknownUserName"):
		return fmt.Errorf("the device doesn't know this SNMPv3 user: %w", err)
	case strings.Contains(msg, "wrong digest"), strings.Contains(msg, "WrongDigests"), strings.Contains(msg, "authentication"),
		strings.Contains(msg, "not authentic"):
		return fmt.Errorf("SNMPv3 authentication failed (check the protocol and passphrase): %w", err)
	}
	return err
}
