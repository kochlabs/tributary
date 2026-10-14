package enrich

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nfa/internal/config"
)

// No vendor data ships with Tributary: the table is downloaded from the IEEE
// registries (the default) or loaded from a URL or file the administrator
// chooses. Until then vendor names are empty.

type ouiTable struct {
	by24, by28, by36 map[uint64]string
}

func newOUITable() *ouiTable {
	return &ouiTable{by24: map[uint64]string{}, by28: map[uint64]string{}, by36: map[uint64]string{}}
}

func (t *ouiTable) size() int { return len(t.by24) + len(t.by28) + len(t.by36) }

// add registers name for a prefix of hex digits (no separators) of the
// given bit length.
func (t *ouiTable) add(hex string, bits int, name string) {
	v, err := strconv.ParseUint(hex, 16, 64)
	if err != nil || name == "" || len(hex) > 12 {
		return
	}
	// Normalise to a 48-bit value, then keep the prefix bits.
	v <<= uint(48 - 4*len(hex))
	key := v >> uint(48-bits)
	switch bits {
	case 24:
		t.by24[key] = name
	case 28:
		t.by28[key] = name
	case 36:
		t.by36[key] = name
	}
}

// parseOUI reads either an IEEE registry CSV or the Wireshark manuf format
// (oui.csv, mam.csv, oui36.csv) into t.
func parseOUI(r io.Reader, t *ouiTable) error {
	br := bufio.NewReader(r)
	if head, _ := br.Peek(20); bytes.HasPrefix(head, []byte("Registry,Assignment")) {
		return parseIEEE(br, t)
	}
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		// Columns: prefix, short name, full name (optional).
		name := strings.TrimSpace(f[1])
		if len(f) >= 3 && strings.TrimSpace(f[2]) != "" {
			name = strings.TrimSpace(f[2])
		}
		prefix, bits := strings.TrimSpace(f[0]), 24
		if p, b, ok := strings.Cut(prefix, "/"); ok {
			prefix = p
			bits, _ = strconv.Atoi(b)
		}
		hex := strings.NewReplacer(":", "", "-", "", ".", "").Replace(prefix)
		if bits > 24 && len(hex) == 12 {
			hex = hex[:bits/4]
		}
		t.add(hex, bits, name)
	}
	return sc.Err()
}

func parseIEEE(r io.Reader, t *ouiTable) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	if _, err := cr.Read(); err != nil { // header
		return err
	}
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(rec) < 3 {
			continue
		}
		hex := strings.TrimSpace(rec[1])
		t.add(hex, 4*len(hex), strings.TrimSpace(rec[2]))
	}
}

var (
	ouiCur   atomic.Pointer[ouiTable]
	ouiEmpty = newOUITable()
)

func currentOUI() *ouiTable {
	if t := ouiCur.Load(); t != nil {
		return t
	}
	return ouiEmpty
}

// Vendor returns the registered manufacturer for a MAC (as a 48-bit
// number), the most specific registration first. Randomised ("locally
// administered") addresses, as used by phones for privacy, have none.
func Vendor(mac uint64) string {
	if mac == 0 {
		return ""
	}
	if mac&(0x02<<40) != 0 {
		return "Private (randomized) address"
	}
	t := currentOUI()
	if n, ok := t.by36[mac>>12]; ok {
		return n
	}
	if n, ok := t.by28[mac>>20]; ok {
		return n
	}
	return t.by24[mac>>24]
}

// The IEEE registration authority's public registries: MA-L (24-bit),
// MA-M (28-bit) and MA-S (36-bit) assignments.
var ieeeRegistries = []struct{ url, file string }{
	{"https://standards-oui.ieee.org/oui/oui.csv", "ieee-oui.csv"},
	{"https://standards-oui.ieee.org/oui28/mam.csv", "ieee-mam.csv"},
	{"https://standards-oui.ieee.org/oui36/oui36.csv", "ieee-oui36.csv"},
}

// VendorDB manages where the MAC vendor table comes from.
type VendorDB struct {
	dir string
	log *slog.Logger
	src atomic.Pointer[config.Enrichment]

	updateMu    sync.Mutex
	lastUpdate  atomic.Value // string
	lastAttempt atomic.Int64
	loadedMod   atomic.Int64 // newest file modification time of the loaded table (unix ms)
	location    atomic.Value // string
}

func NewVendorDB(dir string, log *slog.Logger) *VendorDB {
	v := &VendorDB{dir: dir, log: log}
	d := config.DefaultEnrichment()
	v.src.Store(&d)
	v.location.Store("not loaded")
	return v
}

func (v *VendorDB) source() config.Enrichment { return *v.src.Load() }

// SetSource selects the source and reports whether it changed.
func (v *VendorDB) SetSource(e config.Enrichment) bool {
	old := v.src.Swap(&e)
	return old.OUISource != e.OUISource || old.OUIURL != e.OUIURL || old.OUIFile != e.OUIFile
}

// files returns the local files making up the table for the current source.
func (v *VendorDB) files() []string {
	e := v.source()
	switch e.OUISource {
	case config.OUIURL:
		return []string{filepath.Join(v.dir, "custom-oui")}
	case config.OUIFile:
		return []string{e.OUIFile}
	}
	out := make([]string, len(ieeeRegistries))
	for i, r := range ieeeRegistries {
		out[i] = filepath.Join(v.dir, r.file)
	}
	return out
}

func parseOUIFiles(paths []string) (*ouiTable, int64, error) {
	t := newOUITable()
	var newest int64
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, 0, err
		}
		newest = max(newest, st.ModTime().UnixMilli())
		f, err := openMaybeGzip(p)
		if err != nil {
			return nil, 0, err
		}
		err = parseOUI(f, t)
		f.Close()
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", p, err)
		}
	}
	if t.size() < 100 {
		return nil, 0, errors.New("no vendor entries found: expected an IEEE registry CSV or a Wireshark manuf file")
	}
	return t, newest, nil
}

func validOUI(path string) error {
	_, _, err := parseOUIFiles([]string{path})
	return err
}

// Load builds the table from the current source. If its files can't be
// read (not downloaded yet, or a bad file), whatever table is loaded stays
// in use until they can.
func (v *VendorDB) Load() error {
	paths := v.files()
	t, mod, err := parseOUIFiles(paths)
	if err != nil {
		v.loadedMod.Store(0) // so the files are fetched or re-read
		if currentOUI().size() == 0 {
			v.location.Store("not loaded yet")
		} else if loc, _ := v.location.Load().(string); !strings.HasSuffix(loc, ")") {
			v.location.Store(loc + " (previous source, until the new one loads)")
		}
		if v.source().OUISource != config.OUIFile && errors.Is(err, os.ErrNotExist) {
			return nil // a download is pending
		}
		return err
	}
	ouiCur.Store(t)
	v.loadedMod.Store(mod)
	if v.source().OUISource == config.OUIFile {
		v.location.Store(paths[0])
	} else {
		names := make([]string, len(paths))
		for i, p := range paths {
			names[i] = filepath.Base(p)
		}
		v.location.Store(strings.Join(names, ", "))
	}
	v.log.Info("vendor database loaded", "source", v.source().OUISource, "entries", t.size())
	return nil
}

// Update downloads the table now (or reloads a local file).
func (v *VendorDB) Update(ctx context.Context) error {
	if !v.updateMu.TryLock() {
		return errors.New("an update is already running")
	}
	defer v.updateMu.Unlock()
	e := v.source()
	var errs []error
	switch e.OUISource {
	case config.OUIIEEE:
		for _, r := range ieeeRegistries {
			if err := fetch(ctx, r.url, "", "", filepath.Join(v.dir, r.file), "", validOUI); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", r.url, err))
			}
		}
	case config.OUIURL:
		if err := fetch(ctx, e.OUIURL, "", "", filepath.Join(v.dir, "custom-oui"), "", validOUI); err != nil {
			errs = append(errs, fmt.Errorf("download from %s failed: %w", hostOf(e.OUIURL), redact(err, e.OUIURL)))
		}
	}
	err := errors.Join(errs...)
	if lerr := v.Load(); err == nil {
		err = lerr
	}
	msg := time.Now().Format(time.RFC3339) + ": "
	switch {
	case err != nil:
		msg += "failed: " + err.Error()
		v.log.Warn("vendor database update failed", "err", err)
	case e.OUISource == config.OUIFile:
		msg += "reloaded"
	default:
		msg += "ok"
	}
	v.lastUpdate.Store(msg)
	return err
}

func (v *VendorDB) missing() bool { return v.loadedMod.Load() == 0 }

func (v *VendorDB) stale() bool {
	switch v.source().OUISource {
	case config.OUIIEEE, config.OUIURL:
		mod := v.loadedMod.Load()
		// The registries change daily, but weekly is plenty (and polite).
		return mod == 0 || time.Since(time.UnixMilli(mod)) > 7*24*time.Hour
	}
	return false
}

func (v *VendorDB) fileChanged() bool {
	if v.source().OUISource != config.OUIFile {
		return false
	}
	st, err := os.Stat(v.source().OUIFile)
	return err == nil && st.ModTime().UnixMilli() != v.loadedMod.Load()
}

// Refresh switches to a newly selected source: a URL is downloaded right
// away (it may point somewhere new), the IEEE registry when missing or out of
// date, and other sources are just loaded.
func (v *VendorDB) Refresh(ctx context.Context) {
	src := v.source().OUISource
	err := v.Load()
	if src == config.OUIURL || (src == config.OUIIEEE && v.stale()) {
		_ = v.Update(ctx)
		return
	}
	msg := time.Now().Format(time.RFC3339) + ": switched to " + src
	if err != nil {
		msg += "; failed: " + err.Error()
		v.log.Warn("vendor database could not be loaded", "err", err)
	}
	v.lastUpdate.Store(msg)
}

// AutoUpdate downloads the table when it is missing, refreshes it weekly
// while enabled() is true, and reloads a local file when it changes.
// Failed downloads are retried at most every 12 hours.
func (v *VendorDB) AutoUpdate(ctx context.Context, enabled func() bool) {
	check := func() {
		if v.fileChanged() {
			if err := v.Load(); err != nil {
				v.log.Warn("vendor database could not be loaded", "err", err)
			}
			return
		}
		if v.source().OUISource == config.OUIFile || !v.stale() || (!enabled() && !v.missing()) ||
			time.Now().Unix()-v.lastAttempt.Load() < 12*3600 {
			return
		}
		v.lastAttempt.Store(time.Now().Unix())
		_ = v.Update(ctx)
	}
	check()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}

type VendorStatus struct {
	Source     string `json:"source"`
	Location   string `json:"location"`
	Entries    int    `json:"entries"`
	Updated    int64  `json:"updated"`
	LastUpdate string `json:"lastUpdate"`
}

func (v *VendorDB) Status() VendorStatus {
	s := VendorStatus{Source: v.source().OUISource, Entries: currentOUI().size(), Updated: v.loadedMod.Load()}
	s.Location, _ = v.location.Load().(string)
	s.LastUpdate, _ = v.lastUpdate.Load().(string)
	return s
}

// FormatMAC renders a 48-bit MAC as aa:bb:cc:dd:ee:ff.
func FormatMAC(mac uint64) string {
	b := make([]byte, 0, 17)
	for i := 5; i >= 0; i-- {
		x := byte(mac >> (8 * i))
		b = append(b, "0123456789abcdef"[x>>4], "0123456789abcdef"[x&15])
		if i > 0 {
			b = append(b, ':')
		}
	}
	return string(b)
}

// ParseMAC accepts aa:bb:cc:dd:ee:ff, aa-bb-..., or aabb.ccdd.eeff.
func ParseMAC(s string) (uint64, bool) {
	h := strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.TrimSpace(s))
	if len(h) != 12 {
		return 0, false
	}
	v, err := strconv.ParseUint(h, 16, 64)
	return v, err == nil
}
