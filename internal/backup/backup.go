// Package backup creates and restores encrypted appliance backups: the
// configuration (users, settings, names, identity sources, certificates and
// the secret key that protects stored credentials) and, optionally, the flow
// history from ClickHouse.
//
// A backup file is age-encrypted (to a passphrase with scrypt, or to age
// public keys), zstd-compressed and holds a sequence of entries (see
// container.go), the manifest first.
package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
)

// Format is the version of the backup layout written by this code.
const Format = 1

// MinPassphrase is the shortest passphrase accepted for new backups.
const MinPassphrase = 12

// configFiles are the files in the data directory that make up the
// configuration, by entry name. Optional ones may be missing.
var configFiles = []struct {
	entry, file string
	optional    bool
	mode        os.FileMode
}{
	{"config/config.db", "config.db", false, 0o640},
	{"config/secret.key", "secret.key", false, 0o600},
	{"config/tls.crt", "tls.crt", true, 0o644},
	{"config/tls.key", "tls.key", true, 0o600},
	{"config/tls.pending.key", "tls.pending.key", true, 0o600},
	{"config/tls.pending.csr", "tls.pending.csr", true, 0o644},
}

// flowTables are exported in this order; restoring them replaces the tables.
var flowTables = []string{"flows", "traffic_1m"}

// rollupView feeds traffic_1m from flows; it is detached while flows are
// restored so the restored rollup isn't added to twice.
const rollupView = "netflow.traffic_1m_mv2"

type Manifest struct {
	Format   int         `json:"format"`
	Version  string      `json:"version"`
	Created  int64       `json:"created"` // unix ms
	Hostname string      `json:"hostname"`
	Files    []string    `json:"files"`
	Flows    []TableInfo `json:"flows,omitempty"`
	// Scheduled marks backups made by the schedule; only these are pruned
	// automatically.
	Scheduled bool `json:"scheduled,omitempty"`
}

type TableInfo struct {
	Table string `json:"table"`
	Rows  uint64 `json:"rows"` // at the start of the backup
}

// Info describes a stored backup file.
type Info struct {
	Name      string      `json:"name"`
	Size      int64       `json:"size"`
	Created   int64       `json:"created"`
	Hostname  string      `json:"hostname"`
	Version   string      `json:"version"`
	Flows     []TableInfo `json:"flows,omitempty"`
	Scheduled bool        `json:"scheduled,omitempty"`
}

// Job is the state of the running or last backup/restore.
type Job struct {
	Kind     string `json:"kind"`  // backup | restore
	State    string `json:"state"` // running | done | failed
	Phase    string `json:"phase"`
	Bytes    int64  `json:"bytes"`
	Error    string `json:"error,omitempty"`
	Started  int64  `json:"started"`
	Finished int64  `json:"finished,omitempty"`
	Name     string `json:"name,omitempty"`
}

// ClickHouse is the HTTP interface used to stream flow tables.
type ClickHouse struct {
	URL, User, Password string
}

type Manager struct {
	Dir      string // the appliance data directory
	CH       ClickHouse
	Version  string
	Log      *slog.Logger
	Snapshot func(path string) error // writes a consistent copy of config.db

	mu    sync.Mutex
	job   atomic.Pointer[Job]
	bytes atomic.Int64
}

func (m *Manager) backupsDir() string { return filepath.Join(m.Dir, "backups") }
func (m *Manager) restoreDir() string { return filepath.Join(m.Dir, "restore") }
func (m *Manager) uploadPath() string { return filepath.Join(m.restoreDir(), "upload.tbk") }

// StagedDir holds a restored configuration until the next start applies it.
func StagedDir(dataDir string) string { return filepath.Join(dataDir, "restore", "staged") }

var ageKeyRE = regexp.MustCompile(`AGE-SECRET-KEY-(PQ-)?1[0-9A-Z]+`)

var nameRE = regexp.MustCompile(`^tributary-[A-Za-z0-9._-]+\.tbk$`)

// Job returns the current or last job, with live progress.
func (m *Manager) Job() *Job {
	j := m.job.Load()
	if j == nil {
		return nil
	}
	c := *j
	if c.State == "running" {
		c.Bytes = m.bytes.Load()
	}
	return &c
}

func (m *Manager) setJob(update func(j *Job)) {
	j := *m.job.Load()
	update(&j)
	m.job.Store(&j)
}

func (m *Manager) begin(kind string) error {
	if !m.mu.TryLock() {
		return ErrBusy
	}
	m.bytes.Store(0)
	m.job.Store(&Job{Kind: kind, State: "running", Started: time.Now().UnixMilli()})
	return nil
}

func (m *Manager) finish(err error) {
	m.setJob(func(j *Job) {
		j.Finished = time.Now().UnixMilli()
		j.Bytes = m.bytes.Load()
		if err != nil {
			j.State, j.Error = "failed", err.Error()
			m.Log.Warn(j.Kind+" failed", "err", err)
		} else {
			j.State = "done"
		}
	})
	m.mu.Unlock()
}

func (m *Manager) phase(p string) { m.setJob(func(j *Job) { j.Phase = p }) }

// List returns stored backups, newest first.
func (m *Manager) List() ([]Info, error) {
	entries, err := os.ReadDir(m.backupsDir())
	if errors.Is(err, os.ErrNotExist) {
		return []Info{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Info{}
	for _, e := range entries {
		if !nameRE.MatchString(e.Name()) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		info := Info{Name: e.Name(), Size: fi.Size(), Created: fi.ModTime().UnixMilli()}
		if b, err := os.ReadFile(filepath.Join(m.backupsDir(), e.Name()+".json")); err == nil {
			var man Manifest
			if json.Unmarshal(b, &man) == nil {
				info.Created, info.Hostname, info.Version, info.Flows, info.Scheduled = man.Created, man.Hostname, man.Version, man.Flows, man.Scheduled
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out, nil
}

// Path returns the file of a stored backup.
func (m *Manager) Path(name string) (string, error) {
	if !nameRE.MatchString(name) {
		return "", errors.New("invalid backup name")
	}
	p := filepath.Join(m.backupsDir(), name)
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}

func (m *Manager) Delete(name string) error {
	p, err := m.Path(name)
	if err != nil {
		return err
	}
	_ = os.Remove(p + ".json")
	return os.Remove(p)
}

// FreeSpace is the space available to the data directory.
func FreeSpace(dir string) uint64 {
	var st syscall.Statfs_t
	if syscall.Statfs(dir, &st) != nil {
		return 0
	}
	return st.Bavail * uint64(st.Bsize)
}

// FlowsSize estimates the on-disk size of the flow history, which is close
// to the size it takes in a backup.
func (m *Manager) FlowsSize(ctx context.Context) (uint64, error) {
	var out string
	err := m.query(ctx, "SELECT sum(bytes_on_disk) FROM system.parts WHERE database = 'netflow' AND active AND table IN ('flows', 'traffic_1m')", nil, func(r io.Reader) error {
		b, err := io.ReadAll(io.LimitReader(r, 64))
		out = strings.TrimSpace(string(b))
		return err
	})
	if err != nil {
		return 0, err
	}
	var n uint64
	_, err = fmt.Sscan(out, &n)
	return n, err
}

// ErrBusy means another backup or restore is running.
var ErrBusy = errors.New("a backup or restore is already running")

// Recipients returns what a backup is encrypted to: a passphrase (scrypt),
// or one or more age public keys (age1…, one per line), in which case the
// appliance can write backups but not read them.
func Recipients(passphrase, publicKeys string) ([]age.Recipient, error) {
	if strings.TrimSpace(publicKeys) != "" {
		r, err := age.ParseRecipients(strings.NewReader(publicKeys))
		if err != nil {
			return nil, fmt.Errorf("invalid public key: %w", err)
		}
		return r, nil
	}
	if len(passphrase) < MinPassphrase {
		return nil, fmt.Errorf("the passphrase must be at least %d characters", MinPassphrase)
	}
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	return []age.Recipient{r}, nil
}

// identities turns what the user typed to open a backup into age
// identities: a private key (AGE-SECRET-KEY-…, possibly a whole key file)
// or a passphrase.
func identities(secret string) ([]age.Identity, error) {
	// Keys are found anywhere in the text, so a key file pasted into a
	// single-line field (comments and all, line breaks lost) still works.
	if keys := ageKeyRE.FindAllString(secret, -1); len(keys) > 0 {
		ids, err := age.ParseIdentities(strings.NewReader(strings.Join(keys, "\n")))
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
		return ids, nil
	}
	id, err := age.NewScryptIdentity(secret)
	if err != nil {
		return nil, err
	}
	return []age.Identity{id}, nil
}

func (m *Manager) checkFlowSpace(includeFlows bool) error {
	if !includeFlows {
		return nil
	}
	size, err := m.FlowsSize(context.Background())
	if err != nil {
		return fmt.Errorf("could not size the flow history: %w", err)
	}
	if need := size*3/2 + 200<<20; FreeSpace(m.Dir) < need {
		return fmt.Errorf("not enough free disk space for a backup with flow history (about %d MB needed)", need>>20)
	}
	return nil
}

// StartBackup writes a new backup, encrypted with a passphrase, in the
// background.
func (m *Manager) StartBackup(passphrase string, includeFlows bool) error {
	rcpts, err := Recipients(passphrase, "")
	if err != nil {
		return err
	}
	if err := m.checkFlowSpace(includeFlows); err != nil {
		return err
	}
	if err := m.begin("backup"); err != nil {
		return err
	}
	go func() {
		_, err := m.backup(rcpts, includeFlows, false)
		m.finish(err)
	}()
	return nil
}

// RunScheduled writes a scheduled backup and waits for it; it returns
// ErrBusy if another job is running.
func (m *Manager) RunScheduled(rcpts []age.Recipient, includeFlows bool) (string, error) {
	if err := m.checkFlowSpace(includeFlows); err != nil {
		return "", err
	}
	if err := m.begin("backup"); err != nil {
		return "", err
	}
	name, err := m.backup(rcpts, includeFlows, true)
	m.finish(err)
	return name, err
}

func (m *Manager) backup(rcpts []age.Recipient, includeFlows, scheduled bool) (name string, err error) {
	ctx := context.Background()
	if err := os.MkdirAll(m.backupsDir(), 0o700); err != nil {
		return "", err
	}
	host, _ := os.Hostname()
	now := time.Now()
	name = fmt.Sprintf("tributary-%s-%s.tbk", safeName(host), now.Format("20060102-150405"))
	m.setJob(func(j *Job) { j.Name = name })
	man := Manifest{Format: Format, Version: m.Version, Created: now.UnixMilli(), Hostname: host, Scheduled: scheduled}

	m.phase("config")
	snap := filepath.Join(m.backupsDir(), ".config.db.snapshot")
	_ = os.Remove(snap)
	if err := m.Snapshot(snap); err != nil {
		return "", fmt.Errorf("could not snapshot the configuration: %w", err)
	}
	defer os.Remove(snap)
	type file struct{ entry, path string }
	var files []file
	for _, f := range configFiles {
		p := filepath.Join(m.Dir, f.file)
		if f.file == "config.db" {
			p = snap
		}
		if _, err := os.Stat(p); err != nil {
			if f.optional {
				continue
			}
			return "", fmt.Errorf("%s is missing", f.file)
		}
		files = append(files, file{f.entry, p})
		man.Files = append(man.Files, f.entry)
	}
	if includeFlows {
		for _, t := range flowTables {
			n, err := m.count(ctx, t)
			if err != nil {
				return "", err
			}
			man.Flows = append(man.Flows, TableInfo{Table: t, Rows: n})
		}
	}

	tmp := filepath.Join(m.backupsDir(), "."+name+".partial")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer func() {
		f.Close()
		if err != nil {
			os.Remove(tmp)
		}
	}()
	enc, err := age.Encrypt(&countingWriter{w: f, n: &m.bytes}, rcpts...)
	if err != nil {
		return "", err
	}
	zw, err := zstd.NewWriter(enc, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return "", err
	}
	ew, err := newEntryWriter(zw)
	if err != nil {
		return "", err
	}
	mb, _ := json.Marshal(man)
	if _, err := ew.add("manifest.json", strings.NewReader(string(mb))); err != nil {
		return "", err
	}
	for _, fl := range files {
		r, err := os.Open(fl.path)
		if err != nil {
			return "", err
		}
		_, err = ew.add(fl.entry, r)
		r.Close()
		if err != nil {
			return "", err
		}
	}
	for _, t := range man.Flows {
		m.phase("flows:" + t.Table)
		q := fmt.Sprintf("SELECT * FROM netflow.%s FORMAT Native", t.Table)
		if err := m.query(ctx, q, nil, func(r io.Reader) error {
			_, err := ew.add("flows/"+t.Table+".native", r)
			return err
		}); err != nil {
			return "", fmt.Errorf("exporting %s: %w", t.Table, err)
		}
	}
	m.phase("finishing")
	if err := ew.close(); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, filepath.Join(m.backupsDir(), name)); err != nil {
		return "", err
	}
	// An unencrypted summary for the list (no secrets in it).
	_ = os.WriteFile(filepath.Join(m.backupsDir(), name+".json"), mb, 0o600)
	m.Log.Info("backup written", "name", name, "flows", includeFlows, "scheduled", scheduled)
	return name, nil
}

// Upload stores an uploaded backup for inspection and restore.
func (m *Manager) Upload(r io.Reader, limit int64) (int64, error) {
	if !m.mu.TryLock() {
		return 0, errors.New("a backup or restore is running")
	}
	defer m.mu.Unlock()
	if err := os.MkdirAll(m.restoreDir(), 0o700); err != nil {
		return 0, err
	}
	tmp := m.uploadPath() + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, io.LimitReader(r, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = errors.New("the file is larger than the free disk space allows")
	}
	if err != nil {
		os.Remove(tmp)
		return 0, err
	}
	return n, os.Rename(tmp, m.uploadPath())
}

// open decrypts the uploaded backup and reads its manifest.
func (m *Manager) open(secret string) (*os.File, *entryReader, *Manifest, error) {
	f, err := os.Open(m.uploadPath())
	if err != nil {
		return nil, nil, nil, errors.New("upload a backup file first")
	}
	fail := func(err error) (*os.File, *entryReader, *Manifest, error) {
		f.Close()
		return nil, nil, nil, err
	}
	ids, err := identities(secret)
	if err != nil {
		return fail(err)
	}
	dec, err := age.Decrypt(f, ids...)
	if err != nil {
		return fail(errors.New("wrong passphrase or key, or not a Tributary backup"))
	}
	zr, err := zstd.NewReader(dec)
	if err != nil {
		return fail(err)
	}
	er, err := newEntryReader(zr)
	if err != nil {
		return fail(err)
	}
	name, r, err := er.next()
	if err != nil || name != "manifest.json" {
		return fail(errNotBackup)
	}
	var man Manifest
	if err := json.NewDecoder(io.LimitReader(r, 1<<20)).Decode(&man); err != nil {
		return fail(fmt.Errorf("unreadable manifest: %w", err))
	}
	if man.Format > Format {
		return fail(fmt.Errorf("this backup was made by a newer version of Tributary (%s); upgrade first", man.Version))
	}
	return f, er, &man, nil
}

// Inspect checks the passphrase and returns the uploaded backup's manifest.
func (m *Manager) Inspect(passphrase string) (*Manifest, error) {
	f, _, man, err := m.open(passphrase)
	if err != nil {
		return nil, err
	}
	f.Close()
	return man, nil
}

// StartRestore restores the uploaded backup in the background: the flow
// history right away (if chosen), the configuration at the next start, which
// restart triggers.
func (m *Manager) StartRestore(passphrase string, restoreFlows bool, restart func()) error {
	f, er, man, err := m.open(passphrase)
	if err != nil {
		return err
	}
	if restoreFlows && len(man.Flows) == 0 {
		f.Close()
		return errors.New("this backup has no flow history")
	}
	if err := m.begin("restore"); err != nil {
		f.Close()
		return err
	}
	go func() {
		err := m.restore(f, er, man, restoreFlows)
		f.Close()
		if err == nil {
			_ = os.Remove(m.uploadPath()) // can be large; no longer needed
			m.phase("restarting")
		}
		m.finish(err)
		if err == nil {
			m.Log.Info("restore staged; restarting to apply it")
			time.AfterFunc(1500*time.Millisecond, restart)
		}
	}()
	return nil
}

func (m *Manager) restore(f *os.File, er *entryReader, man *Manifest, restoreFlows bool) (err error) {
	ctx := context.Background()
	staged := StagedDir(m.Dir)
	if err := os.RemoveAll(staged); err != nil {
		return err
	}
	if err := os.MkdirAll(staged, 0o700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(staged)
		}
	}()
	modes := map[string]os.FileMode{}
	for _, c := range configFiles {
		modes[c.entry] = c.mode
	}
	got := map[string]bool{}
	flowsReady := false
	defer func() {
		if flowsReady {
			if aerr := m.exec(ctx, "ATTACH TABLE "+rollupView); aerr != nil && err == nil {
				err = fmt.Errorf("re-attaching the rollup view: %w", aerr)
			}
		}
	}()
	for {
		name, r, err := er.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch {
		case strings.HasPrefix(name, "config/"):
			mode, ok := modes[name]
			if !ok {
				continue // from a newer version; not ours to place
			}
			m.phase("config")
			if err := writeFile(filepath.Join(staged, strings.TrimPrefix(name, "config/")), io.TeeReader(r, &countingWriter{w: io.Discard, n: &m.bytes}), mode); err != nil {
				return err
			}
			got[name] = true
		case strings.HasPrefix(name, "flows/") && restoreFlows:
			table := strings.TrimSuffix(strings.TrimPrefix(name, "flows/"), ".native")
			if !contains(flowTables, table) {
				continue
			}
			if !flowsReady {
				m.phase("flows:prepare")
				if err := m.exec(ctx, "DETACH TABLE "+rollupView); err != nil {
					return fmt.Errorf("detaching the rollup view: %w", err)
				}
				flowsReady = true
				for _, t := range flowTables {
					if err := m.exec(ctx, "TRUNCATE TABLE netflow."+t); err != nil {
						return fmt.Errorf("clearing %s: %w", t, err)
					}
				}
			}
			m.phase("flows:" + table)
			body := io.TeeReader(r, &countingWriter{w: io.Discard, n: &m.bytes})
			if err := m.query(ctx, "INSERT INTO netflow."+table+" FORMAT Native", body, nil); err != nil {
				return fmt.Errorf("restoring %s: %w", table, err)
			}
		}
	}
	for _, c := range configFiles {
		if !c.optional && !got[c.entry] {
			return fmt.Errorf("the backup is missing %s", c.file)
		}
	}
	mb, _ := json.Marshal(man)
	// Written last: its presence tells the next start the staging is complete.
	return writeFile(filepath.Join(staged, "manifest.json"), strings.NewReader(string(mb)), 0o600)
}

// ApplyStaged moves a staged configuration into place. It runs at start-up,
// before the configuration database is opened. The replaced files are kept
// in restore/replaced-<time>. It reports whether a restore was applied.
func ApplyStaged(dataDir string, log *slog.Logger) (bool, error) {
	staged := StagedDir(dataDir)
	b, err := os.ReadFile(filepath.Join(staged, "manifest.json"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var man Manifest
	if err := json.Unmarshal(b, &man); err != nil {
		return false, err
	}
	keep := filepath.Join(dataDir, "restore", "replaced-"+time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(keep, 0o700); err != nil {
		return false, err
	}
	for _, c := range configFiles {
		src := filepath.Join(staged, c.file)
		dst := filepath.Join(dataDir, c.file)
		if _, err := os.Stat(dst); err == nil {
			if err := os.Rename(dst, filepath.Join(keep, c.file)); err != nil {
				return false, err
			}
		}
		if c.file == "config.db" {
			for _, ext := range []string{"-wal", "-shm"} {
				_ = os.Rename(dst+ext, filepath.Join(keep, c.file+ext))
			}
		}
		if _, err := os.Stat(src); err == nil {
			if err := os.Rename(src, dst); err != nil {
				return false, err
			}
		}
	}
	_ = os.RemoveAll(staged)
	log.Warn("restored the configuration from a backup", "created", time.UnixMilli(man.Created).Format(time.RFC3339),
		"host", man.Hostname, "version", man.Version, "replaced_files_kept_in", keep)
	return true, nil
}

// ---- ClickHouse HTTP ----

var httpClient = &http.Client{} // no overall timeout: exports can take a while

// query runs q, sending body (for INSERT) and passing the response to read.
func (m *Manager) query(ctx context.Context, q string, body io.Reader, read func(io.Reader) error) error {
	u := m.CH.URL + "/?" + url.Values{"query": {q}}.Encode()
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("X-ClickHouse-User", m.CH.User)
	req.Header.Set("X-ClickHouse-Key", m.CH.Password)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("ClickHouse: %s", strings.TrimSpace(string(msg)))
	}
	if read != nil {
		return read(resp.Body)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}

func (m *Manager) exec(ctx context.Context, q string) error {
	return m.query(ctx, q, strings.NewReader(""), nil)
}

func (m *Manager) count(ctx context.Context, table string) (uint64, error) {
	var n uint64
	err := m.query(ctx, "SELECT count() FROM netflow."+table, nil, func(r io.Reader) error {
		_, err := fmt.Fscan(r, &n)
		return err
	})
	return n, err
}

// ---- helpers ----

type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

func writeFile(path string, r io.Reader, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func safeName(s string) string {
	s = regexp.MustCompile(`[^A-Za-z0-9.-]+`).ReplaceAllString(s, "-")
	if s == "" {
		return "appliance"
	}
	return s
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ValidName reports whether name is a backup file name this appliance
// writes (and so may be managed or pruned).
func ValidName(name string) bool { return nameRE.MatchString(name) }

// IsOwn reports whether name is a backup made by this appliance (by host
// name and the exact timestamp format), so appliances sharing a destination
// never prune each other's backups, even when one host name is a prefix of
// another.
func IsOwn(name string) bool {
	host, _ := os.Hostname()
	return regexp.MustCompile(`^tributary-` + regexp.QuoteMeta(safeName(host)) + `-\d{8}-\d{6}\.tbk$`).MatchString(name)
}

// PruneScheduled deletes this appliance's scheduled backups beyond the
// newest keep. Backups made by hand are never pruned.
func (m *Manager) PruneScheduled(keep int) ([]string, error) {
	list, err := m.List()
	if err != nil {
		return nil, err
	}
	var gone []string
	n := 0
	for _, b := range list { // newest first
		if !b.Scheduled {
			continue
		}
		if n++; n <= keep {
			continue
		}
		if err := m.Delete(b.Name); err != nil {
			return gone, err
		}
		gone = append(gone, b.Name)
	}
	return gone, nil
}
