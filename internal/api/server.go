// Package api exposes the appliance REST API and serves the web UI.
package api

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nfa/internal/backup"
	"nfa/internal/certs"
	"nfa/internal/collector"
	"nfa/internal/config"
	"nfa/internal/enrich"
	"nfa/internal/store"
	"nfa/internal/syslog"
	"nfa/internal/system"
)

type Server struct {
	Log           *slog.Logger
	Config        *config.DB
	Store         *store.Store
	Writer        *store.Writer
	Collector     *collector.Collector
	Geo           *enrich.Geo
	Vendors       *enrich.VendorDB
	RDNS          *enrich.Resolver
	System        *system.Manager
	Certs         *certs.Manager
	Trust         *certs.TrustStore
	UI            fs.FS
	Version       string
	SourceURL     string
	SecureCookies bool
	// ApplySettings pushes new settings to the collector and database.
	ApplySettings func(ctx context.Context, old, new config.Settings) error

	started time.Time

	Backups *backup.Manager
	Syslog  *syslog.Forwarder
	// Restart stops the process so systemd starts it again (to apply a restore).
	Restart func()
	// DataDir is the appliance's data directory (disk checks, initial password).
	DataDir      string
	notices      atomic.Pointer[[]Notice]
	prevDropped  atomic.Uint64
	prevRejected atomic.Uint64
	noticeRuns   atomic.Int64
	limiter      loginLimiter
	sso          ssoState
}

const cookieName = "nfa_session"

type ctxKey struct{}

func userFrom(r *http.Request) *config.User {
	u, _ := r.Context().Value(ctxKey{}).(*config.User)
	return u
}

func (s *Server) Handler() http.Handler {
	s.started = time.Now()
	s.limiter.m = map[string][]time.Time{}
	s.sso.pending = map[string]ssoPending{}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /api/public/info", s.publicInfo)
	mux.HandleFunc("POST /api/auth/login", s.login)
	mux.HandleFunc("POST /api/auth/logout", s.logout)
	mux.HandleFunc("GET /api/auth/sso/{id}/start", s.ssoStart)
	mux.HandleFunc("GET /api/auth/sso/{id}/callback", s.ssoCallback)

	auth := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(h, false)) }
	admin := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(h, true)) }

	auth("GET /api/auth/me", s.me)
	auth("POST /api/auth/password", s.changePassword)
	auth("GET /api/meta", s.meta)
	auth("GET /api/summary", s.summary)
	auth("GET /api/timeseries", s.timeseries)
	auth("GET /api/top", s.top)
	auth("GET /api/flows", s.flows)
	auth("GET /api/paths", s.paths)
	auth("GET /api/flows.csv", s.flowsCSV)
	auth("GET /api/exporters", s.exporters)
	auth("GET /api/devices", s.devicesList)
	auth("GET /api/exporters/{addr}/interfaces", s.interfaces)
	auth("GET /api/system", s.system)
	auth("GET /api/settings", s.getSettings)
	auth("GET /api/storage-estimate", s.storageEstimate)

	admin("PUT /api/exporters/{addr}", s.updateExporter)
	admin("DELETE /api/exporters/{addr}", s.deleteExporter)
	admin("PUT /api/devices/{mac}", s.deviceRename)
	admin("PUT /api/exporters/{addr}/interfaces/{idx}", s.updateInterface)
	admin("PUT /api/settings", s.putSettings)
	admin("GET /api/users", s.listUsers)
	admin("POST /api/users", s.createUser)
	admin("PUT /api/users/{name}", s.updateUser)
	admin("DELETE /api/users/{name}", s.deleteUser)
	admin("GET /api/audit", s.audit)
	admin("GET /api/certificates/appliance", s.certStatus)
	admin("GET /api/certificates/appliance/download", s.certDownload)
	admin("POST /api/certificates/appliance/upload", s.certUpload)
	admin("POST /api/certificates/appliance/csr", s.certCSR)
	admin("DELETE /api/certificates/appliance/csr", s.certCSRDiscard)
	admin("POST /api/certificates/appliance/self-signed", s.certSelfSigned)
	admin("POST /api/certificates/appliance/restore", s.certRestore)
	admin("GET /api/certificates/trusted", s.trustedList)
	admin("POST /api/certificates/trusted", s.trustedAdd)
	admin("DELETE /api/certificates/trusted/{id}", s.trustedDelete)
	admin("GET /api/identity-sources", s.identitySources)
	admin("GET /api/identity-sources/{id}", s.identitySourceGet)
	admin("POST /api/identity-sources", s.identitySourceSave)
	admin("PUT /api/identity-sources/{id}", s.identitySourceSave)
	admin("DELETE /api/identity-sources/{id}", s.identitySourceDelete)
	admin("POST /api/identity-sources/test", s.identitySourceTest)
	auth("GET /api/geo", s.geoStatus)
	auth("GET /api/notices", s.noticesList)
	admin("GET /api/syslog", s.syslogGet)
	admin("PUT /api/syslog", s.syslogPut)
	admin("POST /api/syslog/test", s.syslogTest)
	admin("GET /api/backups", s.backupsList)
	admin("POST /api/backups", s.backupCreate)
	admin("GET /api/backups/{name}", s.backupDownload)
	admin("DELETE /api/backups/{name}", s.backupDelete)
	admin("POST "+uploadPath, s.restoreUpload)
	admin("POST /api/restore/inspect", s.restoreInspect)
	admin("POST /api/restore", s.restoreApply)
	auth("GET /api/local-suggestions", s.localSuggestions)
	admin("POST /api/geo/update", s.geoUpdate)
	admin("POST /api/oui/update", s.ouiUpdate)
	admin("GET /api/enrichment", s.enrichmentGet)
	admin("PUT /api/enrichment", s.enrichmentPut)
	admin("GET /api/updates", s.updatesStatus)
	admin("GET /api/updates/log", s.updatesLog)
	admin("POST /api/updates", s.updatesRequest)
	admin("GET /api/time", s.timeStatus)
	admin("GET /api/time/zones", s.timeZones)
	admin("PUT /api/time", s.timeSet)
	admin("GET /api/services", s.servicesList)
	admin("POST /api/services/{unit}/{op}", s.serviceAction)
	admin("GET /api/admin/result/{id}", s.adminResult)

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeErr(w, http.StatusNotFound, "not found") })
	mux.Handle("/", s.spa())

	return s.middleware(mux)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		if s.SecureCookies {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		// State-changing API calls must be JSON: browsers cannot send that
		// cross-site without a CORS preflight, which we never grant.
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != http.MethodGet && r.Method != http.MethodHead {
			raw := r.URL.Path == uploadPath && r.Header.Get("Content-Type") == "application/octet-stream"
			if r.ContentLength != 0 && !raw && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				writeErr(w, http.StatusUnsupportedMediaType, "content type must be application/json")
				return
			}
			if r.Header.Get("X-Requested-With") != "nfa" {
				writeErr(w, http.StatusForbidden, "missing X-Requested-With header")
				return
			}
		}
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			s.Log.Debug("http", "method", r.Method, "path", r.URL.Path, "status", sw.status, "dur", time.Since(start))
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) requireUser(next http.HandlerFunc, adminOnly bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		u, err := s.Config.SessionUser(c.Value)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "session expired")
			return
		}
		if adminOnly && u.Role != "admin" {
			writeErr(w, http.StatusForbidden, "administrator role required")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	})
}

func (s *Server) spa() http.Handler {
	locales := uiLocales(s.UI)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ui := s.UI
		if loc := pickLocale(r, locales); loc != "" {
			ui, _ = fs.Sub(s.UI, loc)
			w.Header().Add("Vary", "Cookie, Accept-Language")
		}
		if ui == nil {
			http.Error(w, "The web UI was not built into this binary. Run `make web build`.", http.StatusServiceUnavailable)
			return
		}
		if _, err := fs.Stat(ui, "index.html"); err != nil {
			http.Error(w, "The web UI was not built into this binary. Run `make web build`.", http.StatusServiceUnavailable)
			return
		}
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(ui, p); err != nil {
			if _, err := fs.Stat(s.UI, p); err == nil && p != "index.html" {
				// Shared files at the build root (3rdpartylicenses.txt).
				ui = s.UI
			} else {
				// Client-side route: serve the app shell.
				r = r.Clone(r.Context())
				r.URL.Path = "/"
				p = "index.html"
			}
		}
		if p == "index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		} else if strings.Contains(p, "-") && (strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".css")) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files := http.FileServerFS(ui)
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && compressible(p) {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Add("Vary", "Accept-Encoding")
			gz := gzip.NewWriter(w)
			defer gz.Close()
			files.ServeHTTP(&gzipWriter{ResponseWriter: w, w: gz}, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}

func compressible(p string) bool {
	for _, ext := range []string{".js", ".css", ".html", ".svg", ".txt", ".json"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

type gzipWriter struct {
	http.ResponseWriter
	w io.Writer
}

func (g *gzipWriter) Write(b []byte) (int, error) { return g.w.Write(b) }

func (g *gzipWriter) WriteHeader(code int) {
	g.ResponseWriter.Header().Del("Content-Length")
	g.ResponseWriter.WriteHeader(code)
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid request body: " + err.Error())
	}
	return nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loginLimiter allows 10 failed logins per client address per 5 minutes.
type loginLimiter struct {
	mu sync.Mutex
	m  map[string][]time.Time
}

const (
	loginWindow   = 5 * time.Minute
	loginFailures = 10
)

func (l *loginLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := time.Now().Add(-loginWindow)
	ts := l.m[ip]
	i := 0
	for i < len(ts) && ts[i].Before(cut) {
		i++
	}
	l.m[ip] = ts[i:]
	if len(l.m[ip]) == 0 {
		delete(l.m, ip)
	}
	return len(ts)-i >= loginFailures
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	l.m[ip] = append(l.m[ip], time.Now())
	l.mu.Unlock()
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	delete(l.m, ip)
	l.mu.Unlock()
}
