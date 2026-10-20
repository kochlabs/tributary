// Command nfad is the NetFlow appliance daemon: flow collector, storage
// writer, REST API and web UI in one process.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"nfa/internal/api"
	"nfa/internal/backup"
	"nfa/internal/certs"
	"nfa/internal/collector"
	"nfa/internal/config"
	"nfa/internal/enrich"
	"nfa/internal/flow"
	"nfa/internal/snmp"
	"nfa/internal/store"
	"nfa/internal/syslog"
	"nfa/internal/system"
	"nfa/internal/webui"
)

var version = "dev"

// sourceURL is where users of this build can get its source code, which the
// AGPL requires offering to network users (override with -ldflags -X).
var sourceURL = "https://git.kochlabs.io/dkoch/tributary"

func main() {
	var (
		listen     = flag.String("listen", ":8443", "HTTPS listen address for UI and API")
		plainHTTP  = flag.Bool("http", false, "serve plain HTTP instead of HTTPS (only behind a TLS-terminating proxy)")
		redirect   = flag.String("redirect-http", "", "also listen on this address (e.g. :80) and redirect plain HTTP to HTTPS")
		dataDir    = flag.String("data", "/var/lib/nfa", "directory for configuration database and TLS material")
		chAddr     = flag.String("ch-addr", "127.0.0.1:9000", "ClickHouse native protocol address")
		chHTTP     = flag.String("ch-http-addr", "127.0.0.1:8123", "ClickHouse HTTP address (used to back up and restore flow history)")
		chUser     = flag.String("ch-user", "netflow", "ClickHouse user")
		chPassFile = flag.String("ch-password-file", "/etc/netflow/clickhouse.pw", "file containing the ClickHouse password")
		logLevel   = flag.String("log-level", "info", "debug, info, warn or error")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Println(version)
		return
	}
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(*logLevel))
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	if err := run(log, *listen, *plainHTTP, *redirect, *dataDir, *chAddr, *chHTTP, *chUser, *chPassFile); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, listen string, plainHTTP bool, redirect, dataDir, chAddr, chHTTP, chUser, chPassFile string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return err
	}
	// A restore stages the configuration and restarts; apply it before the
	// database is opened.
	restored, err := backup.ApplyStaged(dataDir, log)
	if err != nil {
		log.Error("could not apply the restored configuration; starting with the current one", "err", err)
	}
	cfg, err := config.Open(filepath.Join(dataDir, "config.db"))
	if err != nil {
		return err
	}
	defer cfg.Close()
	if restored {
		// Sessions from the backup's appliance mean nothing here.
		_ = cfg.DeleteAllSessions()
	}
	if err := bootstrapAdmin(log, cfg, dataDir); err != nil {
		return err
	}
	settings := cfg.Settings()

	pw, err := os.ReadFile(chPassFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read clickhouse password: %w", err)
	}
	var st *store.Store
	for attempt := 1; ; attempt++ {
		octx, cancel := context.WithTimeout(ctx, 10*time.Second)
		st, err = store.Open(octx, store.Options{Addr: chAddr, User: chUser, Password: strings.TrimSpace(string(pw))})
		cancel()
		if err == nil {
			break
		}
		if attempt >= 30 || ctx.Err() != nil {
			return err
		}
		log.Warn("waiting for clickhouse", "err", err)
		time.Sleep(2 * time.Second)
	}
	defer st.Close()
	if err := st.Migrate(ctx, store.Retention{RawDays: settings.RawRetentionDays, RollupDays: settings.RollupRetentionDays}); err != nil {
		return err
	}

	// HTTPS certificate in <data>/tls.crt, managed from the UI and swapped
	// without a restart; trusted CAs apply to outbound TLS (identity providers).
	certMgr := certs.NewManager(dataDir)
	if created, err := certMgr.Load(); err != nil {
		return fmt.Errorf("TLS certificate: %w", err)
	} else if created {
		log.Info("generated self-signed TLS certificate", "dir", dataDir)
	}
	trust := certs.NewTrustStore()
	// Audit entries also go to syslog when forwarding is configured.
	fwd := syslog.New(log, trust.Pool)
	fwd.SetConfig(cfg.Syslog())
	cfg.OnAudit = func(e config.AuditEntry) { fwd.Send(syslog.FromAudit(e)) }
	go fwd.Run(ctx)
	poller := snmp.New(cfg, log)
	go poller.Run(ctx)

	writer := st.NewWriter(log)
	writerDone := make(chan struct{})
	wctx, wcancel := context.WithCancel(context.Background())
	go func() { writer.Run(wctx); close(writerDone) }()

	geo := enrich.NewGeo(filepath.Join(dataDir, "geoip"), log)
	geo.Online = enrich.NewASNLookup()
	geo.Online.Enabled.Store(settings.OnlineASNLookup)
	asnCache := filepath.Join(dataDir, "geoip", "asn-online.json")
	_ = geo.Online.Load(asnCache) // before collectors start, so labels and ingest use it
	go geo.Online.Persist(ctx, asnCache, 5*time.Minute)
	geo.SetLocalNetworks(settings.LocalPrefixes())
	store.SetLocalNetworks(settings.LocalPrefixes())
	enrich.UserAgent = "Tributary/" + version
	sources := cfg.Enrichment()
	geo.SetSource(sources)
	if err := geo.Load(); err != nil {
		log.Warn("geoip databases could not be loaded", "err", err)
	}
	autoUpdate := func() bool { return cfg.Enrichment().AutoUpdate }
	go geo.AutoUpdate(ctx, autoUpdate)
	vendors := enrich.NewVendorDB(filepath.Join(dataDir, "oui"), log)
	vendors.SetSource(sources)
	if err := vendors.Load(); err != nil {
		log.Warn("vendor database could not be loaded", "err", err)
	}
	go vendors.AutoUpdate(ctx, autoUpdate)
	enrich.SetDNSServers(settings.DNSServers)
	rdns := enrich.NewResolver()
	rdns.Enabled.Store(settings.ReverseDNS)

	// Device identity: learn local IP→MAC bindings and attribute flows to
	// devices; bindings persist across restarts.
	saved := map[netip.Addr]collector.IPBinding{}
	if list, err := cfg.DeviceIPs(); err == nil {
		for _, d := range list {
			if a, err := netip.ParseAddr(d.IP); err == nil {
				saved[a] = collector.IPBinding{MAC: d.MAC, Seen: d.Seen}
			}
		}
	}
	devices := collector.NewDeviceTracker(geo.IsLocal, saved)
	saveDevices := func() {
		dirty := devices.Dirty()
		list := make([]config.DeviceIP, 0, len(dirty))
		for ip, b := range dirty {
			list = append(list, config.DeviceIP{IP: ip.String(), MAC: b.MAC, Seen: b.Seen})
		}
		if err := cfg.SaveDeviceIPs(list); err != nil {
			log.Warn("saving device bindings failed", "err", err)
		}
	}
	defer saveDevices()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				saveDevices()
			}
		}
	}()

	col := collector.New(log, collector.Hooks{
		Sink:             writer.Submit,
		NewExporter:      cfg.SeenExporter,
		SamplingOverride: cfg.SamplingOverride,
		Enrich: func(r *flow.Record) {
			geo.Enrich(r)
			devices.Assign(r)
		},
		InterfaceName:   cfg.LearnInterface,
		LearnedSampling: cfg.SetLearnedSampling,
		SeedSampling:    cfg.LearnedSampling,
	})
	col.SetAllowedSources(settings.AllowedExporterPrefixes()) // before listening, so nothing slips through
	if err := col.Start(collector.Ports{NetFlow: settings.NetFlowPort, IPFIX: settings.IPFIXPort, SFlow: settings.SFlowPort}); err != nil {
		log.Error("collector listener failed", "err", err)
	}

	srv := &api.Server{
		Log: log, Config: cfg, Store: st, Writer: writer, Collector: col, Geo: geo, Vendors: vendors, RDNS: rdns, DataDir: dataDir, Restart: stop, Syslog: fwd, SNMP: poller,
		Backups: &backup.Manager{Dir: dataDir, Version: version, Log: log, Snapshot: cfg.Snapshot,
			CH: backup.ClickHouse{URL: "http://" + chHTTP, User: chUser, Password: strings.TrimSpace(string(pw))}}, System: system.New(), Certs: certMgr, Trust: trust, UI: webui.FS(), Version: version, SourceURL: sourceURL, SecureCookies: !plainHTTP,
		ApplySettings: func(ctx context.Context, old, ns config.Settings) error {
			var errs []error
			rdns.Enabled.Store(ns.ReverseDNS)
			enrich.SetDNSServers(ns.DNSServers)
			geo.Online.Enabled.Store(ns.OnlineASNLookup)
			geo.SetLocalNetworks(ns.LocalPrefixes())
			store.SetLocalNetworks(ns.LocalPrefixes())
			col.SetAllowedSources(ns.AllowedExporterPrefixes())
			if old.NetFlowPort != ns.NetFlowPort || old.IPFIXPort != ns.IPFIXPort || old.SFlowPort != ns.SFlowPort {
				errs = append(errs, col.Start(collector.Ports{NetFlow: ns.NetFlowPort, IPFIX: ns.IPFIXPort, SFlow: ns.SFlowPort}))
			}
			if old.RawRetentionDays != ns.RawRetentionDays || old.RollupRetentionDays != ns.RollupRetentionDays {
				errs = append(errs, st.SetRetention(ctx, store.Retention{RawDays: ns.RawRetentionDays, RollupDays: ns.RollupRetentionDays}))
			}
			return errors.Join(errs...)
		},
	}
	if err := srv.ReloadTrust(); err != nil {
		log.Warn("trusted CAs could not be loaded", "err", err)
	}
	httpSrv := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certMgr.GetCertificate},
	}
	go srv.RunNotices(ctx)

	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				cfg.PurgeSessions()
			}
		}
	}()

	errc := make(chan error, 1)
	go func() {
		if plainHTTP {
			log.Info("web UI listening (plain HTTP)", "addr", listen)
			errc <- httpSrv.ListenAndServe()
			return
		}
		log.Info("web UI listening (HTTPS)", "addr", listen)
		errc <- httpSrv.ListenAndServeTLS("", "") // certificate comes from TLSConfig.GetCertificate
	}()
	var redirectSrv *http.Server
	if redirect != "" && !plainHTTP {
		redirectSrv = &http.Server{Addr: redirect, Handler: api.RedirectToHTTPS(listen), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
		go func() {
			log.Info("redirecting plain HTTP to HTTPS", "addr", redirect)
			if err := redirectSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				// Not fatal: the UI still works over HTTPS.
				log.Warn("HTTP redirect listener failed", "addr", redirect, "err", err)
			}
		}()
	}

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			col.Stop()
			wcancel()
			<-writerDone
			return err
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(sctx)
	if redirectSrv != nil {
		_ = redirectSrv.Shutdown(sctx)
	}
	col.Stop()
	wcancel()
	<-writerDone
	return nil
}

// bootstrapAdmin creates the initial administrator when no users exist. The
// password comes from NFA_ADMIN_PASSWORD or is generated and written to
// <data>/initial-admin-password (mode 0600).
func bootstrapAdmin(log *slog.Logger, cfg *config.DB, dataDir string) error {
	n, err := cfg.UserCount()
	if err != nil || n > 0 {
		return err
	}
	pw := os.Getenv("NFA_ADMIN_PASSWORD")
	if pw == "" {
		b := make([]byte, 9)
		_, _ = rand.Read(b)
		pw = hex.EncodeToString(b)
	}
	if err := cfg.CreateUser(config.User{Username: "admin", Role: "admin", FullName: "Administrator"}, pw); err != nil {
		return err
	}
	path := filepath.Join(dataDir, "initial-admin-password")
	if err := os.WriteFile(path, []byte(pw+"\n"), 0o600); err != nil {
		return err
	}
	log.Warn("created initial administrator account", "username", "admin", "password_file", path)
	return nil
}
