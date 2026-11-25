// Command ncc is the Network Control Centre server.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dertown/network-control-centre/internal/api"
	"github.com/dertown/network-control-centre/internal/assistant"
	"github.com/dertown/network-control-centre/internal/audit"
	"github.com/dertown/network-control-centre/internal/auth"
	"github.com/dertown/network-control-centre/internal/certdeploy"
	"github.com/dertown/network-control-centre/internal/config"
	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/dnslog"
	"github.com/dertown/network-control-centre/internal/pki"
	"github.com/dertown/network-control-centre/internal/siem"
	"github.com/dertown/network-control-centre/internal/store"
	"github.com/dertown/network-control-centre/internal/vault"
	"github.com/dertown/network-control-centre/web"

	// drivers and providers register themselves
	_ "github.com/dertown/network-control-centre/internal/dns/azuredns"
	_ "github.com/dertown/network-control-centre/internal/dns/bind"
	_ "github.com/dertown/network-control-centre/internal/dns/powerdns"
	_ "github.com/dertown/network-control-centre/internal/dns/windowsdns"
	_ "github.com/dertown/network-control-centre/internal/drivers/snmpnet"
	_ "github.com/dertown/network-control-centre/internal/drivers/unifi"
	_ "github.com/dertown/network-control-centre/internal/hypervisor/hyperv"
	_ "github.com/dertown/network-control-centre/internal/hypervisor/proxmox"
	_ "github.com/dertown/network-control-centre/internal/hypervisor/vmware"
	_ "github.com/dertown/network-control-centre/internal/siem/elastic"
	_ "github.com/dertown/network-control-centre/internal/siem/graylog"
	_ "github.com/dertown/network-control-centre/internal/siem/sentinel"
	_ "github.com/dertown/network-control-centre/internal/siem/splunk"
	_ "github.com/dertown/network-control-centre/internal/siem/syslog"
	_ "github.com/dertown/network-control-centre/internal/smarthome/homeassistant"
	_ "github.com/dertown/network-control-centre/internal/storage/nfs"
	_ "github.com/dertown/network-control-centre/internal/storage/qnap"
	_ "github.com/dertown/network-control-centre/internal/storage/smb"
	_ "github.com/dertown/network-control-centre/internal/storage/snmpnas"
	_ "github.com/dertown/network-control-centre/internal/storage/synology"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		// for container health checks (the image has no shell or curl)
		os.Exit(healthcheck(os.Getenv("NCC_CONFIG")))
	}
	cfgPath := flag.String("config", os.Getenv("NCC_CONFIG"), "path to config.yaml")
	checkOnly := flag.Bool("check-config", false, "check the configuration file and exit")
	flag.Parse()
	cfg, warnings, err := config.Load(*cfgPath)
	log := newLogger(cfg.Log)
	for _, w := range warnings {
		log.Warn(w)
	}
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
	if *checkOnly {
		fmt.Println("config OK")
		return
	}
	if err := run(log, cfg); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// newLogger builds NCC's log: text (default) or JSON lines, at the configured level.
func newLogger(c config.LogConfig) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(c.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if strings.EqualFold(c.Format, "json") {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// healthcheck asks the local server whether it is ready; 0 means yes.
func healthcheck(cfgPath string) int {
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_, port, _ := net.SplitHostPort(cfg.Listen)
	scheme := "https"
	if cfg.PlainHTTP {
		scheme = "http"
	}
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		// our own server on loopback, usually with its self-signed certificate
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}}
	resp, err := hc.Get(scheme + "://127.0.0.1:" + port + "/api/ready")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "not ready:", resp.Status)
		return 1
	}
	return 0
}

func buildVault(cfg config.Config, st *store.Store) (vault.Store, error) {
	switch cfg.Vault.Backend {
	case "local":
		return vault.NewLocal(st.DB), nil
	case "hashicorp":
		return vault.NewHashiCorp(vault.HashiCorpOptions{
			Address: cfg.Vault.Address, Mount: cfg.Vault.Mount, Prefix: cfg.Vault.Prefix,
			Namespace: cfg.Vault.Namespace, Token: cfg.Vault.Token,
			RoleID: cfg.Vault.RoleID, SecretID: cfg.Vault.SecretID, CACertFile: cfg.Vault.CACert,
		})
	default:
		return nil, fmt.Errorf("unknown vault backend %q (use local or hashicorp)", cfg.Vault.Backend)
	}
}

func run(log *slog.Logger, cfg config.Config) error {
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	vs, err := buildVault(cfg, st)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Unattended unseal for the local vault.
	if u, ok := vs.(vault.Unsealer); ok {
		pass := os.Getenv("NCC_VAULT_PASSPHRASE")
		if pass == "" && cfg.Vault.PassphraseFile != "" {
			b, err := os.ReadFile(cfg.Vault.PassphraseFile)
			if err != nil {
				return fmt.Errorf("read vault passphrase file: %w", err)
			}
			pass = strings.TrimSpace(string(b))
		}
		if pass != "" && vs.Status(ctx).Initialized {
			if err := u.Unseal(ctx, pass); err != nil {
				return fmt.Errorf("unseal vault: %w", err)
			}
			log.Info("local vault unsealed from passphrase file/env")
		}
	}

	hub := core.NewHub()
	targets := &core.Targets{DB: st.DB}
	traffic := &core.Traffic{DB: st.DB}
	poller := &core.Poller{DB: st.DB, Targets: targets, Vault: vs, Hub: hub, Interval: cfg.Poll, Log: log, Traffic: traffic}
	var dnsLog *dnslog.Collector
	if cfg.DNSLog.Listen != "" {
		allow, err := config.ParsePrefixes(cfg.DNSLog.Allow)
		if err != nil {
			return err
		}
		dnsLog = &dnslog.Collector{DB: st.DB, Allow: allow, Retain: cfg.DNSLog.Retain, Log: log}
		go func() {
			if err := dnsLog.Serve(ctx, cfg.DNSLog.Listen); err != nil {
				log.Error("dns log receiver stopped", "err", err)
			}
		}()
		log.Info("DNS query log receiver listening", "addr", cfg.DNSLog.Listen, "allow", cfg.DNSLog.Allow)
	}
	authSvc := auth.New(st.DB)
	authSvc.SessionTTL = cfg.SessionTTL
	proxies, err := config.ParsePrefixes(cfg.TrustedProxies)
	if err != nil {
		return err
	}
	metricsToken := ""
	if cfg.Metrics.TokenFile != "" {
		b, err := os.ReadFile(cfg.Metrics.TokenFile)
		if err != nil {
			return fmt.Errorf("metrics.token_file: %w", err)
		}
		metricsToken = strings.TrimSpace(string(b))
	}
	auditLog := audit.New(st.DB)
	certs := &pki.Inventory{DB: st.DB, Vault: vs}
	deploy := &certdeploy.Service{DB: st.DB, Vault: vs, Certs: certs, Audit: auditLog}
	deploy.MarkInterrupted(ctx)
	// the AI tools NCC installs itself go in its own data folder (absolute: the tools run in
	// other working folders)
	toolsDir, err := filepath.Abs(filepath.Join(cfg.DataDir, "ai-tools"))
	if err != nil {
		toolsDir = ""
	}
	srv := &api.Server{
		Store: st, Auth: authSvc, Audit: auditLog, Vault: vs, Targets: targets,
		Poller: poller, Hub: hub, Certs: certs, Deploy: deploy,
		Traffic: traffic, DNSLog: dnsLog,
		Assistant: &assistant.Service{DB: st.DB, Vault: vs, ToolsDir: toolsDir},
		UI:        web.UI(), Log: log, SecureCookies: !cfg.PlainHTTP || cfg.BehindTLSProxy,
		TrustedProxies: proxies, Version: version, MetricsEnabled: cfg.Metrics.Enabled, MetricsToken: metricsToken,
	}
	poller.Observe = srv.ObservePoll
	siem.Version = version
	srv.SIEM = &core.SIEMForwarder{DB: st.DB, Targets: targets, Vault: vs, Log: log}

	go poller.Run(ctx)
	go srv.SIEM.Run(ctx)
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				authSvc.PurgeExpired(ctx)
			}
		}
	}()

	hs := &http.Server{
		Addr: cfg.Listen, Handler: srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	log.Info("NCC listening", "addr", cfg.Listen, "vault", vs.Backend(), "https", !cfg.PlainHTTP, "version", version)
	if !cfg.PlainHTTP {
		cert, key := cfg.TLSCert, cfg.TLSKey
		if cert == "" {
			if cert, key, err = selfSignedTLS(cfg.DataDir); err != nil {
				return err
			}
			log.Info("serving HTTPS with a self-signed certificate; set tls_cert/tls_key to use your own", "cert", cert)
		}
		hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		err = hs.ListenAndServeTLS(cert, key)
	} else {
		err = hs.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
