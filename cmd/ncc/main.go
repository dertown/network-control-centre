// Command ncc is the Network Control Centre server.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dertown/network-control-centre/internal/api"
	"github.com/dertown/network-control-centre/internal/audit"
	"github.com/dertown/network-control-centre/internal/auth"
	"github.com/dertown/network-control-centre/internal/config"
	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/dnslog"
	"github.com/dertown/network-control-centre/internal/pki"
	"github.com/dertown/network-control-centre/internal/store"
	"github.com/dertown/network-control-centre/internal/vault"
	"github.com/dertown/network-control-centre/web"

	// drivers and providers register themselves
	_ "github.com/dertown/network-control-centre/internal/dns/powerdns"
	_ "github.com/dertown/network-control-centre/internal/drivers/unifi"
)

var version = "dev"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	cfgPath := flag.String("config", os.Getenv("NCC_CONFIG"), "path to config.yaml")
	flag.Parse()
	if err := run(log, *cfgPath); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
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

func run(log *slog.Logger, cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
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
		allow, err := parseAllow(cfg.DNSLog.Allow)
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
	srv := &api.Server{
		Store: st, Auth: authSvc, Audit: audit.New(st.DB), Vault: vs, Targets: targets,
		Poller: poller, Hub: hub, Certs: &pki.Inventory{DB: st.DB, Vault: vs},
		Traffic: traffic, DNSLog: dnsLog,
		UI: web.UI(), Log: log, SecureCookies: !cfg.PlainHTTP || cfg.BehindTLSProxy,
	}

	go poller.Run(ctx)
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

// parseAllow reads dns_log.allow: plain addresses or CIDR prefixes.
func parseAllow(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range in {
		s = strings.TrimSpace(s)
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("dns_log.allow: %q is not an address or CIDR", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
