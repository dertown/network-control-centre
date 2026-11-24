// Package config loads the NCC configuration file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level NCC configuration.
type Config struct {
	Listen         string        `yaml:"listen"`           // e.g. ":8443"
	DataDir        string        `yaml:"data_dir"`         // database and local vault live here
	TLSCert        string        `yaml:"tls_cert"`         // optional; when empty NCC makes a self-signed certificate in data_dir
	TLSKey         string        `yaml:"tls_key"`          //
	Poll           time.Duration `yaml:"poll"`             // device poll interval, default 30s
	Vault          VaultConfig   `yaml:"vault"`            //
	PlainHTTP      bool          `yaml:"plain_http"`       // serve plain HTTP, e.g. behind a reverse proxy that terminates HTTPS
	BehindTLSProxy bool          `yaml:"behind_tls_proxy"` // with plain_http: the proxy uses HTTPS, so cookies still get the Secure flag
	DNSLog         DNSLogConfig  `yaml:"dns_log"`          // optional DNS query log receiver

	// Log sets the format and level of NCC's own log (stderr).
	Log LogConfig `yaml:"log"`
	// SessionTTL is how long a sign-in lasts, default 12h.
	SessionTTL time.Duration `yaml:"session_ttl"`
	// TrustedProxies are the reverse proxies (addresses or CIDRs) whose X-Forwarded-For header
	// NCC believes, so the login rate limit, the access log and the audit log see the real
	// client address instead of the proxy's.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// Metrics serves Prometheus metrics at /metrics.
	Metrics MetricsConfig `yaml:"metrics"`
}

// LogConfig is NCC's own logging.
type LogConfig struct {
	Format string `yaml:"format"` // text (default) or json
	Level  string `yaml:"level"`  // debug, info (default), warn or error
}

// MetricsConfig turns on the Prometheus endpoint.
type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
	// TokenFile holds a bearer token scrapers must send (Authorization: Bearer ...). Without
	// one /metrics is open to anyone who can reach NCC; it holds counts, never names or secrets.
	TokenFile string `yaml:"token_file"`
}

// DNSLogConfig turns on the receiver for PowerDNS Recursor / dnsdist protobuf query logs.
type DNSLogConfig struct {
	Listen string        `yaml:"listen"` // e.g. ":4242"; empty turns the receiver off
	Allow  []string      `yaml:"allow"`  // resolver addresses or CIDRs allowed to send logs
	Retain time.Duration `yaml:"retain"` // default 7 days
}

// VaultConfig picks the secret backend.
type VaultConfig struct {
	Backend string `yaml:"backend"` // "local" (default) or "hashicorp"

	// Local backend: optional file holding the unseal passphrase for unattended starts.
	PassphraseFile string `yaml:"passphrase_file"`

	// HashiCorp backend.
	Address  string `yaml:"address"`   // https://vault.example:8200
	Mount    string `yaml:"mount"`     // KV v2 mount, default "secret"
	Prefix   string `yaml:"prefix"`    // path prefix inside the mount, default "ncc"
	Token    string `yaml:"token"`     // static token, or use AppRole below
	RoleID   string `yaml:"role_id"`   //
	SecretID string `yaml:"secret_id"` //
	// TokenFile and SecretIDFile read the token or AppRole secret id from a file (a Docker or
	// Kubernetes secret, a systemd credential) instead of keeping it in this file.
	TokenFile    string `yaml:"token_file"`
	SecretIDFile string `yaml:"secret_id_file"`
	CACert       string `yaml:"ca_cert"`   // optional PEM bundle to trust
	Namespace    string `yaml:"namespace"` // Vault Enterprise namespace
}

// Default returns a config with sensible defaults.
func Default() Config {
	return Config{
		Listen:     ":8443",
		DataDir:    "./data",
		Poll:       30 * time.Second,
		Vault:      VaultConfig{Backend: "local", Mount: "secret", Prefix: "ncc"},
		Log:        LogConfig{Format: "text", Level: "info"},
		SessionTTL: 12 * time.Hour,
	}
}

// Load reads a YAML config file. A missing path returns the defaults. Environment variables
// override the file: NCC_VAULT_TOKEN, NCC_LOG_FORMAT and NCC_LOG_LEVEL. Keys NCC doesn't know
// are returned as warnings (a typo would otherwise be silently ignored).
func Load(path string) (Config, []string, error) {
	cfg := Default()
	var warnings []string
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return cfg, nil, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return cfg, nil, fmt.Errorf("parse config: %w", err)
		}
		strict := yaml.NewDecoder(bytes.NewReader(b))
		strict.KnownFields(true)
		var probe Config
		if err := strict.Decode(&probe); err != nil && !errors.Is(err, io.EOF) {
			for _, line := range strings.Split(err.Error(), "\n") {
				if strings.Contains(line, "not found in type") {
					warnings = append(warnings, "config: unknown setting ("+strings.TrimSpace(line)+"); it is ignored")
				}
			}
		}
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 30 * time.Second
	}
	if cfg.Vault.Backend == "" {
		cfg.Vault.Backend = "local"
	}
	if cfg.Vault.Mount == "" {
		cfg.Vault.Mount = "secret"
	}
	if cfg.Vault.Prefix == "" {
		cfg.Vault.Prefix = "ncc"
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if v := os.Getenv("NCC_VAULT_TOKEN"); v != "" {
		cfg.Vault.Token = v
	}
	if v := os.Getenv("NCC_LOG_FORMAT"); v != "" {
		cfg.Log.Format = v
	}
	if v := os.Getenv("NCC_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	for _, f := range []struct {
		file string
		dst  *string
		name string
	}{{cfg.Vault.TokenFile, &cfg.Vault.Token, "vault.token_file"}, {cfg.Vault.SecretIDFile, &cfg.Vault.SecretID, "vault.secret_id_file"}} {
		if f.file == "" {
			continue
		}
		b, err := os.ReadFile(f.file)
		if err != nil {
			return cfg, warnings, fmt.Errorf("%s: %w", f.name, err)
		}
		*f.dst = strings.TrimSpace(string(b))
	}
	return cfg, warnings, cfg.Validate()
}

// Validate checks the settings NCC can't start (or start safely) without, so a mistake is
// reported at startup with the setting's name rather than as a failure later.
func (c Config) Validate() error {
	var errs []string
	if _, port, err := net.SplitHostPort(c.Listen); err != nil || port == "" {
		errs = append(errs, fmt.Sprintf("listen: %q is not host:port (e.g. \":8443\")", c.Listen))
	}
	if c.DataDir == "" {
		errs = append(errs, "data_dir is required")
	}
	if c.Poll < 5*time.Second {
		errs = append(errs, fmt.Sprintf("poll: %s is too short; use 5s or more", c.Poll))
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		errs = append(errs, "tls_cert and tls_key go together: set both or neither")
	}
	switch c.Vault.Backend {
	case "local", "hashicorp":
	default:
		errs = append(errs, fmt.Sprintf("vault.backend: %q is not local or hashicorp", c.Vault.Backend))
	}
	if c.Vault.Backend == "hashicorp" && c.Vault.Address == "" {
		errs = append(errs, "vault.address is required for the hashicorp backend")
	}
	switch strings.ToLower(c.Log.Format) {
	case "", "text", "json":
	default:
		errs = append(errs, fmt.Sprintf("log.format: %q is not text or json", c.Log.Format))
	}
	switch strings.ToLower(c.Log.Level) {
	case "", "debug", "info", "warn", "warning", "error":
	default:
		errs = append(errs, fmt.Sprintf("log.level: %q is not debug, info, warn or error", c.Log.Level))
	}
	if c.SessionTTL < 5*time.Minute || c.SessionTTL > 30*24*time.Hour {
		errs = append(errs, "session_ttl must be between 5m and 720h")
	}
	if _, err := ParsePrefixes(c.TrustedProxies); err != nil {
		errs = append(errs, "trusted_proxies: "+err.Error())
	}
	if c.DNSLog.Listen != "" {
		if _, err := ParsePrefixes(c.DNSLog.Allow); err != nil {
			errs = append(errs, "dns_log.allow: "+err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New("config: " + strings.Join(errs, "; "))
	}
	return nil
}

// ParsePrefixes reads plain addresses or CIDR prefixes.
func ParsePrefixes(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range in {
		s = strings.TrimSpace(s)
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or CIDR", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
