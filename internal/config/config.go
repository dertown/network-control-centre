// Package config loads the NCC configuration file.
package config

import (
	"fmt"
	"os"
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
}

// VaultConfig picks the secret backend.
type VaultConfig struct {
	Backend string `yaml:"backend"` // "local" (default) or "hashicorp"

	// Local backend: optional file holding the unseal passphrase for unattended starts.
	PassphraseFile string `yaml:"passphrase_file"`

	// HashiCorp backend.
	Address   string `yaml:"address"`   // https://vault.example:8200
	Mount     string `yaml:"mount"`     // KV v2 mount, default "secret"
	Prefix    string `yaml:"prefix"`    // path prefix inside the mount, default "ncc"
	Token     string `yaml:"token"`     // static token, or use AppRole below
	RoleID    string `yaml:"role_id"`   //
	SecretID  string `yaml:"secret_id"` //
	CACert    string `yaml:"ca_cert"`   // optional PEM bundle to trust
	Namespace string `yaml:"namespace"` // Vault Enterprise namespace
}

// Default returns a config with sensible defaults.
func Default() Config {
	return Config{
		Listen:  ":8443",
		DataDir: "./data",
		Poll:    30 * time.Second,
		Vault:   VaultConfig{Backend: "local", Mount: "secret", Prefix: "ncc"},
	}
}

// Load reads a YAML config file. A missing path returns the defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
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
	if v := os.Getenv("NCC_VAULT_TOKEN"); v != "" {
		cfg.Vault.Token = v
	}
	return cfg, nil
}
