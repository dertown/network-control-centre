package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The Proxmox Terraform writes this shape; it must keep loading unchanged.
func TestTerraformConfigStillLoads(t *testing.T) {
	cfg, warn, err := Load(write(t, `listen: ":8443"
data_dir: /var/lib/ncc
poll: 30s
dns_log:
  listen: ":4242"
  allow: ["192.168.1.70", "10.0.0.0/24"]
  retain: 168h
vault:
  backend: local
  passphrase_file: /etc/ncc/vault-passphrase
`))
	if err != nil || len(warn) != 0 {
		t.Fatalf("err %v, warnings %v", err, warn)
	}
	if cfg.Poll != 30*time.Second || cfg.SessionTTL != 12*time.Hour || cfg.Log.Format != "text" {
		t.Fatalf("%+v", cfg)
	}
}

func TestLoadChecksAndWarns(t *testing.T) {
	_, warn, err := Load(write(t, "listen: \":8443\"\npol: 10s\n"))
	if err != nil || len(warn) != 1 || !strings.Contains(warn[0], "pol") {
		t.Fatalf("typo: err %v, warnings %v", err, warn)
	}
	for body, want := range map[string]string{
		"listen: 8443\n":                     "listen",
		"poll: 1s\n":                         "poll",
		"tls_cert: /a.crt\n":                 "tls_cert and tls_key",
		"log:\n  format: xml\n":              "log.format",
		"trusted_proxies: [\"not-an-ip\"]\n": "trusted_proxies",
		"vault:\n  backend: hashicorp\n":     "vault.address",
		"session_ttl: 1s\n":                  "session_ttl",
	} {
		if _, _, err := Load(write(t, body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error about %s", body, err, want)
		}
	}
}

func TestSecretFiles(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	_ = os.WriteFile(tok, []byte("s.abc123\n"), 0o600)
	cfg, _, err := Load(write(t, "vault:\n  backend: hashicorp\n  address: https://vault:8200\n  token_file: "+tok+"\n"))
	if err != nil || cfg.Vault.Token != "s.abc123" {
		t.Fatalf("token file: %v %q", err, cfg.Vault.Token)
	}
	t.Setenv("NCC_LOG_FORMAT", "json")
	cfg, _, _ = Load("")
	if cfg.Log.Format != "json" {
		t.Fatal("NCC_LOG_FORMAT ignored")
	}
}
