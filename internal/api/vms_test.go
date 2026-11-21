package api_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/mocklab"

	_ "github.com/dertown/network-control-centre/internal/hypervisor/proxmox"
	_ "github.com/dertown/network-control-centre/internal/hypervisor/vmware"
)

func TestVirtualMachines(t *testing.T) {
	ncc, _ := newNCC(t)
	defer ncc.Close()
	pve := httptest.NewTLSServer(mocklab.Proxmox("tok", "pw"))
	defer pve.Close()

	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: ncc.URL, hc: &http.Client{Jar: jar}}
	c.do("POST", "/api/setup", map[string]string{"username": "derek", "password": "a-long-password", "vault_passphrase": "vault passphrase 1"}, nil)
	var login struct {
		CSRF string `json:"csrf"`
	}
	c.do("POST", "/api/login", map[string]string{"username": "derek", "password": "a-long-password"}, &login)
	c.csrf = login.CSRF

	if code := c.do("POST", "/api/targets", map[string]any{
		"kind": "nope", "category": "hypervisor", "name": "x", "address": pve.URL, "credentials": map[string]string{"a": "b"},
	}, nil); code != 400 {
		t.Fatalf("unknown hypervisor kind accepted: %d", code)
	}
	var tgt core.Target
	if code := c.do("POST", "/api/targets", map[string]any{
		"kind": "proxmox", "category": "hypervisor", "name": "pve", "address": pve.URL,
		"credentials": map[string]string{"token_id": "ncc@pve!monitor", "token_secret": "tok"},
	}, &tgt); code != 201 {
		t.Fatalf("create: %d", code)
	}
	if tgt.SecretPath != "targets/hypervisor/pve" {
		t.Errorf("secret path %q", tgt.SecretPath)
	}
	if code := c.do("POST", "/api/targets/"+itoa(tgt.ID)+"/poll", nil, nil); code != 200 && code != 502 {
		t.Fatalf("poll: %d", code)
	}
	var out struct {
		Sources []struct {
			Name      string `json:"name"`
			LastError string `json:"last_error"`
			Version   string `json:"version"`
		} `json:"sources"`
		Hosts []map[string]any `json:"hosts"`
		VMs   []map[string]any `json:"vms"`
	}
	// the background poll started by create may still hold the lock; poll until data shows up
	for i := 0; i < 50 && len(out.VMs) == 0; i++ {
		c.do("POST", "/api/targets/"+itoa(tgt.ID)+"/poll", nil, nil)
		if code := c.do("GET", "/api/vms", nil, &out); code != 200 {
			t.Fatalf("vms: %d", code)
		}
	}
	if len(out.Sources) != 1 || out.Sources[0].LastError != "" || out.Sources[0].Version == "" {
		t.Fatalf("sources: %+v", out.Sources)
	}
	if len(out.Hosts) != 2 || len(out.VMs) != 7 {
		t.Fatalf("got %d hosts %d vms", len(out.Hosts), len(out.VMs))
	}
	// credentials live in the vault, not in the target
	var ts []core.Target
	c.do("GET", "/api/targets?category=hypervisor", nil, &ts)
	if len(ts) != 1 || ts[0].Options["tls_fingerprint"] == "" {
		t.Fatalf("targets: %+v", ts)
	}
	// removing the connection removes its VMs
	c.do("DELETE", "/api/targets/"+itoa(tgt.ID), nil, nil)
	out.VMs = nil
	c.do("GET", "/api/vms", nil, &out)
	if len(out.VMs) != 0 || len(out.Sources) != 0 {
		t.Fatalf("after delete: %d vms %d sources", len(out.VMs), len(out.Sources))
	}
}
