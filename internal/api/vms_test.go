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
	// power, settings and delete
	if code := c.do("POST", "/api/vms/power", map[string]string{"id": "pve/qemu/103", "action": "explode"}, nil); code != 400 {
		t.Fatalf("bad action: %d", code)
	}
	if code := c.do("POST", "/api/vms/power", map[string]string{"id": "nope/qemu/1", "action": "start"}, nil); code != 404 {
		t.Fatalf("unknown connection: %d", code)
	}
	if code := c.do("POST", "/api/vms/power", map[string]string{"id": "pve/qemu/103", "action": "start"}, nil); code != 200 {
		t.Fatalf("start: %d", code)
	}
	if code := c.do("POST", "/api/vms/settings", map[string]any{"id": "pve/qemu/103", "cpus": 6, "memory_mb": 4096}, nil); code != 200 {
		t.Fatalf("settings: %d", code)
	}
	if code := c.do("POST", "/api/vms/settings", map[string]any{"id": "pve/qemu/103", "cpus": 0}, nil); code != 400 {
		t.Fatalf("0 vCPUs accepted: %d", code)
	}
	if code := c.do("POST", "/api/vms/delete", map[string]string{"id": "pve/qemu/103", "confirm": "wrong"}, nil); code != 400 {
		t.Fatalf("delete without the right name: %d", code)
	}
	if code := c.do("POST", "/api/vms/delete", map[string]string{"id": "pve/qemu/103", "confirm": "plex"}, nil); code != 502 {
		t.Fatalf("deleted a running VM: %d", code)
	}
	c.do("POST", "/api/vms/power", map[string]string{"id": "pve/qemu/103", "action": "stop"}, nil)
	if code := c.do("POST", "/api/vms/delete", map[string]string{"id": "pve/qemu/103", "confirm": "plex"}, nil); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	var log []struct {
		Action string `json:"action"`
	}
	c.do("GET", "/api/audit", nil, &log)
	seen := map[string]int{}
	for _, e := range log {
		seen[e.Action]++
	}
	if seen["vm.power"] < 2 || seen["vm.settings"] < 1 || seen["vm.delete"] < 1 {
		t.Fatalf("audit: %v", seen)
	}

	// removing the connection removes its VMs
	c.do("DELETE", "/api/targets/"+itoa(tgt.ID), nil, nil)
	out.VMs = nil
	c.do("GET", "/api/vms", nil, &out)
	if len(out.VMs) != 0 || len(out.Sources) != 0 {
		t.Fatalf("after delete: %d vms %d sources", len(out.VMs), len(out.Sources))
	}
}
