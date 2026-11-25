package api_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/mocklab"
)

// TestTopologyIdentity runs the whole chain against the mock lab: a UniFi console that sees
// the Proxmox hosts as unmanaged switches, the mock Proxmox cluster, and PowerDNS with the
// hosts' names. The map should call the switches what they are, and people can correct it.
func TestTopologyIdentity(t *testing.T) {
	ncc, _ := newNCC(t)
	defer ncc.Close()
	unifi := httptest.NewTLSServer(mocklab.UniFiHomelab())
	defer unifi.Close()
	pve := httptest.NewTLSServer(mocklab.Proxmox("tok", "pw"))
	defer pve.Close()
	pdns := httptest.NewServer(mocklab.NewPowerDNS("k"))
	defer pdns.Close()

	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: ncc.URL, hc: &http.Client{Jar: jar}}
	c.do("POST", "/api/setup", map[string]string{"username": "derek", "password": "a-long-password", "vault_passphrase": "vault passphrase 1"}, nil)
	var login struct {
		CSRF string `json:"csrf"`
	}
	c.do("POST", "/api/login", map[string]string{"username": "derek", "password": "a-long-password"}, &login)
	c.csrf = login.CSRF

	add := func(body map[string]any) int64 {
		var tgt core.Target
		if code := c.do("POST", "/api/targets", body, &tgt); code != 201 {
			t.Fatalf("create %v: %d", body["name"], code)
		}
		return tgt.ID
	}
	ids := []int64{
		add(map[string]any{"kind": "unifi", "category": "device", "name": "dream-router", "address": unifi.URL,
			"credentials": map[string]string{"username": "ncc", "password": "demo-password"}}),
		add(map[string]any{"kind": "proxmox", "category": "hypervisor", "name": "homelab", "address": pve.URL,
			"credentials": map[string]string{"token_id": "ncc@pve!monitor", "token_secret": "tok"}}),
		add(map[string]any{"kind": "powerdns", "category": "dns", "name": "ns1", "address": pdns.URL,
			"credentials": map[string]string{"api_key": "k"}}),
	}
	pve1 := "inferred:aa:bb:cc:00:00:04:9"
	find := func(g core.Graph, id string) *core.Node {
		for i := range g.Nodes {
			if g.Nodes[i].ID == id {
				return &g.Nodes[i]
			}
		}
		return nil
	}
	// the create starts a background poll each; poll until all three have landed
	var g core.Graph
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, id := range ids {
			c.do("POST", "/api/targets/"+itoa(id)+"/poll", nil, nil)
		}
		g = core.Graph{}
		c.do("GET", "/api/topology?clients=1", nil, &g)
		if n := find(g, pve1); n != nil && n.Identity != nil && n.Related != nil && len(n.Related.DNS) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	n := find(g, pve1)
	if n == nil || n.Identity == nil || n.Identity.Role != core.RoleHypervisor || n.Identity.Name != "pve1" || n.Label != "pve1" ||
		n.Identity.Confidence != "high" || n.IP != "192.168.1.12" {
		t.Fatalf("pve1: %+v identity %+v", n, n.Identity)
	}
	if n.Related.Host == nil || n.Related.Host.Platform != "Proxmox VE" || len(n.Related.VMs) != 3 || n.Related.DNS[0].Name != "pve1.home.lan" {
		t.Errorf("pve1 related: %+v", n.Related)
	}
	if find(g, "58:47:ca:70:00:01") != nil {
		t.Error("pve1's own port should fold into the host")
	}
	if p2 := find(g, "inferred:aa:bb:cc:00:00:05:3"); p2 == nil || p2.Identity == nil || p2.Identity.Name != "pve2" {
		t.Errorf("pve2: %+v", p2)
	}
	// the LLDP neighbour that says it's a switch, and the VM the guest agent can't reach
	if sw := find(g, "10:20:30:40:50:60"); sw == nil || sw.Identity == nil || sw.Identity.Role != core.RoleSwitch {
		t.Errorf("office switch: %+v", sw)
	}
	if w := find(g, "bc:24:11:00:00:66"); w == nil || w.Identity == nil || w.Identity.Name != "win11-desktop" || w.Identity.Role != core.RoleVM {
		t.Errorf("Windows VM by MAC alone: %+v", w)
	}
	// the printer has an address Proxmox lists for unifi-backup, but not its MAC
	if pr := find(g, "de:ad:00:00:00:02"); pr == nil || pr.Identity != nil && pr.Identity.Role != core.RoleIoT {
		t.Errorf("printer must not be taken for a VM: %+v", pr.Identity)
	}

	// a person says the Rack switch port 5 "switch" is a NAS called backup-nas
	port5 := "inferred:aa:bb:cc:00:00:04:5"
	if code := c.do("PUT", "/api/topology/identity/"+port5, map[string]any{"role": "toaster"}, nil); code != 400 {
		t.Fatalf("bad role: %d", code)
	}
	if code := c.do("PUT", "/api/topology/identity/"+port5, map[string]any{"role": "nas", "name": "backup-nas"}, nil); code != 200 {
		t.Fatalf("set: %d", code)
	}
	if code := c.do("PUT", "/api/topology/identity/"+pve1, map[string]any{"role": "hypervisor", "name": "pve1", "confirmed": true}, nil); code != 200 {
		t.Fatalf("confirm: %d", code)
	}
	g = core.Graph{}
	c.do("GET", "/api/topology", nil, &g)
	if n := find(g, port5); n.Label != "backup-nas" || n.Identity.Source != core.IdentityManual || n.Identity.By != "derek" || n.Identity.Guess == nil {
		t.Fatalf("override: %+v %+v", n, n.Identity)
	}
	if n := find(g, pve1); n.Identity.Source != core.IdentityConfirmed {
		t.Fatalf("confirmed: %+v", n.Identity)
	}
	if code := c.do("DELETE", "/api/topology/identity/"+port5, nil, nil); code != 200 {
		t.Fatalf("reset: %d", code)
	}
	if code := c.do("DELETE", "/api/topology/identity/"+port5, nil, nil); code != 404 {
		t.Fatalf("reset twice: %d", code)
	}
	g = core.Graph{}
	c.do("GET", "/api/topology", nil, &g)
	if n := find(g, port5); n.Identity == nil || n.Identity.Source != core.IdentityAuto || n.Label == "backup-nas" {
		t.Fatalf("after reset: %+v", n.Identity)
	}
	var audit []map[string]any
	c.do("GET", "/api/audit", nil, &audit)
	seen := map[any]bool{}
	for _, a := range audit {
		seen[a["action"]] = true
	}
	if !seen["topology.identify"] || !seen["topology.confirm"] || !seen["topology.identify.reset"] {
		t.Errorf("audit: %v", seen)
	}
}
