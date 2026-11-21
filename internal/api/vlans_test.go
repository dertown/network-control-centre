package api_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/mocklab"
)

type vlanView struct {
	Targets []struct {
		ID         int64               `json:"id"`
		Writable   bool                `json:"writable"`
		Networks   []inventory.Network `json:"networks"`
		Clients    []inventory.Client  `json:"clients"`
		Suggestion struct {
			VLAN    int    `json:"vlan"`
			Gateway string `json:"gateway"`
		} `json:"suggestion"`
	} `json:"targets"`
}

func vlanSetup(t *testing.T, user string) (*client, *mocklab.UniFiLab, int64, func()) {
	ncc, _ := newNCC(t)
	lab := mocklab.NewUniFi()
	unifi := httptest.NewTLSServer(lab)
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: ncc.URL, hc: &http.Client{Jar: jar}}
	c.do("POST", "/api/setup", map[string]string{"username": "derek", "password": "a-long-password", "vault_passphrase": "vault passphrase 1"}, nil)
	var login struct {
		CSRF string `json:"csrf"`
	}
	c.do("POST", "/api/login", map[string]string{"username": "derek", "password": "a-long-password"}, &login)
	c.csrf = login.CSRF
	var tgt core.Target
	if code := c.do("POST", "/api/targets", map[string]any{
		"kind": "unifi", "category": "device", "name": "udr7", "address": unifi.URL,
		"credentials": map[string]string{"username": user, "password": "demo-password"},
	}, &tgt); code != 201 {
		t.Fatalf("create target: %d", code)
	}
	pollUntil(c, tgt.ID)
	return c, lab, tgt.ID, func() { unifi.Close(); ncc.Close() }
}

func pollUntil(c *client, id int64) {
	deadline := time.Now().Add(5 * time.Second)
	for c.do("POST", "/api/targets/"+itoa(id)+"/poll", nil, nil) != 200 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
}

func clientNet(v vlanView, name string) inventory.Client {
	for _, c := range v.Targets[0].Clients {
		if c.Name == name {
			return c
		}
	}
	return inventory.Client{}
}

func TestVLANs(t *testing.T) {
	c, lab, id, done := vlanSetup(t, "ncc")
	defer done()

	var v vlanView
	c.do("GET", "/api/vlans", nil, &v)
	if len(v.Targets) != 1 || !v.Targets[0].Writable || len(v.Targets[0].Networks) != 5 {
		t.Fatalf("vlans: %+v", v)
	}
	if s := v.Targets[0].Suggestion; s.VLAN != 10 || s.Gateway != "192.168.10.1/24" {
		t.Fatalf("suggestion: %+v", s)
	}

	// bad networks are refused before anything reaches the console
	for _, bad := range []map[string]any{
		{"name": "IoT", "vlan": 40, "mode": "gateway", "gateway": "192.168.40.1/24"},   // name taken
		{"name": "Cams", "vlan": 30, "mode": "gateway", "gateway": "192.168.40.1/24"},  // VLAN taken
		{"name": "Cams", "vlan": 40, "mode": "gateway", "gateway": "192.168.1.129/25"}, // overlaps Default
		{"name": "Cams", "vlan": 40, "mode": "gateway", "gateway": "192.168.40.0/24"},  // network address
		{"name": "Cams", "vlan": 1, "mode": "gateway", "gateway": "192.168.40.1/24"},   // VLAN 1
		{"name": "Cams", "vlan": 40, "mode": "gateway", "gateway": "8.8.8.1/24"},       // public
		{"name": "Cams", "vlan": 40, "mode": "gateway", "gateway": "192.168.40.1/24", "dhcp": true, "dhcp_start": "192.168.40.1", "dhcp_stop": "192.168.40.50"},
	} {
		bad["target_id"] = id
		if code := c.do("POST", "/api/vlans/networks", bad, nil); code != 400 {
			t.Fatalf("accepted %v: %d", bad, code)
		}
	}
	if w := lab.Writes(); len(w) != 0 {
		t.Fatalf("console changed by refused requests: %v", w)
	}

	var created struct {
		ID   string `json:"id"`
		Spec struct {
			DHCPStart string `json:"dhcp_start"`
			DHCPStop  string `json:"dhcp_stop"`
		} `json:"spec"`
	}
	if code := c.do("POST", "/api/vlans/networks", map[string]any{"target_id": id, "name": "Smart home", "vlan": 10, "mode": "gateway",
		"gateway": "192.168.10.1/24", "dhcp": true, "isolated": true, "internet_access": true}, &created); code != 201 {
		t.Fatalf("create network: %d %+v", code, created)
	}
	if created.ID == "" || created.Spec.DHCPStart != "192.168.10.6" || created.Spec.DHCPStop != "192.168.10.254" {
		t.Fatalf("created: %+v", created)
	}
	if w := lab.Writes(); len(w) != 1 || !strings.Contains(w[0], `"vlan":10`) || !strings.Contains(w[0], `"network_isolation_enabled":true`) {
		t.Fatalf("network write: %v", w)
	}
	pollUntil(c, id)

	macs := []string{
		"de:ad:00:00:00:07", // thermostat: Wi-Fi
		"de:ad:00:00:00:02", // printer: Rack switch port 5, shared with the TV
		"de:ad:00:00:00:01", // nas: Dream Router port 2, fixed IP
		"de:ad:00:00:00:05", // desk-pc: behind the NETGEAR switch, cannot move
		"de:ad:00:00:00:06", // web-dmz: port with the DMZ profile
	}
	var plan core.MovePlan
	if code := c.do("POST", "/api/vlans/plan", map[string]any{"target_id": id, "network_id": created.ID, "macs": macs}, &plan); code != 200 {
		t.Fatalf("plan: %d", code)
	}
	steps := map[string]core.MoveStep{}
	for _, s := range plan.Steps {
		steps[s.Name] = s
	}
	if s := steps["thermostat"]; s.Method != "client" {
		t.Errorf("thermostat: %+v", s)
	}
	if s := steps["Printer"]; s.Method != "port" || s.SwitchPort != 5 {
		t.Errorf("printer: %+v", s)
	}
	if s := steps["tv"]; s.Method != "port" || s.Requested {
		t.Errorf("tv should come along with the printer: %+v", s)
	}
	if s := steps["desk-pc"]; s.Blocked == "" || !strings.Contains(s.Blocked, "office-sw") {
		t.Errorf("desk-pc should be blocked: %+v", s)
	}
	if len(plan.Ports) != 3 || len(plan.Warnings) < 2 {
		t.Errorf("ports %+v warnings %v", plan.Ports, plan.Warnings)
	}

	var res struct {
		Results []struct {
			Name  string   `json:"name"`
			OK    bool     `json:"ok"`
			Notes []string `json:"notes"`
		} `json:"results"`
	}
	if code := c.do("POST", "/api/vlans/move", map[string]any{"target_id": id, "network_id": created.ID, "macs": macs, "reconnect": true}, &res); code != 200 {
		t.Fatalf("move: %d %+v", code, res)
	}
	notes := map[string]string{}
	for _, r := range res.Results {
		if !r.OK {
			t.Errorf("%s failed", r.Name)
		}
		notes[r.Name] = strings.Join(r.Notes, "; ")
	}
	if len(res.Results) != 5 || !strings.Contains(notes["nas"], "fixed IP 192.168.1.50 removed") ||
		!strings.Contains(notes["web-dmz"], `port profile "DMZ servers"`) || !strings.Contains(notes["thermostat"], "disconnected") {
		t.Fatalf("results: %+v", res.Results)
	}
	writes := strings.Join(lab.Writes(), "\n")
	for _, want := range []string{"PUT rest/device/dev_aabbcc000004", "PUT rest/device/dev_aabbcc000001", `"virtual_network_override_id":"` + created.ID,
		`"cmd":"kick-sta"`, `"use_fixedip":false`} {
		if !strings.Contains(writes, want) {
			t.Errorf("missing %s in\n%s", want, writes)
		}
	}
	// the Dream Router's existing trunk override on port 1 is kept
	if !strings.Contains(writes, `"portconf_id":"pc_trunk"`) {
		t.Errorf("port 1 override lost:\n%s", writes)
	}

	pollUntil(c, id)
	c.do("GET", "/api/vlans", nil, &v)
	for _, name := range []string{"thermostat", "Printer", "tv", "nas", "web-dmz"} {
		if cl := clientNet(v, name); cl.NetworkID != created.ID || !strings.HasPrefix(cl.IP, "192.168.10.") {
			t.Errorf("%s not moved: %+v", name, cl)
		}
	}
	if cl := clientNet(v, "desk-pc"); cl.NetworkID != "net_default" {
		t.Errorf("desk-pc moved: %+v", cl)
	}

	var audit []map[string]any
	c.do("GET", "/api/audit", nil, &audit)
	moves := 0
	for _, a := range audit {
		if a["action"] == "vlan.move" {
			moves++
		}
	}
	if moves != 5 {
		t.Errorf("audit has %d vlan.move entries", moves)
	}
}

func TestVLANsViewOnlyAccount(t *testing.T) {
	c, lab, id, done := vlanSetup(t, "viewer")
	defer done()
	var out map[string]any
	code := c.do("POST", "/api/vlans/networks", map[string]any{"target_id": id, "name": "Cams", "vlan": 40, "mode": "vlan-only"}, &out)
	if code != 502 || !strings.Contains(out["error"].(string), "can only view") {
		t.Fatalf("view only: %d %v", code, out)
	}
	out = nil
	code = c.do("POST", "/api/vlans/move", map[string]any{"target_id": id, "network_id": "net_iot", "macs": []string{"de:ad:00:00:00:04"}}, &out)
	if code != 502 || !strings.Contains(out["error"].(string), "Site Admin") {
		t.Fatalf("view only move: %d %v", code, out)
	}
	if len(lab.Writes()) != 0 {
		t.Fatalf("writes recorded: %v", lab.Writes())
	}
}
