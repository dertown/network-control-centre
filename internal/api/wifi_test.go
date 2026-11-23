package api_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/inventory"
)

type wifiView struct {
	Targets []struct {
		ID       int64              `json:"id"`
		Writable bool               `json:"writable"`
		SSIDs    []inventory.SSID   `json:"ssids"`
		Radios   []inventory.Radio  `json:"radios"`
		Findings []core.WiFiFinding `json:"findings"`
		Saved    []string           `json:"saved"`
		Clients  []struct {
			Name   string `json:"name"`
			AP     string `json:"ap"`
			Signal int    `json:"signal"`
			Band   string `json:"band"`
		} `json:"clients"`
	} `json:"targets"`
}

func ssidByName(v wifiView, name string) inventory.SSID {
	for _, s := range v.Targets[0].SSIDs {
		if s.Name == name {
			return s
		}
	}
	return inventory.SSID{}
}

func TestWiFi(t *testing.T) {
	c, lab, id, done := vlanSetup(t, "ncc")
	defer done()

	var v wifiView
	if code := c.do("GET", "/api/wifi", nil, &v); code != 200 || len(v.Targets) != 1 {
		t.Fatalf("wifi: %d %+v", code, v)
	}
	tg := v.Targets[0]
	if !tg.Writable || len(tg.SSIDs) != 4 || len(tg.Radios) != 7 {
		t.Fatalf("ssids/radios: %+v", tg)
	}
	if s := ssidByName(v, "Home"); s.Security != inventory.SecWPA2WPA3 || s.Network != "Default" || s.ShortPassphrase || len(s.Bands) != 3 {
		t.Errorf("Home: %+v", s)
	}
	kinds := map[string]bool{}
	for _, f := range tg.Findings {
		kinds[f.SSID+f.Device+"/"+f.Kind] = true
	}
	for _, k := range []string{"Home-Guest/open", "Home-IoT/tkip", "Home-IoT/short-passphrase", "Smart-Plugs/wpa1", "Smart-Plugs/iot-vlan", "Lounge AP/width-2g"} {
		if !kinds[k] {
			t.Errorf("missing finding %s in %+v", k, tg.Findings)
		}
	}
	if tg.Findings[0].Severity != core.WiFiCritical {
		t.Errorf("findings not worst first: %+v", tg.Findings)
	}
	weak := false
	for _, cl := range tg.Clients {
		if cl.Name == "doorbell" && cl.Signal == -81 && cl.Band == "2.4" && cl.AP == "Lounge AP" {
			weak = true
		}
	}
	if !weak {
		t.Errorf("doorbell signal missing: %+v", tg.Clients)
	}

	// preview: fixing Smart-Plugs moves it to the IoT VLAN with WPA2 and a new passphrase
	secret := "plugs-new-passphrase-42"
	body := map[string]any{"target_id": id, "ssid_id": "wl_plugs", "network_id": "net_iot", "security": "wpa2", "passphrase": secret}
	var plan core.WiFiPlan
	if code := c.do("POST", "/api/wifi/plan", body, &plan); code != 200 {
		t.Fatalf("plan: %d", code)
	}
	if len(plan.Changes) != 3 || len(plan.Resolves) != 2 || len(plan.Remaining) != 0 {
		t.Errorf("plan: %+v", plan)
	}
	if b, _ := json.Marshal(plan); strings.Contains(string(b), secret) {
		t.Errorf("plan echoes the passphrase: %s", b)
	}
	if len(lab.Writes()) != 0 {
		t.Fatalf("plan wrote: %v", lab.Writes())
	}
	// weak changes are refused
	var e map[string]string
	if code := c.do("POST", "/api/wifi/plan", map[string]any{"target_id": id, "ssid_id": "wl_plugs", "security": "open"}, &e); code != 400 {
		t.Errorf("open allowed: %d %v", code, e)
	}
	if code := c.do("POST", "/api/wifi/plan", map[string]any{"target_id": id, "ssid_id": "wl_guest", "passphrase": "short"}, &e); code != 400 {
		t.Errorf("short passphrase allowed: %d", code)
	}
	if code := c.do("POST", "/api/wifi/plan", map[string]any{"target_id": id, "ssid_id": "wl_guest", "passphrase": "a-good-guest-pass"}, &e); code != 400 {
		t.Errorf("passphrase on an open network without security allowed: %d", code)
	}

	var res map[string]any
	if code := c.do("POST", "/api/wifi/apply", body, &res); code != 200 || res["vault_path"] != "wifi/udr7/wl_plugs" {
		t.Fatalf("apply: %d %v", code, res)
	}
	w := strings.Join(lab.Writes(), "\n")
	if !strings.Contains(w, "PUT rest/wlanconf/wl_plugs") || !strings.Contains(w, "networkconf_id") || !strings.Contains(w, "x_passphrase") || strings.Contains(w, secret) {
		t.Errorf("writes: %s", w)
	}

	// the vault has the passphrase; the audit log does not
	var reveal map[string]any
	if code := c.do("POST", "/api/wifi/passphrase", map[string]any{"target_id": id, "ssid_id": "wl_plugs"}, &reveal); code != 200 || reveal["passphrase"] != secret || reveal["source"] != "vault" {
		t.Errorf("reveal: %d %v", code, reveal)
	}
	if code := c.do("POST", "/api/wifi/passphrase", map[string]any{"target_id": id, "ssid_id": "wl_home", "from_router": true}, &reveal); code != 200 || reveal["passphrase"] != "correct-horse-battery-staple" || reveal["vault_path"] != "wifi/udr7/wl_home" {
		t.Errorf("reveal from router: %d %v", code, reveal)
	}
	var audit []map[string]any
	c.do("GET", "/api/audit", nil, &audit)
	ab, _ := json.Marshal(audit)
	if strings.Contains(string(ab), secret) || strings.Contains(string(ab), "correct-horse") || !strings.Contains(string(ab), "wifi.update") {
		t.Errorf("audit: %s", ab)
	}

	pollUntil(c, id)
	v = wifiView{}
	c.do("GET", "/api/wifi", nil, &v)
	if s := ssidByName(v, "Smart-Plugs"); s.Network != "IoT" || s.Security != inventory.SecWPA2 || s.TKIP || s.ShortPassphrase {
		t.Errorf("after apply: %+v", s)
	}
	saved := strings.Join(v.Targets[0].Saved, ",")
	if !strings.Contains(saved, "wl_plugs") || !strings.Contains(saved, "wl_home") {
		t.Errorf("saved: %v", saved)
	}
}

func TestWiFiViewOnlyAccount(t *testing.T) {
	c, lab, id, done := vlanSetup(t, "viewer")
	defer done()
	var e map[string]string
	code := c.do("POST", "/api/wifi/apply", map[string]any{"target_id": id, "ssid_id": "wl_home", "enabled": false}, &e)
	if code != 502 || !strings.Contains(e["error"], "can only view") {
		t.Errorf("view-only apply: %d %v", code, e)
	}
	if len(lab.Writes()) != 0 {
		t.Errorf("writes: %v", lab.Writes())
	}
}
