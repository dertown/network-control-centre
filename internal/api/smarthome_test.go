package api_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/mocklab"

	_ "github.com/dertown/network-control-centre/internal/smarthome/homeassistant"
)

type smartHomeView struct {
	Sources []struct {
		ID        int64  `json:"id"`
		LastError string `json:"last_error"`
		Inventory *struct {
			Hub      struct{ Matter bool }   `json:"hub"`
			Devices  []struct{ Name string } `json:"devices"`
			Entities []struct {
				ID      string   `json:"id"`
				State   string   `json:"state"`
				Actions []string `json:"actions"`
			} `json:"entities"`
		} `json:"inventory"`
	} `json:"sources"`
}

func (v smartHomeView) state(id string) string {
	for _, e := range v.Sources[0].Inventory.Entities {
		if e.ID == id {
			return e.State
		}
	}
	return ""
}

func TestSmartHome(t *testing.T) {
	ncc, _ := newNCC(t)
	defer ncc.Close()
	ha := httptest.NewServer(mocklab.HomeAssistant("tok"))
	defer ha.Close()

	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: ncc.URL, hc: &http.Client{Jar: jar}}
	c.do("POST", "/api/setup", map[string]string{"username": "derek", "password": "a-long-password", "vault_passphrase": "vault passphrase 1"}, nil)
	var login struct {
		CSRF string `json:"csrf"`
	}
	c.do("POST", "/api/login", map[string]string{"username": "derek", "password": "a-long-password"}, &login)
	c.csrf = login.CSRF

	var tg core.Target
	if code := c.do("POST", "/api/targets", map[string]any{"kind": "homeassistant", "category": "smarthome", "name": "home", "address": ha.URL,
		"credentials": map[string]string{"token": "tok"}}, &tg); code != 201 {
		t.Fatalf("create: %d", code)
	}
	var v smartHomeView
	for i := 0; i < 50; i++ {
		c.do("POST", "/api/targets/"+itoa(tg.ID)+"/poll", nil, nil)
		c.do("GET", "/api/smarthome", nil, &v)
		if len(v.Sources) == 1 && v.Sources[0].Inventory != nil {
			break
		}
	}
	if len(v.Sources) != 1 || v.Sources[0].Inventory == nil || !v.Sources[0].Inventory.Hub.Matter {
		t.Fatalf("sources: %+v", v.Sources)
	}
	if v.state("light.ceiling_light") != "off" {
		t.Fatalf("ceiling light: %q", v.state("light.ceiling_light"))
	}

	id := tg.ID
	var plan struct {
		Description string `json:"description"`
		Sensitive   bool   `json:"sensitive"`
	}
	if code := c.do("POST", "/api/smarthome/plan", map[string]any{"id": id, "entity": "light.ceiling_light", "action": "toggle"}, &plan); code != 200 || plan.Sensitive || plan.Description != "Switch Ceiling light on" {
		t.Fatalf("plan: %d %+v", code, plan)
	}
	if code := c.do("POST", "/api/smarthome/control", map[string]any{"id": id, "entity": "light.ceiling_light", "action": "toggle"}, nil); code != 200 {
		t.Fatalf("toggle: %d", code)
	}
	c.do("GET", "/api/smarthome", nil, &v)
	if v.state("light.ceiling_light") != "on" {
		t.Fatalf("light should be on now: %q", v.state("light.ceiling_light"))
	}
	if code := c.do("POST", "/api/smarthome/control", map[string]any{"id": id, "entity": "light.ceiling_light", "action": "unlock"}, nil); code != 400 {
		t.Fatalf("unlock a light: %d", code)
	}
	if code := c.do("POST", "/api/smarthome/control", map[string]any{"id": id, "entity": "switch.outdoor_plug", "action": "turn_on"}, nil); code != 400 {
		t.Fatalf("offline plug: %d", code)
	}
	if code := c.do("POST", "/api/smarthome/control", map[string]any{"id": id, "entity": "light.nope", "action": "turn_on"}, nil); code != 404 {
		t.Fatalf("unknown entity: %d", code)
	}
	// unlocking needs a confirmation
	if code := c.do("POST", "/api/smarthome/plan", map[string]any{"id": id, "entity": "lock.front_door", "action": "unlock"}, &plan); code != 200 || !plan.Sensitive {
		t.Fatalf("unlock plan: %d %+v", code, plan)
	}
	if code := c.do("POST", "/api/smarthome/control", map[string]any{"id": id, "entity": "lock.front_door", "action": "unlock"}, nil); code != 409 {
		t.Fatalf("unlock without confirm: %d", code)
	}
	if code := c.do("POST", "/api/smarthome/control", map[string]any{"id": id, "entity": "lock.front_door", "action": "unlock", "confirm": true}, nil); code != 200 {
		t.Fatalf("unlock: %d", code)
	}
	c.do("GET", "/api/smarthome", nil, &v)
	if v.state("lock.front_door") != "unlocked" {
		t.Fatalf("lock: %q", v.state("lock.front_door"))
	}
	if code := c.do("POST", "/api/smarthome/control", map[string]any{"id": id, "entity": "climate.thermostat", "action": "set_temperature", "value": 40}, nil); code != 400 {
		t.Fatalf("40 degrees: %d", code)
	}

	// Matter pairing
	var chk struct {
		Code struct {
			Formatted string `json:"formatted"`
		} `json:"code"`
		MatterReady bool `json:"matter_ready"`
	}
	if code := c.do("POST", "/api/smarthome/matter/check", map[string]any{"id": id, "code": "3497-011-2333"}, nil); code != 400 {
		t.Fatalf("typo code: %d", code)
	}
	if code := c.do("POST", "/api/smarthome/matter/check", map[string]any{"id": id, "code": "3497-011-2332"}, &chk); code != 200 || !chk.MatterReady || chk.Code.Formatted != "3497-011-••••" {
		t.Fatalf("check: %d %+v", code, chk)
	}
	var pr struct {
		NewDevices []string `json:"new_devices"`
	}
	if code := c.do("POST", "/api/smarthome/matter/pair", map[string]any{"id": id, "code": "34970112332"}, &pr); code != 200 || len(pr.NewDevices) != 1 || pr.NewDevices[0] != "Smart plug" {
		t.Fatalf("pair: %d %+v", code, pr)
	}

	var audit []struct {
		Action string `json:"action"`
	}
	c.do("GET", "/api/audit", nil, &audit)
	seen := map[string]int{}
	for _, a := range audit {
		seen[a.Action]++
	}
	if seen["smarthome.control"] != 2 || seen["smarthome.matter.pair"] != 1 {
		t.Fatalf("audit: %+v", seen)
	}
}
