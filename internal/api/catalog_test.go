package api_test

import (
	"net/http"
	"net/http/cookiejar"
	"testing"

	_ "github.com/dertown/network-control-centre/internal/dns/bind"
	_ "github.com/dertown/network-control-centre/internal/drivers/snmpnet"
)

// adminClient sets up NCC and signs in as its first admin.
func adminClient(t *testing.T) *client {
	ncc, _ := newNCC(t)
	t.Cleanup(ncc.Close)
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: ncc.URL, hc: &http.Client{Jar: jar}}
	if code := c.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "a-long-password", "vault_passphrase": "vault passphrase 1"}, nil); code != 201 {
		t.Fatalf("setup: %d", code)
	}
	var login struct {
		CSRF string `json:"csrf"`
	}
	if code := c.do("POST", "/api/login", map[string]string{"username": "admin", "password": "a-long-password"}, &login); code != 200 {
		t.Fatalf("login: %d", code)
	}
	c.csrf = login.CSRF
	return c
}

func TestAddConnectionThroughTheCatalog(t *testing.T) {
	c := adminClient(t)
	var cat struct {
		Groups []struct {
			ID string `json:"id"`
		} `json:"groups"`
		Vendors []struct {
			ID     string   `json:"id"`
			Kind   string   `json:"kind"`
			Groups []string `json:"groups"`
		} `json:"vendors"`
	}
	if code := c.do("GET", "/api/catalog", nil, &cat); code != 200 || len(cat.Groups) < 5 {
		t.Fatalf("catalog: %d %+v", code, cat.Groups)
	}
	found := false
	for _, v := range cat.Vendors {
		found = found || (v.ID == "snmp-fortigate" && v.Kind == "snmpnet")
	}
	if !found {
		t.Fatal("FortiGate is not offered")
	}

	// a vendor entry sets kind, category and its preset options
	var tg struct {
		ID       int64             `json:"id"`
		Kind     string            `json:"kind"`
		Category string            `json:"category"`
		Options  map[string]string `json:"options"`
	}
	code := c.do("POST", "/api/targets", map[string]any{
		"vendor": "snmp-fortigate", "name": "fw1", "address": "127.0.0.1:1",
		"options": map[string]string{"role": "switch"}, "credentials": map[string]string{"snmp_community": "secret"},
	}, &tg)
	if code != 201 || tg.Kind != "snmpnet" || tg.Category != "device" || tg.Options["role"] != "firewall" || tg.Options["vendor"] != "snmp-fortigate" {
		t.Fatalf("create: %d %+v", code, tg)
	}
	// the preset can't be edited away
	var upd struct {
		Options map[string]string `json:"options"`
	}
	c.do("PATCH", "/api/targets/"+itoa(tg.ID), map[string]any{"options": map[string]string{"role": "switch"}}, &upd)
	if upd.Options["role"] != "firewall" || upd.Options["vendor"] != "snmp-fortigate" {
		t.Fatalf("preset lost on edit: %+v", upd.Options)
	}

	// input checks: a URL where one is needed, a choice that isn't offered, an unknown type
	for name, body := range map[string]map[string]any{
		"url": {"vendor": "powerdns", "name": "p", "address": "10.0.0.1", "credentials": map[string]string{"api_key": "k"}},
		"choice": {"vendor": "bind", "name": "b", "address": "10.0.0.1", "options": map[string]string{"zones": "a.lan", "tsig_algorithm": "hmac-md5"},
			"credentials": map[string]string{"tsig_secret": "c2VjcmV0"}},
		"vendor":   {"vendor": "nope", "name": "n", "address": "10.0.0.1", "credentials": map[string]string{"x": "y"}},
		"spaces":   {"vendor": "bind", "name": "b2", "address": "10.0.0.1 ; rm", "options": map[string]string{"zones": "a.lan"}, "credentials": map[string]string{"tsig_secret": "x"}},
		"mismatch": {"kind": "unifi", "category": "dns", "name": "u", "address": "https://10.0.0.1", "credentials": map[string]string{"api_key": "k"}},
	} {
		if code := c.do("POST", "/api/targets", body, nil); code != 400 {
			t.Errorf("%s: got %d, want 400", name, code)
		}
	}
	// the old request shape (kind + category) still works
	if code := c.do("POST", "/api/targets", map[string]any{"kind": "bind", "category": "dns", "name": "bind1", "address": "127.0.0.1:1",
		"options": map[string]string{"zones": "home.lan", "tsig_name": "k"}, "credentials": map[string]string{"tsig_secret": "c2VjcmV0"}}, nil); code != 201 {
		t.Fatalf("kind+category: %d", code)
	}
}
