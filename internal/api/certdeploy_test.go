package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/certdeploy"
	"github.com/dertown/network-control-centre/internal/pki"
)

func TestCertDeployAPI(t *testing.T) {
	ncc, _ := newNCC(t)
	defer ncc.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: ncc.URL, hc: &http.Client{Jar: jar}}
	c.do("POST", "/api/setup", map[string]string{"username": "derek", "password": "a-long-password", "vault_passphrase": "vault passphrase 1"}, nil)
	var login struct {
		CSRF string `json:"csrf"`
	}
	c.do("POST", "/api/login", map[string]string{"username": "derek", "password": "a-long-password"}, &login)
	c.csrf = login.CSRF

	var kinds []certdeploy.Kind
	c.do("GET", "/api/certdeploy/kinds", nil, &kinds)
	want := map[string]bool{"nginx": false, "apache": false, "tomcat": false, "splunk": false, "soar": false, "foundryvtt": false, "iis": false, "linux": false}
	for _, k := range kinds {
		want[k.ID] = true
	}
	for id, ok := range want {
		if !ok {
			t.Errorf("server type %s missing", id)
		}
	}

	certPEM, keyPEM := selfSigned(t, "foundry.example.lan", 60*24*time.Hour)
	var cert pki.Cert
	if code := c.do("POST", "/api/certs", map[string]string{"name": "foundry", "cert_pem": certPEM, "key_pem": keyPEM}, &cert); code != 201 {
		t.Fatalf("import: %d", code)
	}
	other, _ := selfSigned(t, "Some Other CA", time.Hour)
	var chained pki.Cert
	if code := c.do("PUT", "/api/certs/"+itoa(cert.ID)+"/chain", map[string]string{"ca_bundle_pem": other}, &chained); code != 200 || len(chained.Dropped) != 1 || chained.ChainLength != 1 {
		t.Fatalf("set chain: %d %+v", code, chained)
	}
	if code := c.do("PUT", "/api/certs/"+itoa(cert.ID)+"/chain", map[string]string{"ca_bundle_pem": "nonsense"}, nil); code != 400 {
		t.Fatalf("bad bundle: %d", code)
	}
	if code := c.do("PUT", "/api/certs/999/chain", map[string]string{"ca_bundle_pem": ""}, nil); code != 404 {
		t.Fatalf("missing cert: %d", code)
	}
	if code := c.do("POST", "/api/certdeploy/targets", map[string]any{"name": "bad name!", "kind": "foundryvtt", "host": "x"}, nil); code != 400 {
		t.Fatalf("bad name accepted: %d", code)
	}
	if code := c.do("POST", "/api/certdeploy/targets", map[string]any{"name": "x", "kind": "exchange", "host": "x"}, nil); code != 400 {
		t.Fatalf("unknown kind accepted: %d", code)
	}
	var tg certdeploy.Target
	if code := c.do("POST", "/api/certdeploy/targets", map[string]any{
		"name": "foundry", "kind": "foundryvtt", "host": "foundry.example.lan", "cert_id": cert.ID,
		"options":     map[string]string{"data_path": "/srv/foundry", "unknown_key": "dropped"},
		"credentials": map[string]string{"username": "root", "password": "hunter2"},
	}, &tg); code != 201 {
		t.Fatalf("create: %d", code)
	}
	if tg.Port != 22 || tg.Options["unknown_key"] != "" {
		t.Fatalf("target: %+v", tg)
	}
	var list []map[string]any
	c.do("GET", "/api/certdeploy/targets", nil, &list)
	raw, _ := jsonString(list)
	if strings.Contains(raw, "hunter2") || !strings.Contains(raw, `"password":true`) {
		t.Fatalf("list must flag, not show, credentials: %s", raw)
	}

	var plan certdeploy.Plan
	if code := c.do("POST", "/api/certdeploy/plan", map[string]any{"target_id": tg.ID, "cert_id": cert.ID}, &plan); code != 200 {
		t.Fatalf("plan: %d", code)
	}
	if plan.Blocked != "" || len(plan.Steps) != 4 || plan.Steps[2].Path != "/srv/foundry/Config/options.json" {
		t.Fatalf("plan: %+v", plan)
	}
	if code := c.do("POST", "/api/certdeploy/plan", map[string]any{"target_id": tg.ID, "cert_id": 999}, nil); code != 404 {
		t.Fatalf("missing cert: %d", code)
	}

	// a viewer can look but not deploy
	c.do("POST", "/api/users", map[string]string{"username": "viv", "password": "another-long-password", "role": "viewer"}, nil)
	jar2, _ := cookiejar.New(nil)
	v := &client{t: t, base: ncc.URL, hc: &http.Client{Jar: jar2}}
	v.do("POST", "/api/login", map[string]string{"username": "viv", "password": "another-long-password"}, &login)
	v.csrf = login.CSRF
	if code := v.do("GET", "/api/certdeploy/targets", nil, nil); code != 200 {
		t.Fatalf("viewer list: %d", code)
	}
	if code := v.do("POST", "/api/certdeploy/deploy", map[string]any{"target_id": tg.ID, "cert_id": cert.ID}, nil); code != 403 {
		t.Fatalf("viewer deploy: %d", code)
	}

	if code := c.do("DELETE", "/api/certdeploy/targets/"+itoa(tg.ID), nil, nil); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	var paths []string
	c.do("GET", "/api/vault/secrets", nil, &paths)
	for _, p := range paths {
		if strings.HasPrefix(p, "deploy/") {
			t.Fatalf("login left in vault: %v", paths)
		}
	}
}

func jsonString(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
