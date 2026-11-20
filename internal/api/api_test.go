package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/api"
	"github.com/dertown/network-control-centre/internal/audit"
	"github.com/dertown/network-control-centre/internal/auth"
	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/mocklab"
	"github.com/dertown/network-control-centre/internal/pki"
	"github.com/dertown/network-control-centre/internal/store"
	"github.com/dertown/network-control-centre/internal/vault"

	_ "github.com/dertown/network-control-centre/internal/dns/powerdns"
	_ "github.com/dertown/network-control-centre/internal/drivers/unifi"
)

func fakeUniFi(t *testing.T) *httptest.Server { return httptest.NewTLSServer(mocklab.UniFi()) }

type client struct {
	t    *testing.T
	base string
	hc   *http.Client
	csrf string
}

func (c *client) do(method, path string, body any, out any) int {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			c.t.Fatalf("%s %s: %v: %s", method, path, err, raw)
		}
	}
	if resp.StatusCode >= 400 && out == nil {
		c.t.Logf("%s %s -> %d %s", method, path, resp.StatusCode, raw)
	}
	return resp.StatusCode
}

func newNCC(t *testing.T) (*httptest.Server, *core.Poller) {
	st, err := store.OpenPath(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	vs := vault.NewLocal(st.DB)
	hub := core.NewHub()
	targets := &core.Targets{DB: st.DB}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	poller := &core.Poller{DB: st.DB, Targets: targets, Vault: vs, Hub: hub, Interval: time.Hour, Log: log}
	srv := &api.Server{Store: st, Auth: auth.New(st.DB), Audit: audit.New(st.DB), Vault: vs, Targets: targets,
		Poller: poller, Hub: hub, Certs: &pki.Inventory{DB: st.DB, Vault: vs}, Log: log}
	return httptest.NewServer(srv.Handler()), poller
}

func TestEndToEnd(t *testing.T) {
	ncc, _ := newNCC(t)
	defer ncc.Close()
	pd := mocklab.NewPowerDNS("pdns-key")
	pdns := httptest.NewServer(pd)
	defer pdns.Close()
	unifi := fakeUniFi(t)
	defer unifi.Close()

	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: ncc.URL, hc: &http.Client{Jar: jar}}

	// first-run setup
	var setup struct {
		NeedsAdmin bool `json:"needs_admin"`
	}
	c.do("GET", "/api/setup", nil, &setup)
	if !setup.NeedsAdmin {
		t.Fatal("fresh install should need an admin")
	}
	if code := c.do("POST", "/api/setup", map[string]string{"username": "derek", "password": "a-long-password", "vault_passphrase": "vault passphrase 1"}, nil); code != 201 {
		t.Fatalf("setup: %d", code)
	}
	if code := c.do("POST", "/api/setup", map[string]string{"username": "x", "password": "a-long-password"}, nil); code != 409 {
		t.Fatalf("second setup allowed: %d", code)
	}

	// auth required
	if code := c.do("GET", "/api/devices", nil, nil); code != 401 {
		t.Fatalf("unauthenticated: %d", code)
	}
	var login struct {
		CSRF string `json:"csrf"`
	}
	if code := c.do("POST", "/api/login", map[string]string{"username": "derek", "password": "a-long-password"}, &login); code != 200 {
		t.Fatalf("login: %d", code)
	}
	// writes without CSRF are refused
	if code := c.do("POST", "/api/targets", map[string]any{}, nil); code != 403 {
		t.Fatalf("missing csrf: %d", code)
	}
	c.csrf = login.CSRF

	// add the UniFi console and poll it
	var tgt core.Target
	if code := c.do("POST", "/api/targets", map[string]any{
		"kind": "unifi", "category": "device", "name": "dream-router", "address": unifi.URL,
		"credentials": map[string]string{"username": "ncc", "password": "demo-password"},
	}, &tgt); code != 201 {
		t.Fatalf("create target: %d", code)
	}
	var polled map[string]any
	deadline := time.Now().Add(5 * time.Second)
	for {
		code := c.do("POST", "/api/targets/"+itoa(tgt.ID)+"/poll", nil, &polled)
		if code == 200 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond) // the background first poll may still be running
	}
	if n, _ := polled["devices"].(float64); n < 6 {
		t.Fatalf("poll: %v", polled)
	}
	var devices []map[string]any
	c.do("GET", "/api/devices", nil, &devices)
	found := false
	for _, d := range devices {
		if d["model"] == "Dream Router 7" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Dream Router 7 not in %v", devices)
	}
	var ts []core.Target
	c.do("GET", "/api/targets?category=device", nil, &ts)
	if len(ts) != 1 || len(ts[0].Options["tls_fingerprint"]) != 64 {
		t.Fatalf("fingerprint not pinned: %+v", ts)
	}
	var graph core.Graph
	c.do("GET", "/api/topology?clients=1", nil, &graph)
	if len(graph.Nodes) < 10 || len(graph.Edges) < 8 {
		t.Fatalf("graph too small: %d nodes %d edges", len(graph.Nodes), len(graph.Edges))
	}

	// add PowerDNS, list zones, add an A record with PTR
	var dnsT core.Target
	c.do("POST", "/api/targets", map[string]any{
		"kind": "powerdns", "category": "dns", "name": "pdns", "address": pdns.URL,
		"credentials": map[string]string{"api_key": "pdns-key"},
	}, &dnsT)
	var zones []map[string]any
	if code := c.do("GET", "/api/dns/"+itoa(dnsT.ID)+"/zones", nil, &zones); code != 200 || len(zones) != 2 {
		t.Fatalf("zones: %d %v", code, zones)
	}

	// DNS servers are health-checked like devices, and failures show on the target
	if code := c.do("POST", "/api/targets/"+itoa(dnsT.ID)+"/poll", nil, nil); code != 200 {
		t.Fatalf("dns check: %d", code)
	}
	var badKey, badSID core.Target
	c.do("POST", "/api/targets", map[string]any{
		"kind": "powerdns", "category": "dns", "name": "pdns-badkey", "address": pdns.URL,
		"credentials": map[string]string{"api_key": "wrong"},
	}, &badKey)
	c.do("POST", "/api/targets", map[string]any{
		"kind": "powerdns", "category": "dns", "name": "pdns-badsid", "address": pdns.URL + "/api/v1",
		"options": map[string]string{"server_id": "nope"}, "credentials": map[string]string{"api_key": "pdns-key"},
	}, &badSID)
	for _, id := range []int64{badKey.ID, badSID.ID} {
		for i := 0; i < 20; i++ { // the background first check may still be running
			if code := c.do("POST", "/api/targets/"+itoa(id)+"/poll", nil, nil); code == 502 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	var all []core.Target
	c.do("GET", "/api/targets?category=dns", nil, &all)
	status := map[string]core.Target{}
	for _, tg := range all {
		status[tg.Name] = tg
	}
	if tg := status["pdns"]; tg.LastError != "" || tg.LastPoll == nil {
		t.Fatalf("good pdns status: %+v", tg)
	}
	if e := status["pdns-badkey"].LastError; !strings.Contains(e, "API key was rejected") {
		t.Fatalf("bad key status: %q", e)
	}
	if e := status["pdns-badsid"].LastError; !strings.Contains(e, "HTTP 404") || !strings.Contains(e, `server_id "nope"`) {
		t.Fatalf("bad server_id status: %q", e)
	}
	for _, id := range []int64{badKey.ID, badSID.ID} {
		c.do("DELETE", "/api/targets/"+itoa(id), nil, nil)
	}
	var res struct {
		Applied  bool           `json:"applied"`
		Plan     []api.ZonePlan `json:"plan"`
		Warnings []string       `json:"warnings"`
	}
	body := map[string]any{"ptr": true, "dry_run": true, "changes": []map[string]any{
		{"op": "replace", "rrset": map[string]any{"name": "nas", "type": "a", "ttl": 300, "records": []string{"192.168.1.50"}}},
	}}
	c.do("POST", "/api/dns/"+itoa(dnsT.ID)+"/zones/home.lan./changes", body, &res)
	if res.Applied || len(res.Plan) != 2 || res.Plan[1].Zone != "1.168.192.in-addr.arpa." ||
		res.Plan[1].Changes[0].RRSet.Records[0] != "nas.home.lan." {
		t.Fatalf("dry run plan: %+v", res)
	}
	if len(pd.Patches) != 0 {
		t.Fatal("dry run touched PowerDNS")
	}
	body["dry_run"] = false
	if code := c.do("POST", "/api/dns/"+itoa(dnsT.ID)+"/zones/home.lan./changes", body, &res); code != 200 || !res.Applied {
		t.Fatalf("apply: %d %+v", code, res)
	}
	if len(pd.Patches["home.lan."]) != 1 || len(pd.Patches["1.168.192.in-addr.arpa."]) != 1 {
		t.Fatalf("patches: %v", pd.Patches)
	}
	if !strings.Contains(string(pd.Patches["1.168.192.in-addr.arpa."][0]), `"name":"50.1.168.192.in-addr.arpa."`) ||
		!strings.Contains(string(pd.Patches["1.168.192.in-addr.arpa."][0]), `"content":"nas.home.lan."`) {
		t.Fatalf("ptr patch: %s", pd.Patches["1.168.192.in-addr.arpa."][0])
	}
	var recs []map[string]any
	c.do("GET", "/api/dns/"+itoa(dnsT.ID)+"/zones/home.lan./records", nil, &recs)
	foundNAS := false
	for _, r := range recs {
		if r["name"] == "nas.home.lan." {
			foundNAS = true
		}
	}
	if !foundNAS {
		t.Fatal("new record not listed")
	}

	// deleting with ptr looks up the old address to remove the matching PTR
	del := map[string]any{"ptr": true, "dry_run": true, "changes": []map[string]any{
		{"op": "delete", "rrset": map[string]any{"name": "old", "type": "A"}},
	}}
	c.do("POST", "/api/dns/"+itoa(dnsT.ID)+"/zones/home.lan./changes", del, &res)
	if len(res.Plan) != 2 || res.Plan[1].Changes[0].RRSet.Name != "9.1.168.192.in-addr.arpa." {
		t.Fatalf("delete plan: %+v", res.Plan)
	}

	// invalid record refused before reaching PowerDNS
	bad := map[string]any{"changes": []map[string]any{{"op": "replace", "rrset": map[string]any{"name": "x", "type": "A", "records": []string{"999.1.1.1"}}}}}
	if code := c.do("POST", "/api/dns/"+itoa(dnsT.ID)+"/zones/home.lan./changes", bad, nil); code != 400 {
		t.Fatalf("bad record: %d", code)
	}

	// certificates: import with key, which lands in the vault
	certPEM, keyPEM := selfSigned(t, "nas.home.lan", 20*24*time.Hour)
	var cert pki.Cert
	if code := c.do("POST", "/api/certs", map[string]string{"cert_pem": certPEM, "key_pem": keyPEM}, &cert); code != 201 {
		t.Fatalf("import cert: %d", code)
	}
	if cert.Name != "nas.home.lan" || !cert.HasKey || cert.Status != "expiring" {
		t.Fatalf("cert: %+v", cert)
	}
	otherCert, _ := selfSigned(t, "other", time.Hour)
	_, otherKey := selfSigned(t, "other", time.Hour)
	if code := c.do("POST", "/api/certs", map[string]string{"cert_pem": otherCert, "key_pem": otherKey}, nil); code != 400 {
		t.Fatalf("mismatched key accepted: %d", code)
	}
	var paths []string
	c.do("GET", "/api/vault/secrets", nil, &paths)
	if strings.Join(paths, ",") != "certs/nas.home.lan,targets/device/dream-router,targets/dns/pdns" {
		t.Fatalf("vault paths: %v", paths)
	}
	var redacted struct {
		Values map[string]string `json:"values"`
	}
	c.do("GET", "/api/vault/secrets/targets/dns/pdns", nil, &redacted)
	if redacted.Values["api_key"] == "pdns-key" {
		t.Fatal("secret value leaked without reveal")
	}

	// sealing blocks secret use
	c.do("POST", "/api/vault/seal", nil, nil)
	if code := c.do("GET", "/api/dns/"+itoa(dnsT.ID)+"/zones", nil, nil); code != 423 {
		t.Fatalf("sealed vault: %d", code)
	}
	if code := c.do("POST", "/api/vault/unseal", map[string]string{"passphrase": "vault passphrase 1"}, nil); code != 200 {
		t.Fatalf("unseal: %d", code)
	}

	// the audit chain recorded everything and is intact
	var verify struct {
		Intact bool `json:"intact"`
	}
	c.do("GET", "/api/audit/verify", nil, &verify)
	var entries []audit.Entry
	c.do("GET", "/api/audit", nil, &entries)
	if !verify.Intact || len(entries) < 8 {
		t.Fatalf("audit: intact=%v entries=%d", verify.Intact, len(entries))
	}
	for _, e := range entries {
		if strings.Contains(e.Detail, "pdns-key") || strings.Contains(e.Detail, "PRIVATE KEY") {
			t.Fatalf("secret in audit log: %+v", e)
		}
	}

	// a viewer cannot change DNS
	c.do("POST", "/api/users", map[string]string{"username": "guest", "password": "another-long-pw", "role": "viewer"}, nil)
	jar2, _ := cookiejar.New(nil)
	g := &client{t: t, base: ncc.URL, hc: &http.Client{Jar: jar2}}
	g.do("POST", "/api/login", map[string]string{"username": "guest", "password": "another-long-pw"}, &login)
	g.csrf = login.CSRF
	if code := g.do("POST", "/api/dns/"+itoa(dnsT.ID)+"/zones/home.lan./changes", body, nil); code != 403 {
		t.Fatalf("viewer changed DNS: %d", code)
	}
	if code := g.do("GET", "/api/topology", nil, nil); code != 200 {
		t.Fatalf("viewer topology: %d", code)
	}
}

func itoa(i int64) string { return big.NewInt(i).String() }

func selfSigned(t *testing.T, cn string, life time.Duration) (string, string) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		DNSNames: []string{cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(life)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))
}

var _ = context.Background
