package api_test

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dertown/network-control-centre/internal/ca"
	"github.com/dertown/network-control-centre/internal/certdeploy"
	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/mocklab"
	"github.com/dertown/network-control-centre/internal/pki"
)

func TestInternalCAAPI(t *testing.T) {
	c := adminClient(t)

	var list struct {
		CAs      []ca.CA  `json:"cas"`
		KeyTypes []string `json:"key_types"`
	}
	if code := c.do("GET", "/api/ca", nil, &list); code != 200 || len(list.CAs) != 0 || len(list.KeyTypes) == 0 {
		t.Fatalf("empty list: %d %+v", code, list)
	}
	// issuing before there is a CA says what to do
	var e struct{ Error string }
	if code := c.do("POST", "/api/ca/issue", map[string]any{"dns_names": []string{"a.home.lan"}}, &e); code != 400 || !strings.Contains(e.Error, "create an internal CA") {
		t.Fatalf("issue without CA: %d %s", code, e.Error)
	}

	// the wizard: root + intermediate in one call
	var made struct {
		Root         *ca.CA `json:"root"`
		Intermediate *ca.CA `json:"intermediate"`
		Error        string `json:"error"`
	}
	if code := c.do("POST", "/api/ca", map[string]any{"name": "Home Root CA", "organization": "Home", "key_type": "ecdsa-p256", "years": 10,
		"permitted_domains": []string{"home.lan"}, "publish_crl": true, "intermediate": map[string]any{"name": "Home Issuing CA", "years": 5}}, &made); code != 201 || made.Error != "" || made.Intermediate == nil {
		t.Fatalf("create: %d %+v", code, made)
	}
	if !strings.HasSuffix(made.Intermediate.CRLURL, "/pki/ca/"+itoa(made.Intermediate.ID)+".crl") || made.Root.CRLURL == "" {
		t.Fatalf("CRL addresses: %q %q", made.Root.CRLURL, made.Intermediate.CRLURL)
	}
	if code := c.do("POST", "/api/ca", map[string]any{"name": "Home Root CA", "key_type": "ecdsa-p256"}, &e); code != 400 {
		t.Fatalf("duplicate CA: %d", code)
	}

	// suggestions from the PowerDNS zone
	pdns := httptest.NewServer(mocklab.NewPowerDNS("pdns-key"))
	defer pdns.Close()
	var dnsT core.Target
	if code := c.do("POST", "/api/targets", map[string]any{"kind": "powerdns", "category": "dns", "name": "pdns", "address": pdns.URL,
		"credentials": map[string]string{"api_key": "pdns-key"}}, &dnsT); code != 201 {
		t.Fatalf("dns target: %d", code)
	}
	var sug struct {
		Suggestions []ca.Suggestion `json:"suggestions"`
		Problems    []string        `json:"problems"`
	}
	c.do("GET", "/api/ca/suggestions", nil, &sug)
	names := map[string]ca.Suggestion{}
	for _, s := range sug.Suggestions {
		names[s.Name] = s
	}
	if _, ok := names["router.home.lan"]; !ok || names["*.home.lan"].Kind != "wildcard" || len(sug.Problems) != 0 {
		t.Fatalf("suggestions: %+v", sug)
	}
	if names["router.home.lan"].IPs[0] != "192.168.1.1" {
		t.Fatal("router address missing")
	}

	// issue router.home.lan as the wizard would, then it is covered
	var res ca.IssueResult
	if code := c.do("POST", "/api/ca/issue", map[string]any{"dns_names": []string{"router.home.lan"}, "ips": []string{"192.168.1.1"}, "key_type": "ecdsa-p256"}, &res); code != 201 {
		t.Fatalf("issue: %d", code)
	}
	if res.Issued.CAName != "Home Issuing CA" || !res.Cert.HasKey || len(res.Cert.Chain) != 2 {
		t.Fatalf("issued: %+v %+v", res.Issued, res.Cert)
	}
	var leafPEM string
	{
		resp, _ := c.hc.Get(c.base + "/api/certs/" + itoa(res.Cert.ID) + "/pem")
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		leafPEM = string(b)
	}
	if chain, err := pki.ParseChain(leafPEM); err != nil || len(chain[0].CRLDistributionPoints) != 1 || chain[0].CRLDistributionPoints[0] != made.Intermediate.CRLURL {
		t.Fatalf("leaf CRL distribution point: %v", err)
	}
	c.do("GET", "/api/ca/suggestions", nil, &sug)
	for _, s := range sug.Suggestions {
		if s.Name == "router.home.lan" && s.CoveredBy != "router.home.lan" {
			t.Fatalf("router not covered after issuing: %+v", s)
		}
	}
	if code := c.do("POST", "/api/ca/issue", map[string]any{"dns_names": []string{"www.google.com"}}, &e); code != 400 || !strings.Contains(e.Error, "outside") {
		t.Fatalf("outside domains: %d %s", code, e.Error)
	}

	// the CA key never leaves through the vault API
	var paths []string
	c.do("GET", "/api/vault/secrets", nil, &paths)
	caPath := ""
	for _, p := range paths {
		if strings.HasPrefix(p, "ca/") {
			caPath = p
		}
	}
	if caPath == "" {
		t.Fatalf("no CA key in the vault: %v", paths)
	}
	for _, try := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/vault/reveal", map[string]string{"path": caPath}},
		{"POST", "/api/vault/reveal", map[string]string{"path": "/" + caPath + "/"}},
		{"PUT", "/api/vault/secrets/" + caPath, map[string]string{"private_key": "x"}},
		{"DELETE", "/api/vault/secrets/" + caPath, nil},
	} {
		if code := c.do(try.method, try.path, try.body, nil); code != 403 {
			t.Fatalf("%s %s: %d, want 403", try.method, try.path, code)
		}
	}
	// the issued certificate's own key can still be revealed by an admin (as for imports)
	if code := c.do("POST", "/api/vault/reveal", map[string]string{"path": "certs/router.home.lan"}, nil); code != 200 {
		t.Fatalf("reveal leaf key: %d", code)
	}

	// renew keeps the inventory entry; revoke puts it on the CRL
	var ren ca.IssueResult
	if code := c.do("POST", "/api/ca/issued/"+itoa(res.Issued.ID)+"/renew", map[string]any{"revoke_old": false}, &ren); code != 201 || ren.Cert.ID != res.Cert.ID {
		t.Fatalf("renew: %d %+v", code, ren)
	}
	var rev ca.Issued
	if code := c.do("POST", "/api/ca/issued/"+itoa(res.Issued.ID)+"/revoke", map[string]any{"reason": 4}, &rev); code != 200 || rev.Status != "revoked" {
		t.Fatalf("revoke: %d %+v", code, rev)
	}
	var issued []ca.Issued
	c.do("GET", "/api/ca/issued", nil, &issued)
	if len(issued) != 2 {
		t.Fatalf("issued list %d", len(issued))
	}

	// public downloads, no login
	get := func(path string) (int, string, []byte) {
		resp, err := http.Get(c.base + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Content-Type"), b
	}
	rootID := itoa(made.Root.ID)
	code, ct, body := get("/pki/ca/" + rootID + ".pem")
	if code != 200 || ct != "application/x-pem-file" || !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Fatalf("pem: %d %s", code, ct)
	}
	code, _, body = get("/pki/ca/" + rootID + ".crt")
	if x, err := x509.ParseCertificate(body); code != 200 || err != nil || !x.IsCA {
		t.Fatalf("crt (DER): %d %v", code, err)
	}
	code, ct, body = get("/pki/ca/" + itoa(made.Intermediate.ID) + ".crl")
	crl, err := x509.ParseRevocationList(body)
	if code != 200 || ct != "application/pkix-crl" || err != nil || len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("crl: %d %s %v", code, ct, err)
	}
	if code, _, body = get("/pki/ca/" + rootID + ".mobileconfig"); code != 200 || !strings.Contains(string(body), "com.apple.security.root") {
		t.Fatalf("mobileconfig %d", code)
	}
	if code, _, body = get("/pki/ca/" + itoa(made.Intermediate.ID) + "-install.txt"); code != 200 || !strings.Contains(string(body), "Trusting Home Root CA") {
		t.Fatalf("install text %d %s", code, body)
	}
	if code, _, _ = get("/pki/ca/99.pem"); code != 404 {
		t.Fatalf("unknown CA: %d", code)
	}
	if code, _, _ = get("/api/ca"); code != 401 {
		t.Fatalf("the CA list needs a login: %d", code)
	}
	var plats []ca.Platform
	if code := c.do("GET", "/api/ca/"+rootID+"/install", nil, &plats); code != 200 || len(plats) < 5 {
		t.Fatalf("install: %d", code)
	}

	// the root is in the inventory without a key and can go to a trust-store server
	var certs []pki.Cert
	c.do("GET", "/api/certs", nil, &certs)
	var rootCert *pki.Cert
	for i := range certs {
		if certs[i].Name == "Home Root CA" {
			rootCert = &certs[i]
		}
	}
	if rootCert == nil || rootCert.HasKey || !rootCert.IsCA {
		t.Fatalf("root in inventory: %+v", rootCert)
	}
	var kinds []certdeploy.Kind
	c.do("GET", "/api/certdeploy/kinds", nil, &kinds)
	trust := 0
	for _, k := range kinds {
		if k.Trust {
			trust++
		}
	}
	if trust != 2 {
		t.Fatalf("%d trust-store kinds", trust)
	}
	var tg certdeploy.Target
	if code := c.do("POST", "/api/certdeploy/targets", map[string]any{"name": "app1", "kind": "linux-trust", "host": "app1.home.lan"}, &tg); code != 201 {
		t.Fatalf("trust target: %d", code)
	}
	var plan certdeploy.Plan
	c.do("POST", "/api/certdeploy/plan", map[string]any{"target_id": tg.ID, "cert_id": rootCert.ID}, &plan)
	if plan.Blocked != "" || len(plan.Steps) != 3 {
		t.Fatalf("trust plan: %+v", plan)
	}

	// audit trail
	var entries []struct{ Action string }
	c.do("GET", "/api/audit?limit=100", nil, &entries)
	seen := map[string]bool{}
	for _, en := range entries {
		seen[en.Action] = true
	}
	for _, a := range []string{"ca.create", "ca.intermediate", "ca.issue", "ca.renew", "ca.revoke", "vault.reveal.refused", "vault.put.refused"} {
		if !seen[a] {
			t.Errorf("audit lacks %s", a)
		}
	}
}
