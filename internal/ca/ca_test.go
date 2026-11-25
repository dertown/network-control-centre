package ca_test

import (
	"context"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/ca"
	"github.com/dertown/network-control-centre/internal/pki"
	"github.com/dertown/network-control-centre/internal/store"
	"github.com/dertown/network-control-centre/internal/vault"
)

type env struct {
	svc   *ca.Service
	vault *vault.Local
	certs *pki.Inventory
	st    *store.Store
}

func newEnv(t *testing.T) env {
	t.Helper()
	st, err := store.OpenPath(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	v := vault.NewLocal(st.DB)
	if err := v.Initialize(context.Background(), "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	certs := &pki.Inventory{DB: st.DB, Vault: v}
	return env{svc: &ca.Service{DB: st.DB, Vault: v, Certs: certs}, vault: v, certs: certs, st: st}
}

// fast keys keep the tests quick; RSA paths are covered in TestRSADefaults
func makeCA(t *testing.T, e env, domains ...string) (*ca.CA, *ca.CA) {
	t.Helper()
	ctx := context.Background()
	root, err := e.svc.CreateRoot(ctx, ca.RootRequest{Name: "Home Root CA", Organization: "Home", KeyType: "ecdsa-p256", Years: 10, PermittedDomains: domains}, "derek")
	if err != nil {
		t.Fatal(err)
	}
	sub, err := e.svc.CreateIntermediate(ctx, root.ID, ca.IntermediateRequest{Name: "Home Issuing CA", KeyType: "ecdsa-p256"}, "derek")
	if err != nil {
		t.Fatal(err)
	}
	return root, sub
}

func TestCreateRootAndIntermediate(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root, sub := makeCA(t, e, "home.arpa", ".lan")

	if !root.Root || !root.Cert().IsCA || root.Cert().Subject.String() != root.Cert().Issuer.String() {
		t.Fatal("root is not a self-signed CA")
	}
	if root.Cert().KeyUsage&x509.KeyUsageCertSign == 0 || root.Cert().KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Fatal("root cannot sign certificates and CRLs")
	}
	if got := strings.Join(root.PermittedDomains, ","); got != "home.arpa,lan" {
		t.Fatalf("permitted domains %q", got)
	}
	if sub.Root || sub.ParentID != root.ID || !sub.Cert().MaxPathLenZero {
		t.Fatalf("intermediate: %+v", sub)
	}
	if err := sub.Cert().CheckSignatureFrom(root.Cert()); err != nil {
		t.Fatal("intermediate not signed by root:", err)
	}
	if strings.Join(sub.Cert().PermittedDNSDomains, ",") != "home.arpa,lan" {
		t.Fatal("intermediate did not inherit the allowed domains")
	}
	if sub.NotAfter.After(root.NotAfter) {
		t.Fatal("intermediate outlives the root")
	}

	// keys only in the vault, under ca/, encrypted
	paths, _ := e.vault.List(ctx, "ca/")
	if len(paths) != 2 {
		t.Fatalf("vault paths %v", paths)
	}
	var raw string
	_ = e.st.DB.QueryRow(`SELECT COUNT(*) FROM cas WHERE cert_pem LIKE '%PRIVATE KEY%'`).Scan(&raw)
	if raw != "0" {
		t.Fatal("a private key ended up in the cas table")
	}

	// both CA certificates are in the inventory, without keys
	list, _ := e.certs.List(ctx)
	if len(list) != 2 {
		t.Fatalf("inventory has %d entries", len(list))
	}
	for _, c := range list {
		if c.HasKey || !c.IsCA {
			t.Fatalf("inventory entry %s: has_key=%v is_ca=%v", c.Name, c.HasKey, c.IsCA)
		}
	}
	cas, _ := e.svc.List(ctx)
	if len(cas) != 2 || !cas[1].Issuing || cas[0].Issuing || cas[0].InventoryID == 0 {
		t.Fatalf("list: %+v", cas)
	}

	// names must be unique, also against the inventory
	if _, err := e.svc.CreateRoot(ctx, ca.RootRequest{Name: "Home Root CA", KeyType: "ecdsa-p256"}, "x"); err == nil {
		t.Fatal("duplicate CA name accepted")
	}
	if _, err := e.svc.CreateRoot(ctx, ca.RootRequest{Name: "Bad", KeyType: "dsa"}, "x"); err == nil {
		t.Fatal("unknown key type accepted")
	}
	if _, err := e.svc.CreateIntermediate(ctx, sub.ID, ca.IntermediateRequest{Name: "Third level", KeyType: "ecdsa-p256"}, "x"); err == nil {
		t.Fatal("an intermediate under an intermediate was allowed (path length 0)")
	}
}

func TestIssueRenewRevoke(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root, sub := makeCA(t, e, "home.arpa")

	res, err := e.svc.Issue(ctx, 0, ca.IssueRequest{DNSNames: []string{"NAS.home.arpa.", "nas.home.arpa"}, IPs: []string{"192.168.1.10"}, KeyType: "ecdsa-p256"}, "derek")
	if err != nil {
		t.Fatal(err)
	}
	if res.Issued.CAID != sub.ID {
		t.Fatal("not issued by the intermediate (the issuing CA)")
	}
	if res.Cert.Name != "nas.home.arpa" || !res.Cert.HasKey || !res.Cert.ChainComplete || len(res.Cert.Chain) != 2 {
		t.Fatalf("inventory entry: %+v", res.Cert)
	}
	certPEM, keyPEM, err := e.certs.Material(ctx, res.Cert.ID)
	if err != nil || !strings.Contains(keyPEM, "PRIVATE KEY") {
		t.Fatalf("material: %v", err)
	}
	chain, _ := pki.ParseChain(certPEM)
	leaf := chain[0]
	if strings.Join(leaf.DNSNames, ",") != "nas.home.arpa" || len(leaf.IPAddresses) != 1 {
		t.Fatalf("SANs %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
	if leaf.IsCA || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatal("wrong usage")
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d < 396*24*time.Hour || d > 398*24*time.Hour {
		t.Fatalf("validity %v, want 397 days", d)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert())
	inter := x509.NewCertPool()
	inter.AddCert(chain[1])
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: "nas.home.arpa"}); err != nil {
		t.Fatal("does not verify as a client would:", err)
	}

	// outside the allowed domains, too long, duplicate name
	if _, err := e.svc.Issue(ctx, 0, ca.IssueRequest{DNSNames: []string{"www.google.com"}, KeyType: "ecdsa-p256"}, "x"); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("outside name: %v", err)
	}
	if _, err := e.svc.Issue(ctx, 0, ca.IssueRequest{DNSNames: []string{"a.home.arpa"}, Days: 900}, "x"); err == nil {
		t.Fatal("900 days accepted")
	}
	if _, err := e.svc.Issue(ctx, 0, ca.IssueRequest{DNSNames: []string{"nas.home.arpa"}, KeyType: "ecdsa-p256"}, "x"); err == nil || !strings.Contains(err.Error(), "renew") {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := e.svc.Issue(ctx, 0, ca.IssueRequest{DNSNames: []string{"bad name.home.arpa"}}, "x"); err == nil {
		t.Fatal("bad host name accepted")
	}

	// a wildcard, client usage, issued by the root directly
	w, err := e.svc.Issue(ctx, root.ID, ca.IssueRequest{DNSNames: []string{"*.home.arpa"}, Usage: "client", KeyType: "ecdsa-p256"}, "x")
	if err != nil {
		t.Fatal(err)
	}
	if w.Cert.Name != "wildcard.home.arpa" || w.Issued.CAName != "Home Root CA" {
		t.Fatalf("wildcard: %+v %+v", w.Cert, w.Issued)
	}

	// renew: same inventory entry (so deploy targets keep working), new serial
	ren, err := e.svc.Renew(ctx, res.Issued.ID, true, "derek")
	if err != nil {
		t.Fatal(err)
	}
	if ren.Cert.ID != res.Cert.ID || ren.Issued.Serial == res.Issued.Serial || ren.Cert.Fingerprint == res.Cert.Fingerprint {
		t.Fatal("renewal did not replace the inventory certificate in place")
	}
	old, _ := e.svc.GetIssued(ctx, res.Issued.ID)
	if old.Status != "revoked" || old.ReplacedBy != ren.Issued.ID || old.InventoryID != 0 {
		t.Fatalf("old after renew: %+v", old)
	}
	if _, err := e.svc.Renew(ctx, res.Issued.ID, false, "x"); err == nil {
		t.Fatal("renewing a replaced certificate twice was allowed")
	}

	// the CRL lists the revoked serial and is signed by the intermediate
	der, err := e.svc.CRL(ctx, sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(sub.Cert()); err != nil {
		t.Fatal("CRL signature:", err)
	}
	want, _ := new(big.Int).SetString(res.Issued.Serial, 16)
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(want) != 0 || crl.RevokedCertificateEntries[0].ReasonCode != 4 {
		t.Fatalf("CRL entries %+v", crl.RevokedCertificateEntries)
	}
	if _, err := e.svc.Revoke(ctx, res.Issued.ID, 1); err == nil {
		t.Fatal("revoked twice")
	}

	issued, _ := e.svc.ListIssued(ctx, 0)
	if len(issued) != 3 {
		t.Fatalf("%d issued", len(issued))
	}

	// a sealed vault stops signing, but the last CRL is still served
	e.vault.Seal()
	if _, err := e.svc.Issue(ctx, 0, ca.IssueRequest{DNSNames: []string{"x.home.arpa"}}, "x"); !errors.Is(err, vault.ErrSealed) {
		t.Fatalf("issue while sealed: %v", err)
	}
	if _, err := e.svc.Revoke(ctx, ren.Issued.ID, 0); !errors.Is(err, vault.ErrSealed) {
		t.Fatalf("revoke while sealed: %v", err)
	}
	if got, _ := e.svc.GetIssued(ctx, ren.Issued.ID); got.Status == "revoked" {
		t.Fatal("revocation recorded although the CRL could not be signed")
	}
	if again, err := e.svc.CRL(ctx, sub.ID); err != nil || len(again) == 0 {
		t.Fatalf("CRL while sealed: %v", err)
	}
}

func TestDeleteCA(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root, sub := makeCA(t, e)
	res, err := e.svc.Issue(ctx, sub.ID, ca.IssueRequest{DNSNames: []string{"a.lan"}, KeyType: "ecdsa-p256"}, "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Delete(ctx, root.ID); err == nil {
		t.Fatal("deleted a root with an intermediate")
	}
	if _, err := e.svc.Delete(ctx, sub.ID); err == nil {
		t.Fatal("deleted a CA with a valid certificate")
	}
	if _, err := e.svc.Revoke(ctx, res.Issued.ID, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Delete(ctx, sub.ID); err != nil {
		t.Fatal(err)
	}
	if paths, _ := e.vault.List(ctx, "ca/"); len(paths) != 1 {
		t.Fatalf("CA key left in the vault: %v", paths)
	}
}

func TestRSADefaults(t *testing.T) {
	if testing.Short() {
		t.Skip("RSA key generation")
	}
	e := newEnv(t)
	ctx := context.Background()
	root, err := e.svc.CreateRoot(ctx, ca.RootRequest{Name: "RSA Root", KeyType: "rsa-2048"}, "x")
	if err != nil {
		t.Fatal(err)
	}
	if d := root.NotAfter.Sub(root.NotBefore); d < 9*365*24*time.Hour {
		t.Fatalf("default root validity %v", d)
	}
	res, err := e.svc.Issue(ctx, 0, ca.IssueRequest{DNSNames: []string{"printer"}}, "x")
	if err != nil {
		t.Fatal(err)
	}
	if res.Issued.KeyType != "rsa-2048" {
		t.Fatal("default leaf key is not RSA 2048")
	}
	certPEM, _, _ := e.certs.Material(ctx, res.Cert.ID)
	leaf, _ := pki.ParseChain(certPEM)
	if leaf[0].KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatal("RSA leaf without key encipherment")
	}
}

func TestDownloadsAndInstall(t *testing.T) {
	e := newEnv(t)
	root, _ := makeCA(t, e, "home.arpa")
	mc := ca.MobileConfig(root)
	if err := xml.Unmarshal(mc, new(struct{})); err != nil {
		t.Fatal("mobileconfig is not XML:", err)
	}
	if !strings.Contains(string(mc), "com.apple.security.root") {
		t.Fatal("mobileconfig without a root payload")
	}
	txt := ca.InstallText(root, "https://ncc.home.arpa/")
	for _, want := range []string{"https://ncc.home.arpa/pki/ca/1.crt", "update-ca-certificates", "Import-Certificate", "certutil -dspublish", root.Thumbprint} {
		if !strings.Contains(txt, want) {
			t.Errorf("install text lacks %q", want)
		}
	}
	plats := ca.Install(root, "https://ncc")
	push := map[string]string{}
	for _, p := range plats {
		push[p.ID] = p.Pushable
	}
	if push["linux"] != "linux-trust" || push["windows"] != "windows-trust" {
		t.Fatalf("pushable %v", push)
	}
}

func TestSuggest(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, _ = makeCA(t, e, "home.arpa")
	res, err := e.svc.Issue(ctx, 0, ca.IssueRequest{DNSNames: []string{"nas.home.arpa"}, KeyType: "ecdsa-p256"}, "x")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _ := e.certs.PEM(ctx, res.Cert.ID)
	chain, _ := pki.ParseChain(certPEM)
	recs := []ca.HostRecord{
		{Name: "nas.home.arpa.", Type: "A", Values: []string{"192.168.1.10"}, Zone: "home.arpa.", Server: "pdns"},
		{Name: "proxmox.home.arpa.", Type: "A", Values: []string{"192.168.1.20"}, Zone: "home.arpa.", Server: "pdns"},
		{Name: "proxmox.home.arpa.", Type: "AAAA", Values: []string{"fd00::20"}, Zone: "home.arpa.", Server: "pdns"},
		{Name: "grafana.home.arpa.", Type: "CNAME", Values: []string{"proxmox.home.arpa."}, Zone: "home.arpa.", Server: "pdns"},
		{Name: "_dmarc.home.arpa.", Type: "TXT", Values: []string{"v=DMARC1"}, Zone: "home.arpa.", Server: "pdns"},
		{Name: "_sip._tcp.home.arpa.", Type: "A", Values: []string{"1.2.3.4"}, Zone: "home.arpa.", Server: "pdns"},
		{Name: "*.apps.home.arpa.", Type: "A", Values: []string{"1.2.3.4"}, Zone: "home.arpa.", Server: "pdns"},
		{Name: "10.1.168.192.in-addr.arpa.", Type: "A", Values: []string{"1.2.3.4"}, Zone: "1.168.192.in-addr.arpa.", Server: "pdns"},
		{Name: "www.example.com.", Type: "A", Values: []string{"203.0.113.5"}, Zone: "example.com.", Server: "bind"},
	}
	got := ca.Suggest(recs, []ca.Holder{{Name: "nas.home.arpa", Cert: chain[0]}}, []string{"home.arpa"}, time.Now())
	byName := map[string]ca.Suggestion{}
	for _, s := range got {
		byName[s.Name] = s
	}
	if len(got) != 5 {
		t.Fatalf("suggestions: %+v", got)
	}
	if byName["nas.home.arpa"].CoveredBy != "nas.home.arpa" {
		t.Fatal("nas should be covered by its certificate")
	}
	if p := byName["proxmox.home.arpa"]; p.CoveredBy != "" || len(p.IPs) != 2 {
		t.Fatalf("proxmox: %+v", p)
	}
	if byName["grafana.home.arpa"].Alias != "proxmox.home.arpa" {
		t.Fatal("CNAME alias not kept")
	}
	if w := byName["*.home.arpa"]; w.Kind != "wildcard" || w.Hosts != 2 {
		t.Fatalf("wildcard: %+v", w)
	}
	if !byName["www.example.com"].Outside {
		t.Fatal("example.com is outside the CA's domains")
	}
	if _, ok := byName["_dmarc.home.arpa"]; ok {
		t.Fatal("TXT record suggested")
	}
}
