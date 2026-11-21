package certdeploy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/dertown/network-control-centre/internal/pki"
	"github.com/dertown/network-control-centre/internal/store"
	"github.com/dertown/network-control-centre/internal/vault"
)

// ---- test certificates ----

type testPKI struct {
	chainPEM, keyPEM string
	leaf, ca, root   *x509.Certificate
	rootPEM, caPEM   string
}

func newTestPKI(t *testing.T, names ...string) testPKI {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Root CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(3650 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, rootTmpl, &caKey.PublicKey, rootKey)
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		DNSNames: names, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(der)
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	return testPKI{chainPEM: chain, keyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})), leaf: leaf, ca: ca, root: root,
		rootPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})),
		caPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))}
}

type auditRec struct {
	mu      sync.Mutex
	entries []string
}

func (a *auditRec) Record(_ context.Context, actor, action, target string, detail any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, fmt.Sprintf("%s %s %s %v", actor, action, target, detail))
	return nil
}

func newService(t *testing.T) (*Service, *auditRec) {
	t.Helper()
	st, err := store.OpenPath(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	vs := vault.NewLocal(st.DB)
	if err := vs.Initialize(context.Background(), "test passphrase for the vault"); err != nil {
		t.Fatal(err)
	}
	a := &auditRec{}
	return &Service{DB: st.DB, Vault: vs, Certs: &pki.Inventory{DB: st.DB, Vault: vs}, Audit: a, VerifyEvery: 100 * time.Millisecond, VerifyWait: 2 * time.Second}, a
}

func waitDone(t *testing.T, s *Service, id int64) *Deployment {
	t.Helper()
	s.Wait()
	d, err := s.Deployment(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// ---- edits ----

func TestSetINI(t *testing.T) {
	in := "# my web.conf\n[settings]\nhttpport = 8000\nenableSplunkWebSSL = false\n\n[other]\nx = 1\n"
	got := string(SetINI([]byte(in), "settings", []KV{{"enableSplunkWebSSL", "true"}, {"serverCert", "/a.pem"}}))
	want := "# my web.conf\n[settings]\nhttpport = 8000\nenableSplunkWebSSL = true\nserverCert = /a.pem\n\n[other]\nx = 1\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	got = string(SetINI(nil, "sslConfig", []KV{{"serverCert", "/s.pem"}}))
	if got != "[sslConfig]\nserverCert = /s.pem\n" {
		t.Fatalf("new file: %q", got)
	}
	got = string(SetINI([]byte("[general]\r\nserverName = s1\r\n"), "sslConfig", []KV{{"serverCert", "/s.pem"}}))
	if got != "[general]\r\nserverName = s1\r\n\r\n[sslConfig]\r\nserverCert = /s.pem\r\n" {
		t.Fatalf("crlf: %q", got)
	}
}

func TestSetJSONKeepsOrder(t *testing.T) {
	in := `{"port":30000,"upnp":true,"dataPath":"/data","nested":{"a":[1,{"b":2}]},"sslCert":null}`
	out, err := SetJSON([]byte(in), []KV{{"sslCert", "/c.pem"}, {"sslKey", "/k.pem"}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	order := []string{`"port"`, `"upnp"`, `"dataPath"`, `"nested"`, `"sslCert": "/c.pem"`, `"sslKey": "/k.pem"`}
	last := -1
	for _, k := range order {
		i := strings.Index(s, k)
		if i <= last {
			t.Fatalf("%s out of order in\n%s", k, s)
		}
		last = i
	}
}

func TestPFXRoundTrip(t *testing.T) {
	p := newTestPKI(t, "iis.example.lan")
	m, err := NewMaterial("iis", p.chainPEM, p.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pfx, err := m.PFX("secret")
	if err != nil {
		t.Fatal(err)
	}
	_, leaf, cas, err := pkcs12.DecodeChain(pfx, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.Equal(p.leaf) || len(cas) != 1 || !cas[0].Equal(p.ca) {
		t.Fatal("PFX contents differ")
	}
	if len(Thumbprint(leaf)) != 40 {
		t.Fatal("thumbprint length")
	}
}

// ---- in-memory server for kinds whose commands we only record ----

type memConn struct {
	mu    sync.Mutex
	files map[string][]byte
	modes map[string]string
	ran   []string
}

func (m *memConn) WriteFile(_ context.Context, path string, data []byte, mode, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[path] = append([]byte{}, data...)
	m.modes[path] = mode
	return nil
}

func (m *memConn) ReadFile(_ context.Context, path string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return b, nil
}

func (m *memConn) Run(_ context.Context, cmd string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ran = append(m.ran, cmd)
	if strings.HasPrefix(cmd, "id -un") {
		return "root\nsplunk1\n", nil
	}
	return "done", nil
}

func (m *memConn) Close() error { return nil }

func TestSplunkDeployEditsConf(t *testing.T) {
	s, audit := newService(t)
	ctx := context.Background()
	p := newTestPKI(t, "splunk.example.lan")
	c, err := s.Certs.Import(ctx, "splunk.example.lan", p.chainPEM, p.keyPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	mem := &memConn{files: map[string][]byte{
		"/opt/splunk/etc/system/local/web.conf": []byte("[settings]\nhttpport = 8000\n"),
	}, modes: map[string]string{}}
	var accepted string
	s.DialSSH = func(_ context.Context, o SSHOptions) (Conn, string, error) {
		if o.HostKey == "" && o.AcceptHostKey == "" {
			return nil, "SHA256:test", &ErrHostKeyUnknown{Seen: "SHA256:test"}
		}
		accepted = o.AcceptHostKey
		if o.User != "admin" || o.Password != "pw" {
			return nil, "", errors.New("bad login")
		}
		return mem, "SHA256:test", nil
	}
	tg := &Target{Name: "splunk1", Kind: "splunk", Host: "splunk.example.lan", Options: map[string]string{"component": "web+splunkd", "https_port": ""}}
	if err := s.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCredentials(ctx, tg.ID, map[string]string{"username": "admin", "password": "pw"}, nil); err != nil {
		t.Fatal(err)
	}
	plan, err := s.Plan(ctx, tg.ID, c.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Blocked != "" || plan.Connection == nil || !plan.Connection.Trust || plan.Connection.Fingerprint != "SHA256:test" {
		t.Fatalf("plan: %+v conn %+v", plan, plan.Connection)
	}
	d, err := s.Deploy(ctx, tg.ID, c.ID, "SHA256:test", "alice")
	if err != nil {
		t.Fatal(err)
	}
	d = waitDone(t, s, d.ID)
	if d.Status != "ok" {
		t.Fatalf("deploy failed: %+v", d)
	}
	if accepted != "SHA256:test" {
		t.Fatal("fingerprint not passed on")
	}
	web := string(mem.files["/opt/splunk/etc/system/local/web.conf"])
	for _, want := range []string{"httpport = 8000", "enableSplunkWebSSL = true", "serverCert = /opt/splunk/etc/auth/mycerts/splunk.example.lan-web.pem", "privKeyPath = /opt/splunk/etc/auth/mycerts/splunk.example.lan.key"} {
		if !strings.Contains(web, want) {
			t.Fatalf("web.conf missing %q:\n%s", want, web)
		}
	}
	if !strings.Contains(string(mem.files["/opt/splunk/etc/system/local/server.conf"]), "[sslConfig]\nserverCert = /opt/splunk/etc/auth/mycerts/splunk.example.lan-server.pem") {
		t.Fatal("server.conf not written")
	}
	combined := string(mem.files["/opt/splunk/etc/auth/mycerts/splunk.example.lan-server.pem"])
	if strings.Count(combined, "BEGIN CERTIFICATE") != 2 || !strings.Contains(combined, "PRIVATE KEY") {
		t.Fatal("splunkd file should hold leaf, key and chain")
	}
	if mem.modes["/opt/splunk/etc/auth/mycerts/splunk.example.lan.key"] != "0600" {
		t.Fatal("key mode")
	}
	if len(mem.ran) == 0 || mem.ran[len(mem.ran)-1] != "systemctl restart Splunkd" {
		t.Fatalf("restart: %v", mem.ran)
	}
	got, _ := s.Get(ctx, tg.ID)
	if got.Options["host_key"] != "SHA256:test" || got.CertID != c.ID {
		t.Fatalf("host key not pinned / cert not remembered: %+v", got)
	}
	if len(audit.entries) != 1 || !strings.Contains(audit.entries[0], "alice cert.deploy deploy/splunk1") {
		t.Fatalf("audit: %v", audit.entries)
	}
	// a second deploy changes nothing in web.conf
	d, _ = s.Deploy(ctx, tg.ID, c.ID, "", "alice")
	d = waitDone(t, s, d.ID)
	for _, st := range d.Steps {
		if st.Title == "Point Splunk Web at the certificate" && st.Status != "unchanged" {
			t.Fatalf("second run edit status %q", st.Status)
		}
	}
}

func TestPlanBlockedWithoutKey(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	p := newTestPKI(t, "nokey.example.lan")
	c, _ := s.Certs.Import(ctx, "nokey", p.chainPEM, "", "")
	tg := &Target{Name: "web", Kind: "nginx", Host: "web.example.lan"}
	if err := s.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	plan, err := s.Plan(ctx, tg.ID, c.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Blocked == "" {
		t.Fatal("expected blocked plan")
	}
	if _, err := s.Deploy(ctx, tg.ID, c.ID, "", "x"); err == nil {
		t.Fatal("deploy should refuse")
	}
}

func TestPlanWarnsWrongHost(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	p := newTestPKI(t, "a.example.lan")
	c, _ := s.Certs.Import(ctx, "a", p.chainPEM, p.keyPEM, "")
	tg := &Target{Name: "b", Kind: "apache", Host: "b.example.lan", Options: map[string]string{"chain_path": "/etc/ssl/chain.pem"}}
	_ = s.Create(ctx, tg)
	plan, _ := s.Plan(ctx, tg.ID, c.ID, false)
	if len(plan.Warnings) == 0 || !strings.Contains(plan.Warnings[0], "does not cover b.example.lan") {
		t.Fatalf("warnings: %v", plan.Warnings)
	}
	if len(plan.Steps) != 4 || plan.Steps[1].Path != "/etc/ssl/chain.pem" {
		t.Fatalf("apache with chain file: %+v", plan.Steps)
	}
}

func TestIISPlanAndScripts(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	p := newTestPKI(t, "intranet.example.lan")
	c, _ := s.Certs.Import(ctx, "intranet", p.chainPEM, p.keyPEM, "")
	mem := &memConn{files: map[string][]byte{}, modes: map[string]string{}}
	s.DialWinRM = func(_ context.Context, o WinRMOptions) (Conn, string, error) {
		if !o.HTTPS || o.Auth != "ntlm" || o.User != `CORP\svc` {
			return nil, "", fmt.Errorf("unexpected options %+v", o)
		}
		return mem, "abc", nil
	}
	tg := &Target{Name: "iis1", Kind: "iis", Host: "10.0.0.5", Options: map[string]string{"site": "Intranet", "host_header": "intranet.example.lan", "sni": "true", "tls_pin": "abc"}}
	if err := s.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	if tg.Port != 5986 {
		t.Fatalf("default port %d", tg.Port)
	}
	_ = s.SetCredentials(ctx, tg.ID, map[string]string{"username": `CORP\svc`, "password": "pw"}, nil)
	plan, err := s.Plan(ctx, tg.ID, c.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range plan.Steps {
		if strings.Contains(st.Detail, "ConvertTo-SecureString '") && !strings.Contains(st.Detail, "••••••") {
			t.Fatal("PFX password shown in the preview")
		}
	}
	d, _ := s.Deploy(ctx, tg.ID, c.ID, "", "bob")
	d = waitDone(t, s, d.ID)
	if d.Status != "ok" {
		t.Fatalf("%+v", d)
	}
	thumb := Thumbprint(p.leaf)
	all := strings.Join(mem.ran, "\n----\n")
	for _, want := range []string{"Import-PfxCertificate", "Cert:\\LocalMachine\\My\\" + thumb, "'" + Thumbprint(p.ca) + "'",
		"-Name 'Intranet' -Protocol https -Port 443 -HostHeader 'intranet.example.lan' -SslFlags 1", "AddSslCertificate('" + thumb + "','My')"} {
		if !strings.Contains(all, want) {
			t.Fatalf("scripts missing %q:\n%s", want, all)
		}
	}
	var pfx []byte
	for path, b := range mem.files {
		if strings.HasSuffix(path, ".pfx") {
			pfx = b
		}
	}
	if pfx == nil {
		t.Fatal("no PFX uploaded")
	}
}

func TestTomcatKeystorePasswordSaved(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	p := newTestPKI(t, "tomcat.example.lan")
	c, _ := s.Certs.Import(ctx, "tomcat", p.chainPEM, p.keyPEM, "")
	mem := &memConn{files: map[string][]byte{}, modes: map[string]string{}}
	s.DialSSH = func(context.Context, SSHOptions) (Conn, string, error) { return mem, "k", nil }
	tg := &Target{Name: "tc", Kind: "tomcat", Host: "tomcat.example.lan", Options: map[string]string{"host_key": "k", "https_port": ""}}
	_ = s.Create(ctx, tg)
	_ = s.SetCredentials(ctx, tg.ID, map[string]string{"username": "root", "password": "x"}, nil)
	d, _ := s.Deploy(ctx, tg.ID, c.ID, "", "x")
	if d := waitDone(t, s, d.ID); d.Status != "ok" {
		t.Fatalf("%+v", d)
	}
	sec, _ := s.Vault.Get(ctx, tg.SecretPath)
	pw := sec["keystore_password"]
	if pw == "" {
		t.Fatal("keystore password not saved")
	}
	ks := mem.files["/opt/tomcat/conf/tomcat.p12"]
	if _, _, _, err := pkcs12.DecodeChain(ks, pw); err != nil {
		t.Fatalf("keystore does not open with the saved password: %v", err)
	}
	// the next deploy reuses it
	d, _ = s.Deploy(ctx, tg.ID, c.ID, "", "x")
	waitDone(t, s, d.ID)
	sec, _ = s.Vault.Get(ctx, tg.SecretPath)
	if sec["keystore_password"] != pw {
		t.Fatal("password changed on the second deploy")
	}
}

// ---- real SSH: an in-process SSH server that runs commands with the local shell ----

func startSSHServer(t *testing.T, user, pass string) (addr string, fingerprint string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell")
	}
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(hostPriv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if c.User() == user && string(p) == pass {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			go serveSSH(nc, cfg)
		}
	}()
	return l.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey())
}

func serveSSH(nc net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		ch, creqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range creqs {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				var p struct{ Cmd string }
				_ = ssh.Unmarshal(req.Payload, &p)
				_ = req.Reply(true, nil)
				cmd := exec.Command("sh", "-c", p.Cmd)
				cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
				code := 0
				if err := cmd.Run(); err != nil {
					code = 1
					var ee *exec.ExitError
					if errors.As(err, &ee) {
						code = ee.ExitCode()
					}
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{uint32(code)}))
				return
			}
		}()
	}
}

// startFileTLS serves whatever certificate is in certPath/keyPath at handshake time, like a
// web server that has been reloaded.
func startFileTLS(t *testing.T, certPath, keyPath string, initial testPKI) string {
	t.Helper()
	_ = os.MkdirAll(filepath.Dir(certPath), 0o755)
	_ = os.WriteFile(certPath, []byte(initial.chainPEM), 0o644)
	_ = os.WriteFile(keyPath, []byte(initial.keyPEM), 0o600)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(certPath, keyPath)
		return &c, err
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	return l.Addr().String()
}

func TestNginxOverRealSSH(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs to run as root (the deployer insists on root on the server)")
	}
	s, _ := newService(t)
	ctx := context.Background()
	dir := t.TempDir()
	addr, fp := startSSHServer(t, "deployer", "s3cret")
	host, port, _ := net.SplitHostPort(addr)
	portN, _ := strconv.Atoi(port)

	oldCert := newTestPKI(t, "old.example.lan")
	newCert := newTestPKI(t, "web.example.lan")
	certPath, keyPath := filepath.Join(dir, "ssl", "web.crt"), filepath.Join(dir, "ssl", "web.key")
	tlsAddr := startFileTLS(t, certPath, keyPath, oldCert)
	_, tlsPort, _ := net.SplitHostPort(tlsAddr)

	c, err := s.Certs.Import(ctx, "web.example.lan", newCert.chainPEM, newCert.keyPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	tg := &Target{Name: "web1", Kind: "nginx", Host: host, Port: portN, Options: map[string]string{
		"cert_path": certPath, "key_path": keyPath, "owner": "", "use_sudo": "false",
		"reload":     "echo reloaded > " + shQuote(filepath.Join(dir, "reloaded")) + " && echo nginx reloaded",
		"https_port": tlsPort, "check_name": "web.example.lan",
	}}
	if err := s.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	_ = s.SetCredentials(ctx, tg.ID, map[string]string{"username": "deployer", "password": "s3cret"}, nil)

	plan, err := s.Plan(ctx, tg.ID, c.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Connection.Trust || plan.Connection.Fingerprint != fp {
		t.Fatalf("first contact should ask to trust %s: %+v", fp, plan.Connection)
	}
	if _, err := s.Deploy(ctx, tg.ID, c.ID, "SHA256:wrong", "alice"); err != nil {
		t.Fatal(err)
	}
	s.Wait()
	hist, _ := s.History(ctx, tg.ID, 5)
	if hist[0].Status != "failed" || !strings.Contains(hist[0].Error, "host key changed") {
		t.Fatalf("wrong fingerprint must fail: %+v", hist[0])
	}

	d, err := s.Deploy(ctx, tg.ID, c.ID, fp, "alice")
	if err != nil {
		t.Fatal(err)
	}
	d = waitDone(t, s, d.ID)
	if d.Status != "ok" {
		t.Fatalf("deploy failed: %+v", d)
	}
	if !strings.HasPrefix(d.Verified, "ok") {
		t.Fatalf("not verified: %s", d.Verified)
	}
	got, _ := os.ReadFile(certPath)
	if string(got) != newCert.chainPEM {
		t.Fatal("certificate file not replaced")
	}
	if b, _ := os.ReadFile(certPath + ".ncc-bak"); string(b) != oldCert.chainPEM {
		t.Fatal("old certificate not kept as .ncc-bak")
	}
	st, _ := os.Stat(keyPath)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(dir, "reloaded")); err != nil {
		t.Fatal("reload command did not run")
	}
	if d.Steps[2].Output != "nginx reloaded" {
		t.Fatalf("reload output %q", d.Steps[2].Output)
	}
	// host key is pinned now; deploying again needs no confirmation
	t2, _ := s.Get(ctx, tg.ID)
	if t2.Options["host_key"] != fp {
		t.Fatal("host key not pinned")
	}
	served, err := s.ServedBy(ctx, tg.ID)
	if err != nil || served.CertName != "web.example.lan" {
		t.Fatalf("served: %+v %v", served, err)
	}
	// a failing reload is reported, and later steps are not run
	t2.Options["reload"] = "echo 'nginx: [emerg] bad config' >&2; exit 1"
	_ = s.Update(ctx, t2)
	d, _ = s.Deploy(ctx, tg.ID, c.ID, "", "alice")
	d = waitDone(t, s, d.ID)
	if d.Status != "failed" || !strings.Contains(d.Error, "[emerg] bad config") {
		t.Fatalf("expected reload failure: %+v", d)
	}
}

// ---- WinRM protocol against a fake WS-Management endpoint ----

func TestWinRMProtocol(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	files := map[string]string{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "admin" || p != "pw" {
			w.WriteHeader(401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		b := string(body)
		mu.Lock()
		defer mu.Unlock()
		resp := func(inner string) {
			w.Header().Set("Content-Type", "application/soap+xml")
			fmt.Fprintf(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="%s"><s:Body>%s</s:Body></s:Envelope>`, nsShell, inner)
		}
		switch {
		case strings.Contains(b, actCreate):
			resp(`<rsp:Shell><rsp:ShellId>SHELL-1</rsp:ShellId></rsp:Shell>`)
		case strings.Contains(b, actCommand):
			i := strings.Index(b, "-EncodedCommand ")
			enc := b[i+len("-EncodedCommand ") : strings.Index(b, "</rsp:Arguments>")]
			raw, _ := base64.StdEncoding.DecodeString(enc)
			var runes []uint16
			for j := 0; j+1 < len(raw); j += 2 {
				runes = append(runes, uint16(raw[j])|uint16(raw[j+1])<<8)
			}
			script := string(utf16Decode(runes))
			seen = append(seen, script)
			resp(`<rsp:CommandResponse><rsp:CommandId>CMD-` + strconv.Itoa(len(seen)) + `</rsp:CommandId></rsp:CommandResponse>`)
		case strings.Contains(b, actReceive):
			script := seen[len(seen)-1]
			out, code := "hello from windows", 0
			if strings.Contains(script, "Add-Content") {
				q := strings.Index(script, "-Value '")
				chunk := script[q+8:]
				chunk = chunk[:strings.Index(chunk, "'")]
				files["f"] += chunk
			}
			if strings.Contains(script, "throw") {
				out, code = "", 1
			}
			stderr := ""
			if code != 0 {
				stderr = `<rsp:Stream Name="stderr" CommandId="x">` + base64.StdEncoding.EncodeToString([]byte("#< CLIXML\r\n<Objs><S S=\"Error\">site missing_x000D__x000A_</S></Objs>")) + `</rsp:Stream>`
			}
			resp(`<rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="x">` + base64.StdEncoding.EncodeToString([]byte(out)) + `</rsp:Stream>` + stderr +
				`<rsp:CommandState CommandId="x" State="` + stateDone + `"><rsp:ExitCode>` + strconv.Itoa(code) + `</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`)
		default:
			resp("")
		}
	}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	portN, _ := strconv.Atoi(port)
	ctx := context.Background()

	// first contact: learn the certificate and refuse
	_, seenFP, err := DialWinRM(ctx, WinRMOptions{Host: host, Port: portN, HTTPS: true, Auth: "basic", User: "admin", Password: "pw"})
	var pe *ErrTLSPinUnknown
	if !errors.As(err, &pe) || seenFP == "" {
		t.Fatalf("expected pin prompt, got %v (%q)", err, seenFP)
	}
	conn, _, err := DialWinRM(ctx, WinRMOptions{Host: host, Port: portN, HTTPS: true, Auth: "basic", User: "admin", Password: "pw", AcceptPin: seenFP})
	if err != nil {
		t.Fatal(err)
	}
	out, err := conn.Run(ctx, "'hello'")
	if err != nil || out != "hello from windows" {
		t.Fatalf("run: %q %v", out, err)
	}
	data := bytes.Repeat([]byte{1, 2, 3, 250}, 2000)
	if err := conn.WriteFile(ctx, `C:\Windows\Temp\x.pfx`, data, "", ""); err != nil {
		t.Fatal(err)
	}
	if files["f"] != base64.StdEncoding.EncodeToString(data) {
		t.Fatal("chunks did not reassemble")
	}
	_, err = conn.Run(ctx, "throw 'x'")
	if err == nil || !strings.Contains(err.Error(), "site missing") {
		t.Fatalf("error not decoded: %v", err)
	}
	_ = conn.Close()
	if _, _, err := DialWinRM(ctx, WinRMOptions{Host: host, Port: portN, HTTPS: true, Auth: "basic", User: "admin", Password: "bad", AcceptPin: seenFP}); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad password: %v", err)
	}
	if _, _, err := DialWinRM(ctx, WinRMOptions{Host: host, Port: 5985, User: "a", Password: "b"}); err == nil {
		t.Fatal("plain HTTP must be refused")
	}
}

func utf16Decode(u []uint16) []rune {
	out := make([]rune, 0, len(u))
	for _, c := range u {
		out = append(out, rune(c))
	}
	return out
}

func TestCABundle(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	p := newTestPKI(t, "bundle.example.lan")
	other := newTestPKI(t, "other.example.lan")
	leafOnly := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.leaf.Raw}))
	// bundle given root first, with an unrelated CA mixed in
	c, err := s.Certs.Import(ctx, "bundle", leafOnly, p.keyPEM, p.rootPEM+other.caPEM+p.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if c.ChainLength != 3 || !c.ChainComplete || len(c.Chain) != 2 || c.Chain[0] != "Test Intermediate CA" || c.Chain[1] != "Test Root CA" {
		t.Fatalf("chain not ordered: %+v", c)
	}
	if len(c.Dropped) != 1 {
		t.Fatalf("unrelated CA should be dropped: %v", c.Dropped)
	}

	mem := &memConn{files: map[string][]byte{}, modes: map[string]string{}}
	s.DialSSH = func(context.Context, SSHOptions) (Conn, string, error) { return mem, "k", nil }
	tg := &Target{Name: "web", Kind: "nginx", Host: "bundle.example.lan", Options: map[string]string{"host_key": "k", "https_port": "", "ca_path": "/etc/nginx/ssl/{cert}-ca.pem"}}
	_ = s.Create(ctx, tg)
	_ = s.SetCredentials(ctx, tg.ID, map[string]string{"username": "root", "password": "x"}, nil)
	d, _ := s.Deploy(ctx, tg.ID, c.ID, "", "x")
	if d := waitDone(t, s, d.ID); d.Status != "ok" {
		t.Fatalf("%+v", d)
	}
	full := string(mem.files["/etc/nginx/ssl/bundle.crt"])
	if strings.Count(full, "BEGIN CERTIFICATE") != 2 || strings.Contains(full, strings.TrimSpace(p.rootPEM)) {
		t.Fatal("full chain must hold leaf and intermediate, not the root")
	}
	ca := string(mem.files["/etc/nginx/ssl/bundle-ca.pem"])
	if !strings.Contains(ca, strings.TrimSpace(p.caPEM)) || !strings.Contains(ca, strings.TrimSpace(p.rootPEM)) {
		t.Fatal("CA bundle file should hold intermediate and root")
	}

	// splunkd trusts the bundle
	sp := &Target{Name: "sp", Kind: "splunk", Host: "bundle.example.lan", Options: map[string]string{"host_key": "k", "https_port": "", "component": "splunkd", "ca_path": "/opt/splunk/etc/auth/mycerts/ca.pem"}}
	_ = s.Create(ctx, sp)
	_ = s.SetCredentials(ctx, sp.ID, map[string]string{"username": "root", "password": "x"}, nil)
	d, _ = s.Deploy(ctx, sp.ID, c.ID, "", "x")
	waitDone(t, s, d.ID)
	if !strings.Contains(string(mem.files["/opt/splunk/etc/system/local/server.conf"]), "sslRootCAPath = /opt/splunk/etc/auth/mycerts/ca.pem") {
		t.Fatalf("sslRootCAPath not set: %s", mem.files["/opt/splunk/etc/system/local/server.conf"])
	}

	// IIS can trust the root
	s.DialWinRM = func(context.Context, WinRMOptions) (Conn, string, error) { return mem, "p", nil }
	iis := &Target{Name: "iis", Kind: "iis", Host: "bundle.example.lan", Options: map[string]string{"tls_pin": "p", "https_port": "443", "trust_root": "true"}}
	_ = s.Create(ctx, iis)
	plan, _ := s.Plan(ctx, iis.ID, c.ID, false)
	found := false
	for _, st := range plan.Steps {
		if strings.Contains(st.Detail, "'Root','LocalMachine'") && strings.Contains(st.Detail, Thumbprint(p.root)) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no trust-root step: %+v", plan.Steps)
	}

	// replacing the bundle on an existing certificate; empty leaves only the leaf
	c2, err := s.Certs.SetChain(ctx, c.ID, "")
	if err != nil || c2.ChainLength != 1 {
		t.Fatalf("clear chain: %+v %v", c2, err)
	}
	c2, _ = s.Certs.SetChain(ctx, c.ID, p.caPEM)
	if c2.ChainLength != 2 || c2.ChainComplete {
		t.Fatalf("intermediate only: %+v", c2)
	}
	plan, _ = s.Plan(ctx, tg.ID, c.ID, false)
	for _, w := range plan.Warnings {
		if strings.Contains(w, "No intermediate") {
			t.Fatal("should not warn when the intermediate is there")
		}
	}
	if _, err := s.Certs.SetChain(ctx, c.ID, "not pem"); err == nil {
		t.Fatal("bad bundle accepted")
	}
}
