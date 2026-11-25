package certdeploy

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestTrustMaterial(t *testing.T) {
	p := newTestPKI(t, "web.example.lan")
	// a leaf whose chain stops at the intermediate: nothing to trust
	if _, err := NewTrustMaterial("web", p.chainPEM); err == nil {
		t.Fatal("a leaf without its root should not be trusted")
	}
	// with the root in the chain, the root (only) is trusted
	m, err := NewTrustMaterial("web", p.chainPEM+p.rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Trust) != 1 || !m.Trust[0].Equal(p.root) || m.TrustPEM != p.rootPEM {
		t.Fatalf("trust %v", m.Trust)
	}
	// an intermediate stored without its root is trusted itself
	m, err = NewTrustMaterial("int", p.caPEM)
	if err != nil || !m.Trust[0].Equal(p.ca) {
		t.Fatalf("intermediate: %v", err)
	}
}

func TestLinuxTrustDeploy(t *testing.T) {
	s, audit := newService(t)
	ctx := context.Background()
	p := newTestPKI(t, "x.example.lan")
	root, err := s.Certs.Import(ctx, "Home Root CA", p.rootPEM, "", "")
	if err != nil {
		t.Fatal(err)
	}
	mem := &memConn{files: map[string][]byte{}, modes: map[string]string{}}
	s.DialSSH = func(context.Context, SSHOptions) (Conn, string, error) { return mem, "k", nil }
	tg := &Target{Name: "app1", Kind: "linux-trust", Host: "app1.example.lan", Options: map[string]string{"host_key": "k"}}
	if err := s.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	plan, err := s.Plan(ctx, tg.ID, root.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Blocked != "" || len(plan.Steps) != 3 {
		t.Fatalf("plan: %+v", plan)
	}
	d, err := s.Deploy(ctx, tg.ID, root.ID, "", "alice")
	if err != nil {
		t.Fatal(err)
	}
	d = waitDone(t, s, d.ID)
	if d.Status != "ok" || !strings.HasPrefix(d.Verified, "ok") {
		t.Fatalf("deploy: %+v", d)
	}
	if got := string(mem.files["/usr/local/share/ncc-ca/ncc-Home_Root_CA.crt"]); got != p.rootPEM {
		t.Fatalf("staged file %q", got)
	}
	if !strings.Contains(mem.ran[0], "update-ca-certificates") || !strings.Contains(mem.ran[0], "update-ca-trust") {
		t.Fatal("trust script does not cover Debian and RHEL")
	}
	if !strings.Contains(mem.ran[1], pemLine(p.root)) {
		t.Fatal("check does not look for the root")
	}
	if !strings.Contains(audit.entries[0], "cert.deploy deploy/app1") {
		t.Fatalf("audit %v", audit.entries)
	}

	// a server certificate without its root is refused with a reason
	leaf, _ := s.Certs.Import(ctx, "x.example.lan", p.chainPEM, p.keyPEM, "")
	plan, _ = s.Plan(ctx, tg.ID, leaf.ID, false)
	if !strings.Contains(plan.Blocked, "not a CA certificate") {
		t.Fatalf("blocked: %q", plan.Blocked)
	}
}

func TestWindowsTrustPlan(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	p := newTestPKI(t, "x.example.lan")
	// the leaf with its full chain: the root of the chain is what gets trusted
	c, _ := s.Certs.Import(ctx, "x.example.lan", p.chainPEM, p.keyPEM, p.rootPEM)
	tg := &Target{Name: "dc1", Kind: "windows-trust", Host: "dc1.example.lan"}
	if err := s.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	plan, err := s.Plan(ctx, tg.ID, c.ID, false)
	if err != nil || plan.Blocked != "" {
		t.Fatalf("%v %+v", err, plan)
	}
	thumb := Thumbprint(p.root)
	all := ""
	for _, st := range plan.Steps {
		all += st.Title + "\n" + st.Path + "\n" + st.Detail + "\n"
	}
	for _, want := range []string{`Cert:\LocalMachine\Root`, "Import-Certificate", thumb, `C:\Windows\Temp\ncc-ca-`} {
		if !strings.Contains(all, want) {
			t.Fatalf("plan lacks %q:\n%s", want, all)
		}
	}
	if !strings.Contains(strings.Join(plan.Notes, " "), "Installs the root of x.example.lan's chain") {
		t.Fatalf("notes %v", plan.Notes)
	}
}

// TestLinuxTrustOnThisMachine runs the real trust-store steps over SSH against this machine's
// own trust store, then removes the CA again. It changes the system trust store, so it only
// runs when NCC_TEST_TRUST_STORE=1 (and as root).
func TestLinuxTrustOnThisMachine(t *testing.T) {
	if os.Getenv("NCC_TEST_TRUST_STORE") != "1" || os.Geteuid() != 0 {
		t.Skip("set NCC_TEST_TRUST_STORE=1 and run as root to change this machine's trust store")
	}
	s, _ := newService(t)
	ctx := context.Background()
	p := newTestPKI(t, "x.example.lan")
	root, _ := s.Certs.Import(ctx, "NCC Test Root", p.rootPEM, "", "")
	addr, fp := startSSHServer(t, "deployer", "pw")
	host, port, _ := net.SplitHostPort(addr)
	pn, _ := strconv.Atoi(port)
	tg := &Target{Name: "self", Kind: "linux-trust", Host: host, Port: pn, Options: map[string]string{"use_sudo": "false", "file_name": "ncc-test-root"}}
	if err := s.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	_ = s.SetCredentials(ctx, tg.ID, map[string]string{"username": "deployer", "password": "pw"}, nil)
	cleanup := func() {
		_ = os.Remove("/usr/local/share/ca-certificates/ncc-test-root.crt")
		_ = os.Remove("/etc/pki/ca-trust/source/anchors/ncc-test-root.crt")
		_ = os.RemoveAll("/usr/local/share/ncc-ca")
		_ = exec.Command("sh", "-c", "update-ca-certificates --fresh >/dev/null 2>&1 || update-ca-trust extract").Run()
	}
	t.Cleanup(cleanup)
	d, err := s.Deploy(ctx, tg.ID, root.ID, fp, "alice")
	if err != nil {
		t.Fatal(err)
	}
	d = waitDone(t, s, d.ID)
	if d.Status != "ok" {
		t.Fatalf("deploy: %+v", d)
	}
	for _, st := range d.Steps {
		t.Logf("%s: %s %s", st.Title, st.Status, st.Output)
	}
	// openssl, using only the system store, now accepts a certificate the root signed
	if _, err := exec.LookPath("openssl"); err == nil {
		dir := t.TempDir()
		_ = os.WriteFile(dir+"/leaf.pem", []byte(p.chainPEM), 0o644)
		out, err := exec.Command("sh", "-c", "openssl verify -untrusted "+dir+"/leaf.pem "+dir+"/leaf.pem").CombinedOutput()
		if err != nil {
			t.Fatalf("openssl does not trust the chain after deploy: %s", out)
		}
		t.Logf("openssl: %s", out)
	}
}
