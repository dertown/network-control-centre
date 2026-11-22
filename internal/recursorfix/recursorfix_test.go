package recursorfix

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeServer is a DNS server reached over SSH: canned facts, files in memory, and every
// command it was asked to run.
type fakeServer struct {
	facts  string
	files  map[string]string
	ran    []string
	active map[string]bool // systemctl is-active answers
	fail   string          // a command containing this fails
}

func (f *fakeServer) Run(_ context.Context, cmd string) (string, error) {
	if cmd == factsScript {
		return f.facts, nil
	}
	f.ran = append(f.ran, cmd)
	if f.fail != "" && strings.Contains(cmd, f.fail) {
		return "", errors.New("failed: " + f.fail)
	}
	switch {
	case strings.HasPrefix(cmd, "systemctl is-active"):
		for u, ok := range f.active {
			if strings.Contains(cmd, u) {
				if ok {
					return "active\n", nil
				}
				return "failed\n", errors.New("exit 3")
			}
		}
		return "active\n", nil
	case strings.HasPrefix(cmd, "systemctl show"):
		return "{ path=/usr/sbin/pdns_recursor ; argv[]=/usr/sbin/pdns_recursor --daemon=no --write-pid=no --disable-syslog --log-timestamp=no }\n", nil
	case strings.HasPrefix(cmd, "grep -lE"):
		return "", nil
	}
	return "", nil
}

func (f *fakeServer) ReadFile(_ context.Context, p string) ([]byte, error) {
	if s, ok := f.files[p]; ok {
		return []byte(s), nil
	}
	return nil, fs.ErrNotExist
}

func (f *fakeServer) WriteFile(_ context.Context, p string, data []byte, _, _ string) error {
	f.files[p] = string(data)
	return nil
}

func facts(listen string, extra ...string) string {
	s := "@os\nDebian GNU/Linux 12 (bookworm)\n@pkg\napt\n@bin\n/usr/sbin/pdns_recursor\n@version\nPowerDNS Recursor 4.8.4 (C) PowerDNS.COM BV\n" +
		"@units\npdns-recursor.service\n@files\n/etc/powerdns/recursor.conf\n@authbin\n/usr/sbin/pdns_server\n@authunits\npdns.service\n@authconf\n/etc/powerdns/pdns.conf\n" +
		"@listen\n" + listen + "\n@ufw\n@docker\n@end\n"
	for _, e := range extra {
		s = strings.Replace(s, strings.Split(e, "=>")[0], strings.Split(e, "=>")[1], 1)
	}
	return s
}

const (
	ssAuth53  = `LISTEN 0 128 0.0.0.0:53 0.0.0.0:* users:(("pdns_server",pid=601,fd=5))` + "\n" + `LISTEN 0 128 0.0.0.0:8081 0.0.0.0:* users:(("pdns_server",pid=601,fd=7))`
	ssRec53   = `LISTEN 0 128 0.0.0.0:53 0.0.0.0:* users:(("pdns_recursor",pid=700,fd=5))`
	recConf   = "# defaults\nlocal-address=127.0.0.1\ninclude-dir=/etc/powerdns/recursor.d\n# webserver=no\n"
	authConf  = "launch=gsqlite3\napi=yes\napi-key=auth-secret\nwebserver=yes\nwebserver-port=8081\nlocal-address=0.0.0.0\n"
	nccAddr   = "192.168.1.247"
	host      = "192.168.1.70"
	stampTime = "2026-11-22T19:30:00Z"
)

func opts() Options {
	now, _ := time.Parse(time.RFC3339, stampTime)
	return Options{Host: host, NCCAddress: nccAddr, Now: now, Key: "k3y"}
}

func okChecks() Checks {
	return Checks{Wait: time.Millisecond,
		API: func(context.Context, string, string) error { return nil },
		DNS: func(context.Context, string, string) error { return nil }}
}

func TestTurnOnAPIOfARunningRecursor(t *testing.T) {
	srv := &fakeServer{facts: facts(ssRec53), files: map[string]string{"/etc/powerdns/recursor.conf": "local-address=0.0.0.0\nwebserver=no\nwebserver-port=8082\napi-key=old-key\n"}}
	p, err := Inspect(context.Background(), srv, Options{Host: host, NCCAddress: nccAddr})
	if err != nil || p.Blocked != "" {
		t.Fatalf("inspect: %v %q", err, p.Blocked)
	}
	if p.Mode != ModeAPI || p.URL != "http://192.168.1.70:8082" || p.Key() != "old-key" || p.NewKey {
		t.Fatalf("plan: mode %s url %s key %q new %v", p.Mode, p.URL, p.Key(), p.NewKey)
	}
	diff := strings.Join(p.Steps[1].Diff, "\n")
	for _, want := range []string{"- webserver=no", "- api-key=••••", "+ webserver=yes", "+ webserver-address=0.0.0.0", "+ webserver-allow-from=127.0.0.1,::1,192.168.1.247", "+ api-key=" + masked} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff misses %q:\n%s", want, diff)
		}
	}
	if strings.Contains(diff, "old-key") {
		t.Fatal("the key must not be shown")
	}
	var gotURL, gotKey string
	r := Apply(context.Background(), srv, p, Checks{Wait: time.Millisecond, API: func(_ context.Context, u, k string) error { gotURL, gotKey = u, k; return nil }})
	if !r.OK || gotURL != p.URL || gotKey != "old-key" {
		t.Fatalf("apply: %+v (%s %s)", r, gotURL, gotKey)
	}
	conf := srv.files["/etc/powerdns/recursor.conf"]
	if !strings.Contains(conf, "# disabled by NCC: webserver=no") || !strings.Contains(conf, "\nwebserver=yes\n") || !strings.Contains(conf, "api-key=old-key\n") {
		t.Fatalf("new file:\n%s", conf)
	}
	if !strings.Contains(strings.Join(srv.ran, "\n"), "systemctl restart 'pdns-recursor.service'") {
		t.Fatalf("no restart: %v", srv.ran)
	}
}

func TestAuthoritativeOnlyNeedsTheChoice(t *testing.T) {
	srv := &fakeServer{facts: facts(ssAuth53, "@bin\n/usr/sbin/pdns_recursor\n=>@bin\n", "@units\npdns-recursor.service\n=>@units\n", "@files\n/etc/powerdns/recursor.conf\n=>@files\n"), files: map[string]string{}}
	p, err := Inspect(context.Background(), srv, opts())
	if err != nil || p.Blocked == "" || !strings.Contains(p.Blocked, "only runs the authoritative server") {
		t.Fatalf("without the choice NCC only explains: %v %+v", err, p)
	}
	o := opts()
	o.MakeResolver = true
	p, err = Inspect(context.Background(), srv, o)
	if err != nil || p.Blocked != "" || p.Mode != ModeInstall || !strings.Contains(p.Steps[0].Command, "apt-get install -y -q pdns-recursor") || p.Next == "" {
		t.Fatalf("install plan: %v %+v", err, p)
	}
	if r := Apply(context.Background(), srv, p, okChecks()); !r.OK {
		t.Fatalf("install: %+v", r)
	}
}

func TestMakeTheRecursorTheResolver(t *testing.T) {
	srv := &fakeServer{facts: facts(ssAuth53), files: map[string]string{
		"/etc/powerdns/recursor.conf": recConf, "/etc/powerdns/pdns.conf": authConf}}
	o := opts()
	o.MakeResolver = true
	o.AuthZones = []string{"izanami.org.", "1.168.192.in-addr.arpa."}
	o.ISP = []string{"76.76.10.155"}
	p, err := Inspect(context.Background(), srv, o)
	if err != nil || p.Blocked != "" {
		t.Fatalf("inspect: %v %q", err, p.Blocked)
	}
	if p.Mode != ModeResolver || p.Zone != "izanami.org" || p.URL != "http://192.168.1.70:8082" {
		t.Fatalf("plan: %+v", p)
	}
	var all []string
	for _, s := range p.Steps {
		all = append(all, s.Title+" | "+s.Command+" | "+strings.Join(s.Diff, " ; "))
	}
	text := strings.Join(all, "\n")
	for _, want := range []string{
		"+ local-address=127.0.0.1 ; + local-port=5300", // the authoritative server moves
		"- local-address=0.0.0.0",                       // its old line is commented out
		"+ local-address=0.0.0.0 ; + local-port=53",     // the Recursor takes port 53
		"+ forward-zones=1.168.192.in-addr.arpa=127.0.0.1:5300, izanami.org=127.0.0.1:5300",
		"+ forward-zones-recurse=.=76.76.10.155",
		"systemctl restart 'pdns.service'",
		"systemctl enable 'pdns-recursor.service' && systemctl restart 'pdns-recursor.service'",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("plan misses %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "auth-secret") || strings.Contains(text, "k3y") {
		t.Fatal("keys must not be shown")
	}

	// the lookups fail afterwards: everything is put back
	var dnsAsked string
	r := Apply(context.Background(), srv, p, Checks{Wait: time.Millisecond,
		API: func(context.Context, string, string) error { return nil },
		DNS: func(_ context.Context, h, z string) error {
			dnsAsked = h + " " + z
			return errors.New("www.google.com: SERVFAIL")
		}})
	if r.OK || !r.RolledBack || dnsAsked != "192.168.1.70 izanami.org" {
		t.Fatalf("want a rollback: %+v (%s)", r, dnsAsked)
	}
	undo := srv.ran[len(srv.ran)-1]
	for _, want := range []string{"pdns.conf.ncc-bak-20261122T193000Z' '/etc/powerdns/pdns.conf'", "recursor.conf.ncc-bak-20261122T193000Z' '/etc/powerdns/recursor.conf'", "systemctl disable --now 'pdns-recursor.service'", "systemctl restart 'pdns.service'"} {
		if !strings.Contains(undo, want) {
			t.Errorf("undo misses %q: %s", want, undo)
		}
	}

	// and when everything answers it is done
	srv2 := &fakeServer{facts: facts(ssAuth53), files: map[string]string{
		"/etc/powerdns/recursor.conf": recConf, "/etc/powerdns/pdns.conf": authConf}}
	p, _ = Inspect(context.Background(), srv2, o)
	if r := Apply(context.Background(), srv2, p, okChecks()); !r.OK || r.RolledBack {
		t.Fatalf("apply: %+v", r)
	}
	if a := srv2.files["/etc/powerdns/pdns.conf"]; !strings.Contains(a, "\nlocal-port=5300\n") || !strings.Contains(a, "api-key=auth-secret") {
		t.Fatalf("pdns.conf:\n%s", a)
	}
}

func TestRecursorThatWontStartIsRolledBack(t *testing.T) {
	srv := &fakeServer{facts: facts(ssRec53), files: map[string]string{"/etc/powerdns/recursor.conf": "local-address=0.0.0.0\n"},
		active: map[string]bool{"pdns-recursor": false}}
	p, _ := Inspect(context.Background(), srv, opts())
	r := Apply(context.Background(), srv, p, okChecks())
	if r.OK || !r.RolledBack || !strings.Contains(srv.ran[len(srv.ran)-1], "recursor.conf.ncc-bak-") {
		t.Fatalf("rollback: %+v %v", r, srv.ran)
	}
}

func TestDockerAndMissingConfigAreExplained(t *testing.T) {
	srv := &fakeServer{facts: facts(ssAuth53, "@bin\n/usr/sbin/pdns_recursor\n=>@bin\n", "@docker\n=>@docker\npdns-recursor (powerdns/pdns-recursor-51)\n"), files: map[string]string{}}
	if p, _ := Inspect(context.Background(), srv, opts()); !strings.Contains(p.Blocked, "Docker") {
		t.Fatalf("docker: %+v", p)
	}
	srv = &fakeServer{facts: facts(ssRec53, "@files\n/etc/powerdns/recursor.conf\n=>@files\n"), files: map[string]string{}}
	if p, _ := Inspect(context.Background(), srv, opts()); !strings.Contains(p.Blocked, "configuration file") {
		t.Fatalf("no config: %+v", p)
	}
}

func TestPortClashMovesTheWebServer(t *testing.T) {
	srv := &fakeServer{facts: facts(ssRec53 + "\n" + `LISTEN 0 128 0.0.0.0:8082 0.0.0.0:* users:(("node",pid=9,fd=3))`),
		files: map[string]string{"/etc/powerdns/recursor.conf": "local-address=0.0.0.0\n"}}
	p, _ := Inspect(context.Background(), srv, opts())
	if p.URL != "http://192.168.1.70:8083" || len(p.Warnings) == 0 {
		t.Fatalf("port clash: %s %v", p.URL, p.Warnings)
	}
}

func TestYAMLRecursor(t *testing.T) {
	yml := "incoming:\n  listen: [0.0.0.0]\nrecursor:\n  forward_zones:\n    - zone: lab.lan\n      forwarders: [10.0.0.5]\nwebservice:\n  webserver: false\n  # keep me\n  port: 8082\n"
	srv := &fakeServer{facts: facts(ssAuth53, "@files\n/etc/powerdns/recursor.conf\n=>@files\n/etc/powerdns/recursor.yml\n"),
		files: map[string]string{"/etc/powerdns/recursor.yml": yml, "/etc/powerdns/pdns.conf": authConf}}
	o := opts()
	o.MakeResolver, o.AuthZones, o.ISP = true, []string{"izanami.org."}, []string{"76.76.10.155", "76.76.2.155"}
	p, err := Inspect(context.Background(), srv, o)
	if err != nil || p.Blocked != "" || p.Facts.Style != "yaml" {
		t.Fatalf("inspect: %v %+v", err, p)
	}
	if r := Apply(context.Background(), srv, p, okChecks()); !r.OK {
		t.Fatalf("apply: %+v", r)
	}
	got := srv.files["/etc/powerdns/recursor.yml"]
	for _, want := range []string{"webserver: true", "# keep me", "port: 8082", "api_key: k3y", "zone: lab.lan", "zone: izanami.org", "forwarders: ['127.0.0.1:5300']",
		"forward_zones_recurse:", "forwarders: [76.76.10.155, 76.76.2.155]", "allow_from: [127.0.0.1, '::1', 192.168.1.247]", "port: 53"} {
		if !strings.Contains(got, want) {
			t.Errorf("recursor.yml misses %q:\n%s", want, got)
		}
	}
}

func TestDiscover(t *testing.T) {
	rec := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte("<title>PowerDNS Recursor</title>"))
			return
		}
		if r.Header.Get("X-API-Key") != "rec-key" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"daemon_type":"recursor","version":"5.1.0"}`))
	})
	auth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "auth-key" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"daemon_type":"authoritative","version":"4.9"}`))
	})
	// the Recursor on 8083 and the authoritative server on 8081, both on 127.0.0.1
	ls := map[int]http.Handler{8083: rec, 8081: auth}
	for port, h := range ls {
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Skipf("port %d busy: %v", port, err)
		}
		s := httptest.NewUnstartedServer(h)
		s.Listener.Close()
		s.Listener = l
		s.Start()
		defer s.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := Discover(ctx, []string{"127.0.0.1"}, []string{"auth-key", "rec-key"}, nil)
	if d.Found == nil || d.Found.URL != "http://127.0.0.1:8083" || !d.Found.KeyOK || d.Found.Key() != "rec-key" {
		t.Fatalf("found: %+v", d.Found)
	}
	for _, p := range d.Probes {
		if p.URL == "http://127.0.0.1:8081" && (p.Recursor || p.DaemonType != "authoritative") {
			t.Fatalf("8081 is the authoritative server: %+v", p)
		}
		if p.URL == "http://127.0.0.1:8082" && p.Error != "connection refused" {
			t.Fatalf("8082: %+v", p)
		}
	}
	// without the right key the Recursor is still recognised from its start page
	d = Discover(ctx, []string{"127.0.0.1"}, []string{"wrong"}, nil)
	if d.Found == nil || d.Found.KeyOK || d.Found.URL != "http://127.0.0.1:8083" {
		t.Fatalf("found without key: %+v", d.Found)
	}
}

// Ubuntu's Recursor 5 package ships recursor.conf in YAML. NCC must edit it as YAML, check it
// with --config=check before touching the authoritative server, and undo everything when the
// check fails.
const ubuntuRecConf = `# PowerDNS Recursor configuration (YAML)
dnssec:
  # validation: process
  trustanchorfile: /usr/share/dns/root.key
recursor:
  hint_file: /usr/share/dns/root.hints
  include_dir: /etc/powerdns/recursor.d
incoming:
  listen:
    - 127.0.0.1
outgoing:
  source_address:
    - 0.0.0.0
`

func TestUbuntuYAMLInRecursorConf(t *testing.T) {
	newBox := func() *fakeServer {
		return &fakeServer{facts: facts(ssAuth53, "Recursor 4.8.4=>Recursor 5.3.5", "Debian GNU/Linux 12 (bookworm)=>Ubuntu 25.10"),
			files: map[string]string{"/etc/powerdns/recursor.conf": ubuntuRecConf, "/etc/powerdns/pdns.conf": authConf}}
	}
	o := opts()
	o.MakeResolver, o.AuthZones, o.ISP = true, []string{"izanami.org."}, []string{"76.76.10.155"}
	srv := newBox()
	p, err := Inspect(context.Background(), srv, o)
	if err != nil || p.Blocked != "" || p.Facts.Style != "yaml" || p.Facts.Version != "5.3.5" {
		t.Fatalf("inspect: %v %+v", err, p)
	}
	var order []string
	for _, s := range p.Steps {
		order = append(order, s.Title)
	}
	got := strings.Join(order, " | ")
	check := strings.Index(got, "Check the new configuration is valid")
	auth := strings.Index(got, "Restart the authoritative server")
	if check < 0 || auth < 0 || check > auth {
		t.Fatalf("the config must be checked before anything restarts: %s", got)
	}
	if r := Apply(context.Background(), srv, p, okChecks()); !r.OK {
		t.Fatalf("apply: %+v", r)
	}
	out := srv.files["/etc/powerdns/recursor.conf"]
	if strings.Contains(out, "webserver=yes") || !isYAMLConfig([]byte(out)) {
		t.Fatalf("recursor.conf must stay valid YAML:\n%s", out)
	}
	for _, want := range []string{"trustanchorfile: /usr/share/dns/root.key", "zone: izanami.org", "forwarders: ['127.0.0.1:5300']", "webserver: true", "port: 53", "listen: [0.0.0.0]"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(strings.Join(srv.ran, "\n"), "'/usr/sbin/pdns_recursor' --config-dir='/etc/powerdns' --config=check") {
		t.Fatalf("no config check: %v", srv.ran)
	}

	// the Recursor rejects the file: the authoritative server is never touched
	srv = newBox()
	srv.fail = "--config=check"
	p, _ = Inspect(context.Background(), srv, o)
	r := Apply(context.Background(), srv, p, okChecks())
	if r.OK || !r.RolledBack {
		t.Fatalf("want rollback: %+v", r)
	}
	if srv.files["/etc/powerdns/pdns.conf"] != authConf {
		t.Fatal("pdns.conf must not change when the Recursor config is rejected")
	}
	for _, c := range srv.ran {
		if strings.HasPrefix(c, "systemctl restart 'pdns.service'") && !strings.Contains(c, "cp -p") {
			t.Fatalf("the authoritative server was restarted before the check: %v", srv.ran)
		}
	}
}

func TestOldStyleIsNotYAML(t *testing.T) {
	if isYAMLConfig([]byte(recConf)) || isYAMLConfig([]byte("local-address=0.0.0.0\n")) || !isYAMLConfig([]byte(ubuntuRecConf)) {
		t.Fatal("format detection")
	}
}
