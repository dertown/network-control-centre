package api_test

import (
	"context"
	"io/fs"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/dertown/network-control-centre/internal/api"
	"github.com/dertown/network-control-centre/internal/certdeploy"
	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/dnscheck"
	"github.com/dertown/network-control-centre/internal/mocklab"
	"github.com/dertown/network-control-centre/internal/recursorfix"
)

// sshBox is the DNS server as NCC sees it over SSH: a Recursor with its web server off.
type sshBox struct {
	files map[string]string
	ran   []string
}

func (b *sshBox) Run(_ context.Context, cmd string) (string, error) {
	if strings.HasPrefix(cmd, `echo "@os"`) {
		return "@pkg\napt\n@bin\n/usr/sbin/pdns_recursor\n@units\npdns-recursor.service\n@files\n/etc/powerdns/recursor.conf\n" +
			"@listen\nLISTEN 0 128 0.0.0.0:53 0.0.0.0:* users:((\"pdns_recursor\",pid=7,fd=5))\n@end\n", nil
	}
	b.ran = append(b.ran, cmd)
	if strings.HasPrefix(cmd, "systemctl is-active") {
		return "active\n", nil
	}
	return "", nil
}

func (b *sshBox) ReadFile(_ context.Context, p string) ([]byte, error) {
	if s, ok := b.files[p]; ok {
		return []byte(s), nil
	}
	return nil, fs.ErrNotExist
}

func (b *sshBox) WriteFile(_ context.Context, p string, d []byte, _, _ string) error {
	b.files[p] = string(d)
	return nil
}

func TestRecursorFix(t *testing.T) {
	c, _, _, done := vlanSetup(t, "ncc")
	defer done()
	core.ProbeDNS = func(context.Context, string, string, uint16) (string, error) { return "NOERROR", nil }
	defer func() { core.ProbeDNS = dnscheck.Query }()

	pdns := httptest.NewServer(mocklab.NewPowerDNS("pdns-key"))
	defer pdns.Close()
	recursor := httptest.NewServer(mocklab.NewRecursor("rec-key"))
	defer recursor.Close()
	ru, _ := url.Parse(recursor.URL)
	port, _ := strconv.Atoi(ru.Port())
	oldEP := recursorfix.Endpoints
	recursorfix.Endpoints = []recursorfix.Endpoint{{Scheme: "http", Port: 1}, {Scheme: "http", Port: port}}
	defer func() { recursorfix.Endpoints = oldEP }()

	// the URL saved in Settings is a dead port, and "Address clients use" holds a URL
	var dnsT core.Target
	if code := c.do("POST", "/api/targets", map[string]any{
		"kind": "powerdns", "category": "dns", "name": "pdns", "address": pdns.URL,
		"options":     map[string]string{"recursor_url": "http://127.0.0.1:1", "resolver_ips": "http://127.0.0.1:8082"},
		"credentials": map[string]string{"api_key": "pdns-key"},
	}, &dnsT); code != 201 {
		t.Fatalf("create dns target: %d", code)
	}
	pollUntil(c, dnsT.ID)
	var rep dnscheck.Report
	c.do("GET", "/api/dns/check", nil, &rep)
	var fwd dnscheck.Check
	for _, ch := range rep.Checks {
		if ch.Kind == dnscheck.KindForwarders {
			fwd = ch
		}
	}
	if fwd.Status != dnscheck.Unknown || fwd.Action != dnscheck.ActionRecursorAPI || !strings.Contains(fwd.Detail, "Nothing answers at http://127.0.0.1:1") {
		t.Fatalf("can't read: %+v", fwd)
	}
	base := "/api/dns/recursor-fix/" + itoa(dnsT.ID)

	// 1. looking finds the Recursor, but the key NCC has (the authoritative one) is refused
	var disc struct {
		Discovery   recursorfix.Discovery `json:"discovery"`
		NeedsAPIKey bool                  `json:"needs_api_key"`
	}
	if code := c.do("POST", base+"/discover", map[string]any{}, &disc); code != 200 {
		t.Fatalf("discover: %d", code)
	}
	if disc.Discovery.Found != nil {
		t.Fatalf("the mock Recursor's start page needs its key, so it isn't recognised: %+v", disc.Discovery.Found)
	}
	// with the right key it is used, and the settings are cleaned up
	if code := c.do("POST", base+"/use", map[string]string{"url": recursor.URL, "api_key": "wrong"}, nil); code != 400 {
		t.Fatalf("a wrong key must not be saved: %d", code)
	}
	if code := c.do("POST", base+"/use", map[string]string{"url": recursor.URL, "api_key": "rec-key"}, nil); code != 200 {
		t.Fatalf("use: %d", code)
	}
	got, _ := getTarget(c, dnsT.ID)
	if got.Options["recursor_url"] != recursor.URL || got.Options["resolver_ips"] != "127.0.0.1" {
		t.Fatalf("saved options: %v", got.Options)
	}
	c.do("POST", base+"/discover", map[string]any{}, &disc)
	if disc.Discovery.Found == nil || !disc.Discovery.Found.KeyOK || disc.Discovery.Found.URL != "http://127.0.0.1:"+ru.Port() {
		t.Fatalf("found with the saved key: %+v", disc.Discovery)
	}
	c.do("GET", "/api/dns/check", nil, &rep)
	for _, ch := range rep.Checks {
		if ch.Kind == dnscheck.KindForwarders && ch.Status == dnscheck.Unknown {
			t.Fatalf("forwarders still unread: %+v", ch)
		}
	}

	// 2. over SSH: confirm the host key, preview, apply
	box := &sshBox{files: map[string]string{"/etc/powerdns/recursor.conf": "local-address=0.0.0.0\nwebserver-port=" + ru.Port() + "\napi-key=rec-key\n"}}
	var dialed []certdeploy.SSHOptions
	defer api.SetFixDial(func(_ context.Context, o certdeploy.SSHOptions) (recursorfix.Conn, string, error) {
		dialed = append(dialed, o)
		if o.HostKey == "" && o.AcceptHostKey != "SHA256:abc" {
			return nil, "SHA256:abc", &certdeploy.ErrHostKeyUnknown{Seen: "SHA256:abc"}
		}
		return box, "SHA256:abc", nil
	})()
	in := map[string]any{"host": "127.0.0.1", "user": "admin", "password": "pw", "sudo": true, "remember": true}
	var hk map[string]string
	if code := c.do("POST", base+"/plan", in, &hk); code != 200 || hk["host_key_unknown"] != "SHA256:abc" {
		t.Fatalf("host key: %d %v", code, hk)
	}
	in["accept_host_key"] = "SHA256:abc"
	var planOut struct {
		PlanID string           `json:"plan_id"`
		Plan   recursorfix.Plan `json:"plan"`
	}
	if code := c.do("POST", base+"/plan", in, &planOut); code != 200 || planOut.PlanID == "" {
		t.Fatalf("plan: %d %+v", code, planOut)
	}
	if planOut.Plan.Mode != recursorfix.ModeAPI || planOut.Plan.URL != "http://127.0.0.1:"+ru.Port() || len(box.ran) != 1 {
		t.Fatalf("plan: %+v ran %v", planOut.Plan, box.ran)
	}
	got, _ = getTarget(c, dnsT.ID)
	if got.Options["ssh_host_key"] != "SHA256:abc" || got.Options["ssh_user"] != "admin" || got.Options["ssh_sudo"] != "yes" {
		t.Fatalf("remembered login: %v", got.Options)
	}
	var applied struct {
		Result recursorfix.Result `json:"result"`
	}
	if code := c.do("POST", base+"/apply", map[string]string{"plan_id": planOut.PlanID}, &applied); code != 200 || !applied.Result.OK {
		t.Fatalf("apply: %d %+v", code, applied)
	}
	if !strings.Contains(box.files["/etc/powerdns/recursor.conf"], "\nwebserver=yes\n") || dialed[len(dialed)-1].Password != "pw" || dialed[len(dialed)-1].HostKey != "SHA256:abc" {
		t.Fatalf("applied: %s %+v", box.files["/etc/powerdns/recursor.conf"], dialed)
	}
	// a plan is used once
	if code := c.do("POST", base+"/apply", map[string]string{"plan_id": planOut.PlanID}, nil); code != 409 {
		t.Fatalf("second apply: %d", code)
	}
	// the saved login is used next time, with the pinned key
	if code := c.do("POST", base+"/plan", map[string]any{}, &planOut); code != 200 {
		t.Fatalf("plan with the saved login: %d", code)
	}
	var audit []struct{ Action string }
	c.do("GET", "/api/audit", nil, &audit)
	n := 0
	for _, a := range audit {
		if strings.HasPrefix(a.Action, "dns.recursor") {
			n++
		}
	}
	if n < 3 {
		t.Fatalf("audit: %+v", audit)
	}
}

func getTarget(c *client, id int64) (core.Target, int) {
	var ts []core.Target
	code := c.do("GET", "/api/targets?category=dns", nil, &ts)
	for _, t := range ts {
		if t.ID == id {
			return t, code
		}
	}
	return core.Target{}, code
}
