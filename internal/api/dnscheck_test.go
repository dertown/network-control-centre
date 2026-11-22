package api_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/dnscheck"
	"github.com/dertown/network-control-centre/internal/mocklab"
)

func TestDNSChainCheck(t *testing.T) {
	c, _, _, done := vlanSetup(t, "ncc")
	defer done()
	// the live lookups go to a pretend server: it resolves everything until told otherwise
	refuseInternet := false
	var asked []string
	core.ProbeDNS = func(_ context.Context, server, name string, _ uint16) (string, error) {
		asked = append(asked, server+" "+name)
		if refuseInternet && name == dnscheck.InternetTestName {
			return "REFUSED", nil
		}
		return "NOERROR", nil
	}
	defer func() { core.ProbeDNS = dnscheck.Query }()

	// before any DNS server is added there is nothing to check
	var rep dnscheck.Report
	if code := c.do("GET", "/api/dns/check", nil, &rep); code != 200 || rep.Status != "" || len(rep.Checks) != 0 {
		t.Fatalf("no DNS server: %d %+v", code, rep)
	}

	pdns := httptest.NewServer(mocklab.NewPowerDNS("pdns-key"))
	defer pdns.Close()
	rec := mocklab.NewRecursor("pdns-key")
	recursor := httptest.NewServer(rec)
	defer recursor.Close()
	var dnsT core.Target
	if code := c.do("POST", "/api/targets", map[string]any{
		"kind": "powerdns", "category": "dns", "name": "pdns", "address": pdns.URL,
		"options":     map[string]string{"recursor_url": recursor.URL, "resolver_ips": "192.168.1.10"},
		"credentials": map[string]string{"api_key": "pdns-key"},
	}, &dnsT); code != 201 {
		t.Fatalf("create dns target: %d", code)
	}
	pollUntil(c, dnsT.ID)

	c.do("GET", "/api/dns/check", nil, &rep)
	status := map[string]string{}
	for _, ch := range rep.Checks {
		status[ch.Subject] = ch.Status
	}
	// the mock network: Default hands out the internal server, IoT the router itself, DMZ
	// the internal server plus 8.8.8.8, Guest is left alone; the recursor forwards to the
	// ISP servers the router learned on its WAN
	want := map[string]string{
		"udr7 · Default": dnscheck.Pass, "udr7 · IoT": dnscheck.Fail, "udr7 · DMZ": dnscheck.Pass,
		"udr7 · Guest": dnscheck.Skip, "pdns": dnscheck.Pass, "pdns · 192.168.1.10": dnscheck.Pass,
	}
	for subj, st := range want {
		if status[subj] != st {
			t.Errorf("%s: %q, want %q (all: %v)", subj, status[subj], st, status)
		}
	}
	if rep.Status != dnscheck.Fail || rep.ISPSource != "router" || len(rep.ISP) != 2 || rep.Resolvers[0] != "192.168.1.10" {
		t.Fatalf("report: %+v", rep)
	}

	if len(asked) == 0 || !strings.Contains(strings.Join(asked, "|"), "192.168.1.10 "+dnscheck.InternetTestName) {
		t.Fatalf("live lookups: %v", asked)
	}

	// an authoritative-only server refuses internet names: a failure with the Fix button
	refuseInternet = true
	pollUntil(c, dnsT.ID)
	c.do("GET", "/api/dns/check", nil, &rep)
	found := false
	for _, ch := range rep.Checks {
		if ch.Subject == "pdns · 192.168.1.10" {
			found = true
			if ch.Status != dnscheck.Fail || !strings.Contains(ch.Title, "refuses internet names") || ch.Action != dnscheck.ActionRecursorAPI {
				t.Fatalf("refused: %+v", ch)
			}
		}
	}
	if !found {
		t.Fatalf("no live check: %+v", rep.Checks)
	}
	refuseInternet = false

	// the recursor starts sending internet queries to a public resolver instead
	rec.Forwarders = []string{"1.1.1.1:53"}
	pollUntil(c, dnsT.ID)
	c.do("GET", "/api/dns/check", nil, &rep)
	for _, ch := range rep.Checks {
		if ch.Subject == "pdns" && (ch.Status != dnscheck.Warn || ch.Actual != "1.1.1.1") {
			t.Fatalf("public forwarder: %+v", ch)
		}
	}

	// without a Recursor URL NCC says what to set up, and the connection itself stays healthy
	if code := c.do("PATCH", "/api/targets/"+itoa(dnsT.ID), map[string]any{"address": pdns.URL, "options": map[string]string{"resolver_ips": "192.168.1.10"}}, nil); code != 200 {
		t.Fatalf("patch: %d", code)
	}
	pollUntil(c, dnsT.ID)
	c.do("GET", "/api/dns/check", nil, &rep)
	for _, ch := range rep.Checks {
		if ch.Subject == "pdns" && (ch.Status != dnscheck.Unknown || ch.FixURL != "#/settings" || ch.Action != dnscheck.ActionRecursorAPI || ch.Target != dnsT.ID) {
			t.Fatalf("no recursor: %+v", ch)
		}
	}
	var tg []core.Target
	c.do("GET", "/api/targets?category=dns", nil, &tg)
	if len(tg) != 1 || tg[0].LastError != "" {
		t.Fatalf("the DNS connection should still be healthy: %+v", tg)
	}
}
