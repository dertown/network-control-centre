package dnscheck

import (
	"errors"
	"strings"
	"testing"

	"github.com/dertown/network-control-centre/internal/dns"
	inv "github.com/dertown/network-control-centre/internal/inventory"
)

// lan is a router LAN handing out servers (none: the router itself).
func lan(id, name string, servers ...string) inv.Network {
	return inv.Network{ID: id, Name: name, Purpose: "corporate", Zone: "internal",
		DNS: &inv.NetworkDNS{DHCP: true, Gateway: "192.168.1.1", Servers: servers}}
}

func wan(auto bool, upstream ...string) inv.Network {
	return inv.Network{ID: "wan", Name: "Internet 1", Purpose: "wan", DNS: &inv.NetworkDNS{Upstream: upstream, UpstreamAuto: auto}}
}

func router(nets ...inv.Network) Router {
	return Router{Name: "udr", Kind: "unifi", URL: "https://192.168.1.1", Networks: nets}
}

// resolver forwards to the given servers with recursion.
func resolver(fwd ...string) Resolver {
	return Resolver{ID: 7, Name: "pdns", Addresses: []string{"192.168.1.10"},
		Forwarding: &dns.Forwarding{Source: "test", Servers: fwd, RecursionDesired: true}}
}

func byID(t *testing.T, r Report, id string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %q in %+v", id, r.Checks)
	return Check{}
}

func TestHealthyChain(t *testing.T) {
	r := Evaluate([]Router{router(lan("lan", "Default", "192.168.1.10"), wan(true, "203.0.113.53", "203.0.113.54"))},
		[]Resolver{resolver("203.0.113.54", "203.0.113.53")})
	if r.Status != Pass {
		t.Fatalf("status %s: %+v", r.Status, r.Checks)
	}
	if r.ISPSource != "router" || strings.Join(r.ISP, ",") != "203.0.113.53,203.0.113.54" {
		t.Fatalf("isp %v from %q", r.ISP, r.ISPSource)
	}
	if !strings.Contains(r.Summary, "192.168.1.10") || !strings.Contains(r.Summary, "203.0.113.53") {
		t.Fatalf("summary: %s", r.Summary)
	}
	if c := byID(t, r, "fwd-7"); c.Status != Pass || c.Actual != "203.0.113.54, 203.0.113.53" {
		t.Fatalf("forwarders: %+v", c)
	}
}

func TestClientsGetTheRouter(t *testing.T) {
	r := Evaluate([]Router{router(lan("iot", "IoT"), wan(true, "203.0.113.53"))}, []Resolver{resolver("203.0.113.53")})
	c := byID(t, r, "dhcp-udr-iot")
	if c.Status != Fail || r.Status != Fail {
		t.Fatalf("want fail: %+v", c)
	}
	if c.Expected != "192.168.1.10" || c.Actual != "the router itself (192.168.1.1), which asks 203.0.113.53" {
		t.Fatalf("expected/actual: %q / %q", c.Expected, c.Actual)
	}
	if !strings.Contains(c.Fix, "Settings → Networks → IoT") || c.FixURL != "https://192.168.1.1" {
		t.Fatalf("fix: %q %q", c.Fix, c.FixURL)
	}
}

func TestDHCPHandsOutOtherServers(t *testing.T) {
	r := Evaluate([]Router{router(
		lan("a", "Public", "8.8.8.8", "1.1.1.1"),
		lan("b", "DMZ", "192.168.1.10", "8.8.8.8"),
		lan("c", "Lab", "8.8.8.8", "192.168.1.10"),
		wan(true, "203.0.113.53"))}, []Resolver{resolver("203.0.113.53")})
	if c := byID(t, r, "dhcp-udr-a"); c.Status != Fail {
		t.Fatalf("no internal server should fail: %+v", c)
	}
	for _, id := range []string{"dhcp-udr-b", "dhcp-udr-c"} {
		if c := byID(t, r, id); c.Status != Warn || !strings.Contains(c.Detail, "8.8.8.8") {
			t.Fatalf("%s: a backup that isn't internal should warn: %+v", id, c)
		}
	}
}

func TestGuestAndNoDHCPAreSkipped(t *testing.T) {
	guest := lan("g", "Guest")
	guest.Purpose, guest.Zone = "guest", "hotspot"
	static := lan("s", "Servers")
	static.DNS.DHCP = false
	r := Evaluate([]Router{router(guest, static, lan("lan", "Default", "192.168.1.10"), wan(true, "203.0.113.53"))},
		[]Resolver{resolver("203.0.113.53")})
	for _, id := range []string{"dhcp-udr-g", "dhcp-udr-s"} {
		if c := byID(t, r, id); c.Status != Skip {
			t.Fatalf("%s should be skipped: %+v", id, c)
		}
	}
	if r.Status != Pass {
		t.Fatalf("skipped networks must not fail the report: %s", r.Status)
	}
}

func TestForwarders(t *testing.T) {
	nets := []Router{router(lan("lan", "Default", "192.168.1.10"), wan(true, "203.0.113.53", "203.0.113.54"))}
	cases := []struct {
		name   string
		res    Resolver
		status string
		want   string // in the title or detail
	}{
		{"full recursion", resolver(), Fail, "root servers"},
		{"public resolver", resolver("1.1.1.1"), Fail, "1.1.1.1 is not one of your ISP's"},
		{"one ISP one public", resolver("203.0.113.53", "8.8.8.8"), Fail, "8.8.8.8"},
		{"via the router", resolver("192.168.1.1"), Warn, "router"},
		{"to itself", resolver("192.168.1.10"), Fail, "loop"},
		{"no recursion", func() Resolver { r := resolver("203.0.113.53"); r.Forwarding.RecursionDesired = false; return r }(), Fail, "recursion"},
		{"no recursor configured", Resolver{ID: 7, Name: "pdns", Addresses: []string{"192.168.1.10"}, NoResolver: true}, Unknown, "Recursor API URL"},
		{"read error", Resolver{ID: 7, Name: "pdns", Addresses: []string{"192.168.1.10"}, Error: "HTTP 401"}, Unknown, "HTTP 401"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := byID(t, Evaluate(nets, []Resolver{tc.res}), "fwd-7")
			if c.Status != tc.status || !strings.Contains(c.Title+" "+c.Actual+" "+c.Detail+" "+c.Fix, tc.want) {
				t.Fatalf("got %s %q / %q / %q", c.Status, c.Title, c.Detail, c.Fix)
			}
			if (c.Status == Fail || c.Status == Warn) && c.Fix == "" {
				t.Fatal("a failure needs a fix")
			}
		})
	}
}

func TestISPServers(t *testing.T) {
	// the router's WAN DNS typed in by hand doesn't say what the ISP provides
	manual := []Router{router(lan("lan", "Default", "192.168.1.10"), wan(false, "9.9.9.9"))}
	r := Evaluate(manual, []Resolver{resolver("9.9.9.9")})
	c := byID(t, r, "fwd-7")
	if c.Status != Warn || !strings.Contains(c.Detail, "set by hand") || c.FixURL != "#/settings" || len(r.ISP) != 0 {
		t.Fatalf("manual WAN: %+v isp %v", c, r.ISP)
	}

	// servers typed into Settings win over the router
	res := resolver("198.51.100.1")
	res.ISP = []string{"198.51.100.1", "198.51.100.2"}
	r = Evaluate(manual, []Resolver{res})
	if c := byID(t, r, "fwd-7"); c.Status != Pass || r.ISPSource != "setting" {
		t.Fatalf("ISP from settings: %+v %q", c, r.ISPSource)
	}
}

func TestSetupProblems(t *testing.T) {
	if r := Evaluate([]Router{router(lan("lan", "Default"))}, nil); r.Status != "" || len(r.Checks) != 0 {
		t.Fatalf("no DNS server means nothing to check: %+v", r)
	}

	noAddr := resolver("203.0.113.53")
	noAddr.Addresses = nil
	r := Evaluate([]Router{router(lan("lan", "Default", "192.168.1.10"), wan(true, "203.0.113.53"))}, []Resolver{noAddr})
	if c := byID(t, r, "setup-resolver"); c.Status != Unknown {
		t.Fatalf("missing resolver address: %+v", c)
	}
	if c := byID(t, r, "dhcp-udr-lan"); c.Status != Unknown {
		t.Fatalf("can't compare without an address: %+v", c)
	}

	// a router that reported no DHCP settings
	r = Evaluate([]Router{{Name: "old", Networks: []inv.Network{{ID: "x", Name: "LAN"}}}}, []Resolver{resolver("203.0.113.53")})
	if c := byID(t, r, "dhcp-old"); c.Status != Unknown {
		t.Fatalf("router without DHCP info: %+v", c)
	}
}

func TestAddresses(t *testing.T) {
	if got := strings.Join(SplitList(" 192.168.1.10, 192.168.1.11;10.0.0.1 "), "|"); got != "192.168.1.10|192.168.1.11|10.0.0.1" {
		t.Fatalf("split: %s", got)
	}
	lookup := func(h string) ([]string, error) {
		if h == "ns1.home.lan" {
			return []string{"192.168.1.10"}, nil
		}
		return nil, errors.New("nxdomain")
	}
	for in, want := range map[string]string{
		"http://192.168.1.10:8082":     "192.168.1.10",
		"http://ns1.home.lan:8081/api": "192.168.1.10",
		"[2001:db8::53]:8081":          "2001:db8::53",
		"https://[2001:db8::53]/":      "2001:db8::53",
		"http://nowhere:8081":          "",
		"":                             "",
	} {
		if got := strings.Join(HostAddresses(in, lookup), ","); got != want {
			t.Errorf("HostAddresses(%q) = %q, want %q", in, got, want)
		}
	}
	// IPv4-mapped and differently written IPv6 addresses compare equal
	s := set{}
	s.add("2001:DB8::0:53", "::ffff:192.168.1.10")
	if !s.has("2001:db8::53") || !s.has("192.168.1.10") {
		t.Fatalf("set: %v", s)
	}
}

func TestSummary(t *testing.T) {
	r := Evaluate([]Router{router(lan("a", "IoT"), lan("b", "DMZ", "192.168.1.10", "8.8.8.8"), wan(true, "203.0.113.53"))},
		[]Resolver{resolver("203.0.113.53")})
	if r.Summary != "1 problem and 1 warning in the DNS setup." {
		t.Fatalf("summary: %q", r.Summary)
	}
}
