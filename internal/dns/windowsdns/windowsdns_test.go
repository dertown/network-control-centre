package windowsdns

import (
	"context"
	"strings"
	"testing"

	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/winps"
)

type fakeShell struct {
	scripts *[]string
	answer  func(script string) string
}

func (f fakeShell) Run(_ context.Context, s string) (string, error) {
	*f.scripts = append(*f.scripts, s)
	return f.answer(s), nil
}
func (fakeShell) Close() error { return nil }

func TestWindowsDNS(t *testing.T) {
	var scripts []string
	winps.Dial = func(context.Context, string, map[string]string, map[string]string) (winps.Shell, error) {
		return fakeShell{&scripts, func(s string) string {
			switch {
			case strings.Contains(s, "Get-DnsServerZone"):
				return `[{"n":"corp.example","t":"Primary","ad":true},{"n":"1.168.192.in-addr.arpa","t":"Primary","ad":true}]`
			case strings.Contains(s, "ConvertTo-Json") && strings.Contains(s, "Get-DnsServerResourceRecord"):
				return `[{"n":"@","t":"SOA","ttl":3600,"v":"dc01.corp.example. hostmaster.corp.example. 42 900 600 86400 3600"},
					{"n":"@","t":"NS","ttl":3600,"v":"dc01.corp.example."},
					{"n":"nas","t":"A","ttl":1200,"v":"192.168.1.50"},
					{"n":"_ldap._tcp","t":"SRV","ttl":600,"v":"0 100 389 dc01.corp.example."},
					{"n":"@","t":"TXT","ttl":300,"v":"v=spf1 -all"}]`
			}
			return ""
		}}, nil
	}
	s := dns.Server{Kind: "windowsdns", Address: "dc01", Options: map[string]string{}}
	ctx := context.Background()
	p := Provider{}

	zones, err := p.ListZones(ctx, s, nil)
	if err != nil || len(zones) != 2 || zones[1].Name != "corp.example." || zones[1].Kind != "Primary (AD)" {
		t.Fatalf("zones %+v %v", zones, err)
	}
	sets, err := p.ListRecords(ctx, s, nil, "corp.example.")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]dns.RRSet{}
	for _, x := range sets {
		got[x.Name+" "+x.Type] = x
	}
	if a := got["nas.corp.example. A"]; a.TTL != 1200 || a.Records[0] != "192.168.1.50" {
		t.Fatalf("A %+v", a)
	}
	if srv := got["_ldap._tcp.corp.example. SRV"]; srv.Records[0] != "0 100 389 dc01.corp.example." {
		t.Fatalf("SRV %+v", srv)
	}
	if txt := got["corp.example. TXT"]; txt.Records[0] != `"v=spf1 -all"` {
		t.Fatalf("TXT %+v", txt)
	}
	if !strings.Contains(scripts[1], "$z='corp.example'") {
		t.Fatalf("zone not quoted into the script: %s", scripts[1])
	}

	scripts = nil
	err = p.Apply(ctx, s, nil, "corp.example", []dns.Change{
		{Op: dns.Replace, RRSet: dns.RRSet{Name: "nas.corp.example.", Type: "A", TTL: 300, Records: []string{"192.168.1.51", "192.168.1.52"}}},
		{Op: dns.Replace, RRSet: dns.RRSet{Name: "corp.example.", Type: "MX", TTL: 300, Records: []string{"10 mail.corp.example."}}},
		{Op: dns.Delete, RRSet: dns.RRSet{Name: "o'brien.corp.example.", Type: "CNAME"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scripts) != 3 {
		t.Fatalf("%d scripts", len(scripts))
	}
	if !strings.Contains(scripts[0], "$n='nas'") || strings.Count(scripts[0], "-A -IPv4Address") != 2 || !strings.Contains(scripts[0], "Remove-DnsServerResourceRecord") {
		t.Fatalf("A script:\n%s", scripts[0])
	}
	if !strings.Contains(scripts[1], "$n='@'") || !strings.Contains(scripts[1], "-MX -Preference 10 -MailExchange 'mail.corp.example'") {
		t.Fatalf("MX script:\n%s", scripts[1])
	}
	if !strings.Contains(scripts[2], "$n='o''brien'") || strings.Contains(scripts[2], "Add-") {
		t.Fatalf("delete script:\n%s", scripts[2])
	}

	// a bad value stops everything before anything runs
	scripts = nil
	err = p.Apply(ctx, s, nil, "corp.example", []dns.Change{
		{Op: dns.Replace, RRSet: dns.RRSet{Name: "a.corp.example.", Type: "A", TTL: 300, Records: []string{"10.0.0.1"}}},
		{Op: dns.Replace, RRSet: dns.RRSet{Name: "corp.example.", Type: "MX", TTL: 300, Records: []string{"mail.corp.example."}}},
	})
	if err == nil || len(scripts) != 0 {
		t.Fatalf("bad MX: err %v, %d scripts ran", err, len(scripts))
	}
}
