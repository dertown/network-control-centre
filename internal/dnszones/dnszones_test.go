package dnszones

import (
	"context"
	"strings"
	"testing"

	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/store"
)

func lan(id, name string, vlan int, subnet, domain string) inventory.Network {
	return inventory.Network{ID: id, Name: name, Purpose: "corporate", VLAN: vlan, Subnet: subnet, Zone: "internal",
		DNS: &inventory.NetworkDNS{DHCP: true, Domain: domain}}
}

func lab() ([]Router, []Server) {
	dmz := lan("n_dmz", "DMZ", 50, "192.168.50.0/24", "")
	dmz.Zone = "dmz"
	guest := lan("n_guest", "Guest", 20, "192.168.20.0/24", "")
	guest.Purpose = "guest"
	routers := []Router{{ID: 1, Name: "udr7", CanSetDomain: true, Networks: []inventory.Network{
		lan("n_default", "Default", 0, "192.168.1.0/24", "home.lan"),
		lan("n_iot", "IoT", 30, "192.168.30.0/24", ""),
		dmz, guest,
		{ID: "n_wan", Name: "Internet", Purpose: "wan"},
	}}}
	servers := []Server{{ID: 9, Name: "pdns", Kind: "powerdns", CanCreate: true, Zones: []dns.Zone{
		{Name: "home.lan."}, {Name: "dmz.home.lan."}, {Name: "1.168.192.in-addr.arpa."},
	}}}
	return routers, servers
}

func row(rep Report, network string) Row {
	for _, r := range rep.Rows {
		if r.Network == network {
			return r
		}
	}
	return Row{}
}

func codes(r Row) string {
	var c []string
	for _, is := range r.Issues {
		c = append(c, is.Code)
	}
	return strings.Join(c, ",")
}

func TestEvaluate(t *testing.T) {
	routers, servers := lab()

	// nothing assigned yet: zones are suggested under the main LAN's domain
	rep := Evaluate(routers, servers, nil)
	if rep.Domain != "home.lan." || len(rep.Rows) != 4 {
		t.Fatalf("domain %q, %d rows (WAN must be left out)", rep.Domain, len(rep.Rows))
	}
	for net, want := range map[string]string{"Default": "home.lan.", "IoT": "iot.home.lan.", "DMZ": "dmz.home.lan.", "Guest": "guest.home.lan."} {
		if got := row(rep, net).Suggested; got != want {
			t.Errorf("%s suggestion %q, want %q", net, got, want)
		}
	}
	if r := row(rep, "IoT"); r.Status != StatusWarn || codes(r) != IssueNoZone || r.Issues[0].Fix != "Create iot.home.lan. and assign it" {
		t.Fatalf("IoT unassigned: %+v", r)
	}
	if r := row(rep, "DMZ"); r.Issues[0].Fix != "Assign dmz.home.lan." {
		t.Fatalf("DMZ unassigned: %+v", r)
	}
	if r := row(rep, "Guest"); r.Status != StatusSkip || len(r.Issues) != 0 {
		t.Fatalf("guest networks aren't nagged: %+v", r)
	}

	as := []Assignment{
		{ID: 1, ServerID: 9, Zone: "home.lan.", RouterID: 1, NetworkID: "n_default", Network: "Default"},
		{ID: 2, ServerID: 9, Zone: "dmz.home.lan.", RouterID: 1, NetworkID: "n_iot", Network: "IoT", VLAN: 30},
		{ID: 3, ServerID: 9, Zone: "dmz.home.lan.", RouterID: 1, NetworkID: "n_dmz", Network: "DMZ", VLAN: 50},
		{ID: 4, ServerID: 9, Zone: "cams.home.lan.", RouterID: 1, NetworkID: "n_gone", Network: "Cameras", VLAN: 40},
	}
	rep = Evaluate(routers, servers, as)
	if r := row(rep, "Default"); r.Status != StatusPass || !r.ZoneFound || !r.ReverseFound {
		t.Fatalf("Default: %+v", r)
	}
	// IoT got the DMZ's zone: wrong name, shared, no search domain, no reverse zone
	r := row(rep, "IoT")
	if r.Status != StatusWarn || codes(r) != "no_reverse,name_mismatch,shared_zone,dhcp_domain_unset" {
		t.Fatalf("IoT: %s %+v", codes(r), r)
	}
	if !strings.Contains(r.Issues[1].Message, "DMZ (VLAN 50)") || r.ReverseZone != "30.168.192.in-addr.arpa." {
		t.Fatalf("IoT messages: %+v", r.Issues)
	}
	if r := row(rep, "DMZ"); strings.Contains(codes(r), IssueNameMismatch) {
		t.Fatalf("DMZ's own zone is not a mismatch: %s", codes(r))
	}
	if len(rep.Orphans) != 1 || rep.Orphans[0].Network != "Cameras" || rep.Status != StatusFail {
		t.Fatalf("orphans: %+v status %s", rep.Orphans, rep.Status)
	}
	for _, z := range rep.Zones {
		if z.Zone == "dmz.home.lan." && (z.Parent != "home.lan." || len(z.Networks) != 2) {
			t.Fatalf("zone use: %+v", z)
		}
	}
	if rep.Zones[len(rep.Zones)-1].Zone != "1.168.192.in-addr.arpa." {
		t.Fatalf("reverse zones last: %+v", rep.Zones)
	}

	// a zone that isn't on the server, a router handing out another domain, an unreadable server
	routers[0].Networks[1].DNS.Domain = "corp.lan"
	as = []Assignment{{ID: 2, ServerID: 9, Zone: "iot.home.lan.", RouterID: 1, NetworkID: "n_iot", Network: "IoT"}}
	if r := row(Evaluate(routers, servers, as), "IoT"); r.Status != StatusFail || codes(r) != "zone_missing,no_reverse,dhcp_domain_other" {
		t.Fatalf("missing zone: %s", codes(r))
	}
	servers[0].Error, servers[0].Zones = "connection refused", nil
	if r := row(Evaluate(routers, servers, as), "IoT"); r.Status != StatusWarn || codes(r) != "server_error,dhcp_domain_other" {
		t.Fatalf("server down: %s %s", r.Status, codes(r))
	}
	if r := row(Evaluate(routers, nil, as), "IoT"); r.Status != StatusFail || !strings.HasPrefix(codes(r), IssueServerGone) {
		t.Fatalf("server gone: %s", codes(r))
	}
}

// fakeEnv is an Env over an in-memory DNS provider.
type fakeEnv struct {
	p       *fakeDNS
	routers []Router
	domains map[string]string
}

func (e *fakeEnv) DNSServer(ctx context.Context, id int64) (dns.Provider, dns.Server, map[string]string, error) {
	return e.p, dns.Server{ID: id, Name: "pdns", Kind: "fake"}, nil, nil
}
func (e *fakeEnv) Routers(ctx context.Context) ([]Router, error) { return e.routers, nil }
func (e *fakeEnv) SetNetworkDomain(ctx context.Context, routerID int64, networkID, domain string) error {
	e.domains[networkID] = domain
	return nil
}

type fakeDNS struct {
	zones   map[string][]dns.RRSet
	created []dns.ZoneSpec
	applied map[string][]dns.Change
}

func (f *fakeDNS) Kind() string { return "fake" }
func (f *fakeDNS) ListZones(ctx context.Context, s dns.Server, c map[string]string) ([]dns.Zone, error) {
	var out []dns.Zone
	for z := range f.zones {
		out = append(out, dns.Zone{Name: z})
	}
	return out, nil
}
func (f *fakeDNS) ListRecords(ctx context.Context, s dns.Server, c map[string]string, zone string) ([]dns.RRSet, error) {
	return f.zones[zone], nil
}
func (f *fakeDNS) Apply(ctx context.Context, s dns.Server, c map[string]string, zone string, ch []dns.Change) error {
	f.applied[zone] = append(f.applied[zone], ch...)
	return nil
}
func (f *fakeDNS) CreateZone(ctx context.Context, s dns.Server, c map[string]string, spec dns.ZoneSpec) error {
	f.created = append(f.created, spec)
	f.zones[spec.Name] = []dns.RRSet{{Name: spec.Name, Type: "NS", Records: spec.Nameservers}}
	return nil
}
func (f *fakeDNS) DeleteZone(ctx context.Context, s dns.Server, c map[string]string, zone string) error {
	delete(f.zones, zone)
	return nil
}

func TestPlanAndApply(t *testing.T) {
	routers, _ := lab()
	f := &fakeDNS{applied: map[string][]dns.Change{}, zones: map[string][]dns.RRSet{
		"home.lan.": {{Name: "home.lan.", Type: "NS", Records: []string{"ns1.home.lan"}}},
	}}
	env := &fakeEnv{p: f, routers: routers, domains: map[string]string{}}
	ctx := context.Background()

	if _, err := BuildPlan(ctx, env, PlanRequest{ServerID: 9}); err == nil {
		t.Fatal("an empty request should be refused")
	}
	if _, err := BuildPlan(ctx, env, PlanRequest{ServerID: 9, Assign: []AssignSpec{{Zone: "iot.home.lan", RouterID: 1, NetworkID: "n_iot"}}}); err == nil ||
		!strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("assigning a zone that doesn't exist: %v", err)
	}
	if _, err := BuildPlan(ctx, env, PlanRequest{ServerID: 9, Zones: []NewZone{{Name: "corp.example"}}}); err == nil ||
		!strings.Contains(err.Error(), "name server") {
		t.Fatalf("a zone with no parent needs name servers: %v", err)
	}

	// a subdomain per VLAN, delegated, with a reverse zone and the router's search domain
	req := PlanRequest{ServerID: 9,
		Zones: []NewZone{{Name: "cams.iot.home.lan", Delegate: true}, {Name: "iot.home.lan", Delegate: true}, {Name: "home.lan"}},
		Assign: []AssignSpec{{Zone: "iot.home.lan.", RouterID: 1, NetworkID: "n_iot", SetDHCPDomain: true, Reverse: true},
			{Zone: "home.lan", RouterID: 1, NetworkID: "n_default", SetDHCPDomain: true}},
	}
	plan, err := BuildPlan(ctx, env, req)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, s := range plan.Steps {
		kinds = append(kinds, s.Kind+":"+s.Zone+s.Domain)
	}
	want := "create_zone:iot.home.lan.,create_zone:cams.iot.home.lan.,delegate:home.lan.,delegate:iot.home.lan.," +
		"create_reverse:30.168.192.in-addr.arpa.,assign:iot.home.lan.,assign:home.lan.,dhcp_domain:iot.home.lan"
	if strings.Join(kinds, ",") != want {
		t.Fatalf("steps:\n%s\nwant\n%s", strings.Join(kinds, ","), want)
	}
	if len(plan.Warnings) != 1 || !strings.Contains(plan.Warnings[0], "home.lan. already exists") {
		t.Fatalf("warnings: %v", plan.Warnings)
	}
	if ns := plan.Steps[0].Nameservers; len(ns) != 1 || ns[0] != "ns1.home.lan." {
		t.Fatalf("name servers come from the parent: %v", ns)
	}
	if len(f.created) != 0 || len(env.domains) != 0 {
		t.Fatal("planning must not change anything")
	}

	st, err := store.OpenPath(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.DB.Exec(`INSERT INTO targets (id, kind, category, name, address, secret_path) VALUES
		(1, 'unifi', 'device', 'udr7', 'https://udr7', 'targets/1'), (9, 'powerdns', 'dns', 'pdns', 'http://pdns', 'targets/9')`); err != nil {
		t.Fatal(err)
	}
	var audited int
	res, err := Apply(ctx, env, st.DB, "derek", plan, func(StepResult) { audited++ })
	if err != nil || len(res) != len(plan.Steps) || audited != len(plan.Steps) {
		t.Fatalf("apply: %v %d results %d audited", err, len(res), audited)
	}
	if len(f.created) != 3 || f.created[2].Name != "30.168.192.in-addr.arpa." {
		t.Fatalf("created: %+v", f.created)
	}
	if d := f.applied["home.lan."]; len(d) != 1 || d[0].RRSet.Name != "iot.home.lan." || d[0].RRSet.Type != "NS" {
		t.Fatalf("delegation: %+v", f.applied)
	}
	if env.domains["n_iot"] != "iot.home.lan" || len(env.domains) != 1 {
		t.Fatalf("domains: %v (Default already hands out home.lan)", env.domains)
	}
	as, err := List(ctx, st.DB)
	if err != nil || len(as) != 2 || as[1].Zone != "iot.home.lan." || as[1].VLAN != 30 || as[1].UpdatedBy != "derek" {
		t.Fatalf("assignments: %+v %v", as, err)
	}

	// reassigning replaces the network's zone
	if _, err := Put(ctx, st.DB, Assignment{ServerID: 9, Zone: "cams.iot.home.lan", RouterID: 1, NetworkID: "n_iot", Network: "IoT"}); err != nil {
		t.Fatal(err)
	}
	as, _ = List(ctx, st.DB)
	if len(as) != 2 || as[1].Zone != "cams.iot.home.lan." {
		t.Fatalf("reassign: %+v", as)
	}
	if err := Delete(ctx, st.DB, as[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := Delete(ctx, st.DB, as[0].ID); err == nil {
		t.Fatal("deleting twice should fail")
	}
}
