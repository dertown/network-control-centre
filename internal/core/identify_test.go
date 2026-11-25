package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/dns"
	hv "github.com/dertown/network-control-centre/internal/hypervisor"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/iot"
	"github.com/dertown/network-control-centre/internal/storage"
	"github.com/dertown/network-control-centre/internal/store"
)

const sw = "aa:bb:cc:00:00:04"

// lab is a small network: a managed switch with clients on three shared ports, which the
// router turns into three inferred "unmanaged switches".
func lab() inventory.Snapshot {
	inf := func(port string) string { return "inferred:" + sw + ":" + port }
	dev := func(port string) inventory.Device {
		return inventory.Device{ID: inf(port), Name: "Unmanaged switch on Rack switch Port " + port, Kind: inventory.KindUnmanaged,
			Discovery: inventory.SourceInferred, Online: true, Clients: 2}
	}
	cl := func(mac, name, ip, vendor, port string) inventory.Client {
		return inventory.Client{MAC: mac, Name: name, IP: ip, Vendor: vendor, Wired: true, ParentID: inf(port), SwitchMAC: sw}
	}
	return inventory.Snapshot{
		Devices: []inventory.Device{
			{ID: sw, Name: "Rack switch", Kind: inventory.KindSwitch, IP: "192.168.1.30", Discovery: inventory.SourceController, Online: true},
			dev("9"), dev("4"), dev("5"),
			{ID: "11:22:33:44:55:66", Name: "11:22:33:44:55:66", Kind: inventory.KindUnknown, Discovery: inventory.SourceLLDP,
				IP: "192.168.1.13", Detail: "Debian GNU/Linux 12", Online: true},
		},
		Links: []inventory.Link{
			{A: sw, B: inf("9"), Source: "inferred"}, {A: sw, B: inf("4"), Source: "inferred"}, {A: sw, B: inf("5"), Source: "inferred"},
			{A: sw, B: "11:22:33:44:55:66", Source: "lldp"},
		},
		Clients: []inventory.Client{
			// port 9: a Proxmox host and two of its guests
			cl("58:47:ca:00:00:01", "pve1", "192.168.1.12", "Intel", "9"),
			cl("bc:24:11:00:00:64", "ncc", "192.168.1.247", "", "9"),
			cl("bc:24:11:00:00:c8", "pihole", "192.168.1.53", "", "9"),
			// port 4: a Netgear smart switch and a PC behind it
			cl("10:20:30:40:50:60", "office-sw", "192.168.1.40", "Netgear", "4"),
			cl("de:ad:00:00:00:05", "desk-pc", "192.168.1.80", "Dell", "4"),
			// port 5: a printer that reuses an old VM's address, and a TV
			cl("de:ad:00:00:00:02", "Printer", "192.168.1.60", "Brother", "5"),
			cl("de:ad:00:00:00:03", "tv", "192.168.1.61", "Samsung", "5"),
			// the NAS, straight on a port
			{MAC: "de:ad:00:00:00:01", Name: "nas", IP: "192.168.1.50", Vendor: "Synology", Wired: true, ParentID: sw},
		},
	}
}

func labSources() Sources {
	return Sources{
		Targets: []Target{
			{ID: 1, Category: CategoryHypervisor, Kind: "proxmox", Name: "homelab", Address: "https://192.168.1.12:8006", Enabled: true},
			{ID: 2, Category: CategoryStorage, Kind: "qnap", Name: "qnap", Address: "https://nas.home.lan", Enabled: true},
			{ID: 3, Category: CategoryDNS, Kind: "powerdns", Name: "ns1", Address: "http://192.168.1.10:8081", Enabled: true},
		},
		VMs: []hv.Inventory{{Target: "homelab", Platform: "proxmox", Version: "Proxmox VE 8.2",
			Hosts: []hv.Host{{Name: "pve1", Online: true, CPUs: 8}, {Name: "pve2", Online: true, IPs: []string{"192.168.1.13"}}},
			VMs: []hv.VM{
				{ID: "homelab/qemu/100", Name: "ncc", Type: "qemu", State: "running", Host: "pve1", IPs: []string{"192.168.1.247"}, MACs: []string{"bc:24:11:00:00:64"}},
				{ID: "homelab/lxc/200", Name: "pihole", Type: "lxc", State: "running", Host: "pve1", IPs: []string{"192.168.1.53/24"}, MACs: []string{"BC:24:11:00:00:C8"}},
				{ID: "homelab/lxc/201", Name: "unifi-backup", Type: "lxc", State: "running", Host: "pve2", IPs: []string{"192.168.1.60"}, MACs: []string{"bc:24:11:00:00:c9"}},
			}}},
		Storage: []StorageEntry{{TargetID: 2, Inventory: storage.Inventory{Target: "qnap",
			System:  storage.System{Name: "nas", Vendor: "QNAP", Model: "TS-464", Health: "good", NICs: []storage.NIC{{IP: "192.168.1.50", MAC: "24:5E:BE:11:22:33"}}},
			Volumes: []storage.Volume{{ID: "1", Used: 10, Total: 100}}}}},
		DNS: []DNSName{
			{Name: "pve1.home.lan", IP: "192.168.1.12", Type: "A", Server: "ns1"},
			{Name: "pve2.home.lan", IP: "192.168.1.13", Type: "PTR", Server: "ns1"},
			{Name: "nas.home.lan", IP: "192.168.1.50", Type: "A", Server: "ns1"},
		},
	}
}

func node(t *testing.T, g Graph, id string) *Node {
	t.Helper()
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			return &g.Nodes[i]
		}
	}
	return nil
}

func enriched(t *testing.T, src Sources, withClients bool) Graph {
	t.Helper()
	snaps := []inventory.Snapshot{lab()}
	g := BuildGraph(snaps, withClients)
	Enrich(&g, snaps, src)
	return g
}

func sources(ev []Evidence) string {
	var s []string
	for _, e := range ev {
		s = append(s, e.Source)
	}
	return strings.Join(s, ",")
}

func TestEnrichFindsProxmoxHostBehindUnmanagedSwitch(t *testing.T) {
	g := enriched(t, labSources(), true)
	n := node(t, g, "inferred:"+sw+":9")
	if n == nil || n.Identity == nil {
		t.Fatalf("port 9 node: %+v", n)
	}
	id := n.Identity
	if id.Role != RoleHypervisor || id.Name != "pve1" || id.What != "Proxmox VE host" || id.Confidence != "high" || id.Source != IdentityAuto {
		t.Fatalf("identity: %+v", id)
	}
	if n.Label != "pve1" || id.Label != "Unmanaged switch on Rack switch Port 9" || n.IP != "192.168.1.12" {
		t.Errorf("relabel: label %q was %q ip %q", n.Label, id.Label, n.IP)
	}
	if got := sources(id.Evidence); !strings.Contains(got, "hypervisor") || !strings.Contains(got, "clients") {
		t.Errorf("evidence sources %q: %+v", got, id.Evidence)
	}
	if id.Merged != "58:47:ca:00:00:01" || node(t, g, "58:47:ca:00:00:01") != nil {
		t.Errorf("the host's own client should fold into the node: merged %q", id.Merged)
	}
	for _, e := range g.Edges {
		if e.Target == "58:47:ca:00:00:01" {
			t.Errorf("edge to folded client left behind: %+v", e)
		}
	}
	if n.Related == nil || n.Related.Host == nil || n.Related.Host.VMs != 2 || len(n.Related.VMs) != 2 || len(n.Related.DNS) != 1 ||
		n.Related.DNS[0].Name != "pve1.home.lan" || len(n.Related.Connections) != 1 || n.Related.Connections[0].Name != "homelab" {
		t.Errorf("related: %+v", n.Related)
	}
	// its guests are named as VMs and containers
	if c := node(t, g, "bc:24:11:00:00:c8"); c == nil || c.Identity == nil || c.Identity.Role != RoleContainer ||
		c.Identity.What != "Container on pve1" || c.Related == nil || c.Related.VM == nil || c.Related.Host == nil || c.Related.Host.Name != "pve1" {
		t.Errorf("pihole: %+v", c)
	}
	if c := node(t, g, "bc:24:11:00:00:64"); c == nil || c.Identity == nil || c.Identity.Role != RoleVM || c.Identity.Confidence != "high" {
		t.Errorf("ncc VM: %+v", c)
	}
	// without clients drawn the answer is the same
	g = enriched(t, labSources(), false)
	if n := node(t, g, "inferred:"+sw+":9"); n.Identity == nil || n.Identity.Name != "pve1" {
		t.Errorf("without clients: %+v", n)
	}
}

func TestEnrichNamesAnotherSwitch(t *testing.T) {
	g := enriched(t, labSources(), true)
	n := node(t, g, "inferred:"+sw+":4")
	if n.Identity == nil || n.Identity.Role != RoleSwitch || n.Identity.Name != "office-sw" || n.Label != "office-sw" ||
		n.IP != "192.168.1.40" || n.Identity.Merged != "10:20:30:40:50:60" {
		t.Fatalf("port 4: %+v %+v", n, n.Identity)
	}
	if !strings.Contains(n.Identity.Evidence[0].Text, "its name 'office-sw' and its maker Netgear") {
		t.Errorf("evidence: %+v", n.Identity.Evidence)
	}
	if node(t, g, "de:ad:00:00:00:05") == nil {
		t.Error("the PC behind the switch must stay")
	}
}

func TestEnrichMixedPortIsASwitchAndIgnoresReusedAddress(t *testing.T) {
	g := enriched(t, labSources(), true)
	n := node(t, g, "inferred:"+sw+":5")
	if n.Identity == nil || n.Identity.Role != RoleSwitch || n.Identity.Name != "" || n.Label != "Unmanaged switch on Rack switch Port 5" {
		t.Fatalf("port 5: %+v", n.Identity)
	}
	// the printer has the address of a VM whose MAC is different: not that VM
	if p := node(t, g, "de:ad:00:00:00:02"); p.Identity != nil {
		t.Errorf("printer taken for a VM: %+v", p.Identity)
	}
}

func TestEnrichNASAndDNSNamedNeighbour(t *testing.T) {
	g := enriched(t, labSources(), true)
	nas := node(t, g, "de:ad:00:00:00:01")
	if nas.Identity == nil || nas.Identity.Role != RoleNAS || nas.Identity.What != "QNAP NAS" || nas.Related == nil || nas.Related.Storage == nil ||
		nas.Related.Storage.Total != 100 {
		t.Fatalf("nas: %+v %+v", nas.Identity, nas.Related)
	}
	if nas.Label != "nas" {
		t.Errorf("a client with a real name keeps it: %q", nas.Label)
	}
	// an LLDP neighbour with only a MAC for a name: its address is pve2's, and DNS agrees
	n := node(t, g, "11:22:33:44:55:66")
	if n.Identity == nil || n.Identity.Role != RoleHypervisor || n.Identity.Name != "pve2" || n.Label != "pve2" {
		t.Fatalf("neighbour: %+v", n.Identity)
	}
	if got := sources(n.Identity.Evidence); got != "hypervisor,dns" {
		t.Errorf("evidence %q: %+v", got, n.Identity.Evidence)
	}
	// the managed switch is left as the controller says, but still gets what's related
	if s := node(t, g, sw); s.Identity != nil {
		t.Errorf("managed switch identified: %+v", s.Identity)
	}
}

func TestEnrichVMsOnlyAndMACRangeOnly(t *testing.T) {
	snap := lab()
	// drop pve1's own port: only its guests are seen on port 9
	snap.Clients = snap.Clients[1:]
	g := BuildGraph([]inventory.Snapshot{snap}, true)
	Enrich(&g, []inventory.Snapshot{snap}, labSources())
	n := node(t, g, "inferred:"+sw+":9")
	if n.Identity == nil || n.Identity.Name != "pve1" || n.Identity.Merged != "" || n.Identity.Confidence != "medium" {
		t.Fatalf("VMs only: %+v", n.Identity)
	}
	// with no hypervisor connection at all, the MAC range still says Proxmox
	src := labSources()
	src.VMs = nil
	g = BuildGraph([]inventory.Snapshot{snap}, true)
	Enrich(&g, []inventory.Snapshot{snap}, src)
	n = node(t, g, "inferred:"+sw+":9")
	if n.Identity == nil || n.Identity.Role != RoleHypervisor || n.Identity.Name != "" || n.Identity.What != "Proxmox VE host" ||
		n.Identity.Evidence[0].Source != "mac" {
		t.Fatalf("MAC range: %+v", n.Identity)
	}
	if c := node(t, g, "bc:24:11:00:00:64"); c.Identity == nil || c.Identity.Confidence != "low" || c.Identity.Role != RoleVM {
		t.Errorf("guest by MAC range: %+v", c.Identity)
	}
}

func TestEnrichOverrides(t *testing.T) {
	at := time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)
	src := labSources()
	src.IoT = []iot.Device{{MAC: "de:ad:00:00:00:03", Name: "tv", Type: iot.TypeDisplay, Room: "Lounge"}}
	src.Overrides = map[string]IdentityOverride{
		// confirmed NCC's guess
		"inferred:" + sw + ":9": {Role: RoleHypervisor, Name: "pve1", Confirmed: true, By: "derek", At: at},
		// says the "switch" on port 4 is really a NAS, named by hand
		"inferred:" + sw + ":4": {Role: RoleNAS, Name: "backup-nas", By: "derek", At: at},
	}
	g := enriched(t, src, true)
	n := node(t, g, "inferred:"+sw+":9")
	if n.Identity.Source != IdentityConfirmed || n.Identity.By != "derek" || n.Identity.Merged == "" || len(n.Identity.Evidence) == 0 {
		t.Errorf("confirmed: %+v", n.Identity)
	}
	n = node(t, g, "inferred:"+sw+":4")
	if n.Identity.Source != IdentityManual || n.Identity.Role != RoleNAS || n.Label != "backup-nas" || n.Identity.Confidence != "manual" ||
		n.Identity.Guess == nil || n.Identity.Guess.Name != "office-sw" || n.Identity.Merged != "" {
		t.Fatalf("manual: %+v", n.Identity)
	}
	if node(t, g, "10:20:30:40:50:60") == nil || n.IP != "" {
		t.Errorf("overruled guess must not swallow the client or take its address (ip %q)", n.IP)
	}
	if tv := node(t, g, "de:ad:00:00:00:03"); tv.Identity == nil || tv.Identity.Role != RoleIoT || tv.Related.IoT == nil || tv.Related.IoT.Location != "Lounge" {
		t.Errorf("IoT: %+v", tv.Identity)
	}
}

func TestIdentityOverrideStore(t *testing.T) {
	st, err := store.OpenPath(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := SetIdentityOverride(ctx, st.DB, IdentityOverride{NodeID: "x", Role: "toaster"}); err == nil {
		t.Error("unknown role accepted")
	}
	if err := SetIdentityOverride(ctx, st.DB, IdentityOverride{NodeID: "x", Role: RoleNAS, Name: "a\nb"}); err == nil {
		t.Error("two-line name accepted")
	}
	if err := SetIdentityOverride(ctx, st.DB, IdentityOverride{NodeID: "x", Role: RoleNAS, Name: " nas ", By: "derek"}); err != nil {
		t.Fatal(err)
	}
	if err := SetIdentityOverride(ctx, st.DB, IdentityOverride{NodeID: "x", Role: RoleSwitch, Confirmed: true, By: "sam"}); err != nil {
		t.Fatal(err)
	}
	m, err := IdentityOverrides(ctx, st.DB)
	if err != nil || len(m) != 1 || m["x"].Role != RoleSwitch || !m["x"].Confirmed || m["x"].By != "sam" || m["x"].At.IsZero() {
		t.Fatalf("%v %+v", err, m)
	}
	if ok, err := DeleteIdentityOverride(ctx, st.DB, "x"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ := DeleteIdentityOverride(ctx, st.DB, "x"); ok {
		t.Error("deleted twice")
	}
}

func TestAddressNames(t *testing.T) {
	got := AddressNames("ns1", []dns.RRSet{
		{Name: "pve1.home.lan.", Type: "A", Records: []string{"192.168.1.12"}},
		{Name: "pve1.home.lan.", Type: "AAAA", Records: []string{"fd00::12"}},
		{Name: "12.1.168.192.in-addr.arpa.", Type: "PTR", Records: []string{"PVE1.home.lan."}},
		{Name: "2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.", Type: "PTR", Records: []string{"nas.home.lan."}},
		{Name: "www.home.lan.", Type: "CNAME", Records: []string{"pve1.home.lan."}},
		{Name: "bad.in-addr.arpa.", Type: "PTR", Records: []string{"x."}},
	})
	want := []string{"pve1.home.lan=192.168.1.12/A", "pve1.home.lan=fd00::12/AAAA", "pve1.home.lan=192.168.1.12/PTR", "nas.home.lan=fd00::12/PTR"}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i, w := range want {
		if g := got[i].Name + "=" + got[i].IP + "/" + got[i].Type; g != w || got[i].Server != "ns1" {
			t.Errorf("%d: %s, want %s", i, g, w)
		}
	}
}

func TestDNSNamesCache(t *testing.T) {
	st, err := store.OpenPath(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tg := &Targets{DB: st.DB}
	tt := &Target{Kind: "powerdns", Category: CategoryDNS, Name: "ns1", Address: "http://x", Enabled: true}
	if err := tg.Create(ctx, tt); err != nil {
		t.Fatal(err)
	}
	if err := SaveDNSNames(ctx, st.DB, tt.ID, []DNSName{{Name: "a.lan", IP: "10.0.0.1", Type: "A", Server: "ns1"}}); err != nil {
		t.Fatal(err)
	}
	got, err := LatestDNSNames(ctx, st.DB)
	if err != nil || len(got) != 1 || got[0].Name != "a.lan" {
		t.Fatalf("%v %+v", err, got)
	}
}
