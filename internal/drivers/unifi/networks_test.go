package unifi

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	inv "github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/mocklab"
)

func mockSiteConfig(t *testing.T, withZones bool) *siteConfig {
	t.Helper()
	cfg := &siteConfig{}
	for b, out := range map[*[]byte]any{
		&mocklab.RestNetworkConf: &envelope[rawNetwork]{},
		&mocklab.RestPortConf:    &envelope[rawPortConf]{},
		&mocklab.RestWLANConf:    &envelope[rawWLAN]{},
	} {
		if err := json.Unmarshal(*b, out); err != nil {
			t.Fatal(err)
		}
		switch e := out.(type) {
		case *envelope[rawNetwork]:
			cfg.Networks = e.Data
		case *envelope[rawPortConf]:
			cfg.PortConfs = e.Data
		case *envelope[rawWLAN]:
			cfg.WLANs = e.Data
		}
	}
	if withZones {
		if err := json.Unmarshal(mocklab.FirewallZones, &cfg.Zones); err != nil {
			t.Fatal(err)
		}
		cfg.ZonesKnown = true
	}
	return cfg
}

func buildWithNetworks(t *testing.T, withZones bool) *inv.Snapshot {
	t.Helper()
	return Build("home", load[rawDevice](t, "stat_device.json"), load[rawClient](t, "stat_sta.json"), mockSiteConfig(t, withZones), time.Now())
}

func portByName(d *inv.Device, name string) inv.Port {
	for _, p := range d.Ports {
		if p.Name == name {
			return p
		}
	}
	return inv.Port{}
}

func TestBuildNetworksAndZones(t *testing.T) {
	snap := buildWithNetworks(t, true)
	nets := map[string]inv.Network{}
	for _, n := range snap.Networks {
		nets[n.ID] = n
	}
	if len(snap.Networks) != 5 || snap.Networks[len(snap.Networks)-1].ID != "net_wan" {
		t.Fatalf("networks (WAN last): %+v", snap.Networks)
	}
	cases := []struct {
		id, zone, zoneName string
		vlan               int
		subnet             string
	}{
		{"net_default", ZoneInternal, "Internal", 0, "192.168.1.0/24"},
		{"net_guest", ZoneHotspot, "Hotspot", 20, "192.168.20.0/24"},
		{"net_iot", ZoneCustom, "IoT", 30, "192.168.30.0/24"}, // vlan sent as a string
		{"net_dmz", ZoneDMZ, "Dmz", 50, "192.168.50.0/24"},
		{"net_wan", ZoneExternal, "External", 0, ""},
	}
	for _, c := range cases {
		n := nets[c.id]
		if n.Zone != c.zone || n.ZoneName != c.zoneName || n.VLAN != c.vlan || n.Subnet != c.subnet || n.ZoneSource != "firewall" {
			t.Errorf("%s: %+v", c.id, n)
		}
	}
	if !nets["net_iot"].Isolated || !reflect.DeepEqual(nets["net_guest"].SSIDs, []string{"Home-Guest"}) {
		t.Errorf("iot isolation / guest SSIDs: %+v %+v", nets["net_iot"], nets["net_guest"])
	}

	router, rack := deviceByID(snap, "aa:bb:cc:00:00:01"), deviceByID(snap, "aa:bb:cc:00:00:04")
	ports := []struct {
		dev           *inv.Device
		port, profile string
		native        string
		tagged        []string
	}{
		{router, "Port 1", "Trunk to rack", "net_default", []string{"net_iot", "net_dmz"}}, // per-port override
		{router, "Port 2", "", "net_default", []string{"net_guest", "net_iot", "net_dmz"}}, // UniFi default: all
		{router, "WAN", "", "", nil},
		{rack, "Port 12", "DMZ servers", "net_dmz", nil},
	}
	for _, c := range ports {
		p := portByName(c.dev, c.port)
		if p.Profile != c.profile || p.NativeNetwork != c.native || !reflect.DeepEqual(p.TaggedNetworks, c.tagged) {
			t.Errorf("%s %s: profile=%q native=%q tagged=%v", c.dev.Name, c.port, p.Profile, p.NativeNetwork, p.TaggedNetworks)
		}
	}
	if rack.Network != "net_default" {
		t.Errorf("rack switch management network: %q", rack.Network)
	}

	links := map[string]inv.Link{}
	for _, l := range snap.Links {
		links[l.A+">"+l.B] = l
	}
	if l := links["aa:bb:cc:00:00:01>aa:bb:cc:00:00:04"]; !reflect.DeepEqual(l.Networks, []string{"net_default", "net_iot", "net_dmz"}) {
		t.Errorf("router→rack trunk carries %v", l.Networks)
	}
	if l := links["aa:bb:cc:00:00:02>aa:bb:cc:00:00:03"]; len(l.Networks) != 4 {
		t.Errorf("wireless mesh should carry every LAN network: %v", l.Networks)
	}

	clients := map[string]inv.Client{}
	for _, c := range snap.Clients {
		clients[c.Name] = c
	}
	want := map[string]struct {
		id   string
		vlan int
	}{
		"web-dmz": {"net_dmz", 50}, "thermostat": {"net_iot", 30}, // thermostat: no network_id, found by IP
		"guest-laptop": {"net_guest", 20}, "Printer": {"net_default", 0}, "nas": {"net_default", 0},
	}
	for name, w := range want {
		if c := clients[name]; c.NetworkID != w.id || c.VLAN != w.vlan {
			t.Errorf("client %s: network=%q vlan=%d, want %q %d", name, c.NetworkID, c.VLAN, w.id, w.vlan)
		}
	}
	if clients["thermostat"].Network != "IoT" {
		t.Errorf("thermostat network name: %q", clients["thermostat"].Network)
	}
}

func TestZonesInferredWithoutZoneFirewall(t *testing.T) {
	snap := buildWithNetworks(t, false)
	for _, n := range snap.Networks {
		want := map[string]string{"net_default": ZoneInternal, "net_guest": ZoneHotspot, "net_iot": ZoneInternal,
			"net_dmz": ZoneDMZ, "net_wan": ZoneExternal}[n.ID]
		if n.Zone != want || n.ZoneSource != "inferred" {
			t.Errorf("%s: zone %q (%s), want %q", n.ID, n.Zone, n.ZoneSource, want)
		}
	}
}

func TestPortVLANModes(t *testing.T) {
	ix := buildNetIndex("home", mockSiteConfig(t, false), nil)
	cases := []struct {
		name   string
		p      rawPort
		ov     *rawPortOverride
		native string
		tagged []string
	}{
		{"no profile", rawPort{}, nil, "net_default", []string{"net_guest", "net_iot", "net_dmz"}},
		{"block all", rawPort{PortconfID: "pc_iot"}, nil, "net_iot", nil},
		{"custom minus excluded", rawPort{NativeNetworkID: "net_iot", TaggedVLANMgmt: "custom", ExcludedIDs: []string{"net_guest"}}, nil,
			"net_iot", []string{"net_default", "net_dmz"}},
		{"override native", rawPort{}, &rawPortOverride{NativeNetworkID: "net_dmz", Forward: "native"}, "net_dmz", nil},
		{"disabled", rawPort{Forward: "disabled"}, nil, "", nil},
	}
	for _, c := range cases {
		_, native, tagged := ix.port(c.p, c.ov)
		if native != c.native || !reflect.DeepEqual(tagged, c.tagged) {
			t.Errorf("%s: native=%q tagged=%v, want %q %v", c.name, native, tagged, c.native, c.tagged)
		}
	}
	// no network config at all: ports carry no VLAN detail
	if _, n, tg := buildNetIndex("home", nil, nil).port(rawPort{}, nil); n != "" || tg != nil {
		t.Errorf("without config: %q %v", n, tg)
	}
}

func TestNetworkDNS(t *testing.T) {
	devs := load[rawDevice](t, "stat_device.json")
	snap := Build("home", devs, nil, mockSiteConfig(t, true), time.Now())
	got := map[string]*inv.NetworkDNS{}
	for _, n := range snap.Networks {
		got[n.Name] = n.DNS
	}
	if d := got["Default"]; d == nil || !d.DHCP || d.Gateway != "192.168.1.1" || !reflect.DeepEqual(d.Servers, []string{"192.168.1.10"}) {
		t.Fatalf("Default: %+v", d)
	}
	// DHCP DNS on auto: clients get the gateway itself
	if d := got["IoT"]; d == nil || !d.DHCP || d.Gateway != "192.168.30.1" || len(d.Servers) != 0 {
		t.Fatalf("IoT: %+v", d)
	}
	if d := got["DMZ"]; d == nil || !reflect.DeepEqual(d.Servers, []string{"192.168.1.10", "8.8.8.8"}) {
		t.Fatalf("DMZ: %+v", d)
	}
	// WAN DNS on auto: what the gateway reports it got from the provider
	if d := got["Internet 1"]; d == nil || !d.UpstreamAuto || !reflect.DeepEqual(d.Upstream, []string{"203.0.113.53", "203.0.113.54"}) {
		t.Fatalf("WAN: %+v", d)
	}
}

func TestNetworkDNSManualWAN(t *testing.T) {
	gw := []string{"203.0.113.53"}
	// older firmware: no preference field, manual when wan_dns1 is set
	for _, r := range []rawNetwork{
		{Purpose: "wan", WANDNSPreference: "manual", WANDNS1: "9.9.9.9", WANDNS2: "149.112.112.112"},
		{Purpose: "wan", WANDNS1: "9.9.9.9", WANDNS2: "149.112.112.112"},
	} {
		if d := networkDNS(r, gw); d.UpstreamAuto || !reflect.DeepEqual(d.Upstream, []string{"9.9.9.9", "149.112.112.112"}) {
			t.Fatalf("manual WAN %+v: %+v", r, d)
		}
	}
	if d := networkDNS(rawNetwork{Purpose: "wan"}, gw); !d.UpstreamAuto || !reflect.DeepEqual(d.Upstream, gw) {
		t.Fatalf("auto WAN: %+v", d)
	}
	if d := networkDNS(rawNetwork{Purpose: "vlan-only"}, gw); d != nil {
		t.Fatalf("vlan-only networks have no router DNS: %+v", d)
	}
	// gateways that report their nameservers on the uplink instead of wan1
	if got := gatewayDNS([]rawDevice{{Type: "ugw", Uplink: rawUplink{Nameservers: []string{"203.0.113.9"}}}}); !reflect.DeepEqual(got, []string{"203.0.113.9"}) {
		t.Fatalf("uplink nameservers: %v", got)
	}
}
