package core

import (
	"reflect"
	"testing"

	"github.com/dertown/network-control-centre/internal/inventory"
)

func TestBuildGraphNetworks(t *testing.T) {
	snap := inventory.Snapshot{
		Networks: []inventory.Network{
			{ID: "lan", Name: "Default", Zone: "internal", Subnet: "192.168.1.0/24"},
			{ID: "dmz", Name: "DMZ", VLAN: 50, Zone: "dmz"},
		},
		Devices: []inventory.Device{
			{ID: "gw", Name: "gw", Kind: inventory.KindGateway, Network: "lan",
				Ports: []inventory.Port{{Name: "Port 1", NativeNetwork: "lan", TaggedNetworks: []string{"dmz"}}, {Name: "WAN"}}},
			{ID: "sw", Name: "sw", Kind: inventory.KindSwitch, Network: "lan"},
		},
		Links:   []inventory.Link{{A: "gw", B: "sw", Medium: "wired", Networks: []string{"lan", "dmz"}}},
		Clients: []inventory.Client{{MAC: "c1", Name: "web", ParentID: "sw", Wired: true, NetworkID: "dmz"}, {MAC: "c2", Name: "pc", ParentID: "sw", NetworkID: "lan"}},
	}
	for _, withClients := range []bool{false, true} {
		g := BuildGraph([]inventory.Snapshot{snap}, withClients)
		if len(g.Networks) != 2 || g.Networks[0].Devices != 2 || g.Networks[0].Clients != 1 || g.Networks[1].Clients != 1 {
			t.Fatalf("clients=%v networks: %+v", withClients, g.Networks)
		}
		if gw := g.Nodes[0]; len(gw.Ports) != 1 || gw.Ports[0].Native != "lan" || gw.Network != "lan" {
			t.Errorf("gateway node: %+v", gw)
		}
		if !reflect.DeepEqual(g.Edges[0].Networks, []string{"lan", "dmz"}) {
			t.Errorf("trunk edge: %+v", g.Edges[0])
		}
	}
	g := BuildGraph([]inventory.Snapshot{snap}, true)
	for _, n := range g.Nodes {
		if n.ID == "c1" && (n.Zone != "dmz" || n.VLAN != 50 || n.Network != "dmz") {
			t.Errorf("DMZ client: %+v", n)
		}
	}
	for _, e := range g.Edges {
		if e.Target == "c1" && !reflect.DeepEqual(e.Networks, []string{"dmz"}) {
			t.Errorf("client edge: %+v", e)
		}
	}
}

func TestBuildGraphMarksLoops(t *testing.T) {
	s := inventory.Snapshot{
		Devices: []inventory.Device{{ID: "a", Name: "A"}, {ID: "b", Name: "B"}, {ID: "c", Name: "C"}},
		Links:   []inventory.Link{{A: "a", B: "b", APort: "Port 1", BPort: "Port 1", Source: "uplink"}},
		Loops: []inventory.Loop{
			{ID: "l1", Severity: inventory.LoopWarning, Kind: inventory.LoopParallel,
				Ports: []inventory.LoopPort{{Device: "a", Port: 1}, {Device: "a", Port: 2}, {Device: "b", Port: 1}},
				Links: []inventory.Link{{A: "a", APort: "Port 1", B: "b", BPort: "Port 1"}, {A: "a", APort: "Port 2", B: "b"}}},
			{ID: "l2", Severity: inventory.LoopCritical, Kind: inventory.LoopSelf,
				Ports: []inventory.LoopPort{{Device: "c", Port: 5}, {Device: "c", Port: 6}},
				Links: []inventory.Link{{A: "c", APort: "Port 5", B: "c", BPort: "Port 6"}}},
		},
	}
	g := BuildGraph([]inventory.Snapshot{s}, false)
	if len(g.Loops) != 2 || g.Loops[0].ID != "l2" {
		t.Fatalf("loops not sorted critical first: %+v", g.Loops)
	}
	if len(g.Edges) != 3 {
		t.Fatalf("want the uplink plus 2 loop edges, got %+v", g.Edges)
	}
	if len(g.Edges[0].Loops) != 1 || g.Edges[0].Loops[0] != "l1" {
		t.Errorf("existing link not tagged: %+v", g.Edges[0])
	}
	var self *Edge
	for i := range g.Edges {
		if g.Edges[i].Source == "c" && g.Edges[i].Target == "c" {
			self = &g.Edges[i]
		}
	}
	if self == nil || self.Origin != "loop" || self.Label != "Port 5 ↔ Port 6" {
		t.Errorf("self loop edge: %+v", self)
	}
	for _, n := range g.Nodes {
		if len(n.Loops) != 1 {
			t.Errorf("node %s loops %v", n.ID, n.Loops)
		}
	}
}
