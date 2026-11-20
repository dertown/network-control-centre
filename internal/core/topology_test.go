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
