package core

import (
	"testing"

	"github.com/dertown/network-control-centre/internal/inventory"
)

func TestPortsFor(t *testing.T) {
	snap := inventory.Snapshot{
		Devices: []inventory.Device{
			{ID: "sw", MAC: "sw", Name: "Core switch", Kind: inventory.KindSwitch,
				Ports: []inventory.Port{{Index: 1, Name: "Port 1", Up: true}, {Index: 2, Name: "Port 2", Up: true}, {Index: 3, Name: "Port 3"}, {Index: 4, Name: "Port 4", Up: true}}},
			{ID: "ap", MAC: "ap", Name: "Hall AP", Kind: inventory.KindAP, Online: true, Clients: 1},
			{ID: "inferred:sw:2", Name: "Unmanaged switch on Core switch Port 2", Kind: inventory.KindUnmanaged, Clients: 2},
		},
		Links: []inventory.Link{
			{A: "sw", APort: "Port 4", B: "ap", BPort: "Port 1", Source: "uplink"},
			{A: "sw", APort: "Port 2", B: "inferred:sw:2", Source: "inferred"},
		},
		Clients: []inventory.Client{
			{MAC: "c1", Name: "nas", IP: "10.0.0.5", Wired: true, ParentID: "sw", ParentPort: "Port 1", SwitchMAC: "sw", SwitchPort: 1, VLAN: 10},
			{MAC: "c2", Name: "tv", Wired: true, ParentID: "inferred:sw:2", SwitchMAC: "sw", SwitchPort: 2},
			{MAC: "c3", Name: "printer", Wired: true, ParentID: "inferred:sw:2", SwitchMAC: "sw", SwitchPort: 2},
			{MAC: "c5", Name: "cam", Wired: true, ParentID: "sw", ParentPort: "Port 9", SwitchMAC: "sw", SwitchPort: 9},
			{MAC: "c4", Name: "phone", ParentID: "ap", APMAC: "ap", SSID: "Home"},
		},
	}
	got, ok := PortsFor([]inventory.Snapshot{snap}, "sw")
	if !ok || len(got.Ports) != 5 || got.Ports[4].Index != 9 || len(got.Ports[4].Clients) != 1 || !got.Ports[4].Up {
		t.Fatalf("ports: %+v", got)
	}
	if p := got.Ports[0]; len(p.Clients) != 1 || p.Clients[0].Name != "nas" || p.Clients[0].Behind != "" {
		t.Errorf("port 1: %+v", p)
	}
	if p := got.Ports[1]; len(p.Clients) != 2 || p.Clients[0].Name != "printer" || p.Clients[0].Behind == "" || len(p.Devices) != 1 {
		t.Errorf("port 2: %+v", p)
	}
	if p := got.Ports[2]; len(p.Clients) != 0 || len(p.Devices) != 0 {
		t.Errorf("port 3 should be empty: %+v", p)
	}
	if p := got.Ports[3]; len(p.Devices) != 1 || p.Devices[0].Name != "Hall AP" || p.Devices[0].Port != "Port 1" || p.Devices[0].Clients != 1 {
		t.Errorf("port 4: %+v", p)
	}
	if len(got.Attached) != 0 {
		t.Errorf("switch attached: %+v", got.Attached)
	}
	ap, _ := PortsFor([]inventory.Snapshot{snap}, "ap")
	if len(ap.Attached) != 1 || ap.Attached[0].SSID != "Home" {
		t.Errorf("ap wireless: %+v", ap.Attached)
	}
	un, _ := PortsFor([]inventory.Snapshot{snap}, "inferred:sw:2")
	if len(un.Attached) != 2 || un.Attached[0].Behind != "" {
		t.Errorf("unmanaged attached: %+v", un.Attached)
	}
	if _, ok := PortsFor([]inventory.Snapshot{snap}, "nope"); ok {
		t.Error("unknown device found")
	}
}
