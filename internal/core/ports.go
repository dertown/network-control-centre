package core

import (
	"fmt"
	"sort"

	"github.com/dertown/network-control-centre/internal/inventory"
)

// PortClient is an end host seen on a device port.
type PortClient struct {
	MAC       string `json:"mac"`
	Name      string `json:"name"`
	IP        string `json:"ip,omitempty"`
	Vendor    string `json:"vendor,omitempty"`
	Network   string `json:"network,omitempty"`
	NetworkID string `json:"network_id,omitempty"`
	VLAN      int    `json:"vlan,omitempty"`
	SSID      string `json:"ssid,omitempty"`
	// Behind names the switch the client really hangs off when it is not this device itself
	// (an unmanaged switch NCC inferred on the port, or an LLDP neighbour).
	Behind   string `json:"behind,omitempty"`
	BehindID string `json:"behind_id,omitempty"`
}

// PortNeighbour is another network device cabled to a port.
type PortNeighbour struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Port    string `json:"port,omitempty"` // the port on the neighbour's side, when known
	Online  bool   `json:"online"`
	Clients int    `json:"clients"`
}

// PortView is one port with everything plugged into it.
type PortView struct {
	inventory.Port
	Clients []PortClient    `json:"clients"`
	Devices []PortNeighbour `json:"devices"`
}

// DevicePorts lists a device's ports and who is connected to each. Attached holds the clients
// that hang off the device without a known port: an access point's wireless clients, or the
// hosts behind an unmanaged switch NCC inferred.
type DevicePorts struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Kind     string       `json:"kind"`
	Ports    []PortView   `json:"ports"`
	Attached []PortClient `json:"attached"`
}

// PortsFor builds the port view of device id from the latest snapshots; ok is false when no
// target reports that device.
func PortsFor(snaps []inventory.Snapshot, id string) (out DevicePorts, ok bool) {
	var dev *inventory.Device
	devs := map[string]inventory.Device{}
	for _, s := range snaps {
		for i := range s.Devices {
			d := s.Devices[i]
			if _, dup := devs[d.ID]; !dup {
				devs[d.ID] = d
			}
			if d.ID == id && dev == nil {
				dev = &s.Devices[i]
			}
		}
	}
	if dev == nil {
		return out, false
	}
	out = DevicePorts{ID: dev.ID, Name: dev.Name, Kind: dev.Kind, Ports: []PortView{}, Attached: []PortClient{}}
	byIndex := map[int]int{}
	byName := map[string]int{}
	for _, p := range dev.Ports {
		pv := PortView{Port: p, Clients: []PortClient{}, Devices: []PortNeighbour{}}
		if p.Index > 0 {
			byIndex[p.Index] = len(out.Ports)
		}
		if p.Name != "" {
			byName[p.Name] = len(out.Ports)
		}
		out.Ports = append(out.Ports, pv)
	}
	mac := dev.MAC
	if mac == "" {
		mac = dev.ID
	}
	// The controller can see a client on a port its port table left out (older firmware, or a
	// partial report): show that port too, since something is plainly plugged into it.
	var extra []int
	for _, s := range snaps {
		for _, c := range s.Clients {
			if _, known := byIndex[c.SwitchPort]; c.Wired && c.SwitchPort > 0 && c.SwitchMAC == mac && !known {
				byIndex[c.SwitchPort] = -1
				extra = append(extra, c.SwitchPort)
			}
		}
	}
	if len(extra) > 0 {
		for _, i := range extra {
			out.Ports = append(out.Ports, PortView{Port: inventory.Port{Index: i, Name: fmt.Sprintf("Port %d", i), Up: true},
				Clients: []PortClient{}, Devices: []PortNeighbour{}})
		}
		sort.SliceStable(out.Ports, func(i, j int) bool { return out.Ports[i].Index < out.Ports[j].Index })
		byIndex, byName = map[int]int{}, map[string]int{}
		for i, p := range out.Ports {
			if p.Index > 0 {
				byIndex[p.Index] = i
			}
			if p.Name != "" {
				byName[p.Name] = i
			}
		}
	}
	seenClient := map[string]bool{}
	for _, s := range snaps {
		for _, c := range s.Clients {
			if seenClient[c.MAC] {
				continue
			}
			pc := PortClient{MAC: c.MAC, Name: c.Name, IP: c.IP, Vendor: c.Vendor, Network: c.Network,
				NetworkID: c.NetworkID, VLAN: c.VLAN, SSID: c.SSID}
			if c.ParentID != "" && c.ParentID != dev.ID {
				if p, ok := devs[c.ParentID]; ok {
					pc.Behind, pc.BehindID = p.Name, p.ID
				}
			}
			idx, onPort := -1, false
			switch {
			case c.Wired && c.SwitchPort > 0 && c.SwitchMAC == mac:
				idx, onPort = byIndex[c.SwitchPort]
			case c.Wired && c.ParentID == dev.ID && c.ParentPort != "":
				idx, onPort = byName[c.ParentPort]
			}
			switch {
			case onPort:
				out.Ports[idx].Clients = append(out.Ports[idx].Clients, pc)
			case c.ParentID == dev.ID:
				pc.Behind, pc.BehindID = "", ""
				out.Attached = append(out.Attached, pc)
			default:
				continue
			}
			seenClient[c.MAC] = true
		}
	}
	seenLink := map[string]bool{}
	for _, s := range snaps {
		for _, l := range s.Links {
			other, mine, theirs := "", "", ""
			switch {
			case l.A == dev.ID && l.B != dev.ID:
				other, mine, theirs = l.B, l.APort, l.BPort
			case l.B == dev.ID && l.A != dev.ID:
				other, mine, theirs = l.A, l.BPort, l.APort
			default:
				continue
			}
			idx, ok := byName[mine]
			if !ok || seenLink[mine+"|"+other] {
				continue
			}
			seenLink[mine+"|"+other] = true
			n := PortNeighbour{ID: other, Name: other, Port: theirs}
			if d, ok := devs[other]; ok {
				n.Name, n.Kind, n.Online, n.Clients = d.Name, d.Kind, d.Online, d.Clients
			}
			out.Ports[idx].Devices = append(out.Ports[idx].Devices, n)
		}
	}
	byClientName := func(cs []PortClient) {
		sort.SliceStable(cs, func(i, j int) bool { return cs[i].Name < cs[j].Name })
	}
	for i := range out.Ports {
		byClientName(out.Ports[i].Clients)
	}
	byClientName(out.Attached)
	return out, true
}
