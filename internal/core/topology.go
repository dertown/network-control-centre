package core

import (
	"sort"

	"github.com/dertown/network-control-centre/internal/inventory"
)

// Node is a topology vertex for the map.
type Node struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Kind      string `json:"kind"` // gateway | switch | ap | unmanaged-switch | unknown | client
	Make      string `json:"make,omitempty"`
	Model     string `json:"model,omitempty"`
	IP        string `json:"ip,omitempty"`
	Online    bool   `json:"online"`
	Discovery string `json:"discovery,omitempty"`
	Clients   int    `json:"clients,omitempty"`
	Parent    string `json:"parent,omitempty"`
	// Network is the network id the node sits in (a client's VLAN, a device's management
	// network); VLAN and Zone are copied from that network for convenience.
	Network string     `json:"network,omitempty"`
	VLAN    int        `json:"vlan,omitempty"`
	Zone    string     `json:"zone,omitempty"`
	SSID    string     `json:"ssid,omitempty"`
	Ports   []NodePort `json:"ports,omitempty"`
}

// NodePort is a switch or router port's VLAN setup, for ports with VLAN detail.
type NodePort struct {
	Name    string   `json:"name"`
	Up      bool     `json:"up"`
	Uplink  bool     `json:"uplink,omitempty"`
	Profile string   `json:"profile,omitempty"`
	Native  string   `json:"native,omitempty"`
	Tagged  []string `json:"tagged,omitempty"`
}

// GNetwork is a network (VLAN) on the map, with its firewall zone and member counts.
type GNetwork struct {
	inventory.Network
	Clients int `json:"clients"`
	Devices int `json:"devices"`
}

// Edge is a topology link for the map.
type Edge struct {
	ID        string `json:"id"`
	Source    string `json:"source"`
	Target    string `json:"target"`
	Label     string `json:"label,omitempty"`
	Medium    string `json:"medium"`
	SpeedMbps int    `json:"speed_mbps,omitempty"`
	Origin    string `json:"origin"`
	// Networks carried on the link, by network id.
	Networks []string `json:"networks,omitempty"`
}

// Graph is the whole map.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
	// Networks are the VLANs and firewall zones the targets reported.
	Networks []GNetwork `json:"networks"`
}

// BuildGraph merges snapshots into one graph. Clients are included when withClients is set.
func BuildGraph(snaps []inventory.Snapshot, withClients bool) Graph {
	g := Graph{Nodes: []Node{}, Edges: []Edge{}, Networks: []GNetwork{}}
	nets := map[string]int{} // network id -> index in g.Networks
	for _, s := range snaps {
		for _, n := range s.Networks {
			if _, dup := nets[n.ID]; dup {
				continue
			}
			nets[n.ID] = len(g.Networks)
			g.Networks = append(g.Networks, GNetwork{Network: n})
		}
	}
	// clients per network are counted whether or not clients are drawn
	counted := map[string]bool{}
	for _, s := range snaps {
		for _, c := range s.Clients {
			if i, ok := nets[c.NetworkID]; ok && !counted[c.MAC] {
				counted[c.MAC] = true
				g.Networks[i].Clients++
			}
		}
	}
	member := func(n *Node, id string, client bool) {
		i, ok := nets[id]
		if !ok {
			return
		}
		net := &g.Networks[i]
		n.Network, n.VLAN, n.Zone = id, net.VLAN, net.Zone
		if !client {
			net.Devices++
		}
	}
	seen := map[string]bool{}
	for _, s := range snaps {
		for _, d := range s.Devices {
			if seen[d.ID] {
				continue
			}
			seen[d.ID] = true
			n := Node{ID: d.ID, Label: d.Name, Kind: d.Kind, Make: d.Make, Model: d.Model,
				IP: d.IP, Online: d.Online, Discovery: d.Discovery, Clients: d.Clients}
			member(&n, d.Network, false)
			for _, p := range d.Ports {
				if p.NativeNetwork == "" && len(p.TaggedNetworks) == 0 && p.Profile == "" {
					continue
				}
				n.Ports = append(n.Ports, NodePort{Name: p.Name, Up: p.Up, Uplink: p.Uplink, Profile: p.Profile,
					Native: p.NativeNetwork, Tagged: p.TaggedNetworks})
			}
			g.Nodes = append(g.Nodes, n)
		}
	}
	edgeSeen := map[string]bool{}
	add := func(e Edge) {
		if !seen[e.Source] || !seen[e.Target] {
			return
		}
		a, b := e.Source, e.Target
		if a > b {
			a, b = b, a
		}
		if edgeSeen[a+"|"+b] {
			return
		}
		edgeSeen[a+"|"+b] = true
		e.ID = "e" + a + "-" + b
		g.Edges = append(g.Edges, e)
	}
	for _, s := range snaps {
		for _, l := range s.Links {
			label := l.APort
			if l.BPort != "" {
				if label != "" {
					label += " ↔ "
				}
				label += l.BPort
			}
			add(Edge{Source: l.A, Target: l.B, Label: label, Medium: l.Medium, SpeedMbps: l.SpeedMbps, Origin: l.Source,
				Networks: l.Networks})
		}
	}
	if withClients {
		for _, s := range snaps {
			for _, c := range s.Clients {
				if seen[c.MAC] || c.ParentID == "" {
					continue
				}
				seen[c.MAC] = true
				n := Node{ID: c.MAC, Label: c.Name, Kind: "client", Make: c.Vendor, IP: c.IP, Online: true, Parent: c.ParentID, SSID: c.SSID}
				member(&n, c.NetworkID, true)
				if n.Network == "" && c.VLAN > 0 {
					n.VLAN = c.VLAN
				}
				g.Nodes = append(g.Nodes, n)
				medium := "wireless"
				if c.Wired {
					medium = "wired"
				}
				e := Edge{Source: c.ParentID, Target: c.MAC, Label: c.ParentPort, Medium: medium, Origin: "client"}
				if n.Network != "" {
					e.Networks = []string{n.Network}
				}
				add(e)
			}
		}
	}
	sort.SliceStable(g.Nodes, func(i, j int) bool { return rank(g.Nodes[i].Kind) < rank(g.Nodes[j].Kind) })
	return g
}

func rank(kind string) int {
	switch kind {
	case inventory.KindGateway:
		return 0
	case inventory.KindSwitch:
		return 1
	case inventory.KindUnmanaged, inventory.KindUnknown:
		return 2
	case inventory.KindAP:
		return 3
	default:
		return 4
	}
}
