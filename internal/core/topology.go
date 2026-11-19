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
}

// Graph is the whole map.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// BuildGraph merges snapshots into one graph. Clients are included when withClients is set.
func BuildGraph(snaps []inventory.Snapshot, withClients bool) Graph {
	g := Graph{Nodes: []Node{}, Edges: []Edge{}}
	seen := map[string]bool{}
	for _, s := range snaps {
		for _, d := range s.Devices {
			if seen[d.ID] {
				continue
			}
			seen[d.ID] = true
			g.Nodes = append(g.Nodes, Node{ID: d.ID, Label: d.Name, Kind: d.Kind, Make: d.Make, Model: d.Model,
				IP: d.IP, Online: d.Online, Discovery: d.Discovery, Clients: d.Clients})
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
			add(Edge{Source: l.A, Target: l.B, Label: label, Medium: l.Medium, SpeedMbps: l.SpeedMbps, Origin: l.Source})
		}
	}
	if withClients {
		for _, s := range snaps {
			for _, c := range s.Clients {
				if seen[c.MAC] || c.ParentID == "" {
					continue
				}
				seen[c.MAC] = true
				g.Nodes = append(g.Nodes, Node{ID: c.MAC, Label: c.Name, Kind: "client", Make: c.Vendor, IP: c.IP, Online: true, Parent: c.ParentID})
				medium := "wireless"
				if c.Wired {
					medium = "wired"
				}
				add(Edge{Source: c.ParentID, Target: c.MAC, Label: c.ParentPort, Medium: medium, Origin: "client"})
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
