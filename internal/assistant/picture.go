package assistant

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/iot"
)

// Picture is the whole network as the assistant sees it, and what is sent to the model.
// It is built from NCC's latest reads; nothing in it is fetched from a device on the spot.
type Picture struct {
	Routers []Router    `json:"routers"`
	DNS     []DNSServer `json:"dns_servers"`
	// Domain is the internal DNS domain NCC thinks the network uses, e.g. "home.lan.".
	Domain string `json:"internal_domain"`
}

// Router is one router or controller and everything on it.
type Router struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// CanChange is set when NCC can create networks and move clients on it.
	CanChange bool `json:"can_change"`
	// CanSetDomain is set when NCC can set the DNS domain a network hands out.
	CanSetDomain bool                `json:"can_set_domain"`
	Networks     []Net               `json:"networks"`
	Clients      []Client            `json:"clients"`
	Snapshot     *inventory.Snapshot `json:"-"`
}

// Net is one VLAN network.
type Net struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Purpose  string `json:"purpose,omitempty"`
	VLAN     int    `json:"vlan"`
	Subnet   string `json:"subnet,omitempty"`
	Zone     string `json:"firewall_zone,omitempty"`
	Isolated bool   `json:"isolated,omitempty"`
	Internet bool   `json:"internet_access"`
	// IoT is set for networks NCC counts as IoT networks (IoT page setting or the name).
	IoT     bool `json:"iot,omitempty"`
	Clients int  `json:"clients"`
}

// Client is one device on the network.
type Client struct {
	MAC       string `json:"mac"`
	Name      string `json:"name"`
	IP        string `json:"ip,omitempty"`
	Vendor    string `json:"vendor,omitempty"`
	NetworkID string `json:"network_id,omitempty"`
	Wired     bool   `json:"wired"`
	// IoTType is the IoT device type (camera, printer...) or "" for ordinary computers and phones.
	IoTType string `json:"iot_type,omitempty"`
	// KeepWhereItIs is set when people said this IoT device may stay off the IoT networks.
	KeepWhereItIs bool   `json:"keep_where_it_is,omitempty"`
	KeepReason    string `json:"keep_reason,omitempty"`
	// NotIoT is set when people said NCC's IoT guess was wrong.
	NotIoT bool `json:"not_iot,omitempty"`
	// Forwards are the internet port forwards that land on this device ("tcp 443").
	Forwards []string `json:"port_forwards,omitempty"`
	Location string   `json:"location,omitempty"`
}

// DNSServer is one DNS server connection and its zones.
type DNSServer struct {
	ID             int64    `json:"id"`
	Name           string   `json:"name"`
	Kind           string   `json:"kind"`
	Zones          []string `json:"zones"`
	CanCreateZones bool     `json:"can_create_zones"`
	Error          string   `json:"error,omitempty"`
}

// RouterInput is one router connection and its latest read, for BuildPicture.
type RouterInput struct {
	ID           int64
	Name         string
	CanChange    bool
	CanSetDomain bool
	Snapshot     *inventory.Snapshot
}

// Inputs is what BuildPicture works from.
type Inputs struct {
	Routers []RouterInput
	// IoT is the IoT inventory; IoTNetworks the network ids counted as IoT networks.
	IoT         []iot.Device
	IoTNetworks map[string]bool
	DNS         []DNSServer
}

// BuildPicture puts NCC's reads together into one Picture.
func BuildPicture(in Inputs) *Picture {
	p := &Picture{Routers: []Router{}, DNS: []DNSServer{}}
	inv := map[string]*iot.Device{}
	for i := range in.IoT {
		inv[in.IoT[i].MAC] = &in.IoT[i]
	}
	for _, ri := range in.Routers {
		r := Router{ID: ri.ID, Name: ri.Name, CanChange: ri.CanChange, CanSetDomain: ri.CanSetDomain, Networks: []Net{}, Clients: []Client{}, Snapshot: ri.Snapshot}
		snap := ri.Snapshot
		if snap == nil {
			p.Routers = append(p.Routers, r)
			continue
		}
		count := map[string]int{}
		for _, c := range snap.Clients {
			count[c.NetworkID]++
		}
		for _, n := range snap.Networks {
			if n.Purpose == "wan" || strings.Contains(n.Purpose, "vpn") {
				continue
			}
			isIoT := in.IoTNetworks[n.ID]
			if in.IoTNetworks == nil {
				isIoT = iot.DefaultIoTNetwork(n)
			}
			r.Networks = append(r.Networks, Net{ID: n.ID, Name: n.Name, Purpose: n.Purpose, VLAN: n.VLAN, Subnet: n.Subnet,
				Zone: n.Zone, Isolated: n.Isolated, Internet: n.InternetAccess, IoT: isIoT, Clients: count[n.ID]})
		}
		fwd := map[string][]string{}
		if snap.Firewall != nil {
			for _, f := range snap.Firewall.Forwards {
				if f.Enabled && f.ForwardIP != "" {
					fwd[f.ForwardIP] = append(fwd[f.ForwardIP], strings.ToLower(f.Protocol)+" "+f.ExternalPort)
				}
			}
		}
		for _, c := range snap.Clients {
			mac := iot.NormMAC(c.MAC)
			cl := Client{MAC: mac, Name: firstOf(c.Name, mac), IP: c.IP, Vendor: c.Vendor, NetworkID: c.NetworkID, Wired: c.Wired}
			if d := inv[mac]; d != nil {
				if d.Ignored {
					cl.NotIoT = true
				} else {
					cl.IoTType = firstOf(d.Type, iot.TypeOther)
					cl.KeepWhereItIs, cl.KeepReason = d.NetworkOK, d.NetworkOKReason
					if d.Label != "" {
						cl.Name = d.Label
					}
					cl.Location = strings.Join(nonEmpty(d.Site, d.Building, d.Floor, d.Room), " / ")
				}
			} else if t, ok := iot.Classify(c.Vendor, c.Name); ok {
				cl.IoTType = t
			}
			if c.IP != "" {
				cl.Forwards = fwd[c.IP]
			}
			r.Clients = append(r.Clients, cl)
		}
		sort.SliceStable(r.Clients, func(i, j int) bool { return strings.ToLower(r.Clients[i].Name) < strings.ToLower(r.Clients[j].Name) })
		p.Routers = append(p.Routers, r)
	}
	p.DNS = append(p.DNS, in.DNS...)
	p.Domain = guessDomain(p.DNS)
	return p
}

// guessDomain picks the internal domain: the shortest forward zone on the DNS servers that
// looks internal, else "lan.".
func guessDomain(servers []DNSServer) string {
	best := ""
	for _, s := range servers {
		for _, z := range s.Zones {
			z = dns.FQDN(z)
			if strings.HasSuffix(z, ".arpa.") {
				continue
			}
			if best == "" || strings.Count(z, ".") < strings.Count(best, ".") || (strings.Count(z, ".") == strings.Count(best, ".") && internalTLD(z) && !internalTLD(best)) {
				best = z
			}
		}
	}
	if best == "" {
		return "lan."
	}
	return best
}

func internalTLD(z string) bool {
	for _, t := range []string{".lan.", ".home.", ".internal.", ".local.", ".corp.", ".home.arpa."} {
		if strings.HasSuffix("."+z, t) {
			return true
		}
	}
	return false
}

func (p *Picture) router(id int64) *Router {
	for i := range p.Routers {
		if p.Routers[i].ID == id {
			return &p.Routers[i]
		}
	}
	return nil
}

func (p *Picture) dnsServer(id int64) *DNSServer {
	for i := range p.DNS {
		if p.DNS[i].ID == id {
			return &p.DNS[i]
		}
	}
	return nil
}

func (r *Router) client(mac string) *Client {
	for i := range r.Clients {
		if r.Clients[i].MAC == mac {
			return &r.Clients[i]
		}
	}
	return nil
}

func (r *Router) network(ref string) *Net {
	for i := range r.Networks {
		if r.Networks[i].ID == ref {
			return &r.Networks[i]
		}
	}
	for i := range r.Networks {
		if strings.EqualFold(r.Networks[i].Name, ref) {
			return &r.Networks[i]
		}
	}
	return nil
}

// Size is a rough count of what the picture holds, for the page.
func (p *Picture) Size() string {
	nets, clients, zones := 0, 0, 0
	for _, r := range p.Routers {
		nets += len(r.Networks)
		clients += len(r.Clients)
	}
	for _, d := range p.DNS {
		zones += len(d.Zones)
	}
	return fmt.Sprintf("%d networks, %d devices, %d DNS zones", nets, clients, zones)
}

func firstOf(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}
