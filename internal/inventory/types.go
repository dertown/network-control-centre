// Package inventory holds the vendor-neutral network model that device drivers produce.
package inventory

import (
	"strings"
	"time"
)

// Device kinds.
const (
	KindGateway   = "gateway"
	KindSwitch    = "switch"
	KindAP        = "ap"
	KindUnmanaged = "unmanaged-switch"
	KindUnknown   = "unknown"
)

// Discovery sources: how NCC learned a device's make and model.
const (
	SourceController = "controller" // the device is adopted by the controller, which reports its model
	SourceLLDP       = "lldp"       // seen as an LLDP neighbour of a managed device
	SourceInferred   = "inferred"   // several clients share one switch port, so something unmanaged sits there
)

// Device is a router, switch, access point or other infrastructure node.
type Device struct {
	ID        string    `json:"id"` // normalised MAC, or a synthetic id for inferred nodes
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Make      string    `json:"make"`
	Model     string    `json:"model"`      // human model name, e.g. "U6 Pro"
	ModelCode string    `json:"model_code"` // vendor code, e.g. "UAP6MP"
	MAC       string    `json:"mac"`
	IP        string    `json:"ip,omitempty"`
	Firmware  string    `json:"firmware,omitempty"`
	Serial    string    `json:"serial,omitempty"`
	Online    bool      `json:"online"`
	Uptime    int64     `json:"uptime_s,omitempty"`
	Managed   bool      `json:"managed"`
	Discovery string    `json:"discovery"`
	Detail    string    `json:"detail,omitempty"` // e.g. the LLDP system description
	Ports     []Port    `json:"ports,omitempty"`
	Network   string    `json:"network_id,omitempty"` // management network, by subnet
	Clients   int       `json:"clients"`
	Target    string    `json:"target"`
	SeenAt    time.Time `json:"seen_at"`
}

// Port is a physical switch or router port.
type Port struct {
	Index     int     `json:"index"`
	Name      string  `json:"name"`
	Up        bool    `json:"up"`
	SpeedMbps int     `json:"speed_mbps,omitempty"`
	PoE       bool    `json:"poe,omitempty"`
	PoEWatts  float64 `json:"poe_watts,omitempty"`
	Uplink    bool    `json:"uplink,omitempty"`
	// STP is the spanning-tree state the switch reports: forwarding, blocking, discarding...
	STP string `json:"stp,omitempty"`
	// VLANs: the port profile, the untagged (native) network and the tagged networks, by network id.
	Profile        string   `json:"profile,omitempty"`
	NativeNetwork  string   `json:"native_network,omitempty"`
	TaggedNetworks []string `json:"tagged_networks,omitempty"`
	// Infra is set when the port connects to another network device (an uplink, a cable to a
	// switch or access point, an LLDP neighbour, or the gateway's WAN), not to end hosts.
	Infra bool `json:"infra,omitempty"`
}

// Network is a LAN, VLAN, guest or WAN network, with the firewall zone it belongs to.
type Network struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Purpose string `json:"purpose,omitempty"` // corporate | guest | vlan-only | wan | vpn ...
	VLAN    int    `json:"vlan,omitempty"`    // 0 = untagged
	Subnet  string `json:"subnet,omitempty"`
	// Zone is the firewall zone key: internal | external | gateway | vpn | hotspot | dmz | custom.
	Zone     string `json:"zone,omitempty"`
	ZoneName string `json:"zone_name,omitempty"`
	// ZoneSource is "firewall" when the console reported the zone, "inferred" when NCC guessed it
	// from the network's purpose and name (consoles without zone-based firewall).
	ZoneSource     string   `json:"zone_source,omitempty"`
	Isolated       bool     `json:"isolated,omitempty"`
	InternetAccess bool     `json:"internet_access"`
	SSIDs          []string `json:"ssids,omitempty"`
	// DNS is the DNS the router hands out on this network (LANs) or uses itself (WANs);
	// nil when the driver cannot tell.
	DNS    *NetworkDNS `json:"dns,omitempty"`
	Target string      `json:"target"`
}

// NetworkDNS is the DNS setup of one router network.
type NetworkDNS struct {
	// LAN networks.
	// DHCP is set when the router hands out addresses on the network.
	DHCP bool `json:"dhcp"`
	// Gateway is the router's own address on the network (what clients get as DNS when
	// Servers is empty).
	Gateway string `json:"gateway,omitempty"`
	// Servers are the DNS servers DHCP hands out, in order. Empty means the router hands
	// out itself, and answers with its own resolver (which asks the WAN's Upstream).
	Servers []string `json:"servers,omitempty"`
	// Domain is the DNS domain name DHCP hands out (the clients' search domain), without
	// the trailing dot; empty when none is set.
	Domain string `json:"domain,omitempty"`

	// WAN networks.
	// Upstream are the DNS servers the router itself asks on this WAN.
	Upstream []string `json:"upstream,omitempty"`
	// UpstreamAuto is set when Upstream came from the internet provider (DHCP or PPPoE on
	// the WAN) rather than being typed in by hand.
	UpstreamAuto bool `json:"upstream_auto,omitempty"`
}

// Link connects two nodes (devices or clients).
type Link struct {
	A         string `json:"a"`
	APort     string `json:"a_port,omitempty"`
	B         string `json:"b"`
	BPort     string `json:"b_port,omitempty"`
	Medium    string `json:"medium"` // wired | wireless
	SpeedMbps int    `json:"speed_mbps,omitempty"`
	Source    string `json:"source"` // uplink | lldp | client | inferred
	// Networks carried on the link, by network id (from the upstream port's VLAN settings).
	Networks []string `json:"networks,omitempty"`
}

// Client is an end host seen by the network.
type Client struct {
	MAC        string `json:"mac"`
	Name       string `json:"name"`
	IP         string `json:"ip,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	Wired      bool   `json:"wired"`
	ParentID   string `json:"parent_id,omitempty"` // device (or inferred switch) it hangs off
	ParentPort string `json:"parent_port,omitempty"`
	Network    string `json:"network,omitempty"`
	VLAN       int    `json:"vlan,omitempty"`
	NetworkID  string `json:"network_id,omitempty"`
	SSID       string `json:"ssid,omitempty"`
	// SwitchMAC and SwitchPort are the managed switch (or gateway) port the controller sees a
	// wired client on, even when the client really sits behind an unmanaged switch there.
	SwitchMAC  string `json:"switch_mac,omitempty"`
	SwitchPort int    `json:"switch_port,omitempty"`
	// APMAC is the access point a wireless client is associated with.
	APMAC string `json:"ap_mac,omitempty"`
}

// Snapshot is everything one target reported at one moment.
type Snapshot struct {
	Target  string    `json:"target"`
	TakenAt time.Time `json:"taken_at"`
	Devices []Device  `json:"devices"`
	Links   []Link    `json:"links"`
	Clients []Client  `json:"clients"`
	// Networks are the VLANs and their firewall zones; empty when the driver cannot tell.
	Networks []Network `json:"networks,omitempty"`
	// Loops are switching loops: ports cabled back to each other, redundant paths and the
	// controller's own loop and STP warnings.
	Loops []Loop `json:"loops,omitempty"`
	// Firewall is the router's firewall rules and port forwards; nil when the driver cannot tell.
	Firewall *Firewall `json:"firewall,omitempty"`
}

// Loop severities.
const (
	LoopCritical = "critical" // a loop with nothing blocking it, or the switch reported one
	LoopWarning  = "warning"  // a redundant path that spanning tree is holding shut
)

// Loop kinds.
const (
	LoopSelf     = "self"     // two ports on one switch connect back to each other
	LoopParallel = "parallel" // a switch has two or more ports into the same neighbour
	LoopCycle    = "cycle"    // the cables between several devices form a ring
	LoopSTP      = "stp"      // spanning tree is blocking a port: there is a second path
	LoopEvent    = "event"    // the controller logged a loop, STP or MAC-flapping event
)

// Loop is one switching loop NCC found, with the exact switch ports involved.
type Loop struct {
	ID       string     `json:"id"`
	Severity string     `json:"severity"`
	Kind     string     `json:"kind"`
	Summary  string     `json:"summary"`
	Detail   string     `json:"detail,omitempty"`
	Ports    []LoopPort `json:"ports"`
	// Links are the cables that make up the loop, between devices (A may equal B).
	Links  []Link     `json:"links,omitempty"`
	Count  int        `json:"count,omitempty"` // events: how many times it was logged
	SeenAt *time.Time `json:"seen_at,omitempty"`
	Target string     `json:"target"`
}

// LoopPort is a switch port that takes part in a loop.
type LoopPort struct {
	Device     string `json:"device"`
	DeviceName string `json:"device_name"`
	Port       int    `json:"port,omitempty"`
	PortName   string `json:"port_name,omitempty"`
	// STP is the port's spanning-tree state when the switch reports it (forwarding, blocking...).
	STP string `json:"stp,omitempty"`
}

// NormMAC lower-cases a MAC and normalises separators to colons.
func NormMAC(m string) string {
	m = strings.ToLower(strings.TrimSpace(m))
	m = strings.NewReplacer("-", ":", ".", "").Replace(m)
	if len(m) == 12 && !strings.Contains(m, ":") {
		var b strings.Builder
		for i := 0; i < 12; i += 2 {
			if i > 0 {
				b.WriteByte(':')
			}
			b.WriteString(m[i : i+2])
		}
		return b.String()
	}
	return m
}
