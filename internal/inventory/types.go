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
	// VLANs: the port profile, the untagged (native) network and the tagged networks, by network id.
	Profile        string   `json:"profile,omitempty"`
	NativeNetwork  string   `json:"native_network,omitempty"`
	TaggedNetworks []string `json:"tagged_networks,omitempty"`
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
	Target         string   `json:"target"`
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
