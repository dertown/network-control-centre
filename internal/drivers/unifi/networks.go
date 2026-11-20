package unifi

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	inv "github.com/dertown/network-control-centre/internal/inventory"
)

// Networks, VLANs and firewall zones.
//
// UniFi keeps them in four places:
//   - rest/networkconf: networks (VLAN id, subnet, purpose such as corporate, guest or wan)
//   - rest/portconf: switch port profiles (native network, tagged networks)
//   - rest/wlanconf: Wi-Fi networks and the network each SSID drops clients into
//   - the v2 firewall zone list (Network 9 and later, zone-based firewall): which networks
//     sit in the Internal, External, Hotspot, DMZ, VPN or a custom zone
//
// All four are optional: a console that refuses one still gets a topology, just with less
// VLAN detail. Without the zone list, zones are inferred from each network's purpose and name.

// flexInt accepts numbers and numeric strings (UniFi sends vlan as "20" on some versions).
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	*f = flexInt(v)
	return nil
}

type rawNetwork struct {
	ID             string  `json:"_id"`
	Name           string  `json:"name"`
	Purpose        string  `json:"purpose"` // corporate | guest | vlan-only | wan | remote-user-vpn | site-vpn
	VLANEnabled    bool    `json:"vlan_enabled"`
	VLAN           flexInt `json:"vlan"`
	IPSubnet       string  `json:"ip_subnet"` // gateway address with prefix, e.g. 192.168.20.1/24
	NetworkGroup   string  `json:"networkgroup"`
	FirewallZoneID string  `json:"firewall_zone_id"`
	Isolation      bool    `json:"network_isolation_enabled"`
	InternetAccess *bool   `json:"internet_access_enabled"`
	Enabled        *bool   `json:"enabled"`
}

type rawPortConf struct {
	ID              string   `json:"_id"`
	Name            string   `json:"name"`
	Forward         string   `json:"forward"` // all | native | customize | disabled (older firmware)
	NativeNetworkID string   `json:"native_networkconf_id"`
	TaggedIDs       []string `json:"tagged_networkconf_ids"`
	ExcludedIDs     []string `json:"excluded_networkconf_ids"`
	TaggedVLANMgmt  string   `json:"tagged_vlan_mgmt"` // auto | block_all | custom (newer firmware)
}

// rawPortOverride is a per-port setting on a device, overriding its profile.
type rawPortOverride struct {
	PortIdx         int      `json:"port_idx"`
	Name            string   `json:"name"`
	PortconfID      string   `json:"portconf_id"`
	NativeNetworkID string   `json:"native_networkconf_id"`
	Forward         string   `json:"forward"`
	TaggedIDs       []string `json:"tagged_networkconf_ids"`
	ExcludedIDs     []string `json:"excluded_networkconf_ids"`
	TaggedVLANMgmt  string   `json:"tagged_vlan_mgmt"`
}

type rawWLAN struct {
	ID        string `json:"_id"`
	Name      string `json:"name"`
	NetworkID string `json:"networkconf_id"`
	Enabled   *bool  `json:"enabled"`
	IsGuest   bool   `json:"is_guest"`
}

type rawZone struct {
	ID         string   `json:"_id"`
	Name       string   `json:"name"`
	ZoneKey    string   `json:"zone_key"` // internal | external | gateway | vpn | hotspot | dmz; empty for custom zones
	NetworkIDs []string `json:"network_ids"`
}

// siteConfig is the optional network configuration of a site.
type siteConfig struct {
	Networks  []rawNetwork
	PortConfs []rawPortConf
	WLANs     []rawWLAN
	Zones     []rawZone
	// ZonesKnown is set when the console returned its firewall zone list.
	ZonesKnown bool
}

// collectSiteConfig fetches networks, port profiles, WLANs and firewall zones, best effort.
func collectSiteConfig(ctx context.Context, c *client) *siteConfig {
	cfg := &siteConfig{}
	var err error
	if cfg.Networks, err = getList[rawNetwork](ctx, c, "rest/networkconf"); err != nil {
		return nil
	}
	cfg.PortConfs, _ = getList[rawPortConf](ctx, c, "rest/portconf")
	cfg.WLANs, _ = getList[rawWLAN](ctx, c, "rest/wlanconf")
	var zones []rawZone
	// older firmware has no zone-based firewall: zones are then inferred from each network
	if err := c.req(ctx, http.MethodGet, c.v2Path("firewall/zone"), nil, &zones); err == nil {
		cfg.Zones, cfg.ZonesKnown = zones, len(zones) > 0
	}
	return cfg
}

func (c *client) v2Path(p string) string {
	if c.classic {
		return "/v2/api/site/" + url.PathEscape(c.site) + "/" + p
	}
	return "/proxy/network/v2/api/site/" + url.PathEscape(c.site) + "/" + p
}

// Zone keys NCC uses. They match UniFi's zone_key values, plus "guest" for networks with
// the guest purpose on consoles without zone-based firewall, and "custom" for zones the
// admin made.
const (
	ZoneInternal = "internal"
	ZoneExternal = "external"
	ZoneGateway  = "gateway"
	ZoneVPN      = "vpn"
	ZoneHotspot  = "hotspot"
	ZoneDMZ      = "dmz"
	ZoneCustom   = "custom"
)

var zoneNames = map[string]string{
	ZoneInternal: "Internal", ZoneExternal: "External", ZoneGateway: "Gateway",
	ZoneVPN: "VPN", ZoneHotspot: "Hotspot (guest)", ZoneDMZ: "DMZ",
}

// netIndex resolves networks for ports and clients.
type netIndex struct {
	nets     []inv.Network
	byID     map[string]*inv.Network
	byName   map[string]*inv.Network
	byVLAN   map[int]*inv.Network
	prefixes []struct {
		p  netip.Prefix
		id string
	}
	defaultID string
	profiles  map[string]rawPortConf
	ssidNet   map[string]string // SSID -> network id
	// switched lists the networks a switch port can carry (everything except WAN and VPN).
	switched []string
}

func buildNetIndex(target string, cfg *siteConfig) *netIndex {
	ix := &netIndex{byID: map[string]*inv.Network{}, byName: map[string]*inv.Network{}, byVLAN: map[int]*inv.Network{},
		profiles: map[string]rawPortConf{}, ssidNet: map[string]string{}}
	if cfg == nil {
		return ix
	}
	zoneOf := map[string]rawZone{}
	zoneByID := map[string]rawZone{}
	for _, z := range cfg.Zones {
		zoneByID[z.ID] = z
		for _, id := range z.NetworkIDs {
			zoneOf[id] = z
		}
	}
	for _, r := range cfg.Networks {
		if r.ID == "" || (r.Enabled != nil && !*r.Enabled) {
			continue
		}
		n := inv.Network{ID: r.ID, Name: r.Name, Purpose: r.Purpose, Target: target, Isolated: r.Isolation,
			InternetAccess: r.InternetAccess == nil || *r.InternetAccess}
		if r.VLANEnabled && r.VLAN > 0 {
			n.VLAN = int(r.VLAN)
		}
		if p, err := netip.ParsePrefix(strings.TrimSpace(r.IPSubnet)); err == nil {
			n.Subnet = p.Masked().String()
		}
		z, ok := zoneOf[r.ID]
		if !ok && r.FirewallZoneID != "" {
			z, ok = zoneByID[r.FirewallZoneID]
		}
		if ok {
			n.Zone, n.ZoneName, n.ZoneSource = z.ZoneKey, z.Name, "firewall"
			if n.Zone == "" {
				n.Zone = ZoneCustom
			}
		} else {
			n.Zone, n.ZoneSource = inferZone(r), "inferred"
			n.ZoneName = zoneNames[n.Zone]
		}
		if n.ZoneName == "" {
			n.ZoneName = zoneNames[n.Zone]
		}
		ix.nets = append(ix.nets, n)
	}
	sort.SliceStable(ix.nets, func(i, j int) bool {
		a, b := ix.nets[i], ix.nets[j]
		if (a.Purpose == "wan") != (b.Purpose == "wan") {
			return b.Purpose == "wan"
		}
		return a.VLAN < b.VLAN
	})
	for i := range ix.nets {
		n := &ix.nets[i]
		ix.byID[n.ID] = n
		ix.byName[strings.ToLower(n.Name)] = n
		if n.Purpose == "wan" || strings.Contains(n.Purpose, "vpn") {
			continue
		}
		ix.switched = append(ix.switched, n.ID)
		vlan := n.VLAN
		if vlan == 0 {
			vlan = 1
		}
		if _, dup := ix.byVLAN[vlan]; !dup {
			ix.byVLAN[vlan] = n
		}
		if n.VLAN == 0 && ix.defaultID == "" {
			ix.defaultID = n.ID
		}
		if p, err := netip.ParsePrefix(n.Subnet); err == nil {
			ix.prefixes = append(ix.prefixes, struct {
				p  netip.Prefix
				id string
			}{p, n.ID})
		}
	}
	for _, p := range cfg.PortConfs {
		ix.profiles[p.ID] = p
	}
	for _, w := range cfg.WLANs {
		if w.Enabled != nil && !*w.Enabled {
			continue
		}
		id := w.NetworkID
		if id == "" {
			id = ix.defaultID
		}
		if _, ok := ix.byID[id]; ok {
			ix.ssidNet[w.Name] = id
			ix.byID[id].SSIDs = append(ix.byID[id].SSIDs, w.Name)
		}
	}
	return ix
}

// inferZone guesses a zone for consoles without zone-based firewall.
func inferZone(r rawNetwork) string {
	name := strings.ToLower(r.Name)
	switch {
	case r.Purpose == "wan":
		return ZoneExternal
	case strings.Contains(r.Purpose, "vpn"):
		return ZoneVPN
	case strings.Contains(name, "dmz"):
		return ZoneDMZ
	case r.Purpose == "guest":
		return ZoneHotspot
	default:
		return ZoneInternal
	}
}

// byIP returns the network whose subnet holds ip.
func (ix *netIndex) byIP(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	best, bits := "", -1
	for _, p := range ix.prefixes {
		if p.p.Contains(a) && p.p.Bits() > bits {
			best, bits = p.id, p.p.Bits()
		}
	}
	return best
}

// client resolves the network a client sits in.
func (ix *netIndex) client(r rawClient) string {
	if _, ok := ix.byID[r.NetworkID]; ok {
		return r.NetworkID
	}
	if id := ix.byIP(r.IP); id != "" {
		return id
	}
	if n, ok := ix.byName[strings.ToLower(r.Network)]; ok && r.Network != "" {
		return n.ID
	}
	if !r.IsWired {
		if id, ok := ix.ssidNet[r.ESSID]; ok {
			return id
		}
	}
	if n, ok := ix.byVLAN[r.VLAN]; ok && r.VLAN > 0 {
		return n.ID
	}
	return ""
}

// port works out a switch port's profile, native network and tagged networks. With no
// profile at all, UniFi's default applies: native Default network, everything else tagged.
func (ix *netIndex) port(p rawPort, ov *rawPortOverride) (profile, native string, tagged []string) {
	if len(ix.nets) == 0 {
		return "", "", nil
	}
	pc := rawPortConf{Forward: "all"}
	confID := p.PortconfID
	if ov != nil && ov.PortconfID != "" {
		confID = ov.PortconfID
	}
	if c, ok := ix.profiles[confID]; ok {
		pc, profile = c, c.Name
	}
	native = firstNonEmpty(pc.NativeNetworkID)
	mode, mgmt, tags, excl := pc.Forward, pc.TaggedVLANMgmt, pc.TaggedIDs, pc.ExcludedIDs
	// settings on the port itself win over the profile
	if p.NativeNetworkID != "" {
		native = p.NativeNetworkID
	}
	if p.TaggedVLANMgmt != "" {
		mgmt, excl = p.TaggedVLANMgmt, p.ExcludedIDs
	}
	if p.Forward != "" {
		mode = p.Forward
	}
	if ov != nil {
		if ov.NativeNetworkID != "" {
			native = ov.NativeNetworkID
		}
		if ov.Forward != "" {
			mode, tags = ov.Forward, ov.TaggedIDs
		}
		if ov.TaggedVLANMgmt != "" {
			mgmt, excl = ov.TaggedVLANMgmt, ov.ExcludedIDs
		}
	}
	if native == "" && mode != "disabled" {
		native = ix.defaultID
	}
	if _, ok := ix.byID[native]; !ok {
		native = ""
	}
	all := func(skip []string) []string {
		drop := map[string]bool{native: true}
		for _, s := range skip {
			drop[s] = true
		}
		var out []string
		for _, id := range ix.switched {
			if !drop[id] {
				out = append(out, id)
			}
		}
		return out
	}
	switch {
	case mgmt == "block_all":
	case mgmt == "custom":
		tagged = all(excl)
	case mgmt == "auto":
		tagged = all(nil)
	case mode == "native" || mode == "disabled":
	case mode == "customize":
		for _, id := range tags {
			if _, ok := ix.byID[id]; ok && id != native {
				tagged = append(tagged, id)
			}
		}
	default: // "all"
		tagged = all(excl)
	}
	if mode == "disabled" {
		native = ""
	}
	return profile, native, tagged
}

// carried lists every network on a port: native first, then tagged.
func carried(p inv.Port) []string {
	var out []string
	if p.NativeNetwork != "" {
		out = append(out, p.NativeNetwork)
	}
	return append(out, p.TaggedNetworks...)
}
