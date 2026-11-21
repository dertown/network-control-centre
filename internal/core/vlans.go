package core

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/inventory"
)

// VLAN planning: checks a new network against the ones that exist, and works out how each
// client would be moved to another network, from the latest snapshot. Planning never talks to
// the device, so the preview is instant; the driver checks again when the change is made.

// MoveStep is how one client gets to the new network, or why it can't.
type MoveStep struct {
	MAC    string `json:"mac"`
	Name   string `json:"name"`
	IP     string `json:"ip,omitempty"`
	Wired  bool   `json:"wired"`
	Method string `json:"method,omitempty"` // drivers.MovePort or drivers.MoveClient; empty when blocked or already there
	// From is the network the client is in now.
	From     string `json:"from,omitempty"`
	FromName string `json:"from_name,omitempty"`
	// Via names the switch port or Wi-Fi network.
	Via        string `json:"via,omitempty"`
	SwitchMAC  string `json:"switch_mac,omitempty"`
	SwitchPort int    `json:"switch_port,omitempty"`
	// Requested is false for a client that moves only because it shares a switch port with one
	// that was asked for.
	Requested bool   `json:"requested"`
	Already   bool   `json:"already,omitempty"`
	Blocked   string `json:"blocked,omitempty"`
	Note      string `json:"note,omitempty"`
}

// PortChange is one switch port whose untagged network changes.
type PortChange struct {
	SwitchMAC  string   `json:"switch_mac"`
	SwitchName string   `json:"switch_name"`
	Port       int      `json:"port"`
	PortName   string   `json:"port_name"`
	From       string   `json:"from,omitempty"`
	FromName   string   `json:"from_name,omitempty"`
	Profile    string   `json:"profile,omitempty"`
	Clients    []string `json:"clients"`
	Offline    bool     `json:"offline,omitempty"`
}

// MovePlan is the preview of moving clients to a network.
type MovePlan struct {
	Target   string            `json:"target"`
	Network  inventory.Network `json:"network"`
	Steps    []MoveStep        `json:"steps"`
	Ports    []PortChange      `json:"ports"`
	Warnings []string          `json:"warnings,omitempty"`
}

// Moves returns the driver changes for the plan's steps.
func (p *MovePlan) Moves() []drivers.ClientMove {
	var out []drivers.ClientMove
	for _, s := range p.Steps {
		if s.Method == "" {
			continue
		}
		out = append(out, drivers.ClientMove{MAC: s.MAC, Name: s.Name, Method: s.Method, SwitchMAC: s.SwitchMAC, SwitchPort: s.SwitchPort})
	}
	return out
}

// PlanMove works out how to put the clients with the given MACs in network networkID.
func PlanMove(snap *inventory.Snapshot, networkID string, macs []string) (*MovePlan, error) {
	var net *inventory.Network
	netName := map[string]string{}
	for i := range snap.Networks {
		netName[snap.Networks[i].ID] = snap.Networks[i].Name
		if snap.Networks[i].ID == networkID {
			net = &snap.Networks[i]
		}
	}
	if net == nil {
		return nil, fmt.Errorf("no network %q on %s; refresh and try again", networkID, snap.Target)
	}
	if net.Purpose == "wan" || strings.Contains(net.Purpose, "vpn") {
		return nil, fmt.Errorf("%s is a %s network: clients cannot be put in it", net.Name, net.Purpose)
	}
	plan := &MovePlan{Target: snap.Target, Network: *net, Steps: []MoveStep{}, Ports: []PortChange{}}
	devs := map[string]*inventory.Device{}
	for i := range snap.Devices {
		devs[snap.Devices[i].ID] = &snap.Devices[i]
	}
	byMAC := map[string]*inventory.Client{}
	onPort := map[string][]*inventory.Client{}
	portKey := func(mac string, port int) string { return fmt.Sprintf("%s#%d", mac, port) }
	for i := range snap.Clients {
		c := &snap.Clients[i]
		byMAC[c.MAC] = c
		if c.Wired && c.SwitchMAC != "" && c.SwitchPort > 0 {
			k := portKey(c.SwitchMAC, c.SwitchPort)
			onPort[k] = append(onPort[k], c)
		}
	}
	want := map[string]bool{}
	var order []string
	for _, m := range macs {
		m = inventory.NormMAC(m)
		if m != "" && !want[m] {
			want[m] = true
			order = append(order, m)
		}
	}
	if len(order) == 0 {
		return nil, fmt.Errorf("pick at least one client")
	}
	added := map[string]bool{}
	portDone := map[string]bool{}
	step := func(c *inventory.Client, requested bool) MoveStep {
		return MoveStep{MAC: c.MAC, Name: c.Name, IP: c.IP, Wired: c.Wired, From: c.NetworkID, FromName: netName[c.NetworkID], Requested: requested}
	}
	for _, mac := range order {
		if added[mac] {
			// already pulled in by a shared port: it was asked for too
			for i := range plan.Steps {
				if plan.Steps[i].MAC == mac {
					plan.Steps[i].Requested = true
				}
			}
			continue
		}
		c, ok := byMAC[mac]
		if !ok {
			plan.Steps = append(plan.Steps, MoveStep{MAC: mac, Name: mac, Requested: true, Blocked: "not connected now; NCC can only move clients it can see"})
			added[mac] = true
			continue
		}
		s := step(c, true)
		if c.NetworkID == networkID {
			s.Already = true
			s.Note = "already in " + net.Name
			plan.Steps = append(plan.Steps, s)
			added[mac] = true
			continue
		}
		if !c.Wired {
			s.Method, s.Via = drivers.MoveClient, "Wi-Fi "+c.SSID
			if c.SSID == "" {
				s.Via = "Wi-Fi"
			}
			s.Note = "stays on the same Wi-Fi; the access point puts it in " + net.Name
			plan.Steps = append(plan.Steps, s)
			added[mac] = true
			continue
		}
		sw := devs[c.SwitchMAC]
		var port *inventory.Port
		if sw != nil {
			for i := range sw.Ports {
				if sw.Ports[i].Index == c.SwitchPort {
					port = &sw.Ports[i]
				}
			}
		}
		switch {
		case c.SwitchMAC == "" || c.SwitchPort == 0:
			s.Blocked = "NCC does not know which switch port it is cabled to (wait for the next refresh)"
		case sw == nil || !sw.Managed || sw.Discovery != inventory.SourceController:
			s.Blocked = "it is cabled to a switch this console does not manage"
		case port != nil && port.Infra:
			behind := devs[c.ParentID]
			if behind != nil && behind.ID != sw.ID {
				s.Blocked = fmt.Sprintf("it is behind %s on %s %s; changing that port would move %s and everything behind it. Set the VLAN on %s's port instead",
					behind.Name, sw.Name, portLabel(sw, c.SwitchPort), behind.Name, behind.Name)
			} else {
				s.Blocked = fmt.Sprintf("%s %s leads to other network equipment; changing it would cut them off", sw.Name, portLabel(sw, c.SwitchPort))
			}
		}
		if s.Blocked != "" {
			plan.Steps = append(plan.Steps, s)
			added[mac] = true
			continue
		}
		k := portKey(c.SwitchMAC, c.SwitchPort)
		if !portDone[k] {
			portDone[k] = true
			pc := PortChange{SwitchMAC: sw.ID, SwitchName: sw.Name, Port: c.SwitchPort, PortName: portLabel(sw, c.SwitchPort), Offline: !sw.Online}
			if port != nil {
				pc.From, pc.FromName, pc.Profile = port.NativeNetwork, netName[port.NativeNetwork], port.Profile
			}
			mates := onPort[k]
			sort.SliceStable(mates, func(i, j int) bool { return mates[i].Name < mates[j].Name })
			for _, m := range mates {
				pc.Clients = append(pc.Clients, m.Name)
			}
			plan.Ports = append(plan.Ports, pc)
			for _, m := range mates {
				if added[m.MAC] {
					continue
				}
				ms := step(m, want[m.MAC])
				ms.Method, ms.SwitchMAC, ms.SwitchPort = drivers.MovePort, sw.ID, c.SwitchPort
				ms.Via = sw.Name + " " + pc.PortName
				if m.NetworkID == networkID {
					ms.Note = "already in " + net.Name + "; its port changes with the others"
				}
				if !ms.Requested {
					ms.Note = "shares " + ms.Via + " with " + c.Name + ", so it moves too"
				}
				plan.Steps = append(plan.Steps, ms)
				added[m.MAC] = true
			}
		}
	}
	for _, pc := range plan.Ports {
		if pc.Offline {
			plan.Warnings = append(plan.Warnings, pc.SwitchName+" is offline: the console applies the change when it comes back")
		}
		if len(pc.Clients) > 1 {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("%s %s has %d devices on it (probably a small unmanaged switch): they all move together",
				pc.SwitchName, pc.PortName, len(pc.Clients)))
		}
	}
	if net.Purpose == "vlan-only" {
		plan.Warnings = append(plan.Warnings, net.Name+" is VLAN only: the router hands out no addresses on it, so another DHCP server must")
	}
	if net.Isolated {
		plan.Warnings = append(plan.Warnings, net.Name+" is isolated: moved devices can no longer reach your other networks (apps on your phone may lose them)")
	}
	return plan, nil
}

func portLabel(d *inventory.Device, idx int) string {
	for _, p := range d.Ports {
		if p.Index == idx && p.Name != "" {
			return p.Name
		}
	}
	return fmt.Sprintf("Port %d", idx)
}

// ValidateNetwork checks a new network against the existing ones and fills defaults.
func ValidateNetwork(s *drivers.NetworkSpec, existing []inventory.Network) error {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" || len(s.Name) > 32 {
		return fmt.Errorf("give the network a name of up to 32 characters")
	}
	if s.VLAN < 2 || s.VLAN > 4009 {
		return fmt.Errorf("the VLAN ID must be between 2 and 4009")
	}
	if s.Mode == "" {
		s.Mode = "gateway"
	}
	if s.Mode != "gateway" && s.Mode != "vlan-only" {
		return fmt.Errorf("mode must be gateway or vlan-only")
	}
	for _, n := range existing {
		if strings.EqualFold(n.Name, s.Name) {
			return fmt.Errorf("a network named %q already exists", n.Name)
		}
		if n.VLAN == s.VLAN {
			return fmt.Errorf("VLAN %d is already used by %s", s.VLAN, n.Name)
		}
	}
	if s.Mode == "vlan-only" {
		s.Gateway, s.DHCP, s.DHCPStart, s.DHCPStop = "", false, "", ""
		return nil
	}
	gw, err := netip.ParsePrefix(strings.TrimSpace(s.Gateway))
	if err != nil || !gw.Addr().Is4() {
		return fmt.Errorf("the gateway must be an IPv4 address with prefix length, like 192.168.30.1/24")
	}
	if gw.Bits() < 16 || gw.Bits() > 30 {
		return fmt.Errorf("use a prefix length between /16 and /30")
	}
	pfx := gw.Masked()
	if gw.Addr() == pfx.Addr() || gw.Addr() == lastAddr(pfx) {
		return fmt.Errorf("%s is the network or broadcast address of %s; use a host address such as %s", gw.Addr(), pfx, pfx.Addr().Next())
	}
	if !gw.Addr().IsPrivate() {
		return fmt.Errorf("%s is not a private address range", pfx)
	}
	for _, n := range existing {
		if p, err := netip.ParsePrefix(n.Subnet); err == nil && p.Overlaps(pfx) {
			return fmt.Errorf("%s overlaps %s (%s)", pfx, n.Name, n.Subnet)
		}
	}
	s.Gateway = gw.String()
	if !s.DHCP {
		s.DHCPStart, s.DHCPStop = "", ""
		return nil
	}
	if s.DHCPStart == "" && s.DHCPStop == "" {
		start, stop := pfx.Addr().Next(), lastAddr(pfx).Prev()
		if start == gw.Addr() {
			start = start.Next()
		}
		if pfx.Bits() <= 24 && start.Next().IsValid() {
			// leave a few addresses at the bottom for devices set up by hand
			for i := 0; i < 4 && start.Less(stop); i++ {
				start = start.Next()
			}
		}
		s.DHCPStart, s.DHCPStop = start.String(), stop.String()
	}
	a, err1 := netip.ParseAddr(strings.TrimSpace(s.DHCPStart))
	b, err2 := netip.ParseAddr(strings.TrimSpace(s.DHCPStop))
	if err1 != nil || err2 != nil {
		return fmt.Errorf("the DHCP range must be two IPv4 addresses")
	}
	if !pfx.Contains(a) || !pfx.Contains(b) || b.Less(a) {
		return fmt.Errorf("the DHCP range must be inside %s, first address before last", pfx)
	}
	if !gw.Addr().Less(a) && !b.Less(gw.Addr()) {
		return fmt.Errorf("the DHCP range must not include the gateway address %s", gw.Addr())
	}
	if a == pfx.Addr() || b == lastAddr(pfx) {
		return fmt.Errorf("the DHCP range must not include the network or broadcast address")
	}
	s.DHCPStart, s.DHCPStop = a.String(), b.String()
	return nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// SuggestNetwork proposes a free VLAN ID and subnet for a new network.
func SuggestNetwork(existing []inventory.Network) drivers.NetworkSpec {
	used := map[int]bool{}
	var prefixes []netip.Prefix
	for _, n := range existing {
		used[n.VLAN] = true
		if p, err := netip.ParsePrefix(n.Subnet); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	free := func(p netip.Prefix) bool {
		for _, q := range prefixes {
			if q.Overlaps(p) {
				return false
			}
		}
		return true
	}
	vlan := 10
	for used[vlan] {
		vlan += 10
	}
	s := drivers.NetworkSpec{VLAN: vlan, Mode: "gateway", DHCP: true, InternetAccess: true}
	for v := vlan; v < 255; v++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, byte(v), 0}), 24)
		if free(p) {
			s.Gateway = netip.PrefixFrom(p.Addr().Next(), 24).String()
			break
		}
	}
	return s
}
