package unifi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	inv "github.com/dertown/network-control-centre/internal/inventory"
)

// Firewall rules and port forwards, read-only.
//
// UniFi has two firewalls:
//   - zone-based firewall (Network 9 and later): policies between zones, from
//     v2/api/site/<site>/firewall-policies. The console lists its own predefined policies
//     there too; they are marked built-in.
//   - the older rule sets (WAN_IN, LAN_IN, GUEST_IN...): rest/firewallrule.
//
// Port forwards are rest/portforward on both. Address and port groups, used by rules and
// forwards alike, are rest/firewallgroup. Every list is optional: a list the console refuses
// is left out with a note, and the rest of the poll goes on.

type rawFirewallGroup struct {
	ID      string   `json:"_id"`
	Name    string   `json:"name"`
	Type    string   `json:"group_type"` // address-group | ipv6-address-group | port-group
	Members []string `json:"group_members"`
}

type rawPolicyEndpoint struct {
	ZoneID             string   `json:"zone_id"`
	MatchingTarget     string   `json:"matching_target"`      // ANY | IP | NETWORK | CLIENT | REGION | WEB | APP | APP_CATEGORY
	MatchingTargetType string   `json:"matching_target_type"` // SPECIFIC | OBJECT
	IPs                []string `json:"ips"`
	IPGroupID          string   `json:"ip_group_id"`
	NetworkIDs         []string `json:"network_ids"`
	ClientMACs         []string `json:"client_macs"`
	Regions            []string `json:"regions"`
	WebDomains         []string `json:"web_domains"`
	AppIDs             []any    `json:"app_ids"`
	AppCategoryIDs     []any    `json:"app_category_ids"`
	PortMatchingType   string   `json:"port_matching_type"` // ANY | SPECIFIC | OBJECT
	Port               string   `json:"port"`
	PortGroupID        string   `json:"port_group_id"`
	MatchOppositeIPs   bool     `json:"match_opposite_ips"`
	MatchOppositePorts bool     `json:"match_opposite_ports"`
	MatchOppositeNets  bool     `json:"match_opposite_networks"`
}

type rawPolicy struct {
	ID                  string            `json:"_id"`
	Name                string            `json:"name"`
	Description         string            `json:"description"`
	Enabled             bool              `json:"enabled"`
	Action              string            `json:"action"` // ALLOW | BLOCK | REJECT
	Index               flexInt           `json:"index"`
	Predefined          bool              `json:"predefined"`
	Protocol            string            `json:"protocol"`
	MatchOppositeProto  bool              `json:"match_opposite_protocol"`
	IPVersion           string            `json:"ip_version"` // BOTH | IPV4 | IPV6
	Logging             bool              `json:"logging"`
	ConnectionStateType string            `json:"connection_state_type"` // ALL | RESPOND_ONLY | CUSTOM
	ConnectionStates    []string          `json:"connection_states"`
	Source              rawPolicyEndpoint `json:"source"`
	Destination         rawPolicyEndpoint `json:"destination"`
	Schedule            struct {
		Mode string `json:"mode"` // ALWAYS | EVERY_DAY | EVERY_WEEK | ONE_TIME_ONLY | CUSTOM
	} `json:"schedule"`
}

type rawFirewallRule struct {
	ID            string   `json:"_id"`
	Name          string   `json:"name"`
	Enabled       bool     `json:"enabled"`
	Action        string   `json:"action"`  // accept | drop | reject
	Ruleset       string   `json:"ruleset"` // WAN_IN | WAN_OUT | WAN_LOCAL | LAN_IN | ... | GUEST_IN ...
	RuleIndex     flexInt  `json:"rule_index"`
	Protocol      string   `json:"protocol"`
	ProtoExcepted bool     `json:"protocol_match_excepted"`
	Logging       bool     `json:"logging"`
	SrcGroupIDs   []string `json:"src_firewallgroup_ids"`
	SrcAddress    string   `json:"src_address"`
	SrcMAC        string   `json:"src_mac_address"`
	SrcNetworkID  string   `json:"src_networkconf_id"`
	SrcPort       string   `json:"src_port"`
	DstGroupIDs   []string `json:"dst_firewallgroup_ids"`
	DstAddress    string   `json:"dst_address"`
	DstNetworkID  string   `json:"dst_networkconf_id"`
	DstPort       string   `json:"dst_port"`
	StateNew      bool     `json:"state_new"`
	StateEstab    bool     `json:"state_established"`
	StateRelated  bool     `json:"state_related"`
	StateInvalid  bool     `json:"state_invalid"`
}

type rawPortForward struct {
	ID            string `json:"_id"`
	Name          string `json:"name"`
	Enabled       *bool  `json:"enabled"`
	Interface     string `json:"pfwd_interface"` // wan | wan2 | both | all
	Proto         string `json:"proto"`          // tcp_udp | tcp | udp
	Src           string `json:"src"`            // any, or an address / CIDR
	DstPort       string `json:"dst_port"`
	Fwd           string `json:"fwd"`
	FwdPort       string `json:"fwd_port"`
	Log           bool   `json:"log"`
	DestinationIP string `json:"destination_ip"`
	SrcLimiting   bool   `json:"src_limiting_enabled"`
	SrcLimitType  string `json:"src_limiting_type"` // ip | firewall_group
	SrcGroupID    string `json:"src_firewall_group_id"`
}

// firewallData is the raw firewall configuration of a site.
type firewallData struct {
	Groups   []rawFirewallGroup
	Policies []rawPolicy
	// PoliciesKnown is set when the console answered the zone policy list.
	PoliciesKnown bool
	Rules         []rawFirewallRule
	Forwards      []rawPortForward
	Notes         []string
}

// refused says what to tell the admin about a list the console would not give.
func refused(what string, err error) string {
	if errors.Is(err, ErrUnauthorized) {
		return fmt.Sprintf("The router refused the %s list (no permission). Give the NCC account a Network role that can see Firewall settings.", what)
	}
	return fmt.Sprintf("Could not read the %s list: %v", what, err)
}

// notFound is true for an answer that means "this console has no such API".
func notFound(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "HTTP 404") || strings.Contains(err.Error(), "HTTP 400"))
}

// collectFirewall reads groups, zone policies, legacy rules and port forwards, best effort.
func collectFirewall(ctx context.Context, c *client) *firewallData {
	fw := &firewallData{}
	var err error
	if fw.Groups, err = getList[rawFirewallGroup](ctx, c, "rest/firewallgroup"); err != nil && !notFound(err) {
		fw.Notes = append(fw.Notes, refused("firewall group", err))
	}
	var pols []rawPolicy
	switch err := c.req(ctx, http.MethodGet, c.v2Path("firewall-policies"), nil, &pols); {
	case err == nil:
		fw.Policies, fw.PoliciesKnown = pols, true
	case notFound(err):
		// no zone-based firewall: older firmware, or not migrated yet
	default:
		fw.Notes = append(fw.Notes, refused("firewall policy", err))
	}
	if fw.Rules, err = getList[rawFirewallRule](ctx, c, "rest/firewallrule"); err != nil && !notFound(err) {
		fw.Notes = append(fw.Notes, refused("firewall rule", err))
	}
	if fw.Forwards, err = getList[rawPortForward](ctx, c, "rest/portforward"); err != nil && !notFound(err) {
		fw.Notes = append(fw.Notes, refused("port forward", err))
	}
	return fw
}

// BuildFirewall turns the raw firewall configuration into NCC's model, naming the zones,
// networks, groups and clients that rules refer to.
func BuildFirewall(target string, fw *firewallData, cfg *siteConfig, clients []rawClient) *inv.Firewall {
	out := &inv.Firewall{Target: target, Rules: []inv.FirewallRule{}, Forwards: []inv.PortForward{}}
	if fw == nil {
		return out
	}
	out.Notes = fw.Notes
	nm := newFwNames(fw, cfg, clients)

	// A console with zone-based firewall still answers rest/firewallrule, usually with
	// nothing or with rules it no longer applies, so policies win when there are any.
	switch {
	case fw.PoliciesKnown && (len(fw.Policies) > 0 || len(fw.Rules) == 0):
		out.Mode = inv.FirewallZones
		for _, p := range fw.Policies {
			out.Rules = append(out.Rules, nm.policy(target, p))
		}
	case fw.Rules != nil:
		out.Mode = inv.FirewallLegacy
		for _, r := range fw.Rules {
			out.Rules = append(out.Rules, nm.rule(target, r))
		}
	}
	sort.SliceStable(out.Rules, func(i, j int) bool {
		a, b := out.Rules[i], out.Rules[j]
		if a.Builtin != b.Builtin {
			return !a.Builtin
		}
		if a.Ruleset != b.Ruleset {
			return a.Ruleset < b.Ruleset
		}
		return a.Index < b.Index
	})
	for _, f := range fw.Forwards {
		out.Forwards = append(out.Forwards, nm.forward(target, f))
	}
	sort.SliceStable(out.Forwards, func(i, j int) bool {
		return strings.ToLower(out.Forwards[i].Name) < strings.ToLower(out.Forwards[j].Name)
	})
	return out
}

type fwNames struct {
	zones  map[string]string
	nets   map[string]string
	groups map[string]rawFirewallGroup
	byMAC  map[string]string
	byIP   map[string]string
}

func newFwNames(fw *firewallData, cfg *siteConfig, clients []rawClient) *fwNames {
	nm := &fwNames{zones: map[string]string{}, nets: map[string]string{}, groups: map[string]rawFirewallGroup{},
		byMAC: map[string]string{}, byIP: map[string]string{}}
	if cfg != nil {
		for _, z := range cfg.Zones {
			name := z.Name
			if n, ok := zoneNames[z.ZoneKey]; ok && name == "" {
				name = n
			}
			nm.zones[z.ID] = name
		}
		for _, n := range cfg.Networks {
			nm.nets[n.ID] = n.Name
		}
	}
	for _, g := range fw.Groups {
		nm.groups[g.ID] = g
	}
	for _, c := range clients {
		name := firstNonEmpty(c.Name, c.Hostname)
		if name == "" {
			continue
		}
		nm.byMAC[inv.NormMAC(c.MAC)] = name
		if c.IP != "" {
			nm.byIP[c.IP] = name
		}
	}
	return nm
}

func (nm *fwNames) group(id string) string {
	if g, ok := nm.groups[id]; ok {
		return g.Name
	}
	if id == "" {
		return ""
	}
	return "group " + id
}

func (nm *fwNames) network(id string) string {
	if n, ok := nm.nets[id]; ok && n != "" {
		return n
	}
	return "network " + id
}

func (nm *fwNames) mac(m string) string {
	if n, ok := nm.byMAC[inv.NormMAC(m)]; ok {
		return n
	}
	return m
}

func list(items []string, f func(string) string) string {
	var out []string
	for _, s := range items {
		if s = strings.TrimSpace(s); s != "" {
			if f != nil {
				s = f(s)
			}
			out = append(out, s)
		}
	}
	return strings.Join(out, ", ")
}

func (nm *fwNames) endpoint(e rawPolicyEndpoint) inv.FirewallEndpoint {
	out := inv.FirewallEndpoint{Zone: nm.zones[e.ZoneID], Match: "Any"}
	if out.Zone == "" && e.ZoneID != "" {
		out.Zone = "zone " + e.ZoneID
	}
	switch strings.ToUpper(e.MatchingTarget) {
	case "IP":
		if strings.EqualFold(e.MatchingTargetType, "OBJECT") && e.IPGroupID != "" {
			out.Match = nm.group(e.IPGroupID)
		} else if s := list(e.IPs, nil); s != "" {
			out.Match = s
		}
		out.Negate = e.MatchOppositeIPs
	case "NETWORK":
		if s := list(e.NetworkIDs, nm.network); s != "" {
			out.Match = s
		}
		out.Negate = e.MatchOppositeNets
	case "CLIENT":
		if s := list(e.ClientMACs, nm.mac); s != "" {
			out.Match = s
		}
	case "REGION":
		out.Match = "Regions: " + list(e.Regions, nil)
	case "WEB":
		out.Match = "Domains: " + list(e.WebDomains, nil)
	case "APP":
		out.Match = fmt.Sprintf("%d app(s)", len(e.AppIDs))
	case "APP_CATEGORY":
		out.Match = fmt.Sprintf("%d app categor%s", len(e.AppCategoryIDs), map[bool]string{true: "y", false: "ies"}[len(e.AppCategoryIDs) == 1])
	}
	switch strings.ToUpper(e.PortMatchingType) {
	case "SPECIFIC":
		out.Port = strings.TrimSpace(e.Port)
	case "OBJECT":
		out.Port = nm.portGroup(e.PortGroupID)
	}
	if out.Port != "" && e.MatchOppositePorts {
		out.Port = "not " + out.Port
	}
	return out
}

// portGroup names a port group with its ports, e.g. "Web (80, 443)".
func (nm *fwNames) portGroup(id string) string {
	g, ok := nm.groups[id]
	if !ok {
		return nm.group(id)
	}
	if len(g.Members) > 0 && len(g.Members) <= 6 {
		return g.Name + " (" + strings.Join(g.Members, ", ") + ")"
	}
	return g.Name
}

func protocol(p string, excepted bool) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "", "all":
		p = "Any"
	case "tcp_udp":
		p = "TCP/UDP"
	default:
		p = strings.ToUpper(p)
	}
	if excepted && p != "Any" {
		return "not " + p
	}
	return p
}

func action(a string) string {
	switch strings.ToLower(a) {
	case "allow", "accept":
		return "allow"
	case "block", "drop":
		return "block"
	case "reject":
		return "reject"
	}
	return strings.ToLower(a)
}

func (nm *fwNames) policy(target string, p rawPolicy) inv.FirewallRule {
	r := inv.FirewallRule{ID: p.ID, Name: firstNonEmpty(p.Name, "(unnamed)"), Description: p.Description, Enabled: p.Enabled,
		Action: action(p.Action), Index: int(p.Index), Builtin: p.Predefined, Source: nm.endpoint(p.Source),
		Destination: nm.endpoint(p.Destination), Protocol: protocol(p.Protocol, p.MatchOppositeProto),
		Logging: p.Logging, Target: target}
	switch strings.ToUpper(p.IPVersion) {
	case "IPV4":
		r.IPVersion = "IPv4"
	case "IPV6":
		r.IPVersion = "IPv6"
	}
	switch strings.ToUpper(p.ConnectionStateType) {
	case "RESPOND_ONLY":
		r.States = []string{"established", "related"}
	case "CUSTOM":
		for _, s := range p.ConnectionStates {
			r.States = append(r.States, strings.ToLower(s))
		}
	}
	if m := strings.ToUpper(p.Schedule.Mode); m != "" && m != "ALWAYS" {
		r.Schedule = strings.ReplaceAll(strings.ToLower(m), "_", " ")
	}
	return r
}

func (nm *fwNames) rule(target string, raw rawFirewallRule) inv.FirewallRule {
	r := inv.FirewallRule{ID: raw.ID, Name: firstNonEmpty(raw.Name, "(unnamed)"), Enabled: raw.Enabled, Action: action(raw.Action),
		Index: int(raw.RuleIndex), Ruleset: raw.Ruleset, Protocol: protocol(raw.Protocol, raw.ProtoExcepted),
		Logging: raw.Logging, Target: target}
	r.Source = nm.legacyEndpoint(raw.SrcNetworkID, raw.SrcAddress, raw.SrcMAC, raw.SrcGroupIDs, raw.SrcPort)
	r.Destination = nm.legacyEndpoint(raw.DstNetworkID, raw.DstAddress, "", raw.DstGroupIDs, raw.DstPort)
	for s, on := range map[string]bool{"new": raw.StateNew, "established": raw.StateEstab, "related": raw.StateRelated, "invalid": raw.StateInvalid} {
		if on {
			r.States = append(r.States, s)
		}
	}
	sort.Strings(r.States)
	return r
}

func (nm *fwNames) legacyEndpoint(netID, addr, mac string, groups []string, port string) inv.FirewallEndpoint {
	var parts, ports []string
	if netID != "" {
		parts = append(parts, nm.network(netID))
	}
	if addr = strings.TrimSpace(addr); addr != "" {
		parts = append(parts, addr)
	}
	if mac = strings.TrimSpace(mac); mac != "" {
		parts = append(parts, nm.mac(mac))
	}
	for _, id := range groups {
		if g, ok := nm.groups[id]; ok && g.Type == "port-group" {
			ports = append(ports, nm.portGroup(id))
		} else if id != "" {
			parts = append(parts, nm.group(id))
		}
	}
	if port = strings.TrimSpace(port); port != "" {
		ports = append(ports, port)
	}
	e := inv.FirewallEndpoint{Match: strings.Join(parts, ", "), Port: strings.Join(ports, ", ")}
	if e.Match == "" {
		e.Match = "Any"
	}
	return e
}

func (nm *fwNames) forward(target string, f rawPortForward) inv.PortForward {
	pf := inv.PortForward{ID: f.ID, Name: firstNonEmpty(f.Name, "(unnamed)"), Enabled: f.Enabled == nil || *f.Enabled,
		Protocol: protocol(f.Proto, false), ExternalPort: strings.TrimSpace(f.DstPort), ForwardIP: strings.TrimSpace(f.Fwd),
		ForwardPort: strings.TrimSpace(f.FwdPort), Logging: f.Log, Source: "Any", Target: target}
	if pf.Protocol == "Any" {
		pf.Protocol = "TCP/UDP"
	}
	if pf.ForwardPort == "" {
		pf.ForwardPort = pf.ExternalPort
	}
	switch strings.ToLower(f.Interface) {
	case "", "wan":
		pf.Interface = "WAN"
	case "wan2":
		pf.Interface = "WAN2"
	case "both":
		pf.Interface = "Both WANs"
	case "all":
		pf.Interface = "All WANs"
	default:
		pf.Interface = f.Interface
	}
	switch {
	case f.SrcLimiting && f.SrcLimitType == "firewall_group" && f.SrcGroupID != "":
		pf.Source = nm.group(f.SrcGroupID)
	case f.Src != "" && !strings.EqualFold(f.Src, "any"):
		pf.Source = f.Src
	}
	if d := strings.TrimSpace(f.DestinationIP); d != "" && !strings.EqualFold(d, "any") {
		pf.Destination = d
	}
	pf.ForwardClient = nm.byIP[pf.ForwardIP]
	return pf
}
