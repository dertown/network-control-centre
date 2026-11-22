package dnszones

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/inventory"
)

// Router is a router connection and its networks, as the check and the planner see it.
type Router struct {
	ID       int64               `json:"id"`
	Name     string              `json:"name"`
	Networks []inventory.Network `json:"networks"`
	// CanSetDomain is set when NCC can change a network's DHCP domain on this router.
	CanSetDomain bool `json:"can_set_domain"`
}

// Server is a DNS server connection and the zones it holds right now.
type Server struct {
	ID    int64      `json:"id"`
	Name  string     `json:"name"`
	Kind  string     `json:"kind"`
	Zones []dns.Zone `json:"zones"`
	// Error is set when the zones could not be read; Zones is then empty.
	Error string `json:"error,omitempty"`
	// CanCreate is set when NCC can create zones on this server.
	CanCreate bool `json:"can_create"`
}

// Statuses, worst last.
const (
	StatusSkip    = "skip"
	StatusPass    = "pass"
	StatusUnknown = "unknown"
	StatusWarn    = "warn"
	StatusFail    = "fail"
)

var rank = map[string]int{StatusSkip: 0, StatusPass: 1, StatusUnknown: 2, StatusWarn: 3, StatusFail: 4}

// Issue codes.
const (
	IssueNoZone          = "no_zone"           // the network has no zone
	IssueServerGone      = "server_gone"       // the assigned zone's DNS server connection was removed
	IssueServerError     = "server_error"      // the DNS server could not be read
	IssueZoneMissing     = "zone_missing"      // the assigned zone is not on the DNS server
	IssueNameMismatch    = "name_mismatch"     // the zone's name belongs to another network
	IssueSharedZone      = "shared_zone"       // several networks use the same zone
	IssueDHCPDomainUnset = "dhcp_domain_unset" // the router hands out no search domain
	IssueDHCPDomainOther = "dhcp_domain_other" // the router hands out another domain
	IssueNoReverse       = "no_reverse"        // no reverse zone for the subnet, so no PTR records
)

// Issue is one problem with a network's zone.
type Issue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"` // fail | warn | unknown
	Message  string `json:"message"`
	Fix      string `json:"fix,omitempty"`
}

// Row is one router network and its zone.
type Row struct {
	RouterID     int64  `json:"router_id"`
	Router       string `json:"router"`
	CanSetDomain bool   `json:"can_set_domain"`
	NetworkID    string `json:"network_id"`
	Network      string `json:"network"`
	VLAN         int    `json:"vlan"`
	Subnet       string `json:"subnet,omitempty"`
	Purpose      string `json:"purpose,omitempty"`
	FirewallZone string `json:"firewall_zone,omitempty"` // e.g. "DMZ", "Internal"
	DHCP         bool   `json:"dhcp"`
	DHCPDomain   string `json:"dhcp_domain,omitempty"` // what the router hands out, no trailing dot

	AssignmentID int64  `json:"assignment_id,omitempty"`
	Zone         string `json:"zone,omitempty"`
	ServerID     int64  `json:"server_id,omitempty"`
	Server       string `json:"server,omitempty"`
	ZoneFound    bool   `json:"zone_found"`

	ReverseZone  string `json:"reverse_zone,omitempty"`   // the zone PTR records for the subnet belong in
	ReverseFound bool   `json:"reverse_found"`            // a zone on the server covers them
	Suggested    string `json:"suggested_zone,omitempty"` // zone NCC proposes when none is assigned

	Status string  `json:"status"`
	Issues []Issue `json:"issues"`
}

// ZoneUse is one zone on a DNS server and the networks that use it.
type ZoneUse struct {
	ServerID int64    `json:"server_id"`
	Server   string   `json:"server"`
	Zone     string   `json:"zone"`
	Kind     string   `json:"kind,omitempty"`
	Reverse  bool     `json:"reverse"`
	Parent   string   `json:"parent,omitempty"` // the zone it is a subdomain of, on the same server
	Networks []string `json:"networks"`         // "IoT (VLAN 30)"
}

// Report is the zone and VLAN check.
type Report struct {
	Status  string `json:"status"` // worst row; "" when there are no networks
	Summary string `json:"summary"`
	// Domain is the parent domain new zones are suggested under, e.g. "corp.lan.".
	Domain  string       `json:"domain,omitempty"`
	Rows    []Row        `json:"rows"`
	Orphans []Assignment `json:"orphans"` // assignments whose network no longer exists
	Zones   []ZoneUse    `json:"zones"`
	Servers []Server     `json:"servers"`
	Routers []RouterInfo `json:"routers"`
}

// RouterInfo is a router connection without its networks.
type RouterInfo struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	CanSetDomain bool   `json:"can_set_domain"`
}

// Checked reports whether a network gets a zone check: LANs and VLAN-only networks do, WANs
// and VPNs do not.
func Checked(n inventory.Network) bool {
	return n.Purpose != "wan" && !strings.Contains(n.Purpose, "vpn")
}

func isGuest(n inventory.Network) bool { return n.Purpose == "guest" || n.Zone == "hotspot" }

// Label is how a network is named in messages: "IoT (VLAN 30)" or "Default (untagged)".
func Label(n inventory.Network) string {
	if n.VLAN == 0 {
		return n.Name + " (untagged)"
	}
	return fmt.Sprintf("%s (VLAN %d)", n.Name, n.VLAN)
}

// Slug turns a network name into a DNS label: "Smart Home" -> "smart-home".
func Slug(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if b.Len() > 0 && !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.TrimRight(b.String(), "-")
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	return s
}

// tokens are the names a zone label may use for a network: its slug, and "dmz" or "guest"
// for networks in those firewall zones.
func tokens(n inventory.Network) map[string]bool {
	t := map[string]bool{}
	if s := Slug(n.Name); s != "" {
		t[s] = true
	}
	if n.Zone == "dmz" {
		t["dmz"] = true
	}
	if isGuest(n) {
		t["guest"] = true
	}
	return t
}

// isDefault reports whether a network is the router's main untagged LAN, which normally
// lives in the parent domain itself rather than a subdomain.
func isDefault(n inventory.Network) bool {
	return n.VLAN == 0 && (n.Purpose == "corporate" || n.Purpose == "")
}

// ParentDomain picks the domain new VLAN zones go under: the main LAN's DHCP domain when a
// server holds it, else the forward zone with the fewest labels (ties alphabetical).
func ParentDomain(routers []Router, servers []Server) string {
	have := map[string]bool{}
	var forward []string
	for _, s := range servers {
		for _, z := range s.Zones {
			n := dns.FQDN(z.Name)
			if strings.HasSuffix(n, ".arpa.") {
				continue
			}
			if !have[n] {
				forward = append(forward, n)
			}
			have[n] = true
		}
	}
	for _, r := range routers {
		for _, n := range r.Networks {
			if isDefault(n) && n.DNS != nil && n.DNS.Domain != "" && have[dns.FQDN(n.DNS.Domain)] {
				return dns.FQDN(n.DNS.Domain)
			}
		}
	}
	sort.Slice(forward, func(i, j int) bool {
		li, lj := strings.Count(forward[i], "."), strings.Count(forward[j], ".")
		if li != lj {
			return li < lj
		}
		return forward[i] < forward[j]
	})
	if len(forward) == 0 {
		return ""
	}
	return forward[0]
}

// Suggest proposes a zone for a network: the zone its DHCP domain already names, the parent
// domain itself for the main LAN, else <network>.<parent>.
func Suggest(n inventory.Network, parent string, have map[string]bool) string {
	if n.DNS != nil && n.DNS.Domain != "" && have[dns.FQDN(n.DNS.Domain)] {
		return dns.FQDN(n.DNS.Domain)
	}
	if parent == "" {
		return ""
	}
	if isDefault(n) {
		return parent
	}
	label := Slug(n.Name)
	if n.Zone == "dmz" && !strings.Contains(label, "dmz") {
		label = "dmz"
	}
	if label == "" {
		return ""
	}
	return label + "." + parent
}

// ReverseFor returns the reverse zone for a network's subnet, or "".
func ReverseFor(n inventory.Network) string {
	p, err := netip.ParsePrefix(n.Subnet)
	if err != nil {
		return ""
	}
	return dns.ReverseZone(p)
}

// Evaluate checks every router network against the zone assignments and the zones the DNS
// servers hold.
func Evaluate(routers []Router, servers []Server, assignments []Assignment) Report {
	rep := Report{Rows: []Row{}, Orphans: []Assignment{}, Zones: []ZoneUse{}, Servers: servers, Routers: []RouterInfo{}}
	if rep.Servers == nil {
		rep.Servers = []Server{}
	}
	srvByID := map[int64]*Server{}
	allZones := map[string]bool{}
	for i := range servers {
		srvByID[servers[i].ID] = &servers[i]
		for _, z := range servers[i].Zones {
			allZones[dns.FQDN(z.Name)] = true
		}
	}
	rep.Domain = ParentDomain(routers, servers)

	type key struct {
		router  int64
		network string
	}
	byNet := map[key]*Assignment{}
	for i := range assignments {
		byNet[key{assignments[i].RouterID, assignments[i].NetworkID}] = &assignments[i]
	}
	// zone -> network labels using it, per server
	type zkey struct {
		server int64
		zone   string
	}
	users := map[zkey][]string{}
	seen := map[key]bool{}
	for _, r := range routers {
		rep.Routers = append(rep.Routers, RouterInfo{ID: r.ID, Name: r.Name, CanSetDomain: r.CanSetDomain})
		for _, n := range r.Networks {
			if a := byNet[key{r.ID, n.ID}]; a != nil && Checked(n) {
				zk := zkey{a.ServerID, dns.FQDN(a.Zone)}
				users[zk] = append(users[zk], Label(n))
			}
		}
	}

	for _, r := range routers {
		nets := append([]inventory.Network(nil), r.Networks...)
		sort.SliceStable(nets, func(i, j int) bool { return nets[i].VLAN < nets[j].VLAN })
		for _, n := range nets {
			if !Checked(n) {
				continue
			}
			k := key{r.ID, n.ID}
			seen[k] = true
			row := Row{RouterID: r.ID, Router: r.Name, CanSetDomain: r.CanSetDomain, NetworkID: n.ID, Network: n.Name,
				VLAN: n.VLAN, Subnet: n.Subnet, Purpose: n.Purpose, FirewallZone: n.ZoneName, Issues: []Issue{}}
			if n.DNS != nil {
				row.DHCP, row.DHCPDomain = n.DNS.DHCP, n.DNS.Domain
			}
			row.ReverseZone = ReverseFor(n)
			a := byNet[k]
			add := func(code, sev, msg, fix string) {
				row.Issues = append(row.Issues, Issue{Code: code, Severity: sev, Message: msg, Fix: fix})
			}
			if a == nil {
				row.Suggested = Suggest(n, rep.Domain, allZones)
				fix := ""
				if row.Suggested != "" {
					fix = "Assign " + row.Suggested
					if !allZones[row.Suggested] {
						fix = "Create " + row.Suggested + " and assign it"
					}
				}
				if isGuest(n) {
					row.Status = StatusSkip
				} else {
					add(IssueNoZone, StatusWarn, "No DNS zone is assigned to "+Label(n)+".", fix)
				}
				finish(&row)
				rep.Rows = append(rep.Rows, row)
				continue
			}
			zone := dns.FQDN(a.Zone)
			row.AssignmentID, row.Zone, row.ServerID = a.ID, zone, a.ServerID
			srv := srvByID[a.ServerID]
			switch {
			case srv == nil:
				add(IssueServerGone, StatusFail, "The DNS server that held "+zone+" is no longer connected.", "Assign a zone on a connected DNS server")
			case srv.Error != "":
				row.Server = srv.Name
				add(IssueServerError, StatusUnknown, "Can't read the zones on "+srv.Name+": "+srv.Error, "Check the DNS server connection in Settings")
			default:
				row.Server = srv.Name
				for _, z := range srv.Zones {
					if dns.FQDN(z.Name) == zone {
						row.ZoneFound = true
					}
				}
				if !row.ZoneFound {
					add(IssueZoneMissing, StatusFail, zone+" does not exist on "+srv.Name+".", "Create "+zone+" on "+srv.Name)
				}
				if row.ReverseZone != "" {
					row.ReverseFound = dns.BestZone(row.ReverseZone, srv.Zones) != ""
					if !row.ReverseFound {
						add(IssueNoReverse, StatusWarn, "No reverse zone on "+srv.Name+" covers "+n.Subnet+", so NCC can't add PTR records for "+Label(n)+".",
							"Create "+row.ReverseZone)
					}
				}
			}
			// The zone's first label names another network on this router, not this one.
			if rep.Domain == "" || zone != rep.Domain {
				label := strings.SplitN(zone, ".", 2)[0]
				mine := tokens(n)
				if !mine[label] {
					for _, o := range r.Networks {
						if o.ID != n.ID && Checked(o) && tokens(o)[label] {
							fix := "Assign " + Label(n) + " its own zone"
							if sg := Suggest(n, rep.Domain, allZones); sg != "" && sg != zone {
								fix += ", e.g. " + sg
							}
							add(IssueNameMismatch, StatusWarn, zone+" looks like the zone for "+Label(o)+", but it is assigned to "+Label(n)+".", fix)
							break
						}
					}
				}
			}
			if u := users[zkey{a.ServerID, zone}]; len(u) > 1 {
				add(IssueSharedZone, StatusWarn, zone+" is assigned to "+strings.Join(u, ", ")+"; each VLAN should have its own zone.", "")
			}
			if row.DHCP && n.Purpose != "vlan-only" {
				want := strings.TrimSuffix(zone, ".")
				switch {
				case row.DHCPDomain == "":
					add(IssueDHCPDomainUnset, StatusWarn, "The router hands out no domain name on "+Label(n)+", so its clients can't use short names in "+zone+".",
						"Set the network's domain name to "+want)
				case !strings.EqualFold(row.DHCPDomain, want):
					add(IssueDHCPDomainOther, StatusWarn, "The router hands out "+row.DHCPDomain+" on "+Label(n)+", not "+want+".",
						"Set the network's domain name to "+want)
				}
			}
			finish(&row)
			rep.Rows = append(rep.Rows, row)
		}
	}
	for _, a := range assignments {
		if !seen[key{a.RouterID, a.NetworkID}] {
			rep.Orphans = append(rep.Orphans, a)
		}
	}

	for _, s := range servers {
		for _, z := range s.Zones {
			name := dns.FQDN(z.Name)
			u := users[zkey{s.ID, name}]
			if u == nil {
				u = []string{}
			}
			rep.Zones = append(rep.Zones, ZoneUse{ServerID: s.ID, Server: s.Name, Zone: name, Kind: z.Kind,
				Reverse: strings.HasSuffix(name, ".arpa."), Parent: dns.ParentZone(name, s.Zones), Networks: u})
		}
	}
	sort.SliceStable(rep.Zones, func(i, j int) bool {
		if rep.Zones[i].Reverse != rep.Zones[j].Reverse {
			return !rep.Zones[i].Reverse
		}
		return reverseName(rep.Zones[i].Zone) < reverseName(rep.Zones[j].Zone)
	})

	worst, counts := "", map[string]int{}
	for _, r := range rep.Rows {
		counts[r.Status]++
		if worst == "" || rank[r.Status] > rank[worst] {
			worst = r.Status
		}
	}
	if len(rep.Orphans) > 0 {
		worst = StatusFail
	}
	rep.Status = worst
	rep.Summary = summary(rep, counts)
	return rep
}

// reverseName sorts subdomains under their parent: "iot.corp.lan." -> "lan.corp.iot".
func reverseName(z string) string {
	l := strings.Split(strings.TrimSuffix(z, "."), ".")
	for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 {
		l[i], l[j] = l[j], l[i]
	}
	return strings.Join(l, ".")
}

func finish(r *Row) {
	if r.Status != "" {
		return
	}
	r.Status = StatusPass
	for _, is := range r.Issues {
		if rank[is.Severity] > rank[r.Status] {
			r.Status = is.Severity
		}
	}
}

func summary(rep Report, counts map[string]int) string {
	if len(rep.Rows) == 0 {
		return "No router networks yet. Add a router in Settings and NCC will list its VLANs here."
	}
	if len(rep.Servers) == 0 {
		return "No DNS server is connected. Add one in Settings to create zones for your VLANs."
	}
	assigned := 0
	for _, r := range rep.Rows {
		if r.Zone != "" {
			assigned++
		}
	}
	problems := counts[StatusFail] + counts[StatusWarn] + counts[StatusUnknown]
	s := fmt.Sprintf("%d of %d networks have a DNS zone", assigned, len(rep.Rows))
	switch {
	case problems == 0 && len(rep.Orphans) == 0:
		return s + ", and every assigned zone checks out."
	case len(rep.Orphans) > 0:
		return fmt.Sprintf("%s; %d need attention and %d assignment(s) point at networks that no longer exist.", s, problems, len(rep.Orphans))
	default:
		return fmt.Sprintf("%s; %d need attention.", s, problems)
	}
}
