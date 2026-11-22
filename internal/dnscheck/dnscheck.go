// Package dnscheck checks the DNS chain of the network: the router hands out the internal
// DNS server to its DHCP clients, and the internal DNS server forwards internet queries to
// the internet provider's (ISP's) DNS servers.
//
//	clients ──DHCP DNS──► internal resolver ──forwarders──► ISP resolvers
//
// Evaluate is pure: the poller and API gather what the routers and DNS servers report, and
// Evaluate turns that into pass/fail checks phrased for a person, each with what was
// expected, what is configured and how to fix it.
package dnscheck

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/dertown/network-control-centre/internal/dns"
	inv "github.com/dertown/network-control-centre/internal/inventory"
)

// Check statuses, best to worst.
const (
	Pass    = "pass"
	Skip    = "skip"    // not checked on purpose (guest network, no DHCP)
	Unknown = "unknown" // NCC can't tell: something to set up
	Warn    = "warn"    // works, but not as intended
	Fail    = "fail"
)

var rank = map[string]int{Pass: 0, Skip: 0, Unknown: 1, Warn: 2, Fail: 3}

// Check kinds.
const (
	KindDHCP       = "dhcp"       // a router network hands out the internal resolver
	KindForwarders = "forwarders" // the internal resolver forwards to the ISP
	KindSetup      = "setup"      // NCC is missing something it needs to check
	KindLive       = "live"       // a real lookup sent to the internal DNS server
)

// Check is one finding.
type Check struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	// Subject is what was checked: "Dream Router 7 · IoT" or a DNS server's name.
	Subject  string `json:"subject"`
	Title    string `json:"title"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Detail   string `json:"detail,omitempty"`
	// Fix says where and how to fix it; FixURL opens the device's own admin page when known.
	Fix    string `json:"fix,omitempty"`
	FixURL string `json:"fix_url,omitempty"`
	// Action names a fix NCC can carry out itself (after a preview), e.g. ActionRecursorAPI;
	// Target is the connection it applies to.
	Action string `json:"action,omitempty"`
	Target int64  `json:"target,omitempty"`
}

// ActionRecursorAPI finds or turns on the PowerDNS Recursor's API so NCC can read its
// forwarders (the "Fix" button on a "can't read the forwarders" check).
const ActionRecursorAPI = "recursor-api"

// Report is the whole check.
type Report struct {
	// Status is the worst check's status, or "" when there is nothing to check (no DNS server).
	Status  string `json:"status"`
	Summary string `json:"summary"`
	// Resolvers are the internal DNS server addresses clients should be handed.
	Resolvers []string `json:"resolvers"`
	// ISP are the internet provider's DNS servers, and ISPSource where NCC learned them:
	// "router" (the router's WAN DNS on auto) or "setting" (typed into Settings).
	ISP       []string `json:"isp"`
	ISPSource string   `json:"isp_source,omitempty"`
	Checks    []Check  `json:"checks"`
}

// Router is one router connection and the networks its latest snapshot reported.
type Router struct {
	Name     string
	Kind     string // driver kind, e.g. "unifi"
	URL      string // the router's admin address, for the fix link
	Networks []inv.Network
}

// Resolver is one internal DNS server connection.
type Resolver struct {
	ID   int64
	Name string
	// Addresses are what clients should be handed as DNS (the resolver's IPs).
	Addresses []string
	// ISP overrides the ISP's DNS servers when typed into Settings.
	ISP []string
	// Forwarding is what the resolver forwards internet queries to; nil when unread.
	Forwarding *dns.Forwarding
	// NoResolver is set when the connection has nothing NCC can read forwarders from.
	NoResolver bool
	// Error is why reading the forwarders failed.
	Error string
	// Live are real lookups sent to each of Addresses.
	Live []Live
}

// Evaluate runs every check.
func Evaluate(routers []Router, servers []Resolver) Report {
	r := Report{Resolvers: []string{}, ISP: []string{}, Checks: []Check{}}
	if len(servers) == 0 {
		r.Summary = "Add your internal DNS server in Settings to check the router's DNS setup."
		return r
	}

	resolvers := set{}
	for _, s := range servers {
		resolvers.add(s.Addresses...)
	}
	r.Resolvers = resolvers.list()
	if len(r.Resolvers) == 0 {
		r.Checks = append(r.Checks, Check{
			ID: "setup-resolver", Kind: KindSetup, Status: Unknown, Subject: names(servers),
			Title:  "NCC doesn't know your internal DNS server's address",
			Detail: "Without it NCC can't tell whether the router hands it out.",
			Fix:    "In Settings, edit the DNS server connection and fill in “Address clients use”.",
			FixURL: "#/settings",
		})
	}

	// ISP servers: typed in wins, otherwise what the router learned from the provider.
	isp := set{}
	var manualWAN []string
	for _, s := range servers {
		isp.add(s.ISP...)
	}
	if len(isp) > 0 {
		r.ISPSource = "setting"
	} else {
		for _, rt := range routers {
			for _, n := range rt.Networks {
				if n.Purpose != "wan" || n.DNS == nil {
					continue
				}
				if n.DNS.UpstreamAuto {
					isp.add(n.DNS.Upstream...)
				} else if len(n.DNS.Upstream) > 0 {
					manualWAN = append(manualWAN, fmt.Sprintf("%s %s uses %s", rt.Name, n.Name, strings.Join(n.DNS.Upstream, ", ")))
				}
			}
		}
		if len(isp) > 0 {
			r.ISPSource = "router"
		}
	}
	r.ISP = isp.list()

	gateways := set{}
	for _, rt := range routers {
		r.Checks = append(r.Checks, routerChecks(rt, resolvers, &gateways)...)
	}
	for _, s := range servers {
		r.Checks = append(r.Checks, liveChecks(s)...)
		r.Checks = append(r.Checks, forwarderCheck(s, isp, r.ISPSource, manualWAN, resolvers, gateways))
	}

	worst := Pass
	count := map[string]int{}
	for _, c := range r.Checks {
		count[c.Status]++
		if rank[c.Status] > rank[worst] {
			worst = c.Status
		}
	}
	r.Status = worst
	switch worst {
	case Pass:
		r.Summary = fmt.Sprintf("Clients get %s, which forwards internet names to your ISP (%s).", strings.Join(r.Resolvers, ", "), strings.Join(r.ISP, ", "))
	case Fail:
		r.Summary = plural(count[Fail], "problem")
		if count[Warn] > 0 {
			r.Summary += " and " + plural(count[Warn], "warning")
		}
		r.Summary += " in the DNS setup."
	case Warn:
		r.Summary = fmt.Sprintf("%s in the DNS setup, nothing broken.", plural(count[Warn], "thing")+" to look at")
	default:
		r.Summary = "NCC can't check everything yet; see what to set up below."
	}
	return r
}

// liveChecks reports the real lookups sent to one internal DNS server's addresses.
func liveChecks(s Resolver) []Check {
	var out []Check
	for _, l := range s.Live {
		c := Check{ID: fmt.Sprintf("live-%d-%s", s.ID, l.Server), Kind: KindLive, Subject: s.Name + " · " + l.Server,
			Expected: "answers " + l.Internet}
		if l.Internal != "" {
			c.Expected += " and " + l.Internal
		}
		c.Actual = l.Internet + ": " + l.InternetResult
		if l.Internal != "" {
			c.Actual += "; " + l.Internal + ": " + l.InternalResult
		}
		internalOK := l.Internal == "" || l.InternalOK
		switch {
		case l.InternetOK && internalOK:
			c.Status = Pass
			c.Title = l.Server + " answers internet and internal names"
			if l.Internal == "" {
				c.Title = l.Server + " answers internet names"
			}
		case l.InternetResult == "no answer" || l.InternetResult == "port 53 closed":
			c.Status = Fail
			c.Title = l.Server + " doesn't answer DNS queries"
			c.Detail = "NCC sent it a lookup and got " + l.InternetResult + ". Clients handed this server wait for it to time out before trying the next one."
			c.Fix = "Check the DNS service is running on " + l.Server + " and that its firewall allows port 53 from your networks."
		case !l.InternetOK && l.InternetResult == "REFUSED" && l.InternalOK:
			c.Status = Fail
			c.Title = l.Server + " refuses internet names: it is an authoritative server, not a resolver"
			c.Detail = fmt.Sprintf("It answers %s, but refuses to look up %s. Clients that ask it first are refused, then try the next DNS server they were given (slower), and devices with no fallback can't reach the internet by name. Internal names only work through it while it is asked first.", l.Internal, l.Internet)
			c.Fix = "Run a resolver on " + l.Server + ": PowerDNS Recursor on port 53, sending " + l.Internal + " to the authoritative server and everything else to your ISP. Press Fix to have NCC set it up (you see every change before it is made)."
			c.Action, c.Target = ActionRecursorAPI, s.ID
		case !l.InternetOK:
			c.Status = Fail
			c.Title = l.Server + " can't look up internet names"
			c.Detail = fmt.Sprintf("Asking it for %s gave %s. Clients that use it can't reach the internet by name until they fall back to another server.", l.Internet, l.InternetResult)
			c.Fix = "Check the resolver's forwarders and that it can reach the internet (outbound port 53)."
			if l.InternetResult == "REFUSED" {
				c.Fix = "The server refuses recursive lookups: allow your networks in its allow-from setting, or run a resolver on it. Press Fix to have NCC look."
				c.Action, c.Target = ActionRecursorAPI, s.ID
			}
		default:
			c.Status = Fail
			c.Title = l.Server + " doesn't answer for " + l.Internal
			c.Detail = fmt.Sprintf("Internet names work, but asking for %s gave %s, so internal names won't resolve for clients using it.", l.Internal, l.InternalResult)
			c.Fix = "Make the resolver send " + l.Internal + " to the authoritative server (PowerDNS Recursor: forward-zones=" + l.Internal + "=<authoritative server>)."
		}
		out = append(out, c)
	}
	return out
}

// routerChecks checks that every LAN of one router hands out the internal resolver.
func routerChecks(rt Router, resolvers set, gateways *set) []Check {
	var out []Check
	var upstream []string
	for _, n := range rt.Networks {
		if n.Purpose == "wan" && n.DNS != nil {
			upstream = append(upstream, n.DNS.Upstream...)
		}
	}
	seen := false
	for _, n := range rt.Networks {
		if n.DNS == nil || n.Purpose == "wan" {
			continue
		}
		seen = true
		if n.DNS.Gateway != "" {
			gateways.add(n.DNS.Gateway)
		}
		c := Check{ID: "dhcp-" + rt.Name + "-" + n.ID, Kind: KindDHCP, Subject: rt.Name + " · " + n.Name,
			Expected: expectedHanded(resolvers)}
		handed := n.DNS.Servers
		switch {
		case n.Zone == "hotspot" || n.Purpose == "guest":
			c.Status, c.Title = Skip, n.Name+" is a guest network"
			c.Detail = "Guest networks are left on the router's own DNS: guests don't need internal names."
			c.Expected = ""
			c.Actual = describeHanded(n.DNS, upstream)
		case !n.DNS.DHCP:
			c.Status, c.Title = Skip, "The router doesn't hand out addresses on "+n.Name
			c.Detail = "DHCP is off on this network, so whatever serves addresses there sets the DNS server."
			c.Expected = ""
		case len(resolvers) == 0:
			c.Status, c.Title = Unknown, n.Name+": can't compare without the internal DNS server's address"
			c.Actual = describeHanded(n.DNS, upstream)
		case len(handed) == 0:
			c.Status = Fail
			c.Title = n.Name + " clients bypass the internal DNS server"
			c.Actual = describeHanded(n.DNS, upstream)
			c.Detail = "DHCP hands out the router itself, which sends every query straight to its WAN DNS. Internal names won't resolve on this network."
		default:
			// Compare addresses only: "192.168.1.70", "192.168.1.70:53" and "192.168.1.70#53"
			// are the same server. Order matters: clients ask the first server and only move to
			// the next ones when it doesn't answer.
			var internal, other []string
			for _, h := range handed {
				if resolvers.has(h) {
					internal = append(internal, norm(h))
				} else {
					other = append(other, norm(h))
				}
			}
			firstInternal := resolvers.has(handed[0])
			c.Actual = describeOrder(handed, resolvers)
			switch {
			case len(internal) == 0:
				c.Status = Fail
				c.Title = n.Name + " clients don't use the internal DNS server"
				c.Detail = "DHCP hands out " + strings.Join(other, ", ") + ", none of which is the internal DNS server. Internal names won't resolve on this network."
			case !firstInternal:
				c.Status = Warn
				c.Title = n.Name + " clients ask " + norm(handed[0]) + " before the internal DNS server"
				c.Detail = fmt.Sprintf("The internal server is handed out, but not first. Most devices ask the first server and only fall back when it doesn't answer, so they will mostly use %s and internal names won't resolve for them. Put %s first.", norm(handed[0]), internal[0])
			case len(other) > 0:
				c.Status = Pass
				c.Title = n.Name + " clients use the internal DNS server first"
				c.Detail = fmt.Sprintf("%s is a fallback for when the internal server doesn't answer, which keeps the internet working if it is down. While a device is using the fallback, internal names won't resolve for it.", strings.Join(other, ", "))
			default:
				c.Status = Pass
				c.Title = n.Name + " clients use the internal DNS server"
			}
		}
		if c.Status == Fail || c.Status == Warn {
			c.Fix, c.FixURL = dhcpFix(rt, n.Name, resolvers.list())
		}
		out = append(out, c)
	}
	if !seen {
		out = append(out, Check{
			ID: "dhcp-" + rt.Name, Kind: KindDHCP, Status: Unknown, Subject: rt.Name,
			Title:  "Can't read the DHCP settings of " + rt.Name,
			Detail: "The router didn't report its networks' DHCP settings. If it was added recently, wait for the next poll.",
			FixURL: "#/settings",
		})
	}
	return out
}

// expectedHanded is what a LAN should hand out: an internal server first; public servers
// after it are accepted as a fallback.
func expectedHanded(resolvers set) string {
	if len(resolvers) == 0 {
		return ""
	}
	return strings.Join(resolvers.list(), " or ") + " first"
}

// describeOrder lists the handed-out servers in order, marking which are internal.
func describeOrder(handed []string, resolvers set) string {
	parts := make([]string, 0, len(handed))
	for _, h := range handed {
		if resolvers.has(h) {
			parts = append(parts, norm(h)+" (internal)")
		} else {
			parts = append(parts, norm(h))
		}
	}
	return strings.Join(parts, ", ")
}

func describeHanded(d *inv.NetworkDNS, upstream []string) string {
	if len(d.Servers) > 0 {
		out := make([]string, len(d.Servers))
		for i, h := range d.Servers {
			out[i] = norm(h)
		}
		return strings.Join(out, ", ")
	}
	s := "the router itself"
	if d.Gateway != "" {
		s += " (" + d.Gateway + ")"
	}
	if len(upstream) > 0 {
		s += ", which asks " + strings.Join(upstream, ", ")
	}
	return s
}

func dhcpFix(rt Router, network string, resolvers []string) (string, string) {
	want := strings.Join(resolvers, " and ")
	if rt.Kind == "unifi" {
		return fmt.Sprintf("In UniFi Network open Settings → Networks → %s → DHCP Service Management, set DNS Server to manual and enter %s as the first DNS server (UniFi takes addresses only, no port). Public servers such as 1.1.1.1 may follow as a fallback.", network, want), rt.URL
	}
	return fmt.Sprintf("In %s's DHCP settings for %s, make %s the first DNS server handed to clients (address only, no port). Public servers may follow as a fallback.", rt.Name, network, want), rt.URL
}

// forwarderCheck checks that one internal resolver forwards internet queries to the ISP.
func forwarderCheck(s Resolver, isp set, ispSource string, manualWAN []string, resolvers, gateways set) Check {
	c := Check{ID: fmt.Sprintf("fwd-%d", s.ID), Kind: KindForwarders, Subject: s.Name}
	if len(isp) > 0 {
		c.Expected = strings.Join(isp.list(), ", ")
		if ispSource == "router" {
			c.Expected += " (from the router's WAN)"
		}
	}
	recurseFix := fmt.Sprintf("In recursor.conf set forward-zones-recurse=.=%s (Recursor 5.x YAML: recursor.forward_zones_recurse with zone \".\"), then restart the Recursor.",
		strings.Join(orDefault(isp.list(), []string{"<ISP DNS 1>", "<ISP DNS 2>"}), ";"))
	switch {
	case s.NoResolver:
		c.Status = Unknown
		c.Title = "Can't see where " + s.Name + " forwards internet queries"
		c.Detail = "This connection is the authoritative server, which never forwards; the resolver clients talk to is a separate PowerDNS Recursor, and NCC needs its API URL."
		c.Fix, c.FixURL = "Press Fix to have NCC find the Recursor's API (and turn it on if it is off), or in Settings fill in “Recursor API URL” on "+s.Name+" (webserver-address and webserver-port in recursor.conf, e.g. http://ns1:8082).", "#/settings"
		c.Action, c.Target = ActionRecursorAPI, s.ID
		return c
	case s.Error != "":
		c.Status = Unknown
		c.Title = "Can't read the forwarders of " + s.Name
		c.Detail, c.Fix = explainReadError(s.Error)
		c.FixURL = "#/settings"
		c.Action, c.Target = ActionRecursorAPI, s.ID
		return c
	case s.Forwarding == nil:
		c.Status = Unknown
		c.Title = "Waiting for the first check of " + s.Name
		return c
	}
	fwd := s.Forwarding.Servers
	c.Actual = strings.Join(fwd, ", ")
	if len(fwd) == 0 {
		c.Status = Fail
		c.Title = s.Name + " doesn't forward internet queries to your ISP"
		c.Actual = "none: it looks names up from the root servers itself"
		c.Detail = s.Forwarding.Source + " has no forward zone for “.”, so it resolves internet names on its own instead of asking your ISP's DNS servers."
		c.Fix = recurseFix
		return c
	}
	var viaRouter, loop, other []string
	for _, f := range fwd {
		switch {
		case resolvers.has(f):
			loop = append(loop, f)
		case gateways.has(f):
			viaRouter = append(viaRouter, f)
		case !isp.has(f):
			other = append(other, f)
		}
	}
	switch {
	case len(loop) > 0:
		c.Status = Fail
		c.Title = s.Name + " forwards internet queries to itself"
		c.Detail = strings.Join(loop, ", ") + " is an internal DNS server: queries go round in a loop and internet names fail."
		c.Fix = recurseFix
	case !s.Forwarding.RecursionDesired:
		c.Status = Fail
		c.Title = s.Name + " forwards without asking for recursion"
		c.Detail = "It uses forward-zones for “.”, which sends queries without the recursion flag. ISP resolvers refuse those, so internet names fail."
		c.Fix = recurseFix
	case len(viaRouter) > 0:
		c.Status = Warn
		c.Title = s.Name + " forwards internet queries to the router, not the ISP"
		c.Detail = "It works, because the router asks the ISP, but it adds a hop and all DNS stops when the router's resolver does. Forward to the ISP's servers directly."
		c.Fix = recurseFix
	case len(isp) == 0:
		c.Status = Warn
		c.Title = "Can't confirm " + s.Name + " forwards to your ISP"
		c.Expected = "your ISP's DNS servers"
		c.Detail = "NCC doesn't know your ISP's DNS servers."
		if len(manualWAN) > 0 {
			c.Detail += " The router's WAN DNS is set by hand (" + strings.Join(manualWAN, "; ") + "), so it doesn't show what the ISP provides."
		}
		c.Fix, c.FixURL = "In Settings, edit "+s.Name+" and fill in “ISP DNS servers” (from your ISP or the router's WAN status page).", "#/settings"
	case len(other) > 0:
		// Works (public resolvers answer), just not what was asked for: a warning, not a failure.
		c.Status = Warn
		c.Title = s.Name + " forwards internet queries to servers that aren't your ISP's"
		c.Detail = strings.Join(other, ", ") + " is not one of your ISP's DNS servers. Internet names still resolve, but not through your ISP as intended."
		c.Fix = recurseFix
	default:
		c.Status = Pass
		c.Title = s.Name + " forwards internet queries to your ISP"
		c.Detail = "Read from " + s.Forwarding.Source + "."
	}
	return c
}

// explainReadError turns the error from reading the Recursor's API into what it means for a
// person, and what to do about it.
func explainReadError(e string) (detail, fix string) {
	l := strings.ToLower(e)
	where := ""
	if u := urlIn(e); u != "" {
		where = " at " + u
	}
	switch {
	case strings.Contains(l, "connection refused"):
		return "Nothing answers" + where + ": the Recursor's web server is off, listens on another port, or only listens on 127.0.0.1. (" + e + ")",
			"Press Fix: NCC looks for the Recursor's API on the usual ports and, if it is off, shows the exact recursor.conf changes to turn it on over SSH before making them."
	case strings.Contains(l, "rejected"), strings.Contains(l, "401"), strings.Contains(l, "403"):
		return "The Recursor answered but refused NCC's API key. (" + e + ")",
			"Press Fix to read the Recursor's api-key over SSH, or in Settings enter the api-key from recursor.conf as the Recursor API key."
	case strings.Contains(l, "timeout"), strings.Contains(l, "deadline exceeded"), strings.Contains(l, "no route to host"):
		return "No answer" + where + " in time: a firewall on the DNS server or between it and NCC is dropping the connection, or the address is wrong. (" + e + ")",
			"Press Fix to check the address and open the port on the server's firewall, or check the Recursor API URL in Settings."
	case strings.Contains(l, "no such host"):
		return "NCC can't look up the Recursor API URL's host name. (" + e + ")", "Use the server's IP address in the Recursor API URL, or press Fix to find it."
	case strings.Contains(l, "404"):
		return "Something answers" + where + " but it isn't the Recursor's API (wrong port, or the authoritative server's API). (" + e + ")",
			"Press Fix to find the Recursor's API port."
	}
	return e, "Press Fix to find the Recursor's API and check it, or check the Recursor API URL and key in Settings."
}

// urlIn returns the scheme://host:port of the first URL in s, or "".
func urlIn(s string) string {
	i := strings.Index(s, "http://")
	if j := strings.Index(s, "https://"); i < 0 || (j >= 0 && j < i) {
		i = j
	}
	if i < 0 {
		return ""
	}
	u := s[i:]
	if k := strings.IndexAny(u, " \"\n"); k >= 0 {
		u = u[:k]
	}
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		return p.Scheme + "://" + p.Host
	}
	return ""
}

// set is a set of IP addresses compared in canonical form.
type set map[string]struct{}

// norm is the canonical form of a DNS server address. Only the IP counts: a port
// ("192.168.1.70:53", "[2001:db8::1]:53", PowerDNS's "192.168.1.70#53"), a URL scheme and
// path are dropped, so the same server written differently compares equal.
func norm(a string) string {
	a = strings.TrimSpace(a)
	if p, err := netip.ParseAddr(a); err == nil {
		return p.Unmap().String()
	}
	h := a
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, "#"); i > 0 {
		h = h[:i]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	if p, err := netip.ParseAddr(h); err == nil {
		return p.Unmap().String()
	}
	return strings.ToLower(h)
}

func (s set) add(v ...string) {
	for _, x := range v {
		if x = norm(x); x != "" {
			s[x] = struct{}{}
		}
	}
}

func (s set) has(v string) bool { _, ok := s[norm(v)]; return ok }

func (s set) list() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		a, ea := netip.ParseAddr(out[i])
		b, eb := netip.ParseAddr(out[j])
		if ea == nil && eb == nil {
			return a.Less(b)
		}
		return out[i] < out[j]
	})
	return out
}

func names(servers []Resolver) string {
	var n []string
	for _, s := range servers {
		n = append(n, s.Name)
	}
	return strings.Join(n, ", ")
}

func orDefault(v, d []string) []string {
	if len(v) == 0 {
		return d
	}
	return v
}

func plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %ss", n, one)
}

// SplitList splits a comma, space or semicolon separated list of addresses.
func SplitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' })
}

// HostAddresses returns the IP addresses of the host in a URL or host[:port] string,
// looking a name up with lookup. It returns nil when there is no host.
func HostAddresses(address string, lookup func(string) ([]string, error)) []string {
	h := strings.TrimSpace(address)
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	if h == "" {
		return nil
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return []string{h}
	}
	if lookup == nil {
		return nil
	}
	addrs, err := lookup(h)
	if err != nil {
		return nil
	}
	return addrs
}
