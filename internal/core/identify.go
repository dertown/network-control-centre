package core

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	hv "github.com/dertown/network-control-centre/internal/hypervisor"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/iot"
)

// Roles a map node can be identified as. A node's Kind is what the router reports (an
// unmanaged switch it inferred, an LLDP neighbour it can't name); its role is what NCC
// worked out it really is from everything else it knows.
const (
	RoleSwitch     = "switch"
	RoleRouter     = "router"
	RoleAP         = "ap"
	RoleHypervisor = "hypervisor"
	RoleNAS        = "nas"
	RoleServer     = "server"
	RoleVM         = "vm"
	RoleContainer  = "container"
	RoleDNS        = "dns"
	RoleIoT        = "iot"
	RoleComputer   = "computer"
	RoleOther      = "other"
)

// Roles lists the roles in the order the map's "what is this" picker shows them.
var Roles = []string{RoleSwitch, RoleRouter, RoleAP, RoleHypervisor, RoleNAS, RoleServer, RoleVM, RoleContainer,
	RoleDNS, RoleIoT, RoleComputer, RoleOther}

var roleWhat = map[string]string{
	RoleSwitch: "Switch", RoleRouter: "Router", RoleAP: "Access point", RoleHypervisor: "VM host", RoleNAS: "NAS",
	RoleServer: "Server", RoleVM: "Virtual machine", RoleContainer: "Container", RoleDNS: "DNS server",
	RoleIoT: "IoT device", RoleComputer: "Computer", RoleOther: "Other device",
}

// ValidRole reports whether r is one of Roles.
func ValidRole(r string) bool { _, ok := roleWhat[r]; return ok }

// Identity sources: how the identity was arrived at.
const (
	IdentityAuto      = "auto"      // NCC's own correlation
	IdentityConfirmed = "confirmed" // a person confirmed NCC's guess
	IdentityManual    = "manual"    // a person set it
)

// Identity is what NCC found a map node really is, and why.
type Identity struct {
	Role string `json:"role"`
	Name string `json:"name,omitempty"`
	// What says it in words: "Proxmox VE host", "QNAP NAS", "Container on pve1".
	What string `json:"what"`
	// Confidence is high, medium or low for NCC's guesses, and manual for a person's.
	Confidence string     `json:"confidence"`
	Score      int        `json:"score"` // 0-100
	Evidence   []Evidence `json:"evidence,omitempty"`
	Source     string     `json:"source"` // auto | confirmed | manual
	By         string     `json:"by,omitempty"`
	At         *time.Time `json:"at,omitempty"`
	// Guess is NCC's own guess, kept when a person set something else.
	Guess *Identity `json:"guess,omitempty"`
	// Label is the name the network gave the node, when NCC or a person renamed it.
	Label string `json:"label,omitempty"`
	// Merged is the MAC of a client folded into this node: the host's own network port,
	// seen by the router as just another client behind the inferred switch.
	Merged string `json:"merged,omitempty"`
}

// Evidence is one fact behind an identity, and which NCC source it came from.
type Evidence struct {
	// Source is vm, hypervisor, storage, dns, connection, iot, mac, lldp, clients or name.
	Source string `json:"source"`
	Text   string `json:"text"`
}

// Related is what other parts of NCC know about a node: its VMs, storage, DNS names and
// the connections whose address it is.
type Related struct {
	Host        *RelHost    `json:"host,omitempty"`
	VMs         []RelVM     `json:"vms,omitempty"`
	VM          *RelVM      `json:"vm,omitempty"`
	Storage     *RelStorage `json:"storage,omitempty"`
	DNS         []RelDNS    `json:"dns,omitempty"`
	Connections []RelConn   `json:"connections,omitempty"`
	IoT         *RelIoT     `json:"iot,omitempty"`
}

// RelHost is a hypervisor host.
type RelHost struct {
	Name     string  `json:"name"`
	Platform string  `json:"platform"`
	Target   string  `json:"target"`
	Online   bool    `json:"online"`
	Version  string  `json:"version,omitempty"`
	CPUs     int     `json:"cpus,omitempty"`
	CPUUsage float64 `json:"cpu_usage"`
	MemBytes int64   `json:"mem_bytes,omitempty"`
	MemUsed  int64   `json:"mem_used,omitempty"`
	VMs      int     `json:"vms"`
	Running  int     `json:"running"`
}

// RelVM is a virtual machine or container.
type RelVM struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	State string   `json:"state"`
	Host  string   `json:"host"`
	IPs   []string `json:"ips,omitempty"`
	OS    string   `json:"os,omitempty"`
	CPUs  int      `json:"cpus,omitempty"`
	Mem   int64    `json:"mem_bytes,omitempty"`
}

// RelStorage is a NAS or file server NCC reads.
type RelStorage struct {
	TargetID int64  `json:"target_id"`
	Target   string `json:"target"`
	Vendor   string `json:"vendor"`
	Model    string `json:"model,omitempty"`
	Health   string `json:"health"`
	Volumes  int    `json:"volumes"`
	Shares   int    `json:"shares"`
	Used     int64  `json:"used"`
	Total    int64  `json:"total"`
	Alerts   int    `json:"alerts"`
}

// RelDNS is a DNS name for the node's address.
type RelDNS struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Server string `json:"server"`
}

// RelConn is an NCC connection whose address is this node.
type RelConn struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Category string `json:"category"`
}

// RelIoT is the node's IoT inventory entry.
type RelIoT struct {
	Type     string `json:"type"`
	Owner    string `json:"owner,omitempty"`
	Location string `json:"location,omitempty"`
}

// IdentityOverride is what a person said a node is.
type IdentityOverride struct {
	NodeID    string    `json:"node_id"`
	Role      string    `json:"role"`
	Name      string    `json:"name,omitempty"`
	Confirmed bool      `json:"confirmed"` // they accepted NCC's guess rather than typing their own
	By        string    `json:"by"`
	At        time.Time `json:"at"`
}

// Sources is everything besides the routers' snapshots that NCC can identify nodes from.
type Sources struct {
	Targets   []Target
	VMs       []hv.Inventory
	Storage   []StorageEntry
	IoT       []iot.Device
	DNS       []DNSName
	Overrides map[string]IdentityOverride
	// Resolve, when set, looks up connection addresses that are host names and not in any
	// DNS server NCC reads. It should answer from a cache and give up quickly.
	Resolve func(host string) []string
}

// Score thresholds.
const (
	matchMin   = 30 // below this a match is ignored
	scoreHigh  = 80
	scoreMed   = 50
	scoreMACs  = 60
	scoreIP    = 40
	scoreName  = 25
	penaltyMAC = 45 // a VM whose MACs are known but none is this one: the address was reused
)

func confidence(score int) string {
	switch {
	case score >= scoreHigh:
		return "high"
	case score >= scoreMed:
		return "medium"
	}
	return "low"
}

// fact is one thing NCC knows from a source other than the router: a VM, a hypervisor host,
// a NAS, a connection, an IoT entry. Nodes are matched to facts by MAC, address and name.
type fact struct {
	key, role, name, what, source string
	why                           string            // "VM 'ncc' on pve1 (Proxmox VE connection 'homelab')"
	ipVia                         map[string]string // addresses learnt from DNS, and what DNS said
	virtual                       bool
	macs, ips, names              map[string]bool
	host                          *fact // a VM's host
	platform                      string
	fill                          func(r *Related)
}

type identifier struct {
	facts       []*fact
	byMAC, byIP map[string][]*fact
	byName      map[string][]*fact
	dnsByIP     map[string][]DNSName
	dnsByName   map[string][]string // short and full name -> addresses
	conns       map[string][]Target // address -> connections at it
	hostOf      map[string]*fact
}

var platformName = map[string]string{"proxmox": "Proxmox VE", "vmware": "VMware", "hyperv": "Hyper-V"}

// virtualOUIs are MAC prefixes hypervisors hand their VMs by default.
var virtualOUIs = []struct{ prefix, platform string }{
	{"bc:24:11", "Proxmox VE"}, {"52:54:00", "QEMU/KVM"}, {"00:50:56", "VMware"}, {"00:0c:29", "VMware"},
	{"00:05:69", "VMware"}, {"00:15:5d", "Hyper-V"}, {"00:16:3e", "Xen"}, {"02:11:32", "Synology VMM"},
}

func virtualOUI(mac string) string {
	for _, o := range virtualOUIs {
		if strings.HasPrefix(mac, o.prefix) {
			return o.platform
		}
	}
	return ""
}

// switchVendors make switches; a client from one of them behind a shared port is a hint
// that the "unmanaged switch" is that device.
var switchVendors = []string{"netgear", "tp-link", "tplink", "d-link", "dlink", "zyxel", "cisco", "aruba", "hewlett packard enterprise",
	"mikrotik", "routerboard", "juniper", "extreme networks", "allied telesis", "edgecore", "ubiquiti", "trendnet", "linksys"}

var switchName = regexp.MustCompile(`(^|[-_.])(sw|usw|switch|poe-?sw)([-_.0-9]|$)|switch`)

var macLike = regexp.MustCompile(`^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$`)

// shortName is the host part of a name, lower case: "PVE1.home.lan" -> "pve1". Addresses,
// MACs and generic names give "".
func shortName(s string) string {
	s = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
	if s == "" || macLike.MatchString(s) {
		return ""
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return ""
	}
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	s = strings.Trim(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		if r == ' ' || r == '_' {
			return '-'
		}
		return -1
	}, s), "-")
	switch s {
	case "", "localhost", "unknown", "host", "device", "client":
		return ""
	}
	if len(s) < 2 {
		return ""
	}
	return s
}

// hostOfAddress takes the host out of a connection address: a URL, host:port or a bare host.
func hostOfAddress(a string) string {
	a = strings.TrimSpace(a)
	if strings.Contains(a, "://") {
		if u, err := url.Parse(a); err == nil {
			return u.Hostname()
		}
	}
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	return strings.Trim(a, "[]")
}

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		if x != "" {
			m[x] = true
		}
	}
	return m
}

func normIP(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

func newIdentifier(src Sources) *identifier {
	id := &identifier{byMAC: map[string][]*fact{}, byIP: map[string][]*fact{}, byName: map[string][]*fact{},
		dnsByIP: map[string][]DNSName{}, dnsByName: map[string][]string{}, conns: map[string][]Target{}, hostOf: map[string]*fact{}}
	for _, d := range src.DNS {
		ip := normIP(d.IP)
		if ip == "" {
			continue
		}
		id.dnsByIP[ip] = append(id.dnsByIP[ip], d)
		for _, n := range []string{strings.ToLower(d.Name), shortName(d.Name)} {
			if n != "" && !contains(id.dnsByName[n], ip) {
				id.dnsByName[n] = append(id.dnsByName[n], ip)
			}
		}
	}
	targetByName := map[string]Target{}
	for _, t := range src.Targets {
		targetByName[t.Category+"/"+t.Name] = t
	}
	// address resolves a connection's address to IPs (via NCC's DNS servers first) and names
	address := func(t Target) (ips, names []string) {
		h := hostOfAddress(t.Address)
		if ip := normIP(h); ip != "" {
			return []string{ip}, nil
		}
		if h == "" {
			return nil, nil
		}
		names = []string{shortName(h)}
		ips = append(ips, id.dnsByName[strings.ToLower(h)]...)
		if len(ips) == 0 && src.Resolve != nil {
			for _, a := range src.Resolve(h) {
				if ip := normIP(a); ip != "" {
					ips = append(ips, ip)
				}
			}
		}
		return ips, names
	}
	for _, t := range src.Targets {
		if !t.Enabled {
			continue
		}
		ips, names := address(t)
		for _, ip := range ips {
			id.conns[ip] = append(id.conns[ip], t)
		}
		for _, n := range names {
			if n != "" {
				id.conns["name:"+n] = append(id.conns["name:"+n], t)
			}
		}
	}

	// hypervisor hosts and their VMs
	for i := range src.VMs {
		inv := &src.VMs[i]
		plat := platformName[inv.Platform]
		if plat == "" {
			plat = inv.Platform
		}
		t := targetByName[CategoryHypervisor+"/"+inv.Target]
		cips, cnames := address(t)
		running := map[string]int{}
		count := map[string]int{}
		for _, v := range inv.VMs {
			if v.Template {
				continue
			}
			count[v.Host]++
			if v.State == hv.StateRunning {
				running[v.Host]++
			}
		}
		for _, h := range inv.Hosts {
			h := h
			f := &fact{key: "host:" + inv.Target + "/" + h.Name, role: RoleHypervisor, name: h.Name, what: plat + " host",
				source: "hypervisor", platform: plat, macs: set(), ips: set(), names: set(shortName(h.Name)),
				why: fmt.Sprintf("%s host %s (connection '%s')", plat, h.Name, inv.Target)}
			for _, ip := range h.IPs {
				f.ips[normIP(ip)] = true
			}
			// a connection to a single host (Proxmox node, ESXi, Hyper-V) is that host's
			// address; vCenter's address is vCenter's, not a host's
			if len(inv.Hosts) == 1 && !(inv.Platform == "vmware" && strings.Contains(strings.ToLower(inv.Version), "vcenter")) {
				for _, ip := range cips {
					f.ips[ip] = true
				}
				for _, n := range cnames {
					if n != "" {
						f.names[n] = true
					}
				}
			}
			rh := &RelHost{Name: h.Name, Platform: plat, Target: inv.Target, Online: h.Online, Version: h.Version, CPUs: h.CPUs,
				CPUUsage: h.CPUUsage, MemBytes: h.MemBytes, MemUsed: h.MemUsed, VMs: count[h.Name], Running: running[h.Name]}
			vms := []RelVM{}
			for _, v := range inv.VMs {
				if v.Host == h.Name && !v.Template {
					vms = append(vms, relVM(v))
				}
			}
			f.fill = func(r *Related) { r.Host = rh; r.VMs = vms }
			id.add(f)
			id.hostOf[inv.Target+"/"+h.Name] = f
		}
		for _, v := range inv.VMs {
			if v.Template {
				continue
			}
			v := v
			host := id.hostOf[inv.Target+"/"+v.Host]
			role, kind, word := RoleVM, "VM", "VM"
			if v.Type == "lxc" {
				role, kind, word = RoleContainer, "Container", "container"
			}
			f := &fact{key: "vm:" + v.ID, role: role, name: v.Name, what: kind + " on " + v.Host, source: "vm", virtual: true,
				macs: set(), ips: set(), names: set(shortName(v.Name)), host: host, platform: plat,
				why: fmt.Sprintf("%s '%s' on %s (%s connection '%s')", word, v.Name, v.Host, plat, inv.Target)}
			for _, m := range v.MACs {
				f.macs[inventory.NormMAC(m)] = true
			}
			for _, ip := range v.IPs {
				f.ips[normIP(ip)] = true
			}
			rv := relVM(v)
			f.fill = func(r *Related) {
				r.VM = &rv
				if host != nil && host.fill != nil {
					var hr Related
					host.fill(&hr)
					r.Host = hr.Host
				}
			}
			id.add(f)
		}
	}

	// storage
	for _, e := range src.Storage {
		e := e
		var t Target
		for _, x := range src.Targets {
			if x.ID == e.TargetID {
				t = x
			}
		}
		sys := e.Inventory.System
		vendor := sys.Vendor
		role, what := RoleNAS, strings.TrimSpace(vendor+" NAS")
		switch t.Kind {
		case "smb", "nfs":
			role, what = RoleServer, strings.ToUpper(t.Kind)+" file server"
		}
		if vendor == "" && role == RoleNAS {
			what = "NAS"
		}
		name := sys.Name
		if name == "" {
			name = e.Inventory.Target
		}
		f := &fact{key: fmt.Sprintf("storage:%d", e.TargetID), role: role, name: name, what: what, source: "storage",
			macs: set(), ips: set(), names: set(shortName(sys.Name)),
			why: fmt.Sprintf("%s '%s' (storage connection '%s')", what, name, e.Inventory.Target)}
		for _, n := range sys.NICs {
			if m := inventory.NormMAC(n.MAC); macLike.MatchString(m) {
				f.macs[m] = true
			}
			if ip := normIP(n.IP); ip != "" {
				f.ips[ip] = true
			}
		}
		ips, names := address(t)
		for _, ip := range ips {
			f.ips[ip] = true
		}
		for _, n := range names {
			if n != "" {
				f.names[n] = true
			}
		}
		rs := &RelStorage{TargetID: e.TargetID, Target: e.Inventory.Target, Vendor: vendor, Model: sys.Model, Health: sys.Health,
			Volumes: len(e.Inventory.Volumes), Shares: len(e.Inventory.Shares), Alerts: len(e.Inventory.Alerts)}
		for _, v := range e.Inventory.Volumes {
			rs.Used += v.Used
			rs.Total += v.Total
		}
		f.fill = func(r *Related) { r.Storage = rs }
		id.add(f)
	}

	// DNS servers and smart home hubs NCC connects to are machines on the network too
	for _, t := range src.Targets {
		if !t.Enabled || (t.Category != CategoryDNS && t.Category != CategorySmartHome) {
			continue
		}
		ips, names := address(t)
		if len(ips) == 0 && len(names) == 0 {
			continue
		}
		role, what := RoleDNS, "DNS server"
		if t.Category == CategorySmartHome {
			role, what = RoleServer, "Smart home hub"
		}
		f := &fact{key: fmt.Sprintf("conn:%d", t.ID), role: role, name: t.Name, what: what, source: "connection",
			macs: set(), ips: set(ips...), names: set(names...),
			why: fmt.Sprintf("the %s connection '%s' (%s)", t.Kind, t.Name, t.Address)}
		id.add(f)
	}

	// the IoT inventory
	for _, d := range src.IoT {
		if d.Ignored || d.MAC == "" {
			continue
		}
		d := d
		f := &fact{key: "iot:" + d.MAC, role: RoleIoT, name: d.Name, what: "IoT device: " + d.Type, source: "iot",
			macs: set(inventory.NormMAC(d.MAC)), ips: set(), names: set(),
			why: fmt.Sprintf("IoT inventory entry '%s' (%s)", d.Name, d.Type)}
		if d.Label != "" {
			f.names[shortName(d.Label)] = true
		}
		loc := strings.Join(nonEmpty(d.Site, d.Building, d.Floor, d.Room), ", ")
		ri := &RelIoT{Type: d.Type, Owner: d.Owner, Location: loc}
		f.fill = func(r *Related) { r.IoT = ri }
		id.add(f)
	}

	// what DNS says the facts' addresses are called, and the addresses of their names
	for _, f := range id.facts {
		for n := range f.names {
			for _, ip := range id.dnsByName[n] {
				if f.ips[ip] {
					continue
				}
				f.ips[ip] = true
				id.byIP[ip] = append(id.byIP[ip], f)
				if f.ipVia == nil {
					f.ipVia = map[string]string{}
				}
				for _, d := range id.dnsByIP[ip] {
					if shortName(d.Name) == n {
						f.ipVia[ip] = fmt.Sprintf("DNS (%s) names %s %s", d.Server, ip, d.Name)
						break
					}
				}
			}
		}
		for ip := range f.ips {
			for _, d := range id.dnsByIP[ip] {
				if n := shortName(d.Name); n != "" && !f.names[n] {
					f.names[n] = true
					id.byName[n] = append(id.byName[n], f)
				}
			}
		}
	}
	return id
}

func relVM(v hv.VM) RelVM {
	return RelVM{ID: v.ID, Name: v.Name, Type: v.Type, State: v.State, Host: v.Host, IPs: v.IPs, OS: v.OS, CPUs: v.CPUs, Mem: v.MemBytes}
}

func nonEmpty(xs ...string) []string {
	var out []string
	for _, x := range xs {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func (id *identifier) add(f *fact) {
	delete(f.ips, "")
	delete(f.names, "")
	delete(f.macs, "")
	id.facts = append(id.facts, f)
	for m := range f.macs {
		id.byMAC[m] = append(id.byMAC[m], f)
	}
	for ip := range f.ips {
		id.byIP[ip] = append(id.byIP[ip], f)
	}
	for n := range f.names {
		id.byName[n] = append(id.byName[n], f)
	}
}

// endpoint is something on the network to identify: a client, or a device NCC can't name.
type endpoint struct {
	mac, ip, label string
}

// match is the best fact for an endpoint.
type match struct {
	f        *fact
	score    int
	evidence []Evidence
}

// names of an endpoint: its own label and what DNS calls its address, with where each came from.
func (id *identifier) names(e endpoint) map[string]string {
	out := map[string]string{}
	if n := shortName(e.label); n != "" {
		out[n] = ""
	}
	for _, d := range id.dnsByIP[normIP(e.ip)] {
		if n := shortName(d.Name); n != "" {
			if _, have := out[n]; !have {
				out[n] = fmt.Sprintf("DNS (%s) names %s %s", d.Server, e.ip, d.Name)
			}
		}
	}
	return out
}

// best finds the fact an endpoint most likely is.
func (id *identifier) best(e endpoint) *match {
	ip := normIP(e.ip)
	names := id.names(e)
	cands := map[*fact]bool{}
	for _, f := range id.byMAC[e.mac] {
		cands[f] = true
	}
	for _, f := range id.byIP[ip] {
		cands[f] = true
	}
	for n := range names {
		for _, f := range id.byName[n] {
			cands[f] = true
		}
	}
	var best *match
	for f := range cands {
		m := &match{f: f}
		if e.mac != "" && f.macs[e.mac] {
			m.score += scoreMACs
			m.evidence = append(m.evidence, Evidence{f.source, fmt.Sprintf("MAC %s is %s", e.mac, f.why)})
		} else if f.virtual && e.mac != "" && len(f.macs) > 0 {
			m.score -= penaltyMAC
		}
		if ip != "" && f.ips[ip] {
			m.score += scoreIP
			if via := f.ipVia[ip]; via != "" {
				m.evidence = append(m.evidence, Evidence{"dns", fmt.Sprintf("%s, the address of %s", via, f.why)})
			} else {
				m.evidence = append(m.evidence, Evidence{f.source, fmt.Sprintf("Address %s is %s", ip, f.why)})
			}
		}
		var hit []string
		for n := range names {
			if f.names[n] {
				hit = append(hit, n)
			}
		}
		sort.Strings(hit)
		if len(hit) > 0 {
			m.score += scoreName
			n := hit[0]
			if via := names[n]; via != "" {
				m.evidence = append(m.evidence, Evidence{"dns", fmt.Sprintf("%s, the name of %s", via, f.why)})
			} else {
				m.evidence = append(m.evidence, Evidence{f.source, fmt.Sprintf("Name '%s' matches %s", n, f.why)})
			}
		}
		if m.score > 100 {
			m.score = 100
		}
		if best == nil || m.score > best.score || m.score == best.score && f.key < best.f.key {
			best = m
		}
	}
	if best == nil || best.score < matchMin {
		return nil
	}
	return best
}

func (m *match) identity() *Identity {
	return &Identity{Role: m.f.role, Name: m.f.name, What: m.f.what, Score: m.score, Confidence: confidence(m.score),
		Evidence: m.evidence, Source: IdentityAuto}
}

// detailHint reads an LLDP system description for what the neighbour runs.
func detailHint(detail string) (role, what string) {
	d := strings.ToLower(detail)
	switch {
	case strings.Contains(d, "proxmox") || strings.Contains(d, "pve-manager"):
		return RoleHypervisor, "Proxmox VE host"
	case strings.Contains(d, "esxi") || strings.Contains(d, "vmkernel"):
		return RoleHypervisor, "VMware ESXi host"
	case strings.Contains(d, "synology") || strings.Contains(d, "diskstation"):
		return RoleNAS, "Synology NAS"
	case strings.Contains(d, "qnap") || strings.Contains(d, "qts"):
		return RoleNAS, "QNAP NAS"
	case strings.Contains(d, "truenas") || strings.Contains(d, "freenas"):
		return RoleNAS, "TrueNAS"
	case strings.Contains(d, "routeros") || strings.Contains(d, "router"):
		return RoleRouter, "Router"
	case strings.Contains(d, "switch"):
		return RoleSwitch, "Switch"
	case strings.Contains(d, "windows"):
		return RoleServer, "Windows machine"
	case strings.Contains(d, "linux") || strings.Contains(d, "debian") || strings.Contains(d, "ubuntu"):
		return RoleServer, "Linux machine"
	}
	return "", ""
}

func switchHint(c inventory.Client) string {
	var why []string
	if n := strings.ToLower(c.Name); n != "" && switchName.MatchString(n) {
		why = append(why, fmt.Sprintf("its name '%s'", c.Name))
	}
	v := strings.ToLower(c.Vendor)
	for _, s := range switchVendors {
		if v != "" && strings.Contains(v, s) {
			why = append(why, "its maker "+c.Vendor)
			break
		}
	}
	return strings.Join(why, " and ")
}

// behindClient is a client behind an inferred switch, and what NCC made of it.
type behindClient struct {
	c       inventory.Client
	m       *match
	oui     string // virtual MAC range's platform, when no VM matched
	switchy string
}

// inferred identifies an unmanaged switch NCC inferred from several clients sharing one port.
// It returns the identity and the client that is really the node itself (to fold in), if any.
func (id *identifier) inferred(behind []inventory.Client) (*Identity, *inventory.Client, *match) {
	if len(behind) == 0 {
		return nil, nil, nil
	}
	var hosts, virt, switchy, others []behindClient
	for _, c := range behind {
		b := behindClient{c: c, m: id.best(endpoint{mac: inventory.NormMAC(c.MAC), ip: c.IP, label: c.Name})}
		switch {
		case b.m != nil && (b.m.f.role == RoleHypervisor || b.m.f.role == RoleNAS):
			hosts = append(hosts, b)
		case b.m != nil && b.m.f.virtual:
			virt = append(virt, b)
		case b.m == nil && virtualOUI(inventory.NormMAC(c.MAC)) != "":
			b.oui = virtualOUI(inventory.NormMAC(c.MAC))
			virt = append(virt, b)
		default:
			if b.switchy = switchHint(c); b.switchy != "" && b.m == nil {
				switchy = append(switchy, b)
			} else {
				others = append(others, b)
			}
		}
	}
	names := func(bs []behindClient) string {
		var ns []string
		for _, b := range bs {
			n := b.c.Name
			if b.m != nil {
				n = b.m.f.name
			}
			if n == "" {
				n = b.c.MAC
			}
			ns = append(ns, n)
		}
		if len(ns) > 6 {
			ns = append(ns[:6], fmt.Sprintf("and %d more", len(ns)-6))
		}
		return strings.Join(ns, ", ")
	}
	// VMs that belong to host h (by NCC's inventory, or by the platform's MAC range)
	ownedBy := func(h *fact) (own, foreign []behindClient) {
		for _, b := range virt {
			if b.m != nil && b.m.f.host != nil && b.m.f.host != h || b.m == nil && b.oui != "" && b.oui != h.platform && h.role == RoleHypervisor {
				foreign = append(foreign, b)
			} else {
				own = append(own, b)
			}
		}
		return own, foreign
	}

	// A: one physical host, everything else is its VMs: the port leads straight to the host,
	// whose virtual bridge makes its VMs look like clients of a switch
	if len(hosts) == 1 && len(others) == 0 && len(switchy) == 0 && len(virt) > 0 {
		h := hosts[0]
		own, foreign := ownedBy(h.m.f)
		ident := &Identity{Role: h.m.f.role, Name: h.m.f.name, What: h.m.f.what, Source: IdentityAuto,
			Evidence: append([]Evidence{}, h.m.evidence...)}
		score := 50 + h.m.score/2 + min(15, 5*len(own))
		ident.Evidence = append(ident.Evidence, Evidence{"clients",
			fmt.Sprintf("Every other client on this port is a virtual machine on it: %s", names(own))})
		if len(foreign) > 0 {
			score -= 20
			ident.Evidence = append(ident.Evidence, Evidence{"clients",
				fmt.Sprintf("But %s belong to another host, so a switch may sit in between", names(foreign))})
		}
		ident.Score = min(score, 99)
		ident.Confidence = confidence(ident.Score)
		c := h.c
		return ident, &c, h.m
	}
	// B: nothing but VMs, and they all live on one host: that host's bridge, its own port
	// just isn't seen (another NIC carries its management address)
	if len(hosts) == 0 && len(others) == 0 && len(switchy) == 0 && len(virt) == len(behind) {
		var host *fact
		same, byOUI := true, ""
		for _, b := range virt {
			switch {
			case b.m != nil && b.m.f.host != nil:
				if host != nil && host != b.m.f.host {
					same = false
				}
				host = b.m.f.host
			case b.oui != "":
				if byOUI != "" && byOUI != b.oui {
					same = false
				}
				byOUI = b.oui
			}
		}
		if same && host != nil && (byOUI == "" || byOUI == host.platform) {
			ident := &Identity{Role: host.role, Name: host.name, What: host.what, Source: IdentityAuto, Score: 72,
				Evidence: []Evidence{{"vm", fmt.Sprintf("All %d clients on this port are virtual machines on %s: %s", len(virt), host.why, names(virt))}}}
			ident.Confidence = confidence(ident.Score)
			return ident, nil, &match{f: host, score: ident.Score}
		}
		if same && host == nil && byOUI != "" {
			ident := &Identity{Role: RoleHypervisor, What: byOUI + " host", Source: IdentityAuto, Score: 55,
				Evidence: []Evidence{{"mac", fmt.Sprintf("All %d clients on this port have %s virtual machine MAC addresses (%s), but no %s connection in NCC lists them", len(virt), byOUI, names(virt), byOUI)}}}
			ident.Confidence = confidence(ident.Score)
			return ident, nil, nil
		}
	}
	// C: one of the clients looks like a switch: the "unmanaged switch" is that switch, and
	// the client is its management address
	if len(switchy) == 1 {
		s := switchy[0]
		score := 45
		if strings.Contains(s.switchy, "name") {
			score += 20
		}
		if strings.Contains(s.switchy, "maker") {
			score += 10
		}
		ident := &Identity{Role: RoleSwitch, Name: s.c.Name, What: "Switch", Source: IdentityAuto, Score: score,
			Evidence: []Evidence{{"clients", fmt.Sprintf("%s (%s) is behind this port and looks like a switch from %s", firstNonEmptyStr(s.c.Name, s.c.MAC), firstNonEmptyStr(s.c.IP, s.c.MAC), s.switchy)}}}
		if rest := len(behind) - 1; rest > 0 {
			ident.Evidence = append(ident.Evidence, Evidence{"clients", fmt.Sprintf("The other %s on the port hang off it", plural(rest, "client", "clients"))})
		}
		ident.Confidence = confidence(ident.Score)
		c := s.c
		return ident, &c, nil
	}
	// D: different machines share the port, so a real switch (or hub) sits there
	physical := len(hosts) + len(others) + len(switchy)
	if physical >= 2 || physical >= 1 && len(virt) > 0 && len(hosts) == 0 {
		score := 45
		var ev []Evidence
		all := append(append(append([]behindClient{}, hosts...), switchy...), others...)
		if physical >= 2 {
			ev = append(ev, Evidence{"clients", fmt.Sprintf("%d separate machines share this port: %s", physical, names(all))})
		} else {
			ev = append(ev, Evidence{"clients", fmt.Sprintf("%s shares this port with virtual machines that are not its own: %s", names(all), names(virt))})
		}
		for _, h := range hosts {
			score += 10
			own, _ := ownedBy(h.m.f)
			txt := fmt.Sprintf("%s is one of them (%s)", h.m.f.name, h.m.f.what)
			if len(own) > 0 {
				txt += fmt.Sprintf(", with its VMs %s", names(own))
			}
			ev = append(ev, Evidence{h.m.f.source, txt})
		}
		ident := &Identity{Role: RoleSwitch, What: "Unmanaged switch", Source: IdentityAuto, Score: min(score, 75), Evidence: ev}
		ident.Confidence = confidence(ident.Score)
		return ident, nil, nil
	}
	return nil, nil, nil
}

func firstNonEmptyStr(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

// genericLabel reports whether a node's name says nothing NCC should keep over a real one.
func genericLabel(n Node) bool {
	l := strings.ToLower(strings.TrimSpace(n.Label))
	if l == "" || l == strings.ToLower(n.ID) || macLike.MatchString(l) || normIP(l) != "" {
		return true
	}
	return n.Discovery == inventory.SourceInferred || n.Kind == inventory.KindUnknown
}

// Enrich identifies the graph's nodes from every other source NCC reads: hypervisors and
// their VMs, storage, DNS records, the IoT inventory and the connections themselves. Unmanaged
// switches and unknown neighbours get the role NCC thinks they really are, with the evidence
// and a confidence; every node gets what NCC knows about it (its VMs, its storage, its DNS
// names). People's overrides win over NCC's guesses.
func Enrich(g *Graph, snaps []inventory.Snapshot, src Sources) {
	id := newIdentifier(src)
	behind := map[string][]inventory.Client{}
	clientSeen := map[string]bool{}
	for _, s := range snaps {
		for _, c := range s.Clients {
			if clientSeen[c.MAC] {
				continue
			}
			clientSeen[c.MAC] = true
			if c.ParentID != "" {
				behind[c.ParentID] = append(behind[c.ParentID], c)
			}
		}
	}
	fold := map[string]string{} // client MAC -> node it is folded into
	for i := range g.Nodes {
		n := &g.Nodes[i]
		var ident *Identity
		var m *match
		var folded *inventory.Client
		switch {
		case n.Kind == "client":
			m = id.best(endpoint{mac: inventory.NormMAC(n.ID), ip: n.IP, label: n.Label})
			if m != nil {
				ident = m.identity()
			} else if p := virtualOUI(inventory.NormMAC(n.ID)); p != "" {
				ident = &Identity{Role: RoleVM, What: "Virtual machine (" + p + ")", Score: 40, Confidence: "low", Source: IdentityAuto,
					Evidence: []Evidence{{"mac", fmt.Sprintf("MAC %s is in %s's range for virtual machines, but no connection in NCC lists it", n.ID, p)}}}
			}
		case n.Discovery == inventory.SourceInferred:
			ident, folded, m = id.inferred(behind[n.ID])
			if folded != nil {
				ident.Merged = folded.MAC
			}
		default:
			mac := ""
			if macLike.MatchString(strings.ToLower(n.ID)) {
				mac = inventory.NormMAC(n.ID)
			}
			m = id.best(endpoint{mac: mac, ip: n.IP, label: n.Label})
			if n.Discovery == inventory.SourceController {
				// adopted devices are what the controller says; only collect what's related
				ident = nil
				break
			}
			if m != nil {
				ident = m.identity()
			}
			if role, what := detailHint(lldpDetail(snaps, n.ID)); role != "" {
				ev := Evidence{"lldp", fmt.Sprintf("Its LLDP description says %s", what)}
				switch {
				case ident == nil:
					ident = &Identity{Role: role, What: what, Score: 40, Confidence: "low", Source: IdentityAuto, Evidence: []Evidence{ev}}
					if role == RoleSwitch {
						ident.Score = 55
					}
					ident.Confidence = confidence(ident.Score)
				case ident.Role == role:
					ident.Score = min(ident.Score+15, 99)
					ident.Confidence = confidence(ident.Score)
					ident.Evidence = append(ident.Evidence, ev)
				}
			}
		}
		if ident != nil && ident.Merged != "" && folded != nil && n.IP == "" {
			n.IP = folded.IP
		}
		rel := &Related{}
		if m != nil && m.f.fill != nil && ident != nil && ident.Name == m.f.name {
			m.f.fill(rel)
		} else if m != nil && m.f.fill != nil && n.Discovery == inventory.SourceController {
			m.f.fill(rel)
		}
		id.related(n.IP, rel)
		if !rel.empty() {
			n.Related = rel
		}
		if ov, ok := src.Overrides[n.ID]; ok && ValidRole(ov.Role) {
			// a person who says it's something else keeps the client as its own dot
			ident = applyOverride(ident, ov)
		}
		if ident != nil && ident.Merged != "" {
			fold[ident.Merged] = n.ID
		} else if folded != nil && n.IP == folded.IP {
			n.IP = ""
		}
		if ident == nil {
			continue
		}
		if ident.Name != "" && ident.Name != n.Label && (ident.Source != IdentityAuto || genericLabel(*n)) {
			ident.Label = n.Label
			n.Label = ident.Name
		}
		n.Identity = ident
	}
	if len(fold) == 0 {
		return
	}
	// a folded client is the node itself: drop its own dot and link
	keep := g.Nodes[:0]
	for _, n := range g.Nodes {
		if n.Kind == "client" && fold[n.ID] != "" {
			continue
		}
		if n.Discovery == inventory.SourceInferred && n.Identity != nil && n.Identity.Merged != "" && n.Clients > 0 {
			n.Clients--
		}
		keep = append(keep, n)
	}
	g.Nodes = keep
	edges := g.Edges[:0]
	for _, e := range g.Edges {
		if e.Origin == "client" && fold[e.Target] != "" {
			continue
		}
		edges = append(edges, e)
	}
	g.Edges = edges
}

func lldpDetail(snaps []inventory.Snapshot, id string) string {
	for _, s := range snaps {
		for _, d := range s.Devices {
			if d.ID == id {
				return d.Detail + " " + d.Model
			}
		}
	}
	return ""
}

// related adds the DNS names and connections of an address.
func (id *identifier) related(ip string, r *Related) {
	ip = normIP(ip)
	if ip == "" {
		return
	}
	seen := map[string]bool{}
	for _, d := range id.dnsByIP[ip] {
		k := d.Name + "|" + d.Type
		if seen[k] {
			continue
		}
		seen[k] = true
		r.DNS = append(r.DNS, RelDNS{Name: d.Name, Type: d.Type, Server: d.Server})
	}
	have := map[int64]bool{}
	add := func(ts []Target) {
		for _, t := range ts {
			if !have[t.ID] {
				have[t.ID] = true
				r.Connections = append(r.Connections, RelConn{ID: t.ID, Name: t.Name, Kind: t.Kind, Category: t.Category})
			}
		}
	}
	add(id.conns[ip])
	for _, d := range id.dnsByIP[ip] {
		add(id.conns["name:"+shortName(d.Name)])
	}
}

func (r *Related) empty() bool {
	return r.Host == nil && len(r.VMs) == 0 && r.VM == nil && r.Storage == nil && len(r.DNS) == 0 && len(r.Connections) == 0 && r.IoT == nil
}

// applyOverride puts what a person said over NCC's guess, keeping the guess when they differ.
func applyOverride(auto *Identity, ov IdentityOverride) *Identity {
	at := ov.At
	src := IdentityManual
	if ov.Confirmed {
		src = IdentityConfirmed
	}
	if auto != nil && auto.Role == ov.Role && (ov.Name == "" || ov.Name == auto.Name || auto.Name == "") {
		out := *auto
		if ov.Name != "" {
			out.Name = ov.Name
		}
		out.Source, out.By, out.At = src, ov.By, &at
		return &out
	}
	out := &Identity{Role: ov.Role, Name: ov.Name, What: roleWhat[ov.Role], Confidence: "manual", Score: 100,
		Source: src, By: ov.By, At: &at, Guess: auto}
	if auto != nil && auto.Role == ov.Role {
		out.What, out.Evidence, out.Merged = auto.What, auto.Evidence, auto.Merged
		out.Guess = nil
	}
	return out
}
