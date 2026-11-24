// Package snmpnet is the NCC device driver for routers, firewalls and switches of any vendor,
// read over SNMP with the standard MIBs every managed device implements: SNMPv2-MIB (name,
// description, uptime), IF-MIB (ports, speed, state), LLDP-MIB (cabled neighbours, for the
// topology map), Q-BRIDGE/BRIDGE-MIB (which MAC address is on which port) and the ARP table
// (client addresses). It is read-only; vendor APIs (like UniFi's) can do more.
package snmpnet

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/catalog"
	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/storage/snmpnas"
	"github.com/dertown/network-control-centre/internal/vault"
	"github.com/gosnmp/gosnmp"
)

// Options.
const (
	OptRole   = "role"   // router, firewall or switch
	OptVendor = "vendor" // the catalog entry the connection was made from
)

// vendorEntry is one product in the wizard: which groups it shows in, its role and how to turn
// on SNMP there.
type vendorEntry struct {
	id, label, make, role, help string
	groups                      []string
}

var vendors = []vendorEntry{
	{"snmp-cisco-ios", "Cisco IOS / IOS-XE router", "Cisco", "router", "On the router: snmp-server community <community> RO, or for v3 snmp-server group NCC v3 priv and snmp-server user ncc NCC v3 auth sha <pass> priv aes 128 <pass>. Turn on LLDP with lldp run.", []string{catalog.GroupRouter}},
	{"snmp-cisco-catalyst", "Cisco Catalyst / Nexus switch", "Cisco", "switch", "On the switch: snmp-server community <community> RO (or an SNMPv3 user), and lldp run so NCC can draw the cabling.", []string{catalog.GroupSwitch}},
	{"snmp-cisco-asa", "Cisco ASA / Firepower", "Cisco", "firewall", "On the ASA: snmp-server host <interface> <NCC address> poll community <community>, and snmp-server enable.", []string{catalog.GroupFirewall}},
	{"snmp-juniper", "Juniper (Junos)", "Juniper", "router", "set snmp community <community> authorization read-only (or an SNMPv3 USM user) and set protocols lldp interface all.", []string{catalog.GroupRouter, catalog.GroupSwitch, catalog.GroupFirewall}},
	{"snmp-aruba", "HPE Aruba (ArubaOS-CX / ProCurve)", "HPE Aruba", "switch", "snmp-server community <community> (ArubaOS-CX: snmp-server vrf default and snmp-server community <community>). LLDP is on by default.", []string{catalog.GroupSwitch}},
	{"snmp-mikrotik", "MikroTik RouterOS / SwOS", "MikroTik", "router", "IP → SNMP: enable it and set a read-only community (or an SNMPv3 user). Turn on LLDP under IP → Neighbors → Discovery.", []string{catalog.GroupRouter, catalog.GroupSwitch}},
	{"snmp-fortigate", "Fortinet FortiGate", "Fortinet", "firewall", "System → SNMP: enable the agent, add a v2c community or v3 user with NCC's address as a host, and allow SNMP on the interface NCC reaches.", []string{catalog.GroupFirewall}},
	{"snmp-paloalto", "Palo Alto Networks", "Palo Alto Networks", "firewall", "Device → Setup → Operations → SNMP Setup, and allow SNMP in the management interface's settings.", []string{catalog.GroupFirewall}},
	{"snmp-pfsense", "pfSense / OPNsense", "Netgate / Deciso", "firewall", "pfSense: Services → SNMP; OPNsense: install os-net-snmp, then Services → Net-SNMP. Set a read-only community and bind it to the LAN.", []string{catalog.GroupFirewall, catalog.GroupRouter}},
	{"snmp-sonicwall", "SonicWall", "SonicWall", "firewall", "Device → Settings → SNMP: enable it with a read-only community, and allow SNMP on the interface NCC reaches.", []string{catalog.GroupFirewall}},
	{"snmp-sophos", "Sophos Firewall", "Sophos", "firewall", "Administration → SNMP: add an agent and a v3 user or v2c community, then allow SNMP under Device access for the zone NCC is in.", []string{catalog.GroupFirewall}},
	{"snmp-netgear", "Netgear smart / managed switch", "NETGEAR", "switch", "System → SNMP: add a read-only community (or a v3 user) for NCC's address.", []string{catalog.GroupSwitch}},
	{"snmp-tplink", "TP-Link Omada / JetStream switch", "TP-Link", "switch", "SNMP → Global Config: enable SNMP, then add a read-only community. Turn on LLDP under L2 Features.", []string{catalog.GroupSwitch}},
	{"snmp-dell", "Dell PowerSwitch", "Dell", "switch", "snmp-server community <community> ro, and lldp enable.", []string{catalog.GroupSwitch}},
	{"snmp-arista", "Arista EOS", "Arista", "switch", "snmp-server community <community> ro (LLDP is on by default).", []string{catalog.GroupSwitch}},
}

func init() {
	snmp := catalog.SNMPFields("", "")
	role := catalog.Field{Key: OptRole, Label: "It is a", Type: catalog.Select, Store: catalog.StoreOption, Default: "switch", Choices: []catalog.Choice{
		{Value: "switch", Label: "Switch"}, {Value: "router", Label: "Router or gateway"}, {Value: "firewall", Label: "Firewall"}}}
	common := "NCC reads name, model, ports and their state, LLDP neighbours (for the topology map), the MAC table and the ARP table. Read only; nothing is changed. "
	entries := []catalog.Vendor{{
		Label: "Any SNMP device", Groups: []string{catalog.GroupRouter, catalog.GroupFirewall, catalog.GroupSwitch}, Order: 90,
		Summary: "Any router, firewall or switch with SNMP: Cisco, Juniper, Aruba, MikroTik, Fortinet, pfSense and more.",
		Help:    common + "Turn SNMP on (v3 with a user is best; v2c with a community that isn't public is fine on a management network) and LLDP if the device has it.",
		NameDefault: "switch", AddressKind: catalog.AddressHost, AddressDefault: "192.168.1.2",
		Fields: append([]catalog.Field{role}, snmp...),
	}}
	for i, v := range vendors {
		entries = append(entries, catalog.Vendor{
			ID: v.id, Label: v.label, Groups: v.groups, Order: 50 + i, Summary: v.make + " over SNMP: ports, neighbours, MAC and ARP tables.",
			Help: common + v.help, NameDefault: strings.Fields(strings.ToLower(v.make))[0] + "-" + v.role, AddressKind: catalog.AddressHost,
			Preset: map[string]string{OptRole: v.role}, Fields: snmp,
		})
	}
	drivers.Register(Driver{}, entries...)
}

// Driver implements drivers.Driver over SNMP.
type Driver struct{}

// Kind implements drivers.Driver.
func (Driver) Kind() string { return "snmpnet" }

// dial is replaced by tests.
var dial = func(ctx context.Context, cfg snmpnas.Config) (snmpnas.Session, func(), error) { return snmpnas.Dial(ctx, cfg) }

func session(ctx context.Context, t drivers.Target, creds vault.Secret) (snmpnas.Session, func(), error) {
	cfg, ok := snmpnas.FromCreds(t.Address, creds)
	if !ok {
		return nil, nil, fmt.Errorf("snmp: no community or SNMPv3 user saved for %s", t.Name)
	}
	return dial(ctx, cfg)
}

// OIDs.
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidIfTable     = "1.3.6.1.2.1.2.2.1"       // 2 descr, 3 type, 5 speed, 6 phys address, 8 oper status
	oidIfXTable    = "1.3.6.1.2.1.31.1.1.1"    // 1 name, 15 high speed, 18 alias
	oidLLDPLocCh   = "1.0.8802.1.1.2.1.3.2.0"  // local chassis id
	oidLLDPLocSub  = "1.0.8802.1.1.2.1.3.1.0"  // its subtype
	oidLLDPLocPort = "1.0.8802.1.1.2.1.3.7.1"  // 3 port id, 4 port desc
	oidLLDPRem     = "1.0.8802.1.1.2.1.4.1.1"  // 4 chassis subtype, 5 chassis id, 6 port subtype, 7 port id, 8 port desc, 9 sys name, 10 sys desc
	oidBasePortIf  = "1.3.6.1.2.1.17.1.4.1.2"  // bridge port -> ifIndex
	oidQFdbPort    = "1.3.6.1.2.1.17.7.1.2.2.1.2"
	oidFdbPort     = "1.3.6.1.2.1.17.4.3.1.2"
	oidARP         = "1.3.6.1.2.1.4.22.1.2" // ifIndex.a.b.c.d -> MAC
)

// Test implements drivers.Driver: the device answers SNMP with these credentials.
func (Driver) Test(ctx context.Context, t drivers.Target, creds vault.Secret) (*drivers.Result, error) {
	s, closer, err := session(ctx, t, creds)
	if err != nil {
		return nil, err
	}
	defer closer()
	v, err := s.Get([]string{oidSysName, oidSysDescr})
	if err != nil {
		return nil, fmt.Errorf("snmp: %s doesn't answer: %w", t.Address, err)
	}
	if len(v) == 0 {
		return nil, fmt.Errorf("snmp: %s answered without a system name or description", t.Address)
	}
	return &drivers.Result{Snapshot: &inventory.Snapshot{Target: t.Name, TakenAt: time.Now().UTC()}}, nil
}

// Collect implements drivers.Driver.
func (Driver) Collect(ctx context.Context, t drivers.Target, creds vault.Secret) (*drivers.Result, error) {
	s, closer, err := session(ctx, t, creds)
	if err != nil {
		return nil, err
	}
	defer closer()
	snap, err := read(s, t)
	if err != nil {
		return nil, err
	}
	return &drivers.Result{Snapshot: snap}, nil
}

// ---- reading ----

type row = map[int]gosnmp.SnmpPDU

// walk groups a table's values by row index, then column.
func walk(s snmpnas.Session, base string) map[string]row {
	pdus, err := s.Walk(base)
	if err != nil {
		return nil
	}
	out := map[string]row{}
	for _, p := range pdus {
		rest := strings.TrimPrefix(strings.TrimPrefix(p.Name, "."), base+".")
		col, idx, ok := strings.Cut(rest, ".")
		if !ok {
			continue
		}
		c, err := strconv.Atoi(col)
		if err != nil {
			continue
		}
		if out[idx] == nil {
			out[idx] = row{}
		}
		out[idx][c] = p
	}
	return out
}

// column walks a single column (index -> value).
func column(s snmpnas.Session, base string) map[string]gosnmp.SnmpPDU {
	pdus, err := s.Walk(base)
	if err != nil {
		return nil
	}
	out := map[string]gosnmp.SnmpPDU{}
	for _, p := range pdus {
		out[strings.TrimPrefix(strings.TrimPrefix(p.Name, "."), base+".")] = p
	}
	return out
}

func str(p gosnmp.SnmpPDU) string {
	switch v := p.Value.(type) {
	case []byte:
		return strings.TrimSpace(strings.TrimRight(string(v), "\x00"))
	case string:
		return strings.TrimSpace(v)
	case nil:
		return ""
	}
	return fmt.Sprint(p.Value)
}

func num(p gosnmp.SnmpPDU) int64 {
	if p.Value == nil {
		return 0
	}
	if _, ok := p.Value.([]byte); ok {
		return 0
	}
	return gosnmp.ToBigInt(p.Value).Int64()
}

// mac formats a 6-byte value (or a MAC already in text) as aa:bb:cc:dd:ee:ff.
func mac(p gosnmp.SnmpPDU) string {
	if b, ok := p.Value.([]byte); ok && len(b) == 6 {
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
	}
	return inventory.NormMAC(str(p))
}

// macFromIndex reads the last six numbers of an index (FDB rows are indexed by MAC).
func macFromIndex(idx string) string {
	parts := strings.Split(idx, ".")
	if len(parts) < 6 {
		return ""
	}
	b := make([]byte, 6)
	for i, p := range parts[len(parts)-6:] {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return ""
		}
		b[i] = byte(n)
	}
	return mac(gosnmp.SnmpPDU{Value: b})
}

// enterprise maps sysObjectID enterprise numbers to makers.
var enterprise = map[string]string{
	"9": "Cisco", "11": "HPE", "2636": "Juniper", "14988": "MikroTik", "4526": "NETGEAR", "12356": "Fortinet", "25461": "Palo Alto Networks",
	"8741": "SonicWall", "41112": "Ubiquiti", "11863": "TP-Link", "674": "Dell", "6027": "Dell", "14823": "HPE Aruba", "47196": "HPE Aruba",
	"30065": "Arista", "2011": "Huawei", "12325": "pfSense", "2604": "Sophos", "21067": "Sophos", "2620": "Check Point", "8072": "Linux (net-snmp)",
	"171": "D-Link", "890": "Zyxel", "1916": "Extreme Networks", "1991": "Extreme Networks", "4413": "Ubiquiti (EdgeSwitch)",
}

func makerFromOID(oid string) string {
	oid = strings.TrimPrefix(oid, ".")
	if rest, ok := strings.CutPrefix(oid, "1.3.6.1.4.1."); ok {
		n, _, _ := strings.Cut(rest, ".")
		return enterprise[n]
	}
	return ""
}

// physical port types: ethernetCsmacd, fastEther, gigabitEthernet, ieee8023adLag (shown as LAG).
var portTypes = map[int64]bool{6: true, 62: true, 117: true, 69: true, 161: true}

// guessKind reads a neighbour's role from its LLDP description.
func guessKind(descr, name string) string {
	d := strings.ToLower(descr + " " + name)
	switch {
	case strings.Contains(d, "access point") || strings.Contains(d, " ap ") || strings.HasPrefix(d, "uap") || strings.Contains(d, "wireless"):
		return inventory.KindAP
	case strings.Contains(d, "switch") || strings.Contains(d, "catalyst") || strings.Contains(d, "procurve"):
		return inventory.KindSwitch
	case strings.Contains(d, "router") || strings.Contains(d, "gateway") || strings.Contains(d, "firewall") || strings.Contains(d, "fortigate") ||
		strings.Contains(d, "pfsense") || strings.Contains(d, "opnsense") || strings.Contains(d, "routeros"):
		return inventory.KindGateway
	}
	return inventory.KindUnknown
}

// uplinkMACs is the number of MAC addresses on one port above which NCC takes it for a link to
// more network gear rather than a port with hosts on it.
const uplinkMACs = 24

func read(s snmpnas.Session, t drivers.Target) (*inventory.Snapshot, error) {
	now := time.Now().UTC()
	sys, err := s.Get([]string{oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysName, oidLLDPLocCh, oidLLDPLocSub})
	if err != nil {
		return nil, fmt.Errorf("snmp: %s: %w", t.Address, err)
	}
	if len(sys) == 0 {
		return nil, fmt.Errorf("snmp: %s answered without a system name or description", t.Address)
	}
	descr := str(sys[oidSysDescr])
	model, _, _ := strings.Cut(descr, "\n")
	if len(model) > 120 {
		model = model[:120] + "…"
	}
	dev := inventory.Device{
		Name: str(sys[oidSysName]), Make: makerFromOID(str(sys[oidSysObjectID])), Model: strings.TrimSpace(model), ModelCode: str(sys[oidSysObjectID]),
		IP: hostOnly(t.Address), Online: true, Uptime: num(sys[oidSysUpTime]) / 100, Managed: true, Discovery: inventory.SourceController,
		Detail: descr, Target: t.Name, SeenAt: now,
	}
	if v, ok := entryFor(t.Options[OptVendor]); ok && v.make != "" {
		dev.Make = v.make
	}
	if dev.Name == "" {
		dev.Name = t.Name
	}
	switch t.Options[OptRole] {
	case "router", "firewall":
		dev.Kind = inventory.KindGateway
	default:
		dev.Kind = inventory.KindSwitch
	}

	// ports
	ifs, ifx := walk(s, oidIfTable), walk(s, oidIfXTable)
	var ports []portInfo
	byIf := map[string]int{} // ifIndex -> position in ports
	firstMAC := ""
	idxs := make([]string, 0, len(ifs))
	for idx := range ifs {
		idxs = append(idxs, idx)
	}
	sort.Slice(idxs, func(i, j int) bool { a, _ := strconv.Atoi(idxs[i]); b, _ := strconv.Atoi(idxs[j]); return a < b })
	for _, idx := range idxs {
		r := ifs[idx]
		if !portTypes[num(r[3])] {
			continue
		}
		name := str(ifx[idx][1])
		if name == "" {
			name = str(r[2])
		}
		speed := int(num(ifx[idx][15]))
		if speed == 0 {
			speed = int(num(r[5]) / 1_000_000)
		}
		m := mac(r[6])
		if firstMAC == "" && m != "" && m != "00:00:00:00:00:00" {
			firstMAC = m
		}
		n, _ := strconv.Atoi(idx)
		p := inventory.Port{Index: n, Name: name, Up: num(r[8]) == 1, SpeedMbps: speed}
		if alias := str(ifx[idx][18]); alias != "" && alias != name {
			p.Profile = alias
		}
		byIf[idx] = len(ports)
		ports = append(ports, portInfo{port: p, mac: m, ifIdx: idx})
	}
	dev.MAC = firstMAC
	if sub := num(sys[oidLLDPLocSub]); sub == 4 {
		if m := mac(sys[oidLLDPLocCh]); m != "" {
			dev.MAC = m
		}
	}
	dev.ID = inventory.NormMAC(dev.MAC)
	if dev.ID == "" {
		dev.ID = "snmp:" + t.Name
	}

	snap := &inventory.Snapshot{Target: t.Name, TakenAt: now, Devices: []inventory.Device{}, Links: []inventory.Link{}, Clients: []inventory.Client{}}

	// LLDP neighbours: local port numbers are usually ifIndex; otherwise match by port name
	locPorts := walk(s, oidLLDPLocPort)
	portFor := func(localNum string) *portInfo {
		if i, ok := byIf[localNum]; ok {
			return &ports[i]
		}
		lp := locPorts[localNum]
		for _, name := range []string{str(lp[3]), str(lp[4])} {
			for i := range ports {
				if name != "" && (strings.EqualFold(ports[i].port.Name, name) || strings.EqualFold(ports[i].mac, inventory.NormMAC(name))) {
					return &ports[i]
				}
			}
		}
		return nil
	}
	neighbours := map[string]bool{}
	for idx, r := range walk(s, oidLLDPRem) {
		parts := strings.Split(idx, ".") // timeMark.localPortNum.index
		if len(parts) < 3 {
			continue
		}
		id := ""
		if num(r[4]) == 4 {
			id = inventory.NormMAC(mac(r[5]))
		}
		sysName, sysDescr := str(r[9]), str(r[10])
		if id == "" {
			id = "lldp:" + strings.ToLower(firstNonEmpty(sysName, str(r[5])))
		}
		if id == "lldp:" || id == dev.ID {
			continue
		}
		remPort := firstNonEmpty(str(r[8]), str(r[7]))
		if num(r[6]) == 3 { // the port id is a MAC: the description reads better
			remPort = firstNonEmpty(str(r[8]), mac(r[7]))
		}
		local := portFor(parts[1])
		localName := ""
		if local != nil {
			local.port.Infra = true
			localName = local.port.Name
		}
		if !neighbours[id] {
			neighbours[id] = true
			model, _, _ := strings.Cut(sysDescr, "\n")
			snap.Devices = append(snap.Devices, inventory.Device{
				ID: id, Name: firstNonEmpty(sysName, id), Kind: guessKind(sysDescr, sysName), Model: strings.TrimSpace(model),
				MAC: strings.TrimPrefix(id, "lldp:"), Online: true, Discovery: inventory.SourceLLDP, Detail: sysDescr, Target: t.Name, SeenAt: now,
			})
		}
		snap.Links = append(snap.Links, inventory.Link{A: dev.ID, APort: localName, B: id, BPort: remPort, Medium: "wired", Source: "lldp",
			SpeedMbps: speedOf(local)})
	}

	// clients: the MAC table (switches) and the ARP table (addresses)
	arp := map[string]string{} // MAC -> IP
	for idx, p := range column(s, oidARP) {
		parts := strings.Split(idx, ".")
		if len(parts) == 5 {
			if m := mac(p); m != "" {
				arp[m] = strings.Join(parts[1:], ".")
			}
		}
	}
	bridgeIf := map[string]string{}
	for bp, p := range column(s, oidBasePortIf) {
		bridgeIf[bp] = strconv.FormatInt(num(p), 10)
	}
	type seen struct {
		mac, ifIdx string
		vlan       int
	}
	var fdb []seen
	for idx, p := range column(s, oidQFdbPort) {
		parts := strings.SplitN(idx, ".", 2)
		vlan, _ := strconv.Atoi(parts[0])
		fdb = append(fdb, seen{macFromIndex(idx), bridgeIf[strconv.FormatInt(num(p), 10)], vlan})
	}
	if len(fdb) == 0 {
		for idx, p := range column(s, oidFdbPort) {
			fdb = append(fdb, seen{macFromIndex(idx), bridgeIf[strconv.FormatInt(num(p), 10)], 0})
		}
	}
	perPort := map[string]int{}
	for _, f := range fdb {
		perPort[f.ifIdx]++
	}
	own := map[string]bool{}
	for _, p := range ports {
		own[p.mac] = true
	}
	placed := map[string]bool{}
	for _, f := range fdb {
		i, ok := byIf[f.ifIdx]
		if f.mac == "" || own[f.mac] || neighbours[f.mac] || placed[f.mac] || !ok {
			continue
		}
		pi := &ports[i]
		if pi.port.Infra || perPort[f.ifIdx] > uplinkMACs {
			pi.port.Infra = true
			continue
		}
		placed[f.mac] = true
		snap.Clients = append(snap.Clients, inventory.Client{MAC: f.mac, Name: firstNonEmpty(arp[f.mac], f.mac), IP: arp[f.mac], Wired: true,
			ParentID: dev.ID, ParentPort: pi.port.Name, SwitchMAC: dev.ID, SwitchPort: pi.port.Index, VLAN: f.vlan})
	}
	if dev.Kind == inventory.KindGateway && len(fdb) == 0 {
		// a router without a MAC table: its ARP table lists the hosts it talks to
		for m, ip := range arp {
			if own[m] || neighbours[m] {
				continue
			}
			snap.Clients = append(snap.Clients, inventory.Client{MAC: m, Name: ip, IP: ip, Wired: true, ParentID: dev.ID})
		}
	}
	sort.Slice(snap.Clients, func(i, j int) bool { return snap.Clients[i].MAC < snap.Clients[j].MAC })
	for _, p := range ports {
		dev.Ports = append(dev.Ports, p.port)
	}
	dev.Clients = len(snap.Clients)
	snap.Devices = append([]inventory.Device{dev}, snap.Devices...)
	for i := range snap.Links {
		if snap.Links[i].A == "" {
			snap.Links[i].A = dev.ID
		}
	}
	return snap, nil
}

// portInfo is one physical port while a device is read.
type portInfo struct {
	port  inventory.Port
	mac   string
	ifIdx string
}

func speedOf(p *portInfo) int {
	if p == nil {
		return 0
	}
	return p.port.SpeedMbps
}

func entryFor(id string) (vendorEntry, bool) {
	for _, v := range vendors {
		if v.id == id {
			return v, true
		}
	}
	return vendorEntry{}, false
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x = strings.TrimSpace(x); x != "" {
			return x
		}
	}
	return ""
}

func hostOnly(addr string) string {
	a := strings.TrimSpace(addr)
	if i := strings.Index(a, "://"); i >= 0 {
		a = a[i+3:]
	}
	if h, _, ok := strings.Cut(a, ":"); ok && !strings.Contains(h, "]") && strings.Count(a, ":") == 1 {
		return h
	}
	return a
}
