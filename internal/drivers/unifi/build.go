package unifi

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	inv "github.com/dertown/network-control-centre/internal/inventory"
)

// Build turns raw controller data into an inventory snapshot. It is pure so it can be
// tested with recorded controller JSON.
//
// Make/model discovery works in three layers:
//  1. Adopted UniFi devices: make "Ubiquiti", model from the controller's model code.
//  2. LLDP neighbours that are not adopted (e.g. a third-party managed switch): make and
//     model guessed from the LLDP system name and description.
//  3. Ports where several wired clients share one UniFi switch port: an unmanaged switch
//     must sit there, so an "inferred" node is added and the clients hang off it.
//
// cfg (optional) adds networks, VLANs and firewall zones: each port's native and tagged
// networks, the networks each link carries, and the network each client and device is in.
func Build(target string, devs []rawDevice, clients []rawClient, cfg *siteConfig, now time.Time) *inv.Snapshot {
	snap := &inv.Snapshot{Target: target, TakenAt: now}
	ix := buildNetIndex(target, cfg, gatewayDNS(devs))
	snap.Networks = ix.nets
	byMAC := map[string]*inv.Device{}
	order := []string{}
	linkSeen := map[string]bool{}
	addLink := func(l inv.Link) {
		a, b := l.A, l.B
		if a > b {
			a, b = b, a
		}
		key := a + "|" + b
		if linkSeen[key] {
			return
		}
		linkSeen[key] = true
		snap.Links = append(snap.Links, l)
	}
	portName := func(d *inv.Device, idx int) string {
		if idx <= 0 {
			return ""
		}
		for _, p := range d.Ports {
			if p.Index == idx && p.Name != "" {
				return p.Name
			}
		}
		return "Port " + strconv.Itoa(idx)
	}
	// portNets lists the networks on a device port, or nil when unknown.
	portNets := func(d *inv.Device, idx int) []string {
		if d == nil || idx <= 0 {
			return nil
		}
		for _, p := range d.Ports {
			if p.Index == idx {
				return carried(p)
			}
		}
		return nil
	}

	// 1. adopted devices
	for _, r := range devs {
		mac := inv.NormMAC(r.MAC)
		if mac == "" {
			continue
		}
		d := &inv.Device{
			ID: mac, MAC: mac, Name: firstNonEmpty(r.Name, r.MAC),
			Kind: kindFor(r.Type), Make: "Ubiquiti",
			Model: ModelName(r.Model, r.ModelName), ModelCode: r.Model,
			IP: r.IP, Firmware: r.Version, Serial: r.Serial,
			Online: r.State == 1, Uptime: r.Uptime,
			Managed: r.Adopted == nil || *r.Adopted, Discovery: inv.SourceController,
			Target: target, SeenAt: now,
		}
		overrides := map[int]*rawPortOverride{}
		for i := range r.PortOverrides {
			overrides[r.PortOverrides[i].PortIdx] = &r.PortOverrides[i]
		}
		isGateway := d.Kind == inv.KindGateway
		for _, p := range r.PortTable {
			port := inv.Port{
				Index: p.PortIdx, Name: p.Name, Up: p.Up, SpeedMbps: p.Speed,
				PoE: p.PoEEnable, PoEWatts: float64(p.PoEPower), Uplink: p.IsUplink,
				STP: strings.ToLower(p.StpState),
			}
			// a gateway's uplink port is its WAN, not a switched LAN port
			if !(isGateway && p.IsUplink) {
				port.Profile, port.NativeNetwork, port.TaggedNetworks = ix.port(p, overrides[p.PortIdx])
			}
			d.Ports = append(d.Ports, port)
		}
		d.Network = ix.byIP(d.IP)
		byMAC[mac] = d
		order = append(order, mac)
	}

	// uplinks between adopted devices
	uplinkPorts := map[string]bool{} // "mac#port" used by infrastructure links
	for _, r := range devs {
		me := inv.NormMAC(r.MAC)
		up := inv.NormMAC(r.Uplink.UplinkMAC)
		parent, ok := byMAC[up]
		if !ok || me == "" || up == me {
			continue
		}
		medium := "wired"
		if strings.EqualFold(r.Uplink.Type, "wireless") {
			medium = "wireless"
		}
		nets := portNets(parent, r.Uplink.UplinkRemotePort)
		if medium == "wireless" {
			nets = ix.switched // a wireless mesh uplink bridges every network
		}
		addLink(inv.Link{
			A: up, APort: portName(parent, r.Uplink.UplinkRemotePort),
			B: me, BPort: portName(byMAC[me], r.Uplink.PortIdx),
			Medium: medium, SpeedMbps: r.Uplink.Speed, Source: "uplink", Networks: nets,
		})
		uplinkPorts[up+"#"+strconv.Itoa(r.Uplink.UplinkRemotePort)] = true
		uplinkPorts[me+"#"+strconv.Itoa(r.Uplink.PortIdx)] = true
	}

	// 2. LLDP neighbours
	for _, r := range devs {
		me := inv.NormMAC(r.MAC)
		local, ok := byMAC[me]
		if !ok {
			continue
		}
		for _, n := range r.LLDPTable {
			if n.IsWired != nil && !*n.IsWired {
				continue
			}
			nb := inv.NormMAC(n.ChassisID)
			if nb == "" || nb == me {
				continue
			}
			lp := firstNonEmpty(n.LocalPortName, portName(local, n.LocalPortIdx))
			uplinkPorts[me+"#"+strconv.Itoa(n.LocalPortIdx)] = true
			if _, known := byMAC[nb]; !known {
				descr := n.descr()
				mk := GuessMake(descr, n.name())
				model := firstLine(descr)
				if model == "" {
					model = "unknown model"
				}
				kind := inv.KindUnknown
				if strings.Contains(strings.ToLower(descr+" "+n.name()), "switch") {
					kind = inv.KindSwitch
				}
				if mk == "" {
					mk = "unknown"
				}
				byMAC[nb] = &inv.Device{
					ID: nb, MAC: nb, Name: firstNonEmpty(n.name(), nb), Kind: kind,
					Make: mk, Model: model, Online: true, Managed: false,
					Discovery: inv.SourceLLDP, Detail: descr, Target: target, SeenAt: now,
				}
				order = append(order, nb)
			}
			addLink(inv.Link{A: me, APort: lp, B: nb, BPort: firstNonEmpty(n.PortDescr, n.PortID),
				Medium: "wired", Source: "lldp", Networks: portNets(local, n.LocalPortIdx)})
		}
	}

	// 3. clients, and unmanaged switches inferred from shared ports
	type portKey struct {
		mac  string
		port int
	}
	// A port with exactly one LLDP neighbour that is not adopted: clients the controller
	// sees on that port really sit behind the neighbour, so hang them off it.
	behind := map[portKey]string{}
	behindCount := map[portKey]int{}
	for _, r := range devs {
		me := inv.NormMAC(r.MAC)
		for _, n := range r.LLDPTable {
			nb := inv.NormMAC(n.ChassisID)
			if d, ok := byMAC[nb]; ok && !d.Managed && n.LocalPortIdx > 0 {
				k := portKey{me, n.LocalPortIdx}
				behind[k] = nb
				behindCount[k]++
			}
		}
	}
	wiredOnPort := map[portKey][]int{}
	for _, r := range clients {
		mac := inv.NormMAC(r.MAC)
		if d, isInfra := byMAC[mac]; isInfra {
			// an LLDP neighbour that also shows up as a client: enrich it instead
			if d.IP == "" {
				d.IP = r.IP
			}
			if d.Network == "" {
				d.Network = ix.client(r)
			}
			if d.Make == "unknown" && r.OUI != "" {
				d.Make = r.OUI
			}
			continue
		}
		c := inv.Client{
			MAC: mac, Name: firstNonEmpty(r.Name, r.Hostname, r.MAC), IP: r.IP, Vendor: r.OUI,
			Wired: r.IsWired, Network: r.Network, VLAN: r.VLAN, SSID: r.ESSID,
			NetworkID: ix.client(r),
		}
		if n, ok := ix.byID[c.NetworkID]; ok {
			c.Network = n.Name
			if c.VLAN == 0 {
				c.VLAN = n.VLAN
			}
		}
		if r.IsWired {
			sw := inv.NormMAC(r.SwMAC)
			c.ParentID = sw
			if d, ok := byMAC[sw]; ok {
				c.ParentPort = portName(d, r.SwPort)
			}
			if nb, ok := behind[portKey{sw, r.SwPort}]; ok && behindCount[portKey{sw, r.SwPort}] == 1 {
				c.ParentID, c.ParentPort = nb, ""
			}
			if _, ok := byMAC[sw]; ok && r.SwPort > 0 {
				c.SwitchMAC, c.SwitchPort = sw, r.SwPort
			}
			if r.SwPort > 0 && !uplinkPorts[sw+"#"+strconv.Itoa(r.SwPort)] {
				k := portKey{sw, r.SwPort}
				wiredOnPort[k] = append(wiredOnPort[k], len(snap.Clients))
			}
		} else {
			c.ParentID = inv.NormMAC(r.APMAC)
			c.ParentPort = r.ESSID
			c.APMAC = c.ParentID
			c.Signal, c.Band, c.Channel = r.Signal, bandOf(r.Radio), r.Channel
		}
		snap.Clients = append(snap.Clients, c)
	}

	keys := make([]portKey, 0, len(wiredOnPort))
	for k := range wiredOnPort {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].mac != keys[j].mac {
			return keys[i].mac < keys[j].mac
		}
		return keys[i].port < keys[j].port
	})
	for _, k := range keys {
		idxs := wiredOnPort[k]
		parent, ok := byMAC[k.mac]
		if len(idxs) < 2 || !ok {
			continue
		}
		id := fmt.Sprintf("inferred:%s:%d", k.mac, k.port)
		pn := portName(parent, k.port)
		byMAC[id] = &inv.Device{
			ID: id, Name: fmt.Sprintf("Unmanaged switch on %s %s", parent.Name, pn),
			Kind: inv.KindUnmanaged, Make: "unknown", Model: "unmanaged switch or hub",
			Online: true, Discovery: inv.SourceInferred,
			Detail: fmt.Sprintf("%d wired clients share %s on %s", len(idxs), pn, parent.Name),
			Target: target, SeenAt: now,
		}
		order = append(order, id)
		addLink(inv.Link{A: k.mac, APort: pn, B: id, Medium: "wired", Source: "inferred", Networks: portNets(parent, k.port)})
		for _, i := range idxs {
			snap.Clients[i].ParentID = id
			snap.Clients[i].ParentPort = ""
		}
	}

	for _, c := range snap.Clients {
		if d, ok := byMAC[c.ParentID]; ok {
			d.Clients++
		}
	}
	// mark ports that lead to other network devices, so they are never treated as client ports
	for _, r := range devs {
		mac := inv.NormMAC(r.MAC)
		d, ok := byMAC[mac]
		if !ok {
			continue
		}
		for i := range d.Ports {
			p := &d.Ports[i]
			if p.Uplink || uplinkPorts[mac+"#"+strconv.Itoa(p.Index)] {
				p.Infra = true
			}
		}
	}
	for _, id := range order {
		snap.Devices = append(snap.Devices, *byMAC[id])
	}
	snap.WiFi = buildWiFi(target, devs, clients, cfg, ix)
	return snap
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// ---- Integration API fallback (API key, limited detail) ----

type integSite struct {
	ID                string `json:"id"`
	InternalReference string `json:"internalReference"`
	Name              string `json:"name"`
}

type integDevice struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Model           string   `json:"model"`
	MACAddress      string   `json:"macAddress"`
	IPAddress       string   `json:"ipAddress"`
	State           string   `json:"state"`
	FirmwareVersion string   `json:"firmwareVersion"`
	Features        []string `json:"features"`
}

type integClient struct {
	Type           string `json:"type"`
	Name           string `json:"name"`
	MACAddress     string `json:"macAddress"`
	IPAddress      string `json:"ipAddress"`
	UplinkDeviceID string `json:"uplinkDeviceId"`
}

type integPage[T any] struct {
	Data []T `json:"data"`
}

func collectIntegration(ctx context.Context, c *client, target string) (*inv.Snapshot, error) {
	const base = "/proxy/network/integration/v1"
	var sites integPage[integSite]
	if err := c.req(ctx, http.MethodGet, base+"/sites?limit=50", nil, &sites); err != nil {
		return nil, err
	}
	var siteID string
	for _, s := range sites.Data {
		if s.InternalReference == c.site || s.Name == c.site || siteID == "" {
			siteID = s.ID
		}
	}
	if siteID == "" {
		return nil, fmt.Errorf("no sites visible to this API key")
	}
	var devs integPage[integDevice]
	if err := c.req(ctx, http.MethodGet, base+"/sites/"+siteID+"/devices?limit=200", nil, &devs); err != nil {
		return nil, err
	}
	var cls integPage[integClient]
	if err := c.req(ctx, http.MethodGet, base+"/sites/"+siteID+"/clients?limit=200", nil, &cls); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	snap := &inv.Snapshot{Target: target, TakenAt: now}
	idToMAC := map[string]string{}
	for _, d := range devs.Data {
		mac := inv.NormMAC(d.MACAddress)
		idToMAC[d.ID] = mac
		kind := inv.KindUnknown
		for _, f := range d.Features {
			switch strings.ToLower(f) {
			case "switching":
				if kind == inv.KindUnknown {
					kind = inv.KindSwitch
				}
			case "accesspoint":
				kind = inv.KindAP
			case "gateway":
				kind = inv.KindGateway
			}
		}
		snap.Devices = append(snap.Devices, inv.Device{
			ID: mac, MAC: mac, Name: d.Name, Kind: kind, Make: "Ubiquiti",
			Model: ModelName(d.Model, ""), ModelCode: d.Model, IP: d.IPAddress, Firmware: d.FirmwareVersion,
			Online: strings.EqualFold(d.State, "online"), Managed: true,
			Discovery: inv.SourceController, Detail: "via Integration API (no uplink or LLDP detail)",
			Target: target, SeenAt: now,
		})
	}
	for _, cl := range cls.Data {
		snap.Clients = append(snap.Clients, inv.Client{
			MAC: inv.NormMAC(cl.MACAddress), Name: firstNonEmpty(cl.Name, cl.MACAddress), IP: cl.IPAddress,
			Wired: strings.EqualFold(cl.Type, "wired"), ParentID: idToMAC[cl.UplinkDeviceID],
		})
	}
	return snap, nil
}

// gatewayDNS is the DNS servers the site's gateway says it uses upstream: what the
// internet provider handed out when the WAN's DNS is on auto.
func gatewayDNS(devs []rawDevice) []string {
	for _, d := range devs {
		if kindFor(d.Type) != inv.KindGateway {
			continue
		}
		if d.WAN1 != nil && len(d.WAN1.DNS) > 0 {
			return d.WAN1.DNS
		}
		if len(d.Uplink.Nameservers) > 0 {
			return d.Uplink.Nameservers
		}
	}
	return nil
}
