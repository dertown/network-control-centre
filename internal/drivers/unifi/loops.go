package unifi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	inv "github.com/dertown/network-control-centre/internal/inventory"
)

// Loop detection.
//
// A switching loop is a cable (or a chain of cables and switches) that leads from a switch
// port back into the network it already sits in. NCC finds them four ways:
//
//  1. Self loops and parallel links. Every cable NCC can see between infrastructure devices,
//     from uplinks and LLDP, is a pair of port endpoints. Endpoints that are the same cable,
//     or the same unmanaged switch (LLDP passes through most of them), are merged into one
//     "segment". A device with two different ports in one segment is looped: two of its
//     ports reach each other, directly or through a dumb switch. A switch that hears its own
//     LLDP is the classic case of a cable plugged from one port into another.
//  2. Rings. Devices and segments form a graph; any cycle in it is a ring of cables, for
//     example gateway → switch A → switch B → gateway.
//  3. Spanning tree. A port UniFi reports as blocking or discarding is one STP shut because
//     it found a second path. When a loop from 1 or 2 has a blocked port, STP is containing
//     it and the loop is a warning; when nothing is blocked it is critical. A blocked port
//     NCC cannot explain is reported on its own.
//  4. Controller events. UniFi logs loop protection, STP blocking and MAC address flapping
//     events; those from the last 24 hours are reported with the switch and port they name.
//
// Link aggregation (LAG) members are treated as one port, so a LAG is not a loop.

// rawEvent is a UniFi event or alarm (stat/event, stat/alarm). Only the fields used are read.
type rawEvent struct {
	Key      string  `json:"key"`
	Msg      string  `json:"msg"`
	Message  string  `json:"message"`
	Sw       string  `json:"sw"`
	SwName   string  `json:"sw_name"`
	Port     flexInt `json:"port"`
	Time     int64   `json:"time"` // milliseconds since the epoch
	Datetime string  `json:"datetime"`
}

func (e rawEvent) text() string { return firstNonEmpty(e.Msg, e.Message) }

func (e rawEvent) when() time.Time {
	if e.Time > 0 {
		return time.UnixMilli(e.Time).UTC()
	}
	if t, err := time.Parse(time.RFC3339, e.Datetime); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// loopEventKind says whether an event is about a loop, and which kind.
func loopEventKind(e rawEvent) (kind string, critical bool) {
	k := strings.ToLower(e.Key)
	m := strings.ToLower(e.text())
	switch {
	case strings.Contains(k, "loop") || strings.Contains(m, "loop"):
		return "loop", true
	case strings.Contains(k, "flap") || strings.Contains(m, "flapping") || strings.Contains(m, "mac move"):
		return "flap", true
	case strings.Contains(k, "stpportblocking") || strings.Contains(k, "stp") && strings.Contains(k, "block") ||
		strings.Contains(m, "stp") && strings.Contains(m, "block"):
		return "stp", false
	}
	return "", false
}

// collectEvents fetches recent events and alarms, best effort: a console that refuses or
// does not have an endpoint just contributes nothing.
func collectEvents(ctx context.Context, c *client) []rawEvent {
	var out []rawEvent
	if ev, err := getList[rawEvent](ctx, c, "stat/event?within=24&_limit=500"); err == nil {
		out = append(out, ev...)
	}
	if al, err := getList[rawEvent](ctx, c, "stat/alarm?archived=false"); err == nil {
		out = append(out, al...)
	}
	// Network 8 and later move events to the v2 system log; its rows carry "key" and
	// "message" too. The shape varies between versions, so it is decoded loosely.
	now := time.Now()
	body := map[string]any{
		"timestampFrom": now.Add(-24 * time.Hour).UnixMilli(), "timestampTo": now.UnixMilli(),
		"pageSize": 200, "pageNumber": 0,
	}
	var raw json.RawMessage
	if err := c.req(ctx, http.MethodPost, c.v2Path("system-log/all"), body, &raw); err == nil {
		out = append(out, looseEvents(raw)...)
	}
	return out
}

// looseEvents pulls event-like objects out of any JSON document: objects with a "key" and
// a "msg" or "message". Parameters such as the switch MAC and port are looked for in the
// object and in a "parameters" object, where values may be plain or {"id": ..., "name": ...}.
func looseEvents(raw json.RawMessage) []rawEvent {
	var doc any
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	var out []rawEvent
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if depth > 6 {
			return
		}
		switch t := v.(type) {
		case []any:
			for _, x := range t {
				walk(x, depth+1)
			}
		case map[string]any:
			key, _ := t["key"].(string)
			msg, _ := t["message"].(string)
			if msg == "" {
				msg, _ = t["msg"].(string)
			}
			if key != "" && msg != "" {
				e := rawEvent{Key: key, Message: msg}
				params, _ := t["parameters"].(map[string]any)
				look := func(names ...string) string {
					for _, src := range []map[string]any{t, params} {
						for _, n := range names {
							if s := scalar(src[n]); s != "" {
								return s
							}
						}
					}
					return ""
				}
				e.Sw = look("sw", "DEVICE", "device", "SWITCH", "switch")
				e.SwName = look("sw_name", "DEVICE_NAME", "device_name")
				if p, err := strconv.Atoi(look("port", "PORT", "port_idx")); err == nil {
					e.Port = flexInt(p)
				}
				switch ts := t["timestamp"].(type) {
				case float64:
					e.Time = int64(ts)
				}
				if tm, ok := t["time"].(float64); ok && e.Time == 0 {
					e.Time = int64(tm)
				}
				out = append(out, e)
				return
			}
			for _, x := range t {
				walk(x, depth+1)
			}
		}
	}
	walk(doc, 0)
	return out
}

// scalar returns a JSON value as a string; {"id": x} objects give their id (a MAC for devices).
func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.Itoa(int(t))
	case map[string]any:
		for _, k := range []string{"id", "mac", "name"} {
			if s, ok := t[k].(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

var portNumRE = regexp.MustCompile(`(?i)port\s*#?\s*(\d+)`)
var trailingNumRE = regexp.MustCompile(`(\d+)$`)

// endpoint is one end of a cable: a device and its port. Port 0 means unknown.
type endpoint struct {
	mac  string
	port int
	peer string // for unknown ports: the device at the other end, so unknowns stay apart
}

func (e endpoint) key() string {
	if e.port > 0 {
		return e.mac + "#" + strconv.Itoa(e.port)
	}
	return e.mac + "?" + e.peer
}

type observation struct {
	a, b   endpoint
	source string // uplink | lldp
	speed  int
}

type unionFind map[string]string

func (u unionFind) find(x string) string {
	if _, ok := u[x]; !ok {
		u[x] = x
	}
	for u[x] != x {
		u[x] = u[u[x]]
		x = u[x]
	}
	return x
}

func (u unionFind) union(a, b string) bool {
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return false
	}
	u[ra] = rb
	return true
}

// DetectLoops finds switching loops in one poll. snap supplies device names (including LLDP
// neighbours that are not adopted); events are the controller's recent events and alarms.
func DetectLoops(target string, devs []rawDevice, events []rawEvent, snap *inv.Snapshot, now time.Time) []inv.Loop {
	adopted := map[string]*rawDevice{}
	for i := range devs {
		if m := inv.NormMAC(devs[i].MAC); m != "" {
			adopted[m] = &devs[i]
		}
	}
	names := map[string]string{}
	if snap != nil {
		for _, d := range snap.Devices {
			names[d.ID] = d.Name
		}
	}
	for m, d := range adopted {
		if names[m] == "" {
			names[m] = firstNonEmpty(d.Name, d.MAC)
		}
	}
	nameOf := func(mac string) string {
		if n := names[mac]; n != "" {
			return n
		}
		return mac
	}
	// port lookups on adopted devices
	portOf := func(mac string, idx int) *rawPort {
		d := adopted[mac]
		if d == nil || idx <= 0 {
			return nil
		}
		for i := range d.PortTable {
			if d.PortTable[i].PortIdx == idx {
				return &d.PortTable[i]
			}
		}
		return nil
	}
	portName := func(mac string, idx int) string {
		if idx <= 0 {
			return ""
		}
		if p := portOf(mac, idx); p != nil && p.Name != "" {
			return p.Name
		}
		return "Port " + strconv.Itoa(idx)
	}
	// lagGroup collapses the members of a link aggregation into one port.
	lagGroup := func(mac string, idx int) int {
		if p := portOf(mac, idx); p != nil && p.AggregatedBy > 0 {
			return int(p.AggregatedBy)
		}
		return idx
	}
	stpOf := func(mac string, idx int) string {
		if p := portOf(mac, idx); p != nil {
			return strings.ToLower(strings.TrimSpace(p.StpState))
		}
		return ""
	}
	blocked := func(mac string, idx int) bool {
		switch stpOf(mac, idx) {
		case "blocking", "discarding", "broken", "loop_detected", "loop-detected":
			return true
		}
		return false
	}
	// remotePort reads the far end's port from an LLDP port id or description, when the far
	// end is adopted and has that port.
	remotePort := func(mac string, ids ...string) int {
		d := adopted[mac]
		if d == nil {
			return 0
		}
		for _, id := range ids {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			for _, p := range d.PortTable {
				if p.Name != "" && strings.EqualFold(p.Name, id) {
					return p.PortIdx
				}
			}
			var n string
			if m := portNumRE.FindStringSubmatch(id); m != nil {
				n = m[1]
			} else if m := trailingNumRE.FindStringSubmatch(id); m != nil && len(id) <= 6 {
				n = m[1] // "5", "eth5", "g5"
			}
			if v, err := strconv.Atoi(n); err == nil && portOf(mac, v) != nil {
				return v
			}
		}
		return 0
	}

	// 1. every cable observation between infrastructure devices
	var obs []observation
	for i := range devs {
		r := &devs[i]
		me := inv.NormMAC(r.MAC)
		up := inv.NormMAC(r.Uplink.UplinkMAC)
		if me != "" && up != "" && up != me && !strings.EqualFold(r.Uplink.Type, "wireless") {
			if _, ok := adopted[up]; ok {
				obs = append(obs, observation{
					a: endpoint{mac: me, port: r.Uplink.PortIdx, peer: up}, b: endpoint{mac: up, port: r.Uplink.UplinkRemotePort, peer: me},
					source: "uplink", speed: r.Uplink.Speed,
				})
			}
		}
		for _, n := range r.LLDPTable {
			if n.IsWired != nil && !*n.IsWired {
				continue
			}
			nb := inv.NormMAC(n.ChassisID)
			if nb == "" || me == "" || n.LocalPortIdx <= 0 {
				continue
			}
			obs = append(obs, observation{
				a:      endpoint{mac: me, port: n.LocalPortIdx, peer: nb},
				b:      endpoint{mac: nb, port: remotePort(nb, n.PortID, n.PortDescr), peer: me},
				source: "lldp",
			})
		}
	}
	// Fill unknown far ends from the far device's own view: if B sees A on exactly one
	// port, that is the port. For a switch hearing itself, the other port is the far end.
	seenOn := map[[2]string]map[int]bool{} // [local, remote] -> local ports
	for _, o := range obs {
		for _, e := range [][2]endpoint{{o.a, o.b}, {o.b, o.a}} {
			if e[0].port > 0 {
				k := [2]string{e[0].mac, e[1].mac}
				if seenOn[k] == nil {
					seenOn[k] = map[int]bool{}
				}
				seenOn[k][lagGroup(e[0].mac, e[0].port)] = true
			}
		}
	}
	for i := range obs {
		o := &obs[i]
		if o.b.port > 0 {
			continue
		}
		ports := seenOn[[2]string{o.b.mac, o.a.mac}]
		if o.a.mac == o.b.mac {
			if len(ports) == 2 {
				for p := range ports {
					if p != lagGroup(o.a.mac, o.a.port) {
						o.b.port = p
					}
				}
			}
			continue
		}
		if len(ports) == 1 {
			for p := range ports {
				o.b.port = p
			}
		}
	}

	// 2. merge endpoints into segments
	uf := unionFind{}
	norm := func(e endpoint) endpoint {
		if e.port > 0 {
			e.port = lagGroup(e.mac, e.port)
		}
		return e
	}
	for i := range obs {
		obs[i].a, obs[i].b = norm(obs[i].a), norm(obs[i].b)
		uf.union(obs[i].a.key(), obs[i].b.key())
	}
	type segment struct {
		id    string
		ports map[string]map[int]bool // device -> known ports in the segment
		obs   []int
	}
	segs := map[string]*segment{}
	var segOrder []string
	for i, o := range obs {
		root := uf.find(o.a.key())
		s := segs[root]
		if s == nil {
			s = &segment{id: root, ports: map[string]map[int]bool{}}
			segs[root] = s
			segOrder = append(segOrder, root)
		}
		s.obs = append(s.obs, i)
		for _, e := range []endpoint{o.a, o.b} {
			if s.ports[e.mac] == nil {
				s.ports[e.mac] = map[int]bool{}
			}
			if e.port > 0 {
				s.ports[e.mac][e.port] = true
			}
		}
	}
	sort.Strings(segOrder)

	lp := func(mac string, port int) inv.LoopPort {
		return inv.LoopPort{Device: mac, DeviceName: nameOf(mac), Port: port, PortName: portName(mac, port), STP: stpOf(mac, port)}
	}
	sortedPorts := func(m map[int]bool) []int {
		out := make([]int, 0, len(m))
		for p := range m {
			out = append(out, p)
		}
		sort.Ints(out)
		return out
	}
	sortedMACs := func(m map[string]map[int]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	link := func(a string, ap int, b string, bp int, source string) inv.Link {
		return inv.Link{A: a, APort: portName(a, ap), B: b, BPort: portName(b, bp), Medium: "wired", Source: source}
	}

	var loops []inv.Loop
	explained := map[string]bool{} // "mac#port" covered by a finding
	finish := func(l inv.Loop) {
		anyBlocked := false
		var blockedNames []string
		for _, p := range l.Ports {
			explained[p.Device+"#"+strconv.Itoa(p.Port)] = true
			if p.Port > 0 && blocked(p.Device, p.Port) {
				anyBlocked = true
				blockedNames = append(blockedNames, p.PortName+" on "+p.DeviceName)
			}
		}
		if anyBlocked {
			l.Severity = inv.LoopWarning
			l.Detail = strings.TrimSpace(l.Detail + " Spanning tree is blocking " + strings.Join(blockedNames, ", ") +
				", so the loop is contained for now. Remove the extra cable unless the redundant path is intended.")
		} else {
			l.Severity = inv.LoopCritical
			l.Detail = strings.TrimSpace(l.Detail + " No port on this loop is blocked by spanning tree, so traffic can circle " +
				"it and flood the network (a broadcast storm). Unplug one of the cables listed.")
		}
		l.ID = loopID(l)
		l.Target = target
		loops = append(loops, l)
	}

	// self loops and parallel links: one device, two ports, one segment
	for _, id := range segOrder {
		s := segs[id]
		for _, mac := range sortedMACs(s.ports) {
			ports := sortedPorts(s.ports[mac])
			if len(ports) < 2 {
				continue
			}
			others := []string{}
			for _, m := range sortedMACs(s.ports) {
				if m != mac {
					others = append(others, m)
				}
			}
			l := inv.Loop{}
			var pn []string
			for _, p := range ports {
				l.Ports = append(l.Ports, lp(mac, p))
				pn = append(pn, portName(mac, p))
			}
			for i := 1; i < len(ports); i++ {
				if len(others) == 0 {
					l.Links = append(l.Links, link(mac, ports[0], mac, ports[i], "loop"))
				}
			}
			if len(others) == 0 {
				l.Kind = inv.LoopSelf
				l.Summary = fmt.Sprintf("%s: %s loop back to each other", nameOf(mac), joinAnd(pn))
				l.Detail = fmt.Sprintf("%s hears its own LLDP on %s: the ports are cabled to each other, directly or through an unmanaged switch.",
					nameOf(mac), joinAnd(pn))
			} else {
				l.Kind = inv.LoopParallel
				var on []string
				for _, m := range others {
					on = append(on, nameOf(m))
					for _, p := range sortedPorts(s.ports[m]) {
						l.Ports = append(l.Ports, lp(m, p))
					}
					theirs := sortedPorts(s.ports[m])
					for i, p := range ports {
						bp := 0
						if i < len(theirs) {
							bp = theirs[i]
						}
						l.Links = append(l.Links, link(mac, p, m, bp, "loop"))
					}
				}
				l.Summary = fmt.Sprintf("%s: %s all lead to %s", nameOf(mac), joinAnd(pn), joinAnd(on))
				l.Detail = fmt.Sprintf("%s reaches %s on more than one port (%s), so frames sent out of one come back in on the other.",
					nameOf(mac), joinAnd(on), joinAnd(pn))
			}
			finish(l)
		}
	}

	// rings: cycles in the device–segment graph
	type edge struct{ dev, seg string }
	adj := map[string][]string{}
	guf := unionFind{}
	seenRing := map[string]bool{}
	for _, id := range segOrder {
		s := segs[id]
		for _, mac := range sortedMACs(s.ports) {
			dn, sn := "d:"+mac, "s:"+id
			if guf.union(dn, sn) {
				adj[dn] = append(adj[dn], sn)
				adj[sn] = append(adj[sn], dn)
				continue
			}
			path := bfsPath(adj, sn, dn) // sn ... dn, then the new edge dn–sn closes the ring
			if len(path) < 3 {
				continue
			}
			var devsOn []string
			l := inv.Loop{Kind: inv.LoopCycle}
			// walk the ring: device, segment, device ... and through sn back to the start
			ring := append(append([]string(nil), path...), sn, path[1])
			for i := 1; i+2 < len(ring); i++ {
				if !strings.HasPrefix(ring[i], "d:") || !strings.HasPrefix(ring[i+1], "s:") {
					continue
				}
				a, b := strings.TrimPrefix(ring[i], "d:"), strings.TrimPrefix(ring[i+2], "d:")
				seg := segs[strings.TrimPrefix(ring[i+1], "s:")]
				ap, bp := firstPort(seg.ports[a]), firstPort(seg.ports[b])
				l.Links = append(l.Links, link(a, ap, b, bp, "loop"))
				l.Ports = append(l.Ports, lp(a, ap), lp(b, bp))
			}
			for _, n := range path {
				if strings.HasPrefix(n, "d:") {
					devsOn = append(devsOn, nameOf(strings.TrimPrefix(n, "d:")))
				}
			}
			key := append([]string(nil), devsOn...)
			sort.Strings(key)
			if seenRing[strings.Join(key, "|")] {
				continue
			}
			seenRing[strings.Join(key, "|")] = true
			l.Ports = dedupPorts(l.Ports)
			var hops []string
			for _, k := range l.Links {
				hops = append(hops, fmt.Sprintf("%s %s → %s %s", nameOf(k.A), orUnknown(k.APort), nameOf(k.B), orUnknown(k.BPort)))
			}
			l.Summary = fmt.Sprintf("Ring of cables through %s", joinAnd(devsOn))
			l.Detail = "The cables " + strings.Join(hops, ", ") + " form a closed ring."
			finish(l)
		}
	}

	// ports spanning tree has blocked that no finding above explains
	for i := range devs {
		me := inv.NormMAC(devs[i].MAC)
		for _, p := range devs[i].PortTable {
			if !blocked(me, p.PortIdx) || explained[me+"#"+strconv.Itoa(p.PortIdx)] {
				continue
			}
			pn := portName(me, p.PortIdx)
			l := inv.Loop{Kind: inv.LoopSTP, Severity: inv.LoopWarning, Ports: []inv.LoopPort{lp(me, p.PortIdx)}, Target: target}
			var nbs []string
			for _, n := range devs[i].LLDPTable {
				if n.LocalPortIdx == p.PortIdx {
					nbs = append(nbs, firstNonEmpty(nameOf(inv.NormMAC(n.ChassisID)), n.name()))
				}
			}
			l.Summary = fmt.Sprintf("%s: spanning tree is blocking %s", nameOf(me), pn)
			l.Detail = fmt.Sprintf("%s on %s is %s: spanning tree found a second path from this port back into the network and shut it.", pn, nameOf(me), stpOf(me, p.PortIdx))
			if len(nbs) > 0 {
				l.Detail += " LLDP sees " + joinAnd(nbs) + " on this port."
			} else {
				l.Detail += " NCC cannot see what is on the other end, which usually means an unmanaged switch, or a cable from this port back to another port behind one."
			}
			l.ID = loopID(l)
			loops = append(loops, l)
		}
	}

	// controller events from the last 24 hours, one finding per switch, port and kind
	type evKey struct {
		kind, sw string
		port     int
	}
	evs := map[evKey]*inv.Loop{}
	var evOrder []evKey
	for _, e := range events {
		kind, critical := loopEventKind(e)
		if kind == "" {
			continue
		}
		at := e.when()
		if !at.IsZero() && now.Sub(at) > 24*time.Hour {
			continue
		}
		sw := inv.NormMAC(e.Sw)
		port := int(e.Port)
		if port == 0 {
			if m := portNumRE.FindStringSubmatch(e.text()); m != nil {
				port, _ = strconv.Atoi(m[1])
			}
		}
		k := evKey{kind, sw, port}
		if l, ok := evs[k]; ok {
			l.Count++
			if !at.IsZero() && (l.SeenAt == nil || at.After(*l.SeenAt)) {
				t := at
				l.SeenAt = &t
			}
			continue
		}
		name := firstNonEmpty(names[sw], e.SwName, sw, "a switch")
		l := &inv.Loop{Kind: inv.LoopEvent, Severity: inv.LoopWarning, Count: 1, Target: target, Detail: e.text()}
		if critical {
			l.Severity = inv.LoopCritical
		}
		if !at.IsZero() {
			t := at
			l.SeenAt = &t
		}
		if sw != "" {
			p := inv.LoopPort{Device: sw, DeviceName: name, Port: port, STP: stpOf(sw, port)}
			if port > 0 {
				p.PortName = portName(sw, port)
			}
			l.Ports = []inv.LoopPort{p}
		}
		where := name
		if port > 0 {
			where += " " + portName(sw, port)
		}
		switch kind {
		case "loop":
			l.Summary = "UniFi detected a loop on " + where
		case "flap":
			l.Summary = "MAC address flapping on " + where
			l.Detail = strings.TrimSpace(l.Detail + " A MAC address moving back and forth between ports is a sign of a loop.")
		default:
			l.Summary = "Spanning tree blocked " + where
		}
		evs[k] = l
		evOrder = append(evOrder, k)
	}
	for _, k := range evOrder {
		l := evs[k]
		// an event about a port NCC already explained joins that finding
		if merged := mergeEvent(loops, l, k.sw, k.port); merged {
			continue
		}
		l.ID = loopID(*l)
		loops = append(loops, *l)
	}

	sort.SliceStable(loops, func(i, j int) bool {
		return loops[i].Severity == inv.LoopCritical && loops[j].Severity != inv.LoopCritical
	})
	return loops
}

// mergeEvent adds a controller event to the cabling finding that already covers its switch
// port, so one loop is not listed twice. It reports whether it found one.
func mergeEvent(loops []inv.Loop, e *inv.Loop, sw string, port int) bool {
	if sw == "" || port == 0 {
		return false
	}
	for i := range loops {
		l := &loops[i]
		if l.Kind == inv.LoopEvent || l.Kind == inv.LoopSTP {
			continue
		}
		for _, p := range l.Ports {
			if p.Device == sw && p.Port == port {
				l.Count += e.Count
				if e.SeenAt != nil && (l.SeenAt == nil || e.SeenAt.After(*l.SeenAt)) {
					l.SeenAt = e.SeenAt
				}
				l.Detail = strings.TrimSpace(l.Detail + " UniFi also logged: \"" + e.Detail + "\"")
				if e.Severity == inv.LoopCritical {
					l.Severity = inv.LoopCritical
				}
				return true
			}
		}
	}
	return false
}

func bfsPath(adj map[string][]string, from, to string) []string {
	prev := map[string]string{from: ""}
	q := []string{from}
	for len(q) > 0 {
		n := q[0]
		q = q[1:]
		if n == to {
			var path []string
			for x := to; x != ""; x = prev[x] {
				path = append([]string{x}, path...)
			}
			return path
		}
		for _, m := range adj[n] {
			if _, ok := prev[m]; !ok {
				prev[m] = n
				q = append(q, m)
			}
		}
	}
	return nil
}

func firstPort(m map[int]bool) int {
	best := 0
	for p := range m {
		if best == 0 || p < best {
			best = p
		}
	}
	return best
}

func dedupPorts(ps []inv.LoopPort) []inv.LoopPort {
	seen := map[string]bool{}
	var out []inv.LoopPort
	for _, p := range ps {
		k := p.Device + "#" + strconv.Itoa(p.Port)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	return out
}

func loopID(l inv.Loop) string {
	h := sha256.New()
	h.Write([]byte(l.Kind))
	var ks []string
	for _, p := range l.Ports {
		ks = append(ks, p.Device+"#"+strconv.Itoa(p.Port))
	}
	sort.Strings(ks)
	h.Write([]byte(strings.Join(ks, ",")))
	h.Write([]byte(l.Summary))
	return "loop-" + hex.EncodeToString(h.Sum(nil))[:12]
}

func joinAnd(s []string) string {
	switch len(s) {
	case 0:
		return ""
	case 1:
		return s[0]
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}

func orUnknown(s string) string {
	if s == "" {
		return "(port unknown)"
	}
	return s
}
