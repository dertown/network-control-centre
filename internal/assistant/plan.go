package assistant

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/iot"
)

// Step kinds.
const (
	StepCreateVLAN = "create_vlan"  // create a VLAN network on a router
	StepMove       = "move_clients" // move clients to a network
	StepCreateZone = "create_zone"  // create a DNS zone
	StepAssignZone = "assign_zone"  // make a network hand out a DNS zone as its domain
)

// Plan statuses.
const (
	PlanProposed  = "proposed"
	PlanDeploying = "deploying"
	PlanDeployed  = "deployed"
	PlanPartial   = "partial"
	PlanFailed    = "failed"
	PlanDiscarded = "discarded"
)

// Plan is a set of changes the assistant proposes. Nothing in it is applied until a person
// picks the steps and confirms.
type Plan struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	Provider  string    `json:"provider"`
	Model     string    `json:"model,omitempty"`
	Goal      string    `json:"goal,omitempty"`
	Summary   string    `json:"summary"`
	Notes     []string  `json:"notes"`
	Steps     []Step    `json:"steps"`
	// Source is "ai" when the model's plan is used, "rules" when NCC's own rules made it
	// (no provider chosen, or the model's answer could not be used: see AIError).
	Source     string     `json:"source"`
	AIError    string     `json:"ai_error,omitempty"`
	Status     string     `json:"status"`
	DeployedAt *time.Time `json:"deployed_at,omitempty"`
	DeployedBy string     `json:"deployed_by,omitempty"`
	// Picture is what was sent to the model (kept so the page can show it).
	Picture string `json:"-"`
}

// Step is one change.
type Step struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Title string `json:"title"`
	Why   string `json:"why"`

	RouterID    int64  `json:"router_id,omitempty"`
	RouterName  string `json:"router_name,omitempty"`
	DNSServerID int64  `json:"dns_server_id,omitempty"`
	DNSServer   string `json:"dns_server,omitempty"`
	// Network is the new network (create_vlan).
	Network *drivers.NetworkSpec `json:"network,omitempty"`
	// NetworkID is the network clients move to or a zone is assigned to: an existing id, or
	// "new:<name>" for a network an earlier step creates.
	NetworkID   string       `json:"network_id,omitempty"`
	NetworkName string       `json:"network_name,omitempty"`
	Clients     []StepClient `json:"clients,omitempty"`
	Zone        string       `json:"zone,omitempty"`

	Warnings []string `json:"warnings"`
	// Problem says why the step cannot be applied as it is; such steps can't be picked.
	Problem string `json:"problem,omitempty"`
	// Recommended steps are picked to begin with.
	Recommended bool    `json:"recommended"`
	Result      *Result `json:"result,omitempty"`
}

// StepClient is one client a move step moves.
type StepClient struct {
	MAC  string `json:"mac"`
	Name string `json:"name"`
	IP   string `json:"ip,omitempty"`
	From string `json:"from,omitempty"`
	Type string `json:"type,omitempty"`
	Via  string `json:"via,omitempty"`
	// Blocked says why NCC can't move it (it stays where it is).
	Blocked string `json:"blocked,omitempty"`
	// AlongWith is set when it was not asked for but shares a switch port with one that was.
	AlongWith bool `json:"along_with,omitempty"`
}

// Result is what happened when a step was deployed.
type Result struct {
	State   string    `json:"state"` // ok | failed | skipped
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

// Answer is the plan in the shape the model writes it (and NCC's own rules produce it).
type Answer struct {
	Summary string       `json:"summary"`
	Notes   []string     `json:"notes"`
	Steps   []AnswerStep `json:"steps"`
}

// AnswerStep is one proposed change as the model writes it.
type AnswerStep struct {
	Kind        string   `json:"kind"`
	RouterID    int64    `json:"router_id,omitempty"`
	DNSServerID int64    `json:"dns_server_id,omitempty"`
	Name        string   `json:"name,omitempty"`    // create_vlan
	VLAN        int      `json:"vlan,omitempty"`    // create_vlan
	Gateway     string   `json:"gateway,omitempty"` // create_vlan: router address with prefix, e.g. 192.168.30.1/24
	Isolated    *bool    `json:"isolated,omitempty"`
	Internet    *bool    `json:"internet_access,omitempty"`
	Network     string   `json:"network,omitempty"` // move_clients, assign_zone: network name or id
	MACs        []string `json:"macs,omitempty"`
	Zone        string   `json:"zone,omitempty"`
	Why         string   `json:"why"`
	Recommended *bool    `json:"recommended,omitempty"`
}

// Baseline is the plan NCC's own rules make: the starting point the model improves on, and
// the plan used when no model is available.
//
//   - IoT devices that are not on an IoT network (and that nobody said may stay) move to the
//     router's IoT network, which is created (isolated, with internet) when there is none.
//   - Devices that the internet reaches through a port forward belong in a DMZ; NCC proposes
//     one but doesn't pick it, because moving them changes their address and the forward.
//   - With a DNS server, each new network gets a zone under the internal domain (iot.<domain>,
//     dmz.<domain>) and hands it out as its domain.
func Baseline(p *Picture) Answer {
	a := Answer{Notes: []string{}, Steps: []AnswerStep{}}
	var r *Router
	for i := range p.Routers {
		if p.Routers[i].Snapshot != nil && (r == nil || (p.Routers[i].CanChange && !r.CanChange)) {
			r = &p.Routers[i]
		}
	}
	if r == nil {
		a.Summary = "NCC has not read a router yet, so there is nothing to plan."
		return a
	}
	planned := []inventory.Network{}
	existing := func() []inventory.Network {
		out := append([]inventory.Network{}, r.Snapshot.Networks...)
		return append(out, planned...)
	}
	yes, no := true, false
	newNet := func(name string, prefVLAN int, why string) string {
		spec := core.SuggestNetwork(existing())
		if prefVLAN > 0 {
			free := true
			for _, n := range existing() {
				if n.VLAN == prefVLAN {
					free = false
				}
			}
			if free {
				spec.VLAN = prefVLAN
				if g := freeSubnet(existing(), prefVLAN); g != "" {
					spec.Gateway = g
				}
			}
		}
		a.Steps = append(a.Steps, AnswerStep{Kind: StepCreateVLAN, RouterID: r.ID, Name: name, VLAN: spec.VLAN, Gateway: spec.Gateway,
			Isolated: &yes, Internet: &yes, Why: why})
		planned = append(planned, inventory.Network{ID: "new:" + name, Name: name, VLAN: spec.VLAN, Subnet: prefixOf(spec.Gateway)})
		return name
	}

	// IoT
	var iotNet *Net
	for i := range r.Networks {
		n := &r.Networks[i]
		if n.IoT && (iotNet == nil || strings.Contains(strings.ToLower(n.Name), "iot") && !strings.Contains(strings.ToLower(iotNet.Name), "iot")) {
			iotNet = n
		}
	}
	var movers []string
	types := map[string]int{}
	for _, c := range r.Clients {
		if c.IoTType == "" || c.NotIoT || c.KeepWhereItIs || len(c.Forwards) > 0 {
			continue
		}
		if n := r.network(c.NetworkID); n != nil && n.IoT {
			continue
		}
		movers = append(movers, c.MAC)
		types[c.IoTType]++
	}
	iotRef, iotCreated := "", false
	if iotNet != nil {
		iotRef = iotNet.Name
	}
	if len(movers) > 0 {
		if iotNet == nil {
			iotRef = newNet("IoT", 30, "There is no IoT network yet. Smart devices get their own VLAN, cut off from your computers and servers but still online, so a hacked camera or plug can't reach the rest of the network.")
			iotCreated = true
		}
		a.Steps = append(a.Steps, AnswerStep{Kind: StepMove, RouterID: r.ID, Network: iotRef, MACs: movers,
			Why: fmt.Sprintf("%s %s on your main networks. IoT devices rarely get security updates; keeping them on %s limits what an attacker can reach through one.",
				countTypes(types), isAre(len(movers)), iotRef)})
	} else if iotNet != nil {
		a.Notes = append(a.Notes, "Every IoT device NCC knows of is already on "+iotNet.Name+" or allowed to stay where it is.")
	} else {
		a.Notes = append(a.Notes, "NCC found no IoT devices among the clients. Add any it missed on the IoT devices page and plan again.")
	}

	// DMZ
	var dmzNet *Net
	for i := range r.Networks {
		if r.Networks[i].Zone == "dmz" {
			dmzNet = &r.Networks[i]
			break
		}
	}
	var exposed []string
	var exposedNames []string
	for _, c := range r.Clients {
		if len(c.Forwards) == 0 {
			continue
		}
		if n := r.network(c.NetworkID); n != nil && n.Zone == "dmz" {
			continue
		}
		exposed = append(exposed, c.MAC)
		exposedNames = append(exposedNames, c.Name)
	}
	dmzRef, dmzCreated := "", false
	if dmzNet != nil {
		dmzRef = dmzNet.Name
	}
	if len(exposed) > 0 {
		if dmzNet == nil {
			dmzRef = newNet("DMZ", 50, "Devices the internet can reach belong in a DMZ: if one is broken into, the attacker is stuck there instead of inside your network.")
			dmzCreated = true
		}
		a.Steps = append(a.Steps, AnswerStep{Kind: StepMove, RouterID: r.ID, Network: dmzRef, MACs: exposed, Recommended: &no,
			Why: fmt.Sprintf("%s %s reachable from the internet through port forwards. Not picked to begin with: moving changes the address, so the port forwards must be pointed at the new address afterwards.",
				strings.Join(exposedNames, ", "), isAre(len(exposed)))})
	}

	// DNS
	var srv *DNSServer
	for i := range p.DNS {
		if srv == nil || (p.DNS[i].CanCreateZones && !srv.CanCreateZones) {
			srv = &p.DNS[i]
		}
	}
	if srv != nil {
		zoneFor := func(label, netRef string) {
			if netRef == "" {
				return
			}
			z := dns.FQDN(label + "." + strings.TrimSuffix(p.Domain, "."))
			has := false
			for _, ez := range srv.Zones {
				if dns.FQDN(ez) == z {
					has = true
				}
			}
			if !has {
				a.Steps = append(a.Steps, AnswerStep{Kind: StepCreateZone, DNSServerID: srv.ID, Zone: z,
					Why: "A zone of its own for " + netRef + " keeps its device names apart (camera1." + strings.TrimSuffix(z, ".") + ") and lets you see at a glance which network a name belongs to."})
			}
			a.Steps = append(a.Steps, AnswerStep{Kind: StepAssignZone, RouterID: r.ID, Network: netRef, Zone: z,
				Why: "Devices on " + netRef + " are told their domain is " + strings.TrimSuffix(z, ".") + ", so short names resolve there."})
		}
		if iotRef != "" && (iotCreated || len(movers) > 0) {
			zoneFor("iot", iotRef)
		}
		if dmzRef != "" && dmzCreated {
			zoneFor("dmz", dmzRef)
		}
	} else if len(a.Steps) > 0 {
		a.Notes = append(a.Notes, "No DNS server is connected, so the plan has no DNS zones. Add PowerDNS in Settings to get iot and dmz zones too.")
	}

	switch {
	case len(a.Steps) == 0:
		a.Summary = "Your network already follows NCC's rules: nothing to change."
	default:
		parts := []string{}
		if len(movers) > 0 {
			parts = append(parts, fmt.Sprintf("move %d IoT device%s to %s", len(movers), plural(len(movers)), iotRef))
		}
		if len(exposed) > 0 {
			parts = append(parts, fmt.Sprintf("optionally put %d internet-facing device%s in %s", len(exposed), plural(len(exposed)), dmzRef))
		}
		if srv != nil {
			parts = append(parts, "give the new networks DNS zones under "+strings.TrimSuffix(p.Domain, "."))
		}
		a.Summary = "Proposed: " + strings.Join(parts, ", ") + "."
	}
	return a
}

func freeSubnet(existing []inventory.Network, third int) string {
	if third < 1 || third > 254 {
		return ""
	}
	p := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, byte(third), 0}), 24)
	for _, n := range existing {
		if q, err := netip.ParsePrefix(n.Subnet); err == nil && q.Overlaps(p) {
			return ""
		}
	}
	return netip.PrefixFrom(p.Addr().Next(), 24).String()
}

func prefixOf(gw string) string {
	if p, err := netip.ParsePrefix(gw); err == nil {
		return p.Masked().String()
	}
	return ""
}

func countTypes(types map[string]int) string {
	keys := make([]string, 0, len(types))
	for k := range types {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if types[keys[i]] != types[keys[j]] {
			return types[keys[i]] > types[keys[j]]
		}
		return keys[i] < keys[j]
	})
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", types[k], typeNoun(k, types[k])))
	}
	if len(parts) > 1 {
		return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
	}
	return strings.Join(parts, "")
}

var typeNouns = map[string][2]string{
	iot.TypeCamera: {"camera", "cameras"}, iot.TypePrinter: {"printer", "printers"}, iot.TypePhone: {"desk phone", "desk phones"},
	iot.TypeConference: {"meeting-room system", "meeting-room systems"}, iot.TypeDisplay: {"display or TV", "displays and TVs"},
	iot.TypeAccess: {"door or badge controller", "door and badge controllers"}, iot.TypeBuilding: {"building controller", "building controllers"},
	iot.TypePower: {"UPS or smart plug", "UPSs and smart plugs"}, iot.TypeSensor: {"sensor", "sensors"}, iot.TypeLighting: {"light", "lights"},
	iot.TypeSpeaker: {"speaker", "speakers"}, iot.TypeOther: {"other IoT device", "other IoT devices"},
}

func typeNoun(t string, n int) string {
	w, ok := typeNouns[t]
	if !ok {
		w = [2]string{t, t + "s"}
	}
	if n == 1 {
		return w[0]
	}
	return w[1]
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// Prompt is what the model is asked: the rules, the network, NCC's own plan and the person's goal.
func Prompt(p *Picture, base Answer, goal string) (string, error) {
	pic, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	bj, _ := json.Marshal(base)
	if goal = strings.TrimSpace(goal); goal == "" {
		goal = "Make the network safer: put IoT devices on their own VLAN, put internet-facing devices in a DMZ, and give each network a DNS zone."
	}
	var b strings.Builder
	b.WriteString(`You are the network assistant inside NCC, a network control centre for a small company or home network.
Propose changes to the network described below. NCC shows your plan to a person, who picks the steps and approves them; nothing is applied without that.

Rules:
- Use only the routers, networks, clients (by MAC), DNS servers and zones in NETWORK. Never invent devices.
- Allowed step kinds, as JSON objects:
  {"kind":"create_vlan","router_id":N,"name":"IoT","vlan":30,"gateway":"192.168.30.1/24","isolated":true,"internet_access":true,"why":"..."}
  {"kind":"move_clients","router_id":N,"network":"<existing network name or id, or the name of a network an earlier step creates>","macs":["aa:bb:cc:dd:ee:ff"],"why":"..."}
  {"kind":"create_zone","dns_server_id":N,"zone":"iot.example.lan.","why":"..."}
  {"kind":"assign_zone","router_id":N,"network":"<network>","zone":"iot.example.lan.","why":"..."}
  Any step may add "recommended":false when the person should think before picking it.
- VLAN IDs and subnets must not clash with existing networks. Use private /24 subnets.
- IoT devices (iot_type set) belong on an IoT network unless keep_where_it_is is set or not_iot is set. Group sensibly: cameras and door controllers may warrant their own VLAN in a company.
- Devices with port_forwards are reachable from the internet and belong in a DMZ; moving them changes their address, so mark such moves "recommended":false and say the port forward must be updated.
- New DNS zones go under the internal domain (internal_domain) and should match the network they serve (iot.<domain>, dmz.<domain>).
- Never move routers, switches, access points, servers, computers or phones unless the goal asks for it.
- Keep "why" to one or two plain sentences a non-expert understands.

NCC's own rule-based plan is in BASELINE. Improve on it for the GOAL: keep what is right, fix what is wrong, add what is missing, drop what is not needed.

Answer with only one JSON object, no prose and no code fences:
{"summary":"one or two sentences","notes":["anything the person should know"],"steps":[...]}

GOAL:
`)
	b.WriteString(goal)
	b.WriteString("\n\nNETWORK:\n")
	b.Write(pic)
	b.WriteString("\n\nBASELINE:\n")
	b.Write(bj)
	b.WriteString("\n")
	return b.String(), nil
}

var fenceRe = regexp.MustCompile("(?s)```(?:json)?\\s*(\\{.*\\})\\s*```")

// ParseAnswer reads the model's JSON plan out of its answer.
func ParseAnswer(text string) (Answer, error) {
	var a Answer
	s := strings.TrimSpace(text)
	if m := fenceRe.FindStringSubmatch(s); m != nil {
		s = m[1]
	}
	i, j := strings.Index(s, "{"), strings.LastIndex(s, "}")
	if i < 0 || j < i {
		return a, errors.New("the answer holds no JSON plan")
	}
	if err := json.Unmarshal([]byte(s[i:j+1]), &a); err != nil {
		return a, fmt.Errorf("the plan is not valid JSON: %v", err)
	}
	if len(a.Steps) > 60 {
		return a, errors.New("the plan has too many steps")
	}
	return a, nil
}

var zoneLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validZone(z string) error {
	z = strings.TrimSuffix(dns.FQDN(z), ".")
	if z == "" || len(z) > 253 {
		return errors.New("the zone name is empty or too long")
	}
	labels := strings.Split(z, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%s is not inside a domain", z)
	}
	for _, l := range labels {
		if !zoneLabel.MatchString(l) {
			return fmt.Errorf("%q is not a valid DNS name", z)
		}
	}
	return nil
}

// Check turns an answer into plan steps, checking every step against the network: unknown
// devices are dropped, clashes and steps NCC can't apply are marked with a Problem, and
// every move is previewed with the same rules as the VLANs page (shared switch ports,
// ports to other switches, clients NCC can't see).
func Check(p *Picture, a Answer) ([]Step, []string) {
	var steps []Step
	var notes []string
	planned := map[int64][]inventory.Network{} // new networks per router, by earlier steps
	brokenNew := map[int64]map[string]bool{}   // new networks that can't be created as planned
	newZones := map[string]bool{}
	brokenZones := map[string]bool{} // zones a step creates, but can't yet
	for i, as := range a.Steps {
		st := Step{ID: "s" + strconv.Itoa(len(steps)+1), Kind: as.Kind, Why: strings.TrimSpace(as.Why), Warnings: []string{}, Recommended: true}
		if as.Recommended != nil {
			st.Recommended = *as.Recommended
		}
		switch as.Kind {
		case StepCreateVLAN, StepMove, StepAssignZone:
			r := p.router(as.RouterID)
			if r == nil && as.RouterID == 0 && len(p.Routers) == 1 {
				r = &p.Routers[0]
			}
			if r == nil {
				notes = append(notes, fmt.Sprintf("Step %d named a router NCC doesn't know (%d); it was left out.", i+1, as.RouterID))
				continue
			}
			st.RouterID, st.RouterName = r.ID, r.Name
			if r.Snapshot == nil {
				st.Problem = "NCC has not read " + r.Name + " yet"
			}
			// resolve a network reference to an existing or planned network
			resolve := func(ref string) (string, string, *inventory.Network) {
				ref = strings.TrimSpace(strings.TrimPrefix(ref, "new:"))
				if n := r.network(ref); n != nil {
					return n.ID, n.Name, nil
				}
				for k := range planned[r.ID] {
					n := &planned[r.ID][k]
					if strings.EqualFold(n.Name, ref) {
						return n.ID, n.Name, n
					}
				}
				if brokenNew[r.ID][strings.ToLower(ref)] {
					return "new:" + ref, ref, nil
				}
				return "", ref, nil
			}
			switch as.Kind {
			case StepCreateVLAN:
				spec := drivers.NetworkSpec{Name: strings.TrimSpace(as.Name), VLAN: as.VLAN, Mode: "gateway", Gateway: as.Gateway, DHCP: true, Isolated: true, InternetAccess: true}
				if as.Isolated != nil {
					spec.Isolated = *as.Isolated
				}
				if as.Internet != nil {
					spec.InternetAccess = *as.Internet
				}
				st.Title = "Create the " + spec.Name + " network"
				if r.Snapshot != nil {
					existing := append(append([]inventory.Network{}, r.Snapshot.Networks...), planned[r.ID]...)
					if spec.VLAN == 0 || spec.Gateway == "" {
						sug := core.SuggestNetwork(existing)
						if spec.VLAN == 0 {
							spec.VLAN = sug.VLAN
						}
						if spec.Gateway == "" {
							spec.Gateway = sug.Gateway
						}
					}
					if err := core.ValidateNetwork(&spec, existing); err != nil {
						st.Problem = err.Error()
					}
				}
				if !r.CanChange && st.Problem == "" {
					st.Problem = "NCC cannot create networks on " + r.Name
				}
				st.Network = &spec
				st.NetworkID, st.NetworkName = "new:"+spec.Name, spec.Name
				st.Title = fmt.Sprintf("Create the %s network (VLAN %d, %s)", spec.Name, spec.VLAN, prefixOf(spec.Gateway))
				switch {
				case spec.Isolated && spec.InternetAccess:
					st.Warnings = append(st.Warnings, spec.Name+" is isolated: devices on it can reach the internet but not your other networks, so apps on computers and phones elsewhere may lose them.")
				case spec.Isolated:
					st.Warnings = append(st.Warnings, spec.Name+" is isolated and has no internet: devices on it reach nothing but each other until you add firewall rules.")
				case !spec.InternetAccess:
					st.Warnings = append(st.Warnings, spec.Name+" has no internet access.")
				}
				if st.Problem != "" {
					if brokenNew[r.ID] == nil {
						brokenNew[r.ID] = map[string]bool{}
					}
					brokenNew[r.ID][strings.ToLower(spec.Name)] = true
				}
				if st.Problem == "" {
					planned[r.ID] = append(planned[r.ID], inventory.Network{ID: "new:" + spec.Name, Name: spec.Name, VLAN: spec.VLAN,
						Subnet: prefixOf(spec.Gateway), Purpose: "corporate", Isolated: spec.Isolated, InternetAccess: spec.InternetAccess, Target: r.Name})
				}
			case StepMove:
				id, name, _ := resolve(as.Network)
				st.NetworkID, st.NetworkName = id, name
				st.Title = "Move devices to " + name
				if id == "" {
					st.Problem = "there is no network called " + name + " and no step creates it"
				}
				var macs []string
				for _, m := range as.MACs {
					m = iot.NormMAC(m)
					if c := r.client(m); c != nil {
						macs = append(macs, m)
					} else if m != "" {
						notes = append(notes, "The plan named a device NCC doesn't see ("+m+"); it was left out.")
					}
				}
				if len(macs) == 0 {
					if st.Problem == "" {
						notes = append(notes, fmt.Sprintf("A move to %s named no device NCC knows; it was left out.", name))
					}
					continue
				}
				if !r.CanChange && st.Problem == "" {
					st.Problem = "NCC cannot move clients on " + r.Name
				}
				if id == "" || brokenNew[r.ID][strings.ToLower(name)] {
					for _, m := range macs {
						c := r.client(m)
						st.Clients = append(st.Clients, StepClient{MAC: m, Name: c.Name, IP: c.IP, Type: c.IoTType})
					}
				} else if r.Snapshot != nil {
					snap := *r.Snapshot
					snap.Networks = append(append([]inventory.Network{}, r.Snapshot.Networks...), planned[r.ID]...)
					mp, err := core.PlanMove(&snap, id, macs)
					if err != nil {
						st.Problem = err.Error()
					} else {
						movable := 0
						for _, ms := range mp.Steps {
							sc := StepClient{MAC: ms.MAC, Name: ms.Name, IP: ms.IP, From: ms.FromName, Via: ms.Via, Blocked: ms.Blocked, AlongWith: !ms.Requested}
							if c := r.client(ms.MAC); c != nil {
								sc.Type = c.IoTType
							}
							if ms.Already {
								continue
							}
							if ms.Method != "" {
								movable++
							}
							st.Clients = append(st.Clients, sc)
						}
						for _, w := range mp.Warnings {
							// the step that creates the network already says it is isolated
							if strings.HasPrefix(id, "new:") && strings.Contains(w, " is isolated:") {
								continue
							}
							st.Warnings = append(st.Warnings, w)
						}
						if movable == 0 && st.Problem == "" {
							st.Problem = "none of these devices can be moved by NCC (see each one)"
						}
						if len(st.Clients) == 0 {
							notes = append(notes, "Every device in a move to "+name+" is already there; that step was left out.")
							continue
						}
					}
				}
				n := 0
				for _, c := range st.Clients {
					if c.Blocked == "" {
						n++
					}
				}
				st.Title = fmt.Sprintf("Move %d device%s to %s", n, plural(n), name)
				st.Warnings = append(st.Warnings, "Moved devices get a new address in "+name+": Wi-Fi devices rejoin and wired ports are switched off for a few seconds.")
			case StepAssignZone:
				id, name, _ := resolve(as.Network)
				st.NetworkID, st.NetworkName = id, name
				st.Zone = dns.FQDN(as.Zone)
				st.Title = "Hand out " + strings.TrimSuffix(st.Zone, ".") + " as the domain on " + name
				switch {
				case id == "":
					st.Problem = "there is no network called " + name + " and no step creates it"
				case validZone(st.Zone) != nil:
					st.Problem = validZone(st.Zone).Error()
				case brokenZones[st.Zone]:
					st.Problem = "it needs the zone " + strings.TrimSuffix(st.Zone, ".") + ", which can't be created as planned"
				case !zoneKnown(p, st.Zone) && !newZones[st.Zone]:
					st.Problem = "no DNS server has the zone " + strings.TrimSuffix(st.Zone, ".") + " and no step creates it"
				case !r.CanSetDomain:
					st.Problem = "NCC cannot set the DNS domain of a network on " + r.Name + " yet"
				}
			}
		case StepCreateZone:
			srv := p.dnsServer(as.DNSServerID)
			if srv == nil && as.DNSServerID == 0 && len(p.DNS) == 1 {
				srv = &p.DNS[0]
			}
			if srv == nil {
				notes = append(notes, fmt.Sprintf("Step %d named a DNS server NCC doesn't know; it was left out.", i+1))
				continue
			}
			st.DNSServerID, st.DNSServer = srv.ID, srv.Name
			st.Zone = dns.FQDN(as.Zone)
			st.Title = "Create the DNS zone " + strings.TrimSuffix(st.Zone, ".") + " on " + srv.Name
			if err := validZone(st.Zone); err != nil {
				st.Problem = err.Error()
			}
			for _, z := range srv.Zones {
				if dns.FQDN(z) == st.Zone {
					notes = append(notes, srv.Name+" already has the zone "+strings.TrimSuffix(st.Zone, ".")+"; that step was left out.")
					st.Kind = ""
				}
			}
			if st.Kind == "" {
				continue
			}
			if newZones[st.Zone] {
				continue
			}
			if st.Problem == "" && !srv.CanCreateZones {
				st.Problem = "NCC cannot create zones on " + srv.Name + " yet"
			}
			if st.Problem == "" {
				newZones[st.Zone] = true
			} else {
				brokenZones[st.Zone] = true
			}
			if parent := parentZone(srv.Zones, st.Zone); parent != "" {
				st.Warnings = append(st.Warnings, "It sits under "+strings.TrimSuffix(parent, ".")+": NCC adds the delegation (NS records) there so names in it resolve.")
			}
		default:
			notes = append(notes, fmt.Sprintf("Step %d is of a kind NCC can't apply (%q); it was left out.", i+1, as.Kind))
			continue
		}
		if st.Why == "" {
			st.Why = "Proposed by the assistant."
		}
		if st.Problem != "" {
			st.Recommended = false
		}
		steps = append(steps, st)
	}
	// a step that depends on one with a problem can't be applied either
	broken := map[string]bool{}
	for i := range steps {
		s := &steps[i]
		if s.Kind == StepCreateVLAN && s.Problem != "" {
			broken[s.NetworkID] = true
		}
	}
	for i := range steps {
		s := &steps[i]
		if (s.Kind == StepMove || s.Kind == StepAssignZone) && s.Problem == "" && broken[s.NetworkID] {
			s.Problem, s.Recommended = "it needs the "+s.NetworkName+" network, which can't be created as planned", false
		}
	}
	return steps, notes
}

func zoneKnown(p *Picture, z string) bool {
	for _, s := range p.DNS {
		for _, ez := range s.Zones {
			if dns.FQDN(ez) == dns.FQDN(z) {
				return true
			}
		}
	}
	return false
}

func parentZone(zones []string, z string) string {
	best := ""
	for _, ez := range zones {
		ez = dns.FQDN(ez)
		if ez != z && dns.InZone(z, ez) && len(ez) > len(best) {
			best = ez
		}
	}
	return best
}
