package dnszones

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/inventory"
)

// Env is what the planner needs from the rest of NCC. The API server implements it.
type Env interface {
	// DNSServer returns a DNS server connection's provider, settings and credentials.
	DNSServer(ctx context.Context, id int64) (dns.Provider, dns.Server, map[string]string, error)
	// Routers returns every router connection with the networks NCC last read from it.
	Routers(ctx context.Context) ([]Router, error)
	// SetNetworkDomain sets the DHCP domain a router network hands out.
	SetNetworkDomain(ctx context.Context, routerID int64, networkID, domain string) error
}

// NewZone is a zone or subdomain to create.
type NewZone struct {
	Name string `json:"name"` // e.g. "iot.corp.lan."
	// ServerID is the DNS server to create it on; 0 uses the request's ServerID.
	ServerID int64 `json:"server_id,omitempty"`
	// Nameservers default to the parent zone's NS records when the parent is on the same server.
	Nameservers []string `json:"nameservers,omitempty"`
	// Delegate adds NS records for the new zone in its parent zone (a delegated subdomain).
	Delegate bool `json:"delegate"`
}

// AssignSpec assigns a zone to a router network.
type AssignSpec struct {
	Zone string `json:"zone"`
	// ServerID is the DNS server holding the zone; 0 uses the request's ServerID.
	ServerID  int64  `json:"server_id,omitempty"`
	RouterID  int64  `json:"router_id"`
	NetworkID string `json:"network_id"`
	// SetDHCPDomain makes the router hand out the zone as the network's domain name.
	SetDHCPDomain bool `json:"set_dhcp_domain"`
	// Reverse creates the reverse zone for the network's subnet when no zone covers it.
	Reverse bool `json:"reverse"`
}

// PlanRequest is a set of zone and VLAN changes to plan.
type PlanRequest struct {
	ServerID int64        `json:"server_id"`
	Zones    []NewZone    `json:"zones"`
	Assign   []AssignSpec `json:"assign"`
}

// Step kinds, in the order Apply runs them.
const (
	StepCreateZone    = "create_zone"
	StepDelegate      = "delegate"
	StepCreateReverse = "create_reverse"
	StepAssign        = "assign"
	StepDHCPDomain    = "dhcp_domain"
)

// Step is one change in a plan.
type Step struct {
	Kind     string `json:"kind"`
	Title    string `json:"title"`
	ServerID int64  `json:"server_id,omitempty"`
	Server   string `json:"server,omitempty"`
	// Zone is the zone created, the parent the delegation goes in, or the zone assigned.
	Zone        string      `json:"zone,omitempty"`
	Nameservers []string    `json:"nameservers,omitempty"`
	Change      *dns.Change `json:"change,omitempty"` // delegate: the NS records added to Zone
	RouterID    int64       `json:"router_id,omitempty"`
	Router      string      `json:"router,omitempty"`
	NetworkID   string      `json:"network_id,omitempty"`
	Network     string      `json:"network,omitempty"`
	VLAN        int         `json:"vlan,omitempty"`
	Domain      string      `json:"domain,omitempty"` // dhcp_domain: the domain name set, no trailing dot
}

// Plan is the steps a PlanRequest takes, and things worth knowing that don't stop it.
type Plan struct {
	Steps    []Step   `json:"steps"`
	Warnings []string `json:"warnings"`
}

type serverInfo struct {
	p     dns.Provider
	srv   dns.Server
	creds map[string]string
	zones []dns.Zone
}

type planner struct {
	ctx     context.Context
	env     Env
	servers map[int64]*serverInfo
	planned map[int64]map[string][]string // server -> zone -> nameservers, zones this plan creates
	plan    *Plan
}

func (pl *planner) server(id int64) (*serverInfo, error) {
	if id == 0 {
		return nil, errors.New("choose a DNS server")
	}
	if s := pl.servers[id]; s != nil {
		return s, nil
	}
	p, srv, creds, err := pl.env.DNSServer(pl.ctx, id)
	if err != nil {
		return nil, err
	}
	zs, err := p.ListZones(pl.ctx, srv, creds)
	if err != nil {
		return nil, fmt.Errorf("can't read the zones on %s: %w", srv.Name, err)
	}
	s := &serverInfo{p: p, srv: srv, creds: creds, zones: zs}
	pl.servers[id] = s
	return s, nil
}

// exists reports whether a zone is on the server or created earlier in this plan.
func (pl *planner) exists(s *serverInfo, zone string) bool {
	if _, ok := pl.planned[s.srv.ID][zone]; ok {
		return true
	}
	for _, z := range s.zones {
		if dns.FQDN(z.Name) == zone {
			return true
		}
	}
	return false
}

// known lists the server's zones plus those this plan creates on it.
func (pl *planner) known(s *serverInfo) []dns.Zone {
	out := append([]dns.Zone(nil), s.zones...)
	for z := range pl.planned[s.srv.ID] {
		out = append(out, dns.Zone{Name: z})
	}
	return out
}

// nameservers returns a zone's NS records: from the plan when it creates the zone, else
// from the server.
func (pl *planner) nameservers(s *serverInfo, zone string) ([]string, error) {
	if ns, ok := pl.planned[s.srv.ID][zone]; ok {
		return ns, nil
	}
	rs, err := s.p.ListRecords(pl.ctx, s.srv, s.creds, zone)
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		if r.Type == "NS" && dns.FQDN(r.Name) == zone {
			out := make([]string, 0, len(r.Records))
			for _, v := range r.Records {
				out = append(out, dns.FQDN(v))
			}
			return out, nil
		}
	}
	return nil, nil
}

func (pl *planner) createZone(s *serverInfo, kind, zone string, ns []string, title string) error {
	if _, ok := s.p.(dns.ZoneManager); !ok {
		return fmt.Errorf("%s (%s) can't create zones from NCC", s.srv.Name, s.srv.Kind)
	}
	if len(ns) == 0 {
		return fmt.Errorf("%s needs at least one name server, e.g. ns1.%s", zone, zone)
	}
	if pl.planned[s.srv.ID] == nil {
		pl.planned[s.srv.ID] = map[string][]string{}
	}
	pl.planned[s.srv.ID][zone] = ns
	pl.plan.Steps = append(pl.plan.Steps, Step{Kind: kind, Title: title, ServerID: s.srv.ID, Server: s.srv.Name, Zone: zone, Nameservers: ns})
	return nil
}

// BuildPlan checks a request and turns it into steps. It reads the DNS servers and the
// routers' last known networks but changes nothing.
func BuildPlan(ctx context.Context, env Env, req PlanRequest) (*Plan, error) {
	pl := &planner{ctx: ctx, env: env, servers: map[int64]*serverInfo{}, planned: map[int64]map[string][]string{},
		plan: &Plan{Steps: []Step{}, Warnings: []string{}}}
	if len(req.Zones) == 0 && len(req.Assign) == 0 {
		return nil, errors.New("nothing to plan: add a zone to create or a VLAN to assign")
	}

	// Parents first, so "corp.lan." and "iot.corp.lan." in one request work in either order.
	zones := append([]NewZone(nil), req.Zones...)
	for i := range zones {
		fq, err := dns.ValidateZoneName(zones[i].Name)
		if err != nil {
			return nil, err
		}
		zones[i].Name = fq
	}
	for i := 1; i < len(zones); i++ {
		for j := i; j > 0 && strings.Count(zones[j].Name, ".") < strings.Count(zones[j-1].Name, "."); j-- {
			zones[j], zones[j-1] = zones[j-1], zones[j]
		}
	}
	for _, z := range zones {
		sid := z.ServerID
		if sid == 0 {
			sid = req.ServerID
		}
		s, err := pl.server(sid)
		if err != nil {
			return nil, err
		}
		if pl.exists(s, z.Name) {
			pl.plan.Warnings = append(pl.plan.Warnings, z.Name+" already exists on "+s.srv.Name+"; it is left as it is.")
			continue
		}
		parent := dns.ParentZone(z.Name, pl.known(s))
		ns := make([]string, 0, len(z.Nameservers))
		for _, n := range z.Nameservers {
			if n = strings.TrimSpace(n); n != "" {
				ns = append(ns, dns.FQDN(n))
			}
		}
		if len(ns) == 0 && parent != "" {
			if ns, err = pl.nameservers(s, parent); err != nil {
				return nil, err
			}
		}
		title := "Create zone " + z.Name + " on " + s.srv.Name
		if parent != "" {
			title = "Create subdomain " + z.Name + " (under " + parent + ") on " + s.srv.Name
		}
		if err := pl.createZone(s, StepCreateZone, z.Name, ns, title); err != nil {
			return nil, err
		}
		if z.Delegate {
			if parent == "" {
				pl.plan.Warnings = append(pl.plan.Warnings, "No parent zone of "+z.Name+" is on "+s.srv.Name+", so there is nothing to delegate it from.")
				continue
			}
			ch := dns.Change{Op: dns.Replace, RRSet: dns.RRSet{Name: z.Name, Type: "NS", TTL: 3600, Records: ns}}
			pl.plan.Steps = append(pl.plan.Steps, Step{Kind: StepDelegate, Title: "Delegate " + z.Name + " from " + parent + " (NS " + strings.Join(ns, ", ") + ")",
				ServerID: s.srv.ID, Server: s.srv.Name, Zone: parent, Nameservers: ns, Change: &ch})
		}
	}

	if len(req.Assign) == 0 {
		return pl.plan, nil
	}
	routers, err := env.Routers(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, as := range req.Assign {
		zone, err := dns.ValidateZoneName(as.Zone)
		if err != nil {
			return nil, err
		}
		sid := as.ServerID
		if sid == 0 {
			sid = req.ServerID
		}
		s, err := pl.server(sid)
		if err != nil {
			return nil, err
		}
		var rt *Router
		var nw *inventory.Network
		for i := range routers {
			if routers[i].ID != as.RouterID {
				continue
			}
			rt = &routers[i]
			for j := range rt.Networks {
				if rt.Networks[j].ID == as.NetworkID {
					nw = &rt.Networks[j]
				}
			}
		}
		if rt == nil {
			return nil, fmt.Errorf("router connection %d not found", as.RouterID)
		}
		if nw == nil {
			return nil, fmt.Errorf("%s has no network %q (NCC may not have read it yet)", rt.Name, as.NetworkID)
		}
		if !Checked(*nw) {
			return nil, fmt.Errorf("%s is a %s network; only LANs and VLANs get a DNS zone", nw.Name, nw.Purpose)
		}
		k := fmt.Sprint(rt.ID, "/", nw.ID)
		if seen[k] {
			return nil, fmt.Errorf("%s is assigned twice in this plan", Label(*nw))
		}
		seen[k] = true
		if !pl.exists(s, zone) {
			return nil, fmt.Errorf("%s does not exist on %s; add it to the zones to create", zone, s.srv.Name)
		}
		if as.Reverse {
			if rz := ReverseFor(*nw); rz != "" && dns.BestZone(rz, pl.known(s)) == "" {
				ns, err := pl.nameservers(s, zone)
				if err != nil {
					return nil, err
				}
				if err := pl.createZone(s, StepCreateReverse, rz, ns, "Create reverse zone "+rz+" for "+nw.Subnet+" on "+s.srv.Name); err != nil {
					return nil, err
				}
			}
		}
		pl.plan.Steps = append(pl.plan.Steps, Step{Kind: StepAssign, Title: "Assign " + zone + " to " + Label(*nw) + " on " + rt.Name,
			ServerID: s.srv.ID, Server: s.srv.Name, Zone: zone, RouterID: rt.ID, Router: rt.Name, NetworkID: nw.ID, Network: nw.Name, VLAN: nw.VLAN})
		if as.SetDHCPDomain {
			domain := strings.TrimSuffix(zone, ".")
			switch {
			case !rt.CanSetDomain:
				pl.plan.Warnings = append(pl.plan.Warnings, "NCC can't change the DHCP domain on "+rt.Name+"; set "+nw.Name+"'s domain name to "+domain+" on the router.")
			case nw.DNS == nil || !nw.DNS.DHCP || nw.Purpose == "vlan-only":
				pl.plan.Warnings = append(pl.plan.Warnings, rt.Name+" doesn't hand out addresses on "+nw.Name+"; set the domain name "+domain+" on the DHCP server that does.")
			case strings.EqualFold(nw.DNS.Domain, domain):
				// already right
			default:
				from := ""
				if nw.DNS.Domain != "" {
					from = " (now " + nw.DNS.Domain + ")"
				}
				pl.plan.Steps = append(pl.plan.Steps, Step{Kind: StepDHCPDomain, Title: "Hand out domain name " + domain + " on " + Label(*nw) + from,
					RouterID: rt.ID, Router: rt.Name, NetworkID: nw.ID, Network: nw.Name, VLAN: nw.VLAN, Domain: domain})
			}
		}
	}
	// Zones first, then assignments, then router changes.
	order := map[string]int{StepCreateZone: 0, StepDelegate: 1, StepCreateReverse: 2, StepAssign: 3, StepDHCPDomain: 4}
	steps := pl.plan.Steps
	for i := 1; i < len(steps); i++ {
		for j := i; j > 0 && order[steps[j].Kind] < order[steps[j-1].Kind]; j-- {
			steps[j], steps[j-1] = steps[j-1], steps[j]
		}
	}
	return pl.plan, nil
}

// StepResult is what happened to one step.
type StepResult struct {
	Step
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Apply runs a plan's steps in order and stops at the first failure. record, when not nil,
// is called after every step (for the audit log).
func Apply(ctx context.Context, env Env, db *sql.DB, actor string, p *Plan, record func(StepResult)) ([]StepResult, error) {
	out := make([]StepResult, 0, len(p.Steps))
	for _, st := range p.Steps {
		err := applyStep(ctx, env, db, actor, st)
		res := StepResult{Step: st, OK: err == nil}
		if err != nil {
			res.Error = err.Error()
		}
		out = append(out, res)
		if record != nil {
			record(res)
		}
		if err != nil {
			return out, fmt.Errorf("%s: %w", st.Title, err)
		}
	}
	return out, nil
}

func applyStep(ctx context.Context, env Env, db *sql.DB, actor string, st Step) error {
	switch st.Kind {
	case StepCreateZone, StepCreateReverse:
		p, srv, creds, err := env.DNSServer(ctx, st.ServerID)
		if err != nil {
			return err
		}
		zm, ok := p.(dns.ZoneManager)
		if !ok {
			return fmt.Errorf("%s can't create zones", srv.Name)
		}
		return zm.CreateZone(ctx, srv, creds, dns.ZoneSpec{Name: st.Zone, Nameservers: st.Nameservers})
	case StepDelegate:
		p, srv, creds, err := env.DNSServer(ctx, st.ServerID)
		if err != nil {
			return err
		}
		if st.Change == nil {
			return errors.New("no records to add")
		}
		if err := dns.Validate(st.Zone, *st.Change); err != nil {
			return err
		}
		return p.Apply(ctx, srv, creds, st.Zone, []dns.Change{*st.Change})
	case StepAssign:
		_, err := Put(ctx, db, Assignment{ServerID: st.ServerID, Zone: st.Zone, RouterID: st.RouterID, NetworkID: st.NetworkID,
			Network: st.Network, VLAN: st.VLAN, UpdatedBy: actor})
		return err
	case StepDHCPDomain:
		return env.SetNetworkDomain(ctx, st.RouterID, st.NetworkID, st.Domain)
	}
	return fmt.Errorf("unknown step %q", st.Kind)
}
