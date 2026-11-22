package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/dnszones"
	"github.com/dertown/network-control-centre/internal/drivers"
)

// DNS zones and VLANs: which zone each router network uses, the check, and planned changes
// (create zones and subdomains, assign them to VLANs, set the DHCP domain on the router).

// zonesEnv implements dnszones.Env on top of the server's connections.
type zonesEnv struct{ s *Server }

func (e zonesEnv) DNSServer(ctx context.Context, id int64) (dns.Provider, dns.Server, map[string]string, error) {
	t, err := e.s.Targets.Get(ctx, id)
	if err != nil {
		return nil, dns.Server{}, nil, err
	}
	if t.Category != core.CategoryDNS {
		return nil, dns.Server{}, nil, errors.New(t.Name + " is not a DNS server connection")
	}
	p, err := dns.Get(t.Kind)
	if err != nil {
		return nil, dns.Server{}, nil, err
	}
	creds, err := e.s.Vault.Get(ctx, t.SecretPath)
	if err != nil {
		return nil, dns.Server{}, nil, err
	}
	return p, dns.Server{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Options: t.Options}, creds, nil
}

func (e zonesEnv) Routers(ctx context.Context) ([]dnszones.Router, error) {
	ts, err := e.s.Targets.List(ctx, core.CategoryDevice)
	if err != nil {
		return nil, err
	}
	snaps, err := core.LatestSnapshots(ctx, e.s.Store.DB)
	if err != nil {
		return nil, err
	}
	out := []dnszones.Router{}
	for _, t := range ts {
		r := dnszones.Router{ID: t.ID, Name: t.Name}
		if d, err := drivers.Get(t.Kind); err == nil {
			_, r.CanSetDomain = d.(drivers.NetworkDomainSetter)
		}
		for i := range snaps {
			if snaps[i].Target == t.Name {
				r.Networks = snaps[i].Networks
			}
		}
		if len(r.Networks) == 0 {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func (e zonesEnv) SetNetworkDomain(ctx context.Context, routerID int64, networkID, domain string) error {
	t, err := e.s.Targets.Get(ctx, routerID)
	if err != nil {
		return err
	}
	d, err := drivers.Get(t.Kind)
	if err != nil {
		return err
	}
	ds, ok := d.(drivers.NetworkDomainSetter)
	if !ok {
		return errors.New(t.Kind + " connections can't change a network's domain name")
	}
	creds, err := e.s.Vault.Get(ctx, t.SecretPath)
	if err != nil {
		return err
	}
	return ds.SetNetworkDomain(ctx, devTarget(t), creds, networkID, domain)
}

// zoneServers reads the zones of every DNS server connection, side by side.
func (s *Server) zoneServers(ctx context.Context) ([]dnszones.Server, error) {
	ts, err := s.Targets.List(ctx, core.CategoryDNS)
	if err != nil {
		return nil, err
	}
	out := make([]dnszones.Server, len(ts))
	var wg sync.WaitGroup
	for i, t := range ts {
		out[i] = dnszones.Server{ID: t.ID, Name: t.Name, Kind: t.Kind, Zones: []dns.Zone{}}
		p, err := dns.Get(t.Kind)
		if err != nil {
			out[i].Error = err.Error()
			continue
		}
		_, out[i].CanCreate = p.(dns.ZoneManager)
		if !t.Enabled {
			out[i].Error = "the connection is disabled"
			continue
		}
		wg.Add(1)
		go func(i int, t core.Target) {
			defer wg.Done()
			_, srv, creds, err := zonesEnv{s}.DNSServer(ctx, t.ID)
			if err == nil {
				c, cancel := context.WithTimeout(ctx, 15*time.Second)
				var zs []dns.Zone
				zs, err = p.ListZones(c, srv, creds)
				cancel()
				if zs != nil {
					out[i].Zones = zs
				}
			}
			if err != nil {
				out[i].Error = err.Error()
			}
		}(i, t)
	}
	wg.Wait()
	return out, nil
}

// dnsZoneMap is the zone and VLAN check: every router network, its zone and what's wrong.
func (s *Server) dnsZoneMap(w http.ResponseWriter, r *http.Request) {
	routers, err := zonesEnv{s}.Routers(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	servers, err := s.zoneServers(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	as, err := dnszones.List(r.Context(), s.Store.DB)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, dnszones.Evaluate(routers, servers, as))
}

// dnsZonePlan previews (dry_run) or applies zone and VLAN changes.
func (s *Server) dnsZonePlan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		dnszones.PlanRequest
		DryRun bool `json:"dry_run"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	env := zonesEnv{s}
	plan, err := dnszones.BuildPlan(r.Context(), env, in.PlanRequest)
	if err != nil {
		code := 400
		if errors.Is(err, core.ErrNoTarget) {
			code = 404
		}
		writeErr(w, code, err.Error())
		return
	}
	if in.DryRun {
		writeJSON(w, 200, map[string]any{"applied": false, "plan": plan})
		return
	}
	if len(plan.Steps) == 0 {
		writeJSON(w, 200, map[string]any{"applied": true, "plan": plan, "results": []dnszones.StepResult{}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	who := actor(r)
	routersTouched := map[int64]bool{}
	results, err := dnszones.Apply(ctx, env, s.Store.DB, who, plan, func(res dnszones.StepResult) {
		action := "dnszone." + res.Kind
		if !res.OK {
			action += ".failed"
		}
		target := "dns/" + res.Server + "/" + res.Zone
		if res.Kind == dnszones.StepDHCPDomain {
			target = "network/" + res.Router + "/" + res.Network
			routersTouched[res.RouterID] = true
		}
		_ = s.Audit.Record(r.Context(), who, action, target, map[string]any{"step": res.Step, "error": res.Error})
	})
	for id := range routersTouched {
		s.refreshTarget(id, 0)
	}
	s.Hub.Publish("dns", map[string]any{"zones": len(results)})
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error(), "applied": false, "plan": plan, "results": results})
		return
	}
	writeJSON(w, 200, map[string]any{"applied": true, "plan": plan, "results": results})
}

// dnsZoneUnassign removes a zone assignment; the zone and the router are left alone.
func (s *Server) dnsZoneUnassign(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 404, "no such assignment")
		return
	}
	a, err := dnszones.Get(r.Context(), s.Store.DB, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "no such assignment")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := dnszones.Delete(r.Context(), s.Store.DB, id); err != nil {
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "dnszone.unassign", "dns/"+a.Zone, map[string]any{"assignment": a})
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// dnsZoneDelete deletes a zone from a DNS server, unless a VLAN still uses it.
func (s *Server) dnsZoneDelete(w http.ResponseWriter, r *http.Request) {
	p, srv, creds, err := s.dnsServer(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	zm, ok := p.(dns.ZoneManager)
	if !ok {
		writeErr(w, 501, srv.Name+" can't delete zones from NCC")
		return
	}
	zone := dns.FQDN(r.PathValue("zone"))
	as, err := dnszones.List(r.Context(), s.Store.DB)
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, a := range as {
		if a.ServerID == srv.ID && dns.FQDN(a.Zone) == zone {
			writeErr(w, 409, zone+" is assigned to "+a.Network+"; unassign it first")
			return
		}
	}
	err = zm.DeleteZone(r.Context(), srv, creds, zone)
	action := "dnszone.delete"
	if err != nil {
		action += ".failed"
	}
	_ = s.Audit.Record(r.Context(), actor(r), action, "dns/"+srv.Name+"/"+zone, map[string]any{"error": errText(err)})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Hub.Publish("dns", map[string]any{"server": srv.Name, "deleted": zone})
	writeJSON(w, 200, map[string]any{"deleted": zone})
}
