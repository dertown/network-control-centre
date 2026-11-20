package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/vault"
)

func (s *Server) bg() context.Context {
	return context.Background()
}

func (s *Server) listDrivers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string][]string{"device": drivers.Kinds(), "dns": dns.Kinds()})
}

// ---- targets ----

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request) {
	ts, err := s.Targets.List(r.Context(), r.URL.Query().Get("category"))
	if err != nil {
		s.fail(w, err)
		return
	}
	if ts == nil {
		ts = []core.Target{}
	}
	writeJSON(w, 200, ts)
}

func (s *Server) createTarget(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind        string            `json:"kind"`
		Category    string            `json:"category"`
		Name        string            `json:"name"`
		Address     string            `json:"address"`
		Options     map[string]string `json:"options"`
		Credentials vault.Secret      `json:"credentials"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	switch in.Category {
	case core.CategoryDevice:
		if _, err := drivers.Get(in.Kind); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	case core.CategoryDNS:
		if _, err := dns.Get(in.Kind); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	default:
		writeErr(w, 400, "category must be device or dns")
		return
	}
	if !strings.HasPrefix(in.Address, "https://") && !strings.HasPrefix(in.Address, "http://") {
		writeErr(w, 400, "address must be a URL, e.g. https://192.168.1.1")
		return
	}
	if len(in.Credentials) == 0 {
		writeErr(w, 400, "credentials are required")
		return
	}
	t := &core.Target{Kind: in.Kind, Category: in.Category, Name: in.Name, Address: in.Address, Options: in.Options, Enabled: true}
	if err := s.Targets.Create(r.Context(), t); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if _, err := s.Vault.Put(r.Context(), t.SecretPath, in.Credentials); err != nil {
		_ = s.Targets.Delete(r.Context(), t.ID)
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "target.create", "target/"+t.Name,
		map[string]string{"kind": t.Kind, "address": t.Address})
	go func() { _, _ = s.Poller.PollOne(s.bg(), t.ID) }()
	writeJSON(w, 201, t)
}

func pathID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func (s *Server) updateTarget(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	var in struct {
		Address *string           `json:"address"`
		Options map[string]string `json:"options"`
		Enabled *bool             `json:"enabled"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	t, err := s.Targets.Get(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if in.Address != nil {
		t.Address = *in.Address
	}
	if in.Options != nil {
		t.Options = in.Options
	}
	if in.Enabled != nil {
		t.Enabled = *in.Enabled
	}
	if err := s.Targets.Update(r.Context(), t); err != nil {
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "target.update", "target/"+t.Name, in)
	writeJSON(w, 200, t)
}

func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	t, err := s.Targets.Get(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.Vault.Delete(r.Context(), t.SecretPath); err != nil && !errors.Is(err, vault.ErrNotFound) {
		s.fail(w, err)
		return
	}
	if err := s.Targets.Delete(r.Context(), id); err != nil {
		s.fail(w, err)
		return
	}
	if s.Traffic != nil {
		s.Traffic.Forget(t.Name)
	}
	_ = s.Audit.Record(r.Context(), actor(r), "target.delete", "target/"+t.Name, nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) setTargetCredentials(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	var in vault.Secret
	if !readJSON(w, r, &in) {
		return
	}
	t, err := s.Targets.Get(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if _, err := s.Vault.Put(r.Context(), t.SecretPath, in); err != nil {
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "target.credentials", "target/"+t.Name, nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) pollTarget(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	snap, err := s.Poller.PollOne(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if snap == nil { // DNS server check
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	writeJSON(w, 200, map[string]any{"devices": len(snap.Devices), "clients": len(snap.Clients), "links": len(snap.Links)})
}

// ---- inventory ----

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	snaps, err := core.LatestSnapshots(r.Context(), s.Store.DB)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := []inventory.Device{}
	for _, sn := range snaps {
		out = append(out, sn.Devices...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	writeJSON(w, 200, out)
}

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) {
	snaps, err := core.LatestSnapshots(r.Context(), s.Store.DB)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := []inventory.Client{}
	for _, sn := range snaps {
		out = append(out, sn.Clients...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, 200, out)
}

func (s *Server) topology(w http.ResponseWriter, r *http.Request) {
	snaps, err := core.LatestSnapshots(r.Context(), s.Store.DB)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, core.BuildGraph(snaps, r.URL.Query().Get("clients") == "1"))
}

// loops lists the switching loops found in the latest poll of every target.
func (s *Server) loops(w http.ResponseWriter, r *http.Request) {
	snaps, err := core.LatestSnapshots(r.Context(), s.Store.DB)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, core.Loops(snaps))
}

// events streams live updates as Server-Sent Events.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch, cancel := s.Hub.Subscribe()
	defer cancel()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case b, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		}
	}
}

// ---- DNS ----

func (s *Server) dnsServer(r *http.Request) (dns.Provider, dns.Server, map[string]string, error) {
	id, err := strconv.ParseInt(r.PathValue("server"), 10, 64)
	if err != nil {
		return nil, dns.Server{}, nil, core.ErrNoTarget
	}
	t, err := s.Targets.Get(r.Context(), id)
	if err != nil {
		return nil, dns.Server{}, nil, err
	}
	if t.Category != core.CategoryDNS {
		return nil, dns.Server{}, nil, core.ErrNoTarget
	}
	p, err := dns.Get(t.Kind)
	if err != nil {
		return nil, dns.Server{}, nil, err
	}
	creds, err := s.Vault.Get(r.Context(), t.SecretPath)
	if err != nil {
		return nil, dns.Server{}, nil, err
	}
	return p, dns.Server{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Options: t.Options}, creds, nil
}

func (s *Server) dnsZones(w http.ResponseWriter, r *http.Request) {
	p, srv, creds, err := s.dnsServer(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	zs, err := p.ListZones(r.Context(), srv, creds)
	// Keep the Settings status in step with what the DNS page just saw.
	_ = s.Targets.RecordPoll(r.Context(), srv.ID, err)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, zs)
}

func (s *Server) dnsRecords(w http.ResponseWriter, r *http.Request) {
	p, srv, creds, err := s.dnsServer(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	rs, err := p.ListRecords(r.Context(), srv, creds, r.PathValue("zone"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, rs)
}

// ZonePlan is the set of changes for one zone.
type ZonePlan struct {
	Zone    string       `json:"zone"`
	Changes []dns.Change `json:"changes"`
}

// PlanDNS validates changes and adds matching PTR changes in reverse zones when asked.
func PlanDNS(ctx context.Context, p dns.Provider, srv dns.Server, creds map[string]string, zone string,
	changes []dns.Change, withPTR bool) ([]ZonePlan, []string, error) {
	zone = dns.FQDN(zone)
	var warnings []string
	for i := range changes {
		changes[i].Op = strings.ToUpper(changes[i].Op)
		changes[i].RRSet.Type = strings.ToUpper(changes[i].RRSet.Type)
		changes[i].RRSet.Name = dns.Qualify(changes[i].RRSet.Name, zone)
		if err := dns.Validate(zone, changes[i]); err != nil {
			return nil, nil, err
		}
	}
	plans := []ZonePlan{{Zone: zone, Changes: changes}}
	if !withPTR {
		return plans, nil, nil
	}
	zones, err := p.ListZones(ctx, srv, creds)
	if err != nil {
		return nil, nil, err
	}
	var current []dns.RRSet
	reverse := map[string][]dns.Change{}
	for _, c := range changes {
		if c.RRSet.Type != "A" && c.RRSet.Type != "AAAA" {
			continue
		}
		ips := c.RRSet.Records
		if c.Op == dns.Delete {
			if current == nil {
				if current, err = p.ListRecords(ctx, srv, creds, zone); err != nil {
					return nil, nil, err
				}
			}
			for _, rs := range current {
				if dns.FQDN(rs.Name) == c.RRSet.Name && rs.Type == c.RRSet.Type {
					ips = rs.Records
				}
			}
		}
		for _, ip := range ips {
			ptr, err := dns.PTRName(ip)
			if err != nil {
				continue
			}
			rz := dns.BestZone(ptr, zones)
			if rz == "" {
				warnings = append(warnings, fmt.Sprintf("no reverse zone on this server holds %s, so no PTR was added for %s", ptr, ip))
				continue
			}
			ch := dns.Change{Op: c.Op, RRSet: dns.RRSet{Name: ptr, Type: "PTR", TTL: c.RRSet.TTL}}
			if c.Op == dns.Replace {
				ch.RRSet.Records = []string{c.RRSet.Name}
			}
			reverse[rz] = append(reverse[rz], ch)
		}
	}
	rzs := make([]string, 0, len(reverse))
	for z := range reverse {
		rzs = append(rzs, z)
	}
	sort.Strings(rzs)
	for _, z := range rzs {
		plans = append(plans, ZonePlan{Zone: z, Changes: reverse[z]})
	}
	return plans, warnings, nil
}

func (s *Server) dnsChanges(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Changes []dns.Change `json:"changes"`
		PTR     bool         `json:"ptr"`
		DryRun  bool         `json:"dry_run"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.Changes) == 0 {
		writeErr(w, 400, "no changes")
		return
	}
	p, srv, creds, err := s.dnsServer(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	plans, warnings, err := PlanDNS(r.Context(), p, srv, creds, r.PathValue("zone"), in.Changes, in.PTR)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if in.DryRun {
		writeJSON(w, 200, map[string]any{"applied": false, "plan": plans, "warnings": warnings})
		return
	}
	for i, pl := range plans {
		if err := p.Apply(r.Context(), srv, creds, pl.Zone, pl.Changes); err != nil {
			_ = s.Audit.Record(r.Context(), actor(r), "dns.apply.failed", "dns/"+srv.Name+"/"+pl.Zone,
				map[string]any{"changes": pl.Changes, "error": err.Error()})
			if i > 0 {
				err = fmt.Errorf("forward records were applied but the reverse zone %s failed: %w", pl.Zone, err)
			}
			s.fail(w, err)
			return
		}
		_ = s.Audit.Record(r.Context(), actor(r), "dns.apply", "dns/"+srv.Name+"/"+pl.Zone, map[string]any{"changes": pl.Changes})
	}
	s.Hub.Publish("dns", map[string]any{"server": srv.Name, "zones": len(plans)})
	writeJSON(w, 200, map[string]any{"applied": true, "plan": plans, "warnings": warnings})
}
