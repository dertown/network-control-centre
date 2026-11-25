package api

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/inventory"
)

// VLAN page: networks per router, the clients in each, creating networks and moving clients.

type vlanDevice struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Online bool   `json:"online"`
}

type vlanTarget struct {
	ID         int64                `json:"id"`
	Name       string               `json:"name"`
	Kind       string               `json:"kind"`
	Writable   bool                 `json:"writable"`
	TakenAt    *time.Time           `json:"taken_at,omitempty"`
	LastError  string               `json:"last_error,omitempty"`
	Networks   []inventory.Network  `json:"networks"`
	Clients    []vlanClient         `json:"clients"`
	Devices    []vlanDevice         `json:"devices"`
	Suggestion drivers.NetworkSpec  `json:"suggestion"`
	Ports      map[string]portBrief `json:"ports"`
}

// vlanClient is a client, and whether it still has an address from its old network.
type vlanClient struct {
	inventory.Client
	Stale bool `json:"stale,omitempty"`
}

// portBrief says what a client's switch port is, keyed "switch-mac#port".
type portBrief struct {
	Name    string `json:"name"`
	Profile string `json:"profile,omitempty"`
	Infra   bool   `json:"infra,omitempty"`
	Clients int    `json:"clients"`
}

func (s *Server) snapshotFor(ctx context.Context, t *core.Target) (*inventory.Snapshot, error) {
	snaps, err := core.LatestSnapshots(ctx, s.Store.DB)
	if err != nil {
		return nil, err
	}
	for i := range snaps {
		if snaps[i].Target == t.Name {
			return &snaps[i], nil
		}
	}
	return nil, nil
}

func (s *Server) listVLANs(w http.ResponseWriter, r *http.Request) {
	ts, err := s.Targets.List(r.Context(), core.CategoryDevice)
	if err != nil {
		s.fail(w, err)
		return
	}
	snaps, err := core.LatestSnapshots(r.Context(), s.Store.DB)
	if err != nil {
		s.fail(w, err)
		return
	}
	byName := map[string]*inventory.Snapshot{}
	for i := range snaps {
		byName[snaps[i].Target] = &snaps[i]
	}
	out := []vlanTarget{}
	for _, t := range ts {
		if !t.Enabled {
			continue
		}
		vt := vlanTarget{ID: t.ID, Name: t.Name, Kind: t.Kind, LastError: t.LastError, Networks: []inventory.Network{},
			Clients: []vlanClient{}, Devices: []vlanDevice{}, Ports: map[string]portBrief{}}
		if d, err := drivers.Get(t.Kind); err == nil {
			_, vt.Writable = d.(drivers.NetworkWriter)
		}
		if snap := byName[t.Name]; snap != nil {
			at := snap.TakenAt
			vt.TakenAt = &at
			vt.Networks = append(vt.Networks, snap.Networks...)
			for _, c := range snap.Clients {
				vt.Clients = append(vt.Clients, vlanClient{Client: c})
			}
			for _, d := range snap.Devices {
				vt.Devices = append(vt.Devices, vlanDevice{ID: d.ID, Name: d.Name, Kind: d.Kind, Online: d.Online})
				for _, p := range d.Ports {
					vt.Ports[d.ID+"#"+strconv.Itoa(p.Index)] = portBrief{Name: p.Name, Profile: p.Profile, Infra: p.Infra}
				}
			}
			for i, c := range snap.Clients {
				vt.Clients[i].Stale = core.StaleAddress(c, snap.Networks)
				if c.Wired && c.SwitchMAC != "" {
					k := c.SwitchMAC + "#" + strconv.Itoa(c.SwitchPort)
					pb := vt.Ports[k]
					pb.Clients++
					vt.Ports[k] = pb
				}
			}
			vt.Suggestion = core.SuggestNetwork(snap.Networks)
		}
		sort.SliceStable(vt.Clients, func(i, j int) bool { return vt.Clients[i].Name < vt.Clients[j].Name })
		out = append(out, vt)
	}
	writeJSON(w, 200, map[string]any{"targets": out})
}

// vlanWriter resolves a device target that can write networks.
func (s *Server) vlanWriter(r *http.Request, id int64) (*core.Target, drivers.NetworkWriter, map[string]string, int, error) {
	t, err := s.Targets.Get(r.Context(), id)
	if err != nil {
		return nil, nil, nil, 404, err
	}
	if t.Category != core.CategoryDevice {
		return nil, nil, nil, 400, errors.New(t.Name + " is not a router or switch connection")
	}
	if !t.Enabled {
		return nil, nil, nil, 409, errors.New(t.Name + " is disabled")
	}
	d, err := drivers.Get(t.Kind)
	if err != nil {
		return nil, nil, nil, 500, err
	}
	nw, ok := d.(drivers.NetworkWriter)
	if !ok {
		return nil, nil, nil, 501, errors.New(t.Kind + " connections cannot change networks yet")
	}
	creds, err := s.Vault.Get(r.Context(), t.SecretPath)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	return t, nw, creds, 0, nil
}

func devTarget(t *core.Target) drivers.Target {
	return drivers.Target{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Options: t.Options}
}

// refreshTarget polls a device again after a change, retrying while a poll is running.
func (s *Server) refreshTarget(id int64, delays ...time.Duration) {
	go func() {
		for _, d := range delays {
			time.Sleep(d)
			for i := 0; i < 3; i++ {
				_, err := s.Poller.PollOne(s.bg(), id)
				if err == nil || err.Error() != "poll already running" {
					break
				}
				time.Sleep(2 * time.Second)
			}
		}
	}()
}

func (s *Server) createVLAN(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TargetID int64 `json:"target_id"`
		drivers.NetworkSpec
	}
	if !readJSON(w, r, &in) {
		return
	}
	t, nw, creds, code, err := s.vlanWriter(r, in.TargetID)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	snap, err := s.snapshotFor(r.Context(), t)
	if err != nil {
		s.fail(w, err)
		return
	}
	if snap == nil {
		writeErr(w, 409, "NCC has not read "+t.Name+" yet; wait for the first refresh")
		return
	}
	spec := in.NetworkSpec
	if err := core.ValidateNetwork(&spec, snap.Networks); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	id, err := nw.CreateNetwork(ctx, devTarget(t), creds, spec)
	_ = s.Audit.Record(r.Context(), actor(r), "vlan.create", "network/"+t.Name+"/"+spec.Name,
		map[string]any{"spec": spec, "id": id, "result": errText(err)})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	s.refreshTarget(t.ID, 0)
	writeJSON(w, 201, map[string]any{"id": id, "spec": spec})
}

type moveIn struct {
	TargetID  int64    `json:"target_id"`
	NetworkID string   `json:"network_id"`
	MACs      []string `json:"macs"`
	Reconnect bool     `json:"reconnect"`
}

func (s *Server) planFor(w http.ResponseWriter, r *http.Request, in moveIn) (*core.Target, *core.MovePlan, bool) {
	t, err := s.Targets.Get(r.Context(), in.TargetID)
	if err != nil {
		s.fail(w, err)
		return nil, nil, false
	}
	snap, err := s.snapshotFor(r.Context(), t)
	if err != nil {
		s.fail(w, err)
		return nil, nil, false
	}
	if snap == nil {
		writeErr(w, 409, "NCC has not read "+t.Name+" yet; wait for the first refresh")
		return nil, nil, false
	}
	if len(in.MACs) > 500 {
		writeErr(w, 400, "move at most 500 clients at a time")
		return nil, nil, false
	}
	plan, err := core.PlanMove(snap, in.NetworkID, in.MACs)
	if err != nil {
		writeErr(w, 400, err.Error())
		return nil, nil, false
	}
	return t, plan, true
}

func (s *Server) planVLANMove(w http.ResponseWriter, r *http.Request) {
	var in moveIn
	if !readJSON(w, r, &in) {
		return
	}
	if _, plan, ok := s.planFor(w, r, in); ok {
		writeJSON(w, 200, plan)
	}
}

func (s *Server) moveVLANClients(w http.ResponseWriter, r *http.Request) {
	var in moveIn
	if !readJSON(w, r, &in) {
		return
	}
	t, plan, ok := s.planFor(w, r, in)
	if !ok {
		return
	}
	moves := plan.Moves()
	if len(moves) == 0 {
		writeErr(w, 400, "nothing to change: the clients are already there or cannot be moved")
		return
	}
	_, nw, creds, code, err := s.vlanWriter(r, t.ID)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	results, err := nw.MoveClients(ctx, devTarget(t), creds, plan.Network.ID, moves, in.Reconnect)
	for _, res := range results {
		detail := map[string]any{"network": plan.Network.Name, "vlan": plan.Network.VLAN, "result": "ok"}
		for _, st := range plan.Steps {
			if st.MAC == res.MAC {
				detail["from"], detail["method"], detail["via"] = st.FromName, st.Method, st.Via
			}
		}
		if !res.OK {
			detail["result"] = "failed: " + res.Error
		} else if res.Warning != "" {
			detail["result"] = "saved, not applied: " + res.Warning
		}
		if len(res.Notes) > 0 {
			detail["notes"] = res.Notes
		}
		_ = s.Audit.Record(r.Context(), actor(r), "vlan.move", "client/"+t.Name+"/"+res.Name+" ("+res.MAC+")", detail)
	}
	// the console needs a few seconds to provision switches and access points
	s.refreshTarget(t.ID, 3*time.Second, 15*time.Second)
	out := map[string]any{"results": results, "network": plan.Network}
	if err != nil {
		out["error"] = err.Error()
		writeJSON(w, 502, out)
		return
	}
	writeJSON(w, 200, out)
}

// reconnectVLANClients makes clients ask for a new address, e.g. ones still on an address
// from their old network after a move.
func (s *Server) reconnectVLANClients(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TargetID int64    `json:"target_id"`
		MACs     []string `json:"macs"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.MACs) == 0 || len(in.MACs) > 500 {
		writeErr(w, 400, "pick between 1 and 500 clients")
		return
	}
	t, nw, creds, code, err := s.vlanWriter(r, in.TargetID)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	snap, err := s.snapshotFor(r.Context(), t)
	if err != nil {
		s.fail(w, err)
		return
	}
	if snap == nil {
		writeErr(w, 409, "NCC has not read "+t.Name+" yet; wait for the first refresh")
		return
	}
	moves, steps := core.PlanReconnect(snap, in.MACs)
	var results []drivers.MoveResult
	if len(moves) > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()
		results, err = nw.Reconnect(ctx, devTarget(t), creds, moves)
	}
	byMAC := map[string]drivers.MoveResult{}
	for _, res := range results {
		byMAC[res.MAC] = res
	}
	// every step gets a result: port mates share their port's result
	portRes := map[string]drivers.MoveResult{}
	for _, m := range moves {
		if m.Method == drivers.MovePort {
			portRes[m.SwitchMAC+"#"+strconv.Itoa(m.SwitchPort)] = byMAC[m.MAC]
		}
	}
	out := []drivers.MoveResult{}
	for _, st := range steps {
		res := drivers.MoveResult{MAC: st.MAC, Name: st.Name}
		switch {
		case st.Blocked != "":
			res.Error = st.Blocked
		case st.Method == drivers.MovePort:
			pr := portRes[st.SwitchMAC+"#"+strconv.Itoa(st.SwitchPort)]
			res.OK, res.Error, res.Notes = pr.OK, pr.Error, pr.Notes
		default:
			pr := byMAC[st.MAC]
			res.OK, res.Error, res.Notes = pr.OK, pr.Error, pr.Notes
		}
		if !res.OK && res.Error == "" && err != nil {
			res.Error = err.Error()
		}
		detail := map[string]any{"via": st.Via, "result": "ok"}
		if !res.OK {
			detail["result"] = "failed: " + res.Error
		}
		_ = s.Audit.Record(r.Context(), actor(r), "vlan.reconnect", "client/"+t.Name+"/"+res.Name+" ("+res.MAC+")", detail)
		out = append(out, res)
	}
	s.refreshTarget(t.ID, 5*time.Second, 20*time.Second)
	resp := map[string]any{"results": out}
	if err != nil {
		resp["error"] = err.Error()
		writeJSON(w, 502, resp)
		return
	}
	writeJSON(w, 200, resp)
}
