package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/dertown/network-control-centre/internal/auth"
	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/smarthome"
)

// smartHomeSource is one hub as the Smart home page shows it, with its latest read.
type smartHomeSource struct {
	ID        int64                `json:"id"`
	Name      string               `json:"name"`
	Kind      string               `json:"kind"`
	Address   string               `json:"address"`
	Enabled   bool                 `json:"enabled"`
	LastError string               `json:"last_error,omitempty"`
	TakenAt   *time.Time           `json:"taken_at,omitempty"`
	Inventory *smarthome.Inventory `json:"inventory,omitempty"`
}

func (s *Server) listSmartHome(w http.ResponseWriter, r *http.Request) {
	ts, err := s.Targets.List(r.Context(), core.CategorySmartHome)
	if err != nil {
		s.fail(w, err)
		return
	}
	entries, err := core.LatestSmartHome(r.Context(), s.Store.DB)
	if err != nil {
		s.fail(w, err)
		return
	}
	byID := map[int64]*smarthome.Inventory{}
	for i := range entries {
		byID[entries[i].TargetID] = &entries[i].Inventory
	}
	out := struct {
		Sources []smartHomeSource `json:"sources"`
	}{Sources: []smartHomeSource{}}
	for _, t := range ts {
		src := smartHomeSource{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Enabled: t.Enabled, LastError: t.LastError}
		if inv, ok := byID[t.ID]; ok && t.Enabled {
			at := inv.TakenAt
			src.TakenAt, src.Inventory = &at, inv
		}
		out.Sources = append(out.Sources, src)
	}
	writeJSON(w, 200, out)
}

// smartHomeTarget resolves a hub and its latest read for a change.
func (s *Server) smartHomeTarget(r *http.Request, id int64) (*core.Target, smarthome.Provider, map[string]string, *smarthome.Inventory, int, error) {
	t, err := s.Targets.Get(r.Context(), id)
	if err != nil || t.Category != core.CategorySmartHome {
		return nil, nil, nil, nil, 404, errors.New("no such smart home connection")
	}
	if !t.Enabled {
		return nil, nil, nil, nil, 409, errors.New(t.Name + " is disabled")
	}
	prov, err := smarthome.Get(t.Kind)
	if err != nil {
		return nil, nil, nil, nil, 500, err
	}
	inv, err := core.SmartHomeFor(r.Context(), s.Store.DB, t.ID)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	if inv == nil {
		return nil, nil, nil, nil, 409, errors.New(t.Name + " has not been read yet; refresh it first")
	}
	creds, err := s.Vault.Get(r.Context(), t.SecretPath)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	return t, prov, creds, inv, 0, nil
}

type smartHomeCommand struct {
	ID int64 `json:"id"`
	smarthome.Command
	Confirm bool `json:"confirm"`
}

// smartHomePlanOut is the preview of a control.
type smartHomePlanOut struct {
	Entity      string         `json:"entity"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Sensitive   bool           `json:"sensitive"` // needs an admin and confirm: true
	Call        smarthome.Call `json:"call"`
}

func planSmartHome(inv *smarthome.Inventory, c smarthome.Command) (*smartHomePlanOut, *smarthome.Entity, int, error) {
	e := inv.Entity(c.Entity)
	if e == nil {
		return nil, nil, 404, errors.New("that device is not in the latest read; refresh and try again")
	}
	call, desc, err := smarthome.Plan(e, c)
	if err != nil {
		return nil, nil, 400, err
	}
	return &smartHomePlanOut{Entity: e.ID, Name: e.Name, Description: desc, Sensitive: smarthome.Sensitive(e, c.Action), Call: call}, e, 0, nil
}

// smartHomePlan previews a control without running it.
func (s *Server) smartHomePlan(w http.ResponseWriter, r *http.Request) {
	var in smartHomeCommand
	if !readJSON(w, r, &in) {
		return
	}
	_, _, _, inv, code, err := s.smartHomeTarget(r, in.ID)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	plan, _, code, err := planSmartHome(inv, in.Command)
	if err != nil {
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, 200, plan)
}

// smartHomeControl runs a control. Unlocking doors, opening garage doors and gates and
// disarming alarms need an admin and confirm: true (after a preview).
func (s *Server) smartHomeControl(w http.ResponseWriter, r *http.Request) {
	var in smartHomeCommand
	if !readJSON(w, r, &in) {
		return
	}
	t, prov, creds, inv, code, err := s.smartHomeTarget(r, in.ID)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	plan, _, code, err := planSmartHome(inv, in.Command)
	if err != nil {
		writeErr(w, code, err.Error())
		return
	}
	if plan.Sensitive {
		if sess := sessionFrom(r); sess == nil || !auth.Allows(sess.User.Role, auth.RoleAdmin) {
			writeErr(w, 403, plan.Description+" needs an admin")
			return
		}
		if !in.Confirm {
			writeErr(w, 409, "confirm this change first: "+plan.Description)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	changed, err := prov.Call(ctx, core.SmartHomeTarget(t), creds, plan.Call)
	detail := map[string]string{"action": in.Action, "service": plan.Call.Domain + "." + plan.Call.Service, "result": errText(err)}
	if in.Value != nil {
		detail["value"] = num(*in.Value)
	}
	if in.Mode != "" {
		detail["mode"] = in.Mode
	}
	_ = s.Audit.Record(r.Context(), actor(r), "smarthome.control", "smarthome/"+t.Name+"/"+plan.Entity, detail)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	// show the new state at once, then read the hub again for anything slower
	if len(changed) > 0 {
		inv.Apply(changed)
		_ = core.SaveSmartHome(r.Context(), s.Store.DB, t.ID, inv)
	}
	if s.Hub != nil {
		s.Hub.Publish("smarthome", map[string]any{"target": t.Name, "entity": plan.Entity})
	}
	s.refreshSmartHome(t.ID, 2*time.Second)
	writeJSON(w, 200, map[string]any{"ok": true, "description": plan.Description, "entity": inv.Entity(plan.Entity)})
}

func (s *Server) refreshSmartHome(id int64, after time.Duration) {
	go func() {
		time.Sleep(after)
		for i := 0; i < 3; i++ {
			_, err := s.Poller.PollOne(s.bg(), id)
			if err == nil || err.Error() != "poll already running" {
				return
			}
			time.Sleep(2 * time.Second)
		}
	}()
}

type matterIn struct {
	ID          int64  `json:"id"`
	Code        string `json:"code"`
	NetworkOnly *bool  `json:"network_only"`
}

// matterCheck previews a Matter pairing: it checks the code and that the hub can pair.
func (s *Server) matterCheck(w http.ResponseWriter, r *http.Request) {
	var in matterIn
	if !readJSON(w, r, &in) {
		return
	}
	pc, err := smarthome.ParsePairingCode(in.Code)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	t, _, _, inv, code, err := s.smartHomeTarget(r, in.ID)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	writeJSON(w, 200, map[string]any{"code": pc, "hub": t.Name, "matter_ready": inv.Hub.Matter, "devices": len(inv.Devices)})
}

// matterPair adds a Matter device to the hub from a pairing code.
func (s *Server) matterPair(w http.ResponseWriter, r *http.Request) {
	var in matterIn
	if !readJSON(w, r, &in) {
		return
	}
	pc, err := smarthome.ParsePairingCode(in.Code)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	t, prov, creds, inv, code, err := s.smartHomeTarget(r, in.ID)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	if !inv.Hub.Matter {
		writeErr(w, 409, "Matter isn't set up in "+t.Name+" yet: in Home Assistant open Settings → Devices & services → Add integration → Matter, then refresh")
		return
	}
	// codes shared from another app are for devices already on the network
	networkOnly := pc.Kind == "manual"
	if in.NetworkOnly != nil {
		networkOnly = *in.NetworkOnly
	}
	before := map[string]bool{}
	for _, d := range inv.Devices {
		before[d.ID] = true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	err = prov.PairMatter(ctx, core.SmartHomeTarget(t), creds, pc.Code, networkOnly)
	_ = s.Audit.Record(r.Context(), actor(r), "smarthome.matter.pair", "smarthome/"+t.Name,
		map[string]string{"code": pc.Formatted, "network_only": map[bool]string{true: "yes", false: "no"}[networkOnly], "result": errText(err)})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	out := smarthome.PairResult{}
	// read the hub again to name the new device
	time.Sleep(time.Second)
	if _, err := s.Poller.PollOne(r.Context(), t.ID); err == nil {
		if now, err := core.SmartHomeFor(r.Context(), s.Store.DB, t.ID); err == nil && now != nil {
			for _, d := range now.Devices {
				if !before[d.ID] {
					out.NewDevices = append(out.NewDevices, d.Name)
				}
			}
		}
	}
	writeJSON(w, 200, out)
}

func num(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }
