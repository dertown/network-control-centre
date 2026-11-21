package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/core"
	hv "github.com/dertown/network-control-centre/internal/hypervisor"
)

// vmSource is one Proxmox or VMware connection as the Virtual machines page shows it.
type vmSource struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Kind      string     `json:"kind"`
	Address   string     `json:"address"`
	Enabled   bool       `json:"enabled"`
	Version   string     `json:"version,omitempty"`
	TakenAt   *time.Time `json:"taken_at,omitempty"`
	LastError string     `json:"last_error,omitempty"`
	Warnings  []string   `json:"warnings,omitempty"`
}

// listVMs returns every virtual machine and host from the latest read of each hypervisor.
func (s *Server) listVMs(w http.ResponseWriter, r *http.Request) {
	ts, err := s.Targets.List(r.Context(), core.CategoryHypervisor)
	if err != nil {
		s.fail(w, err)
		return
	}
	invs, err := core.LatestVMInventories(r.Context(), s.Store.DB)
	if err != nil {
		s.fail(w, err)
		return
	}
	byName := map[string]hv.Inventory{}
	for _, inv := range invs {
		byName[inv.Target] = inv
	}
	out := struct {
		Sources []vmSource `json:"sources"`
		Hosts   []hv.Host  `json:"hosts"`
		VMs     []hv.VM    `json:"vms"`
	}{Sources: []vmSource{}, Hosts: []hv.Host{}, VMs: []hv.VM{}}
	for _, t := range ts {
		src := vmSource{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Enabled: t.Enabled, LastError: t.LastError}
		if inv, ok := byName[t.Name]; ok && t.Enabled {
			at := inv.TakenAt
			src.TakenAt, src.Version, src.Warnings = &at, inv.Version, inv.Warnings
			out.Hosts = append(out.Hosts, inv.Hosts...)
			out.VMs = append(out.VMs, inv.VMs...)
		}
		out.Sources = append(out.Sources, src)
	}
	writeJSON(w, 200, out)
}

// vmTarget resolves a VM id ("<connection>/...") to its connection, controller and credentials.
func (s *Server) vmTarget(r *http.Request, id string) (*core.Target, hv.Controller, map[string]string, *hv.VM, int, error) {
	name, _, ok := strings.Cut(id, "/")
	if !ok || name == "" {
		return nil, nil, nil, nil, 400, errors.New("bad VM id")
	}
	ts, err := s.Targets.List(r.Context(), core.CategoryHypervisor)
	if err != nil {
		return nil, nil, nil, nil, 500, err
	}
	var t *core.Target
	for i := range ts {
		if ts[i].Name == name {
			t = &ts[i]
		}
	}
	if t == nil {
		return nil, nil, nil, nil, 404, errors.New("no connection named " + name)
	}
	if !t.Enabled {
		return nil, nil, nil, nil, 409, errors.New(name + " is disabled")
	}
	prov, err := hv.Get(t.Kind)
	if err != nil {
		return nil, nil, nil, nil, 500, err
	}
	ctl, ok := prov.(hv.Controller)
	if !ok {
		return nil, nil, nil, nil, 501, errors.New(t.Kind + " connections cannot change machines")
	}
	creds, err := s.Vault.Get(r.Context(), t.SecretPath)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	var vm *hv.VM
	if invs, err := core.LatestVMInventories(r.Context(), s.Store.DB); err == nil {
		for _, inv := range invs {
			for i := range inv.VMs {
				if inv.VMs[i].ID == id {
					vm = &inv.VMs[i]
				}
			}
		}
	}
	return t, ctl, creds, vm, 0, nil
}

func (s *Server) vmFail(w http.ResponseWriter, code int, err error) {
	if code != 0 {
		writeErr(w, code, err.Error())
		return
	}
	s.fail(w, err)
}

// refreshVMs re-reads a connection after a change, so the page shows the new state.
func (s *Server) refreshVMs(id int64) {
	go func() {
		for i := 0; i < 3; i++ {
			_, err := s.Poller.PollOne(s.bg(), id)
			if err == nil || err.Error() != "poll already running" {
				return
			}
			time.Sleep(2 * time.Second)
		}
	}()
}

func vmLabel(id string, vm *hv.VM) string {
	if vm != nil {
		return "vm/" + vm.Target + "/" + vm.Name
	}
	return "vm/" + id
}

func (s *Server) vmPower(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID     string `json:"id"`
		Action string `json:"action"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !hv.ValidAction(in.Action) {
		writeErr(w, 400, "action must be start, shutdown, stop or reboot")
		return
	}
	t, ctl, creds, vm, code, err := s.vmTarget(r, in.ID)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	err = ctl.Power(ctx, hvTarget(t), creds, in.ID, in.Action)
	_ = s.Audit.Record(r.Context(), actor(r), "vm.power", vmLabel(in.ID, vm), map[string]string{"action": in.Action, "result": errText(err)})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	s.refreshVMs(t.ID)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) vmSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID string `json:"id"`
		hv.Settings
	}
	if !readJSON(w, r, &in) {
		return
	}
	if err := in.Settings.Validate(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	t, ctl, creds, vm, code, err := s.vmTarget(r, in.ID)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	err = ctl.Configure(ctx, hvTarget(t), creds, in.ID, in.Settings)
	_ = s.Audit.Record(r.Context(), actor(r), "vm.settings", vmLabel(in.ID, vm), map[string]any{"change": in.Settings, "result": errText(err)})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	s.refreshVMs(t.ID)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) vmDelete(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID      string `json:"id"`
		Confirm string `json:"confirm"` // must be the machine's name
	}
	if !readJSON(w, r, &in) {
		return
	}
	t, ctl, creds, vm, code, err := s.vmTarget(r, in.ID)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	if vm == nil {
		writeErr(w, 404, "that machine is not in the latest list; refresh and try again")
		return
	}
	if in.Confirm != vm.Name {
		writeErr(w, 400, "type the machine's name to confirm deleting it")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	err = ctl.Delete(ctx, hvTarget(t), creds, in.ID)
	_ = s.Audit.Record(r.Context(), actor(r), "vm.delete", vmLabel(in.ID, vm), map[string]string{"host": vm.Host, "result": errText(err)})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	s.refreshVMs(t.ID)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func hvTarget(t *core.Target) hv.Target {
	return hv.Target{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Options: t.Options}
}

func errText(err error) string {
	if err != nil {
		return "failed: " + err.Error()
	}
	return "ok"
}
