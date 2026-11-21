package api

import (
	"net/http"
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
