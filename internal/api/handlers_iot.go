package api

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/iot"
)

// iotNetwork is a network as the IoT page shows it.
type iotNetwork struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	VLAN      int    `json:"vlan,omitempty"`
	Subnet    string `json:"subnet,omitempty"`
	Zone      string `json:"zone,omitempty"`
	Target    string `json:"target"`
	IoT       bool   `json:"iot"`       // counted as an IoT network
	Suggested bool   `json:"suggested"` // its name says it is for IoT devices
	Devices   int    `json:"devices"`   // IoT devices on it now
}

// iotCandidate is a network client that is not in the IoT inventory yet.
type iotCandidate struct {
	MAC     string `json:"mac"`
	Name    string `json:"name"`
	IP      string `json:"ip,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	Network string `json:"network,omitempty"`
	Guess   string `json:"guess,omitempty"` // type NCC would give it
	Ignored bool   `json:"ignored"`         // marked not IoT before
}

type iotView struct {
	Devices    []iot.Device   `json:"devices"`
	Networks   []iotNetwork   `json:"networks"`
	Chosen     bool           `json:"networks_chosen"` // false: IoT networks are guessed from their names
	Types      []string       `json:"types"`
	Candidates []iotCandidate `json:"candidates"`
	Sources    int            `json:"sources"` // network controllers read
}

// iotState gathers the inventory with what the latest network reads say about it.
func (s *Server) iotState(ctx context.Context) (*iotView, []inventory.Snapshot, error) {
	devs, err := iot.List(ctx, s.Store.DB)
	if err != nil {
		return nil, nil, err
	}
	snaps, err := core.LatestSnapshots(ctx, s.Store.DB)
	if err != nil {
		return nil, nil, err
	}
	chosenIDs, chosen, err := iot.IoTNetworks(ctx, s.Store.DB)
	if err != nil {
		return nil, nil, err
	}
	targets, err := s.Targets.List(ctx, core.CategoryDevice)
	if err != nil {
		return nil, nil, err
	}
	targetName := map[int64]string{}
	for _, t := range targets {
		targetName[t.ID] = t.Name
	}

	isChosen := map[string]bool{}
	for _, id := range chosenIDs {
		isChosen[id] = true
	}
	view := &iotView{Devices: devs, Networks: []iotNetwork{}, Chosen: chosen, Types: iot.Types, Candidates: []iotCandidate{}, Sources: len(snaps)}
	iotNets := map[string]bool{}
	netByID := map[string]*inventory.Network{}
	devName := map[string]string{}
	for i := range snaps {
		for j := range snaps[i].Networks {
			n := &snaps[i].Networks[j]
			if n.Purpose == "wan" || n.Purpose == "vpn" || netByID[n.ID] != nil {
				continue
			}
			netByID[n.ID] = n
			sug := iot.DefaultIoTNetwork(*n)
			on := sug
			if chosen {
				on = isChosen[n.ID]
			}
			if on {
				iotNets[n.ID] = true
			}
			view.Networks = append(view.Networks, iotNetwork{ID: n.ID, Name: n.Name, VLAN: n.VLAN, Subnet: n.Subnet,
				Zone: n.ZoneName, Target: snaps[i].Target, IoT: on, Suggested: sug})
		}
		for _, d := range snaps[i].Devices {
			if m := iot.NormMAC(d.MAC); m != "" {
				devName[m] = d.Name
			}
		}
	}
	// a hub that knows a device by its MAC adds model and firmware
	type hubInfo struct{ model, firmware string }
	hub := map[string]hubInfo{}
	if entries, err := core.LatestSmartHome(ctx, s.Store.DB); err == nil {
		for _, e := range entries {
			for _, d := range e.Inventory.Devices {
				if m := iot.NormMAC(d.MAC); m != "" {
					hub[m] = hubInfo{strings.TrimSpace(d.Manufacturer + " " + d.Model), d.Firmware}
				}
			}
		}
	}
	inInventory := map[string]bool{}
	for i := range devs {
		d := &devs[i]
		inInventory[d.MAC] = true
		d.Target = targetName[d.TargetID]
		if n := netByID[d.NetworkID]; n != nil {
			if d.Network == "" {
				d.Network = n.Name
			}
			if d.VLAN == 0 {
				d.VLAN = n.VLAN
			}
		}
		switch {
		case d.Wired && d.SwitchMAC != "":
			d.Uplink = firstNonEmpty(devName[iot.NormMAC(d.SwitchMAC)], d.SwitchMAC)
			if d.SwitchPort > 0 {
				d.Uplink += " port " + strconv.Itoa(d.SwitchPort)
			}
		case !d.Wired && d.APMAC != "":
			d.Uplink = firstNonEmpty(devName[iot.NormMAC(d.APMAC)], d.APMAC)
			if d.SSID != "" {
				d.Uplink += " (" + d.SSID + ")"
			}
		}
		if h, ok := hub[d.MAC]; ok {
			d.Model, d.Firmware = h.model, h.firmware
		}
	}
	iot.Assess(devs, iotNets)
	for i := range view.Networks {
		for _, d := range devs {
			if d.NetworkID == view.Networks[i].ID && d.Online && !d.Ignored {
				view.Networks[i].Devices++
			}
		}
	}
	sort.Slice(view.Networks, func(i, j int) bool { return view.Networks[i].VLAN < view.Networks[j].VLAN })
	seen := map[string]bool{}
	for _, sn := range snaps {
		for _, c := range sn.Clients {
			m := iot.NormMAC(c.MAC)
			if m == "" || inInventory[m] || seen[m] {
				continue
			}
			seen[m] = true
			guess, _ := iot.Classify(c.Vendor, c.Name)
			view.Candidates = append(view.Candidates, iotCandidate{MAC: m, Name: firstNonEmpty(c.Name, m), IP: c.IP, Vendor: c.Vendor,
				Network: firstNonEmpty(c.Network, netName(netByID[c.NetworkID])), Guess: guess})
		}
	}
	// ignored devices can be brought back from the same list
	for _, d := range devs {
		if d.Ignored {
			view.Candidates = append(view.Candidates, iotCandidate{MAC: d.MAC, Name: d.Name, IP: d.IP, Vendor: d.Vendor, Network: d.Network,
				Guess: d.AutoType, Ignored: true})
		}
	}
	sort.Slice(view.Candidates, func(i, j int) bool {
		return strings.ToLower(view.Candidates[i].Name) < strings.ToLower(view.Candidates[j].Name)
	})
	return view, snaps, nil
}

func netName(n *inventory.Network) string {
	if n == nil {
		return ""
	}
	return n.Name
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func (s *Server) listIoT(w http.ResponseWriter, r *http.Request) {
	view, _, err := s.iotState(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, view)
}

type iotUpdateIn struct {
	MACs []string `json:"macs"`
	iot.Patch
}

// updateIoT records details (type, owner, location, notes, network exceptions) for one
// or more devices.
func (s *Server) updateIoT(w http.ResponseWriter, r *http.Request) {
	var in iotUpdateIn
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.MACs) == 0 || len(in.MACs) > 1000 {
		writeErr(w, 400, "choose between 1 and 1000 devices")
		return
	}
	if in.Patch.Empty() {
		writeErr(w, 400, "nothing to change")
		return
	}
	n, err := iot.Update(r.Context(), s.Store.DB, in.MACs, in.Patch, actor(r))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	target := "iot/" + strconv.Itoa(len(in.MACs)) + " devices"
	if len(in.MACs) == 1 {
		target = "iot/" + iot.NormMAC(in.MACs[0])
	}
	_ = s.Audit.Record(r.Context(), actor(r), "iot.update", target, map[string]any{"macs": in.MACs, "changes": in.Patch})
	if s.Hub != nil {
		s.Hub.Publish("iot", map[string]any{"updated": n})
	}
	writeJSON(w, 200, map[string]any{"updated": n})
}

type iotAddIn struct {
	MAC  string `json:"mac"`
	Type string `json:"type"`
}

// addIoT puts a network client in the IoT inventory.
func (s *Server) addIoT(w http.ResponseWriter, r *http.Request) {
	var in iotAddIn
	if !readJSON(w, r, &in) {
		return
	}
	mac := iot.NormMAC(in.MAC)
	if mac == "" {
		writeErr(w, 400, "that is not a MAC address")
		return
	}
	snaps, err := core.LatestSnapshots(r.Context(), s.Store.DB)
	if err != nil {
		s.fail(w, err)
		return
	}
	targets, err := s.Targets.List(r.Context(), core.CategoryDevice)
	if err != nil {
		s.fail(w, err)
		return
	}
	targetID := map[string]int64{}
	for _, t := range targets {
		targetID[t.Name] = t.ID
	}
	var found *inventory.Client
	var at inventory.Snapshot
	for _, sn := range snaps {
		for i := range sn.Clients {
			if iot.NormMAC(sn.Clients[i].MAC) == mac {
				found, at = &sn.Clients[i], sn
			}
		}
	}
	devs, err := iot.List(r.Context(), s.Store.DB)
	if err != nil {
		s.fail(w, err)
		return
	}
	known := false
	for _, d := range devs {
		known = known || d.MAC == mac
	}
	if found == nil && !known {
		writeErr(w, 404, "no client with that MAC is on the network now")
		return
	}
	c := inventory.Client{MAC: mac}
	var tid int64
	if found != nil {
		c, tid = *found, targetID[at.Target]
	}
	if err := iot.Add(r.Context(), s.Store.DB, tid, c, at.TakenAt, found != nil, in.Type, actor(r)); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "iot.add", "iot/"+mac, map[string]string{"name": c.Name, "type": in.Type})
	writeJSON(w, 200, map[string]any{"ok": true, "mac": mac})
}

// deleteIoT forgets a device.
func (s *Server) deleteIoT(w http.ResponseWriter, r *http.Request) {
	mac := iot.NormMAC(r.PathValue("mac"))
	ok, err := iot.Delete(r.Context(), s.Store.DB, mac)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !ok {
		writeErr(w, 404, "no such device")
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "iot.delete", "iot/"+mac, nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

type iotNetworksIn struct {
	IDs   []string `json:"ids"`
	Guess bool     `json:"guess"` // go back to guessing from names
}

// setIoTNetworks chooses which networks IoT devices belong on.
func (s *Server) setIoTNetworks(w http.ResponseWriter, r *http.Request) {
	var in iotNetworksIn
	if !readJSON(w, r, &in) {
		return
	}
	ids := in.IDs
	if in.Guess {
		ids = nil
	} else if ids == nil {
		ids = []string{}
	}
	if err := iot.SetIoTNetworks(r.Context(), s.Store.DB, ids); err != nil {
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "iot.networks", "iot/networks", map[string]any{"ids": ids, "guess": in.Guess})
	writeJSON(w, 200, map[string]any{"ok": true})
}
