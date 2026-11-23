package api

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/vault"
)

// Wi-Fi page: each router's SSIDs, access point radios and wireless clients, the weak settings
// NCC flags, and SSID changes (preview first, then apply). Passphrases NCC sets or reads are
// kept in the vault under wifi/<connection>/<ssid id> and never written to the audit log or
// the server log.

type wifiClient struct {
	MAC     string `json:"mac"`
	Name    string `json:"name"`
	IP      string `json:"ip,omitempty"`
	SSID    string `json:"ssid,omitempty"`
	APID    string `json:"ap_id,omitempty"`
	AP      string `json:"ap,omitempty"`
	Band    string `json:"band,omitempty"`
	Channel int    `json:"channel,omitempty"`
	Signal  int    `json:"signal,omitempty"`
	Network string `json:"network,omitempty"`
}

type wifiNetwork struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	VLAN     int    `json:"vlan,omitempty"`
	Purpose  string `json:"purpose,omitempty"`
	Zone     string `json:"zone,omitempty"`
	Isolated bool   `json:"isolated,omitempty"`
}

type wifiTarget struct {
	ID        int64              `json:"id"`
	Name      string             `json:"name"`
	Kind      string             `json:"kind"`
	Writable  bool               `json:"writable"`
	TakenAt   *time.Time         `json:"taken_at,omitempty"`
	LastError string             `json:"last_error,omitempty"`
	SSIDs     []inventory.SSID   `json:"ssids"`
	Radios    []inventory.Radio  `json:"radios"`
	Clients   []wifiClient       `json:"clients"`
	Networks  []wifiNetwork      `json:"networks"`
	Findings  []core.WiFiFinding `json:"findings"`
	// Saved lists the SSIDs (by id) whose passphrase NCC has a copy of in the vault.
	Saved []string `json:"saved"`
}

func wifiSecretPath(t *core.Target, ssidID string) string {
	return "wifi/" + t.Name + "/" + ssidID
}

func (s *Server) listWiFi(w http.ResponseWriter, r *http.Request) {
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
	out := []wifiTarget{}
	for i := range ts {
		t := &ts[i]
		if !t.Enabled {
			continue
		}
		wt := wifiTarget{ID: t.ID, Name: t.Name, Kind: t.Kind, LastError: t.LastError, SSIDs: []inventory.SSID{},
			Radios: []inventory.Radio{}, Clients: []wifiClient{}, Networks: []wifiNetwork{}, Findings: []core.WiFiFinding{}, Saved: []string{}}
		if d, err := drivers.Get(t.Kind); err == nil {
			_, wt.Writable = d.(drivers.WiFiWriter)
		}
		snap := byName[t.Name]
		if snap != nil {
			at := snap.TakenAt
			wt.TakenAt = &at
			if snap.WiFi != nil {
				wt.SSIDs = append(wt.SSIDs, snap.WiFi.SSIDs...)
				wt.Radios = append(wt.Radios, snap.WiFi.Radios...)
			}
			wt.Findings = core.WiFiFindings(snap)
			names := map[string]string{}
			for _, d := range snap.Devices {
				names[d.ID] = d.Name
			}
			for _, c := range snap.Clients {
				if c.Wired {
					continue
				}
				wt.Clients = append(wt.Clients, wifiClient{MAC: c.MAC, Name: c.Name, IP: c.IP, SSID: c.SSID, APID: c.APMAC,
					AP: names[c.APMAC], Band: c.Band, Channel: c.Channel, Signal: c.Signal, Network: c.Network})
			}
			sort.SliceStable(wt.Clients, func(i, j int) bool { return wt.Clients[i].Name < wt.Clients[j].Name })
			for _, n := range snap.Networks {
				if n.Purpose == "wan" || strings.Contains(n.Purpose, "vpn") {
					continue
				}
				wt.Networks = append(wt.Networks, wifiNetwork{ID: n.ID, Name: n.Name, VLAN: n.VLAN, Purpose: n.Purpose, Zone: n.Zone, Isolated: n.Isolated})
			}
		}
		// a sealed vault just means nothing is shown as saved
		if paths, err := s.Vault.List(r.Context(), "wifi/"+t.Name+"/"); err == nil {
			for _, p := range paths {
				wt.Saved = append(wt.Saved, p[strings.LastIndex(p, "/")+1:])
			}
		}
		if snap == nil || snap.WiFi == nil {
			// routers without Wi-Fi (or not read yet) are only listed when they failed, so the error shows
			if t.LastError == "" && snap != nil {
				continue
			}
		}
		out = append(out, wt)
	}
	writeJSON(w, 200, map[string]any{"targets": out})
}

// wifiIn is a requested SSID change. Passphrase travels only in this request: it is sent to
// the router and saved in the vault, never echoed back, logged or audited.
type wifiIn struct {
	TargetID   int64   `json:"target_id"`
	SSIDID     string  `json:"ssid_id"`
	Name       *string `json:"name,omitempty"`
	Enabled    *bool   `json:"enabled,omitempty"`
	Hidden     *bool   `json:"hidden,omitempty"`
	NetworkID  *string `json:"network_id,omitempty"`
	Security   *string `json:"security,omitempty"`
	Passphrase *string `json:"passphrase,omitempty"`
}

func (in wifiIn) change() *drivers.WLANChange {
	return &drivers.WLANChange{Name: in.Name, Enabled: in.Enabled, Hidden: in.Hidden, NetworkID: in.NetworkID,
		Security: in.Security, Passphrase: in.Passphrase}
}

func (s *Server) wifiPlanFor(w http.ResponseWriter, r *http.Request, in wifiIn) (*core.Target, *core.WiFiPlan, *drivers.WLANChange, bool) {
	t, err := s.Targets.Get(r.Context(), in.TargetID)
	if err != nil {
		s.fail(w, err)
		return nil, nil, nil, false
	}
	snap, err := s.snapshotFor(r.Context(), t)
	if err != nil {
		s.fail(w, err)
		return nil, nil, nil, false
	}
	if snap == nil {
		writeErr(w, 409, "NCC has not read "+t.Name+" yet; wait for the first refresh")
		return nil, nil, nil, false
	}
	ch := in.change()
	plan, err := core.PlanWiFiChange(snap, in.SSIDID, ch)
	if err != nil {
		writeErr(w, 400, err.Error())
		return nil, nil, nil, false
	}
	return t, plan, ch, true
}

func (s *Server) planWiFi(w http.ResponseWriter, r *http.Request) {
	var in wifiIn
	if !readJSON(w, r, &in) {
		return
	}
	if _, plan, _, ok := s.wifiPlanFor(w, r, in); ok {
		writeJSON(w, 200, plan)
	}
}

// wifiWriter resolves a device target whose driver can change Wi-Fi.
func (s *Server) wifiWriter(r *http.Request, t *core.Target) (drivers.WiFiWriter, vault.Secret, int, error) {
	if t.Category != core.CategoryDevice {
		return nil, nil, 400, errors.New(t.Name + " is not a router connection")
	}
	if !t.Enabled {
		return nil, nil, 409, errors.New(t.Name + " is disabled")
	}
	d, err := drivers.Get(t.Kind)
	if err != nil {
		return nil, nil, 500, err
	}
	ww, ok := d.(drivers.WiFiWriter)
	if !ok {
		return nil, nil, 501, errors.New(t.Kind + " connections cannot change Wi-Fi yet")
	}
	creds, err := s.Vault.Get(r.Context(), t.SecretPath)
	if err != nil {
		return nil, nil, 0, err
	}
	return ww, creds, 0, nil
}

func (s *Server) applyWiFi(w http.ResponseWriter, r *http.Request) {
	var in wifiIn
	if !readJSON(w, r, &in) {
		return
	}
	t, plan, ch, ok := s.wifiPlanFor(w, r, in)
	if !ok {
		return
	}
	ww, creds, code, err := s.wifiWriter(r, t)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	err = ww.UpdateWLAN(ctx, devTarget(t), creds, in.SSIDID, *ch)
	// the plan's change lines describe the passphrase without its value
	_ = s.Audit.Record(r.Context(), actor(r), "wifi.update", "wifi/"+t.Name+"/"+plan.SSID.Name,
		map[string]any{"ssid_id": in.SSIDID, "changes": plan.Changes, "result": errText(err)})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	resp := map[string]any{"ok": true, "ssid": plan.SSID.Name}
	if ch.Passphrase != nil {
		path := wifiSecretPath(t, in.SSIDID)
		if _, verr := s.Vault.Put(r.Context(), path, vault.Secret{"ssid": plan.SSID.Name, "passphrase": *ch.Passphrase}); verr != nil {
			resp["warning"] = "The router has the new passphrase, but NCC could not save a copy in the vault: " + verr.Error()
		} else {
			resp["vault_path"] = path
			_ = s.Audit.Record(r.Context(), actor(r), "vault.put", "secret/"+path, map[string]any{"keys": []string{"ssid", "passphrase"}})
		}
	}
	s.refreshTarget(t.ID, 0, 10*time.Second)
	writeJSON(w, 200, resp)
}

// wifiPassphrase shows an SSID's passphrase: the vault's copy, or the router's (which is then
// saved in the vault). Every call is audited, without the value.
func (s *Server) wifiPassphrase(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TargetID int64  `json:"target_id"`
		SSIDID   string `json:"ssid_id"`
		// FromRouter reads it from the router even when the vault has a copy.
		FromRouter bool `json:"from_router"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	t, err := s.Targets.Get(r.Context(), in.TargetID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if in.SSIDID == "" || strings.ContainsAny(in.SSIDID, "/") {
		writeErr(w, 400, "ssid_id is required")
		return
	}
	path := wifiSecretPath(t, in.SSIDID)
	if !in.FromRouter {
		if sec, err := s.Vault.Get(r.Context(), path); err == nil && sec["passphrase"] != "" {
			_ = s.Audit.Record(r.Context(), actor(r), "vault.reveal", "secret/"+path, nil)
			writeJSON(w, 200, map[string]any{"passphrase": sec["passphrase"], "source": "vault", "vault_path": path})
			return
		}
	}
	ww, creds, code, err := s.wifiWriter(r, t)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	pass, err := ww.WLANPassphrase(ctx, devTarget(t), creds, in.SSIDID)
	_ = s.Audit.Record(r.Context(), actor(r), "wifi.reveal", "wifi/"+t.Name+"/"+in.SSIDID, map[string]any{"result": errText(err)})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	resp := map[string]any{"passphrase": pass, "source": "router"}
	name := in.SSIDID
	if snap, _ := s.snapshotFor(r.Context(), t); snap != nil && snap.WiFi != nil {
		for _, x := range snap.WiFi.SSIDs {
			if x.ID == in.SSIDID {
				name = x.Name
			}
		}
	}
	if _, err := s.Vault.Put(r.Context(), path, vault.Secret{"ssid": name, "passphrase": pass}); err == nil {
		resp["vault_path"] = path
	}
	writeJSON(w, 200, resp)
}
