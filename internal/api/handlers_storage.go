package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/storage"
)

// storageSource is one storage connection as the Storage page shows it, with its latest read.
type storageSource struct {
	ID        int64              `json:"id"`
	Name      string             `json:"name"`
	Kind      string             `json:"kind"`
	Address   string             `json:"address"`
	Enabled   bool               `json:"enabled"`
	LastError string             `json:"last_error,omitempty"`
	TakenAt   *time.Time         `json:"taken_at,omitempty"`
	Inventory *storage.Inventory `json:"inventory,omitempty"`
	// SNMP is true when a QNAP connection also reads volume and RAID state over SNMP.
	SNMP bool `json:"snmp,omitempty"`
}

func (s *Server) listStorage(w http.ResponseWriter, r *http.Request) {
	ts, err := s.Targets.List(r.Context(), core.CategoryStorage)
	if err != nil {
		s.fail(w, err)
		return
	}
	entries, err := core.LatestStorage(r.Context(), s.Store.DB)
	if err != nil {
		s.fail(w, err)
		return
	}
	byID := map[int64]*storage.Inventory{}
	for i := range entries {
		byID[entries[i].TargetID] = &entries[i].Inventory
	}
	out := struct {
		Sources []storageSource `json:"sources"`
	}{Sources: []storageSource{}}
	for _, t := range ts {
		src := storageSource{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Enabled: t.Enabled, LastError: t.LastError,
			SNMP: t.Options["snmp"] == "on"}
		if inv, ok := byID[t.ID]; ok && t.Enabled {
			at := inv.TakenAt
			src.TakenAt, src.Inventory = &at, inv
		}
		out.Sources = append(out.Sources, src)
	}
	writeJSON(w, 200, out)
}

func (s *Server) storageHistory(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 90 {
		days = 30
	}
	h, err := core.StorageHistory(r.Context(), s.Store.DB, id, days)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"days": days, "volumes": h})
}

// storageTarget resolves a connection for a change and checks it offers a capability.
func (s *Server) storageTarget(r *http.Request, id int64, capability string) (*core.Target, storage.Controller, map[string]string, *storage.Inventory, int, error) {
	t, err := s.Targets.Get(r.Context(), id)
	if err != nil || t.Category != core.CategoryStorage {
		return nil, nil, nil, nil, 404, errors.New("no such storage connection")
	}
	if !t.Enabled {
		return nil, nil, nil, nil, 409, errors.New(t.Name + " is disabled")
	}
	prov, err := storage.Get(t.Kind)
	if err != nil {
		return nil, nil, nil, nil, 500, err
	}
	ctl, ok := prov.(storage.Controller)
	if !ok {
		return nil, nil, nil, nil, 501, errors.New(t.Kind + " connections are read-only")
	}
	var inv *storage.Inventory
	if entries, err := core.LatestStorage(r.Context(), s.Store.DB); err == nil {
		for i := range entries {
			if entries[i].TargetID == id {
				inv = &entries[i].Inventory
			}
		}
	}
	if inv == nil {
		return nil, nil, nil, nil, 409, errors.New(t.Name + " has not been read yet; refresh it first")
	}
	if !inv.Has(capability) {
		return nil, nil, nil, nil, 501, errors.New(t.Name + " (" + t.Kind + ") can't do that")
	}
	creds, err := s.Vault.Get(r.Context(), t.SecretPath)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	return t, ctl, creds, inv, 0, nil
}

func hasShare(inv *storage.Inventory, name string) bool {
	for _, sh := range inv.Shares {
		if sh.Name == name {
			return true
		}
	}
	return false
}

func (s *Server) refreshStorage(id int64, after time.Duration) {
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

// storagePower restarts or shuts down a whole NAS. The caller must type the connection name.
func (s *Server) storagePower(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID      int64  `json:"id"`
		Action  string `json:"action"`
		Confirm string `json:"confirm"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Action != storage.CapRestart && in.Action != storage.CapShutdown {
		writeErr(w, 400, "action must be restart or shutdown")
		return
	}
	t, ctl, creds, _, code, err := s.storageTarget(r, in.ID, in.Action)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	if in.Confirm != t.Name {
		writeErr(w, 400, "type the connection's name to confirm")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	err = ctl.Power(ctx, core.StorageTarget(t), creds, in.Action)
	_ = s.Audit.Record(r.Context(), actor(r), "storage.power", "storage/"+t.Name, map[string]string{"action": in.Action, "result": errText(err)})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	if in.Action == storage.CapRestart {
		s.refreshStorage(t.ID, 4*time.Minute)
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) storageCreateShare(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID int64 `json:"id"`
		storage.ShareSpec
	}
	if !readJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if err := in.ShareSpec.Validate(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	t, ctl, creds, inv, code, err := s.storageTarget(r, in.ID, storage.CapShareCreate)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	if hasShare(inv, in.Name) {
		writeErr(w, 409, "a share named "+in.Name+" already exists")
		return
	}
	found := false
	for _, v := range inv.Volumes {
		found = found || v.ID == in.Volume
	}
	if !found {
		writeErr(w, 400, "that volume is not on "+t.Name)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	err = ctl.CreateShare(ctx, core.StorageTarget(t), creds, in.ShareSpec)
	_ = s.Audit.Record(r.Context(), actor(r), "storage.share.create", "storage/"+t.Name+"/"+in.Name,
		map[string]string{"volume": in.Volume, "result": errText(err)})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	s.refreshStorage(t.ID, 0)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) storageCreateFolder(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID    int64  `json:"id"`
		Share string `json:"share"`
		Path  string `json:"path"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if err := storage.ValidFolder(in.Path); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	t, ctl, creds, inv, code, err := s.storageTarget(r, in.ID, storage.CapFolderCreate)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	if !hasShare(inv, in.Share) {
		writeErr(w, 404, "no share named "+in.Share+" on "+t.Name)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	path := strings.Trim(in.Path, "/")
	err = ctl.CreateFolder(ctx, core.StorageTarget(t), creds, in.Share, path)
	_ = s.Audit.Record(r.Context(), actor(r), "storage.folder.create", "storage/"+t.Name+"/"+in.Share+"/"+path,
		map[string]string{"result": errText(err)})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) storageCreateSnapshot(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID      int64  `json:"id"`
		Share   string `json:"share"`
		Comment string `json:"comment"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.Comment) > 256 {
		writeErr(w, 400, "the description is limited to 256 characters")
		return
	}
	t, ctl, creds, inv, code, err := s.storageTarget(r, in.ID, storage.CapSnapshotCreate)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	if !hasShare(inv, in.Share) {
		writeErr(w, 404, "no share named "+in.Share+" on "+t.Name)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	err = ctl.CreateSnapshot(ctx, core.StorageTarget(t), creds, in.Share, in.Comment)
	_ = s.Audit.Record(r.Context(), actor(r), "storage.snapshot.create", "storage/"+t.Name+"/"+in.Share,
		map[string]string{"comment": in.Comment, "result": errText(err)})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	s.refreshStorage(t.ID, 0)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) storageDeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID       int64  `json:"id"`
		Share    string `json:"share"`
		Snapshot string `json:"snapshot"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	t, ctl, creds, inv, code, err := s.storageTarget(r, in.ID, storage.CapSnapshotDelete)
	if err != nil {
		s.vmFail(w, code, err)
		return
	}
	var snap *storage.Snapshot
	for i := range inv.Snapshots {
		if inv.Snapshots[i].Share == in.Share && inv.Snapshots[i].ID == in.Snapshot {
			snap = &inv.Snapshots[i]
		}
	}
	if snap == nil {
		writeErr(w, 404, "that snapshot is not in the latest read; refresh and try again")
		return
	}
	if snap.Locked {
		writeErr(w, 409, "that snapshot is locked (kept by a retention policy); unlock it on the NAS first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	err = ctl.DeleteSnapshot(ctx, core.StorageTarget(t), creds, in.Share, in.Snapshot)
	_ = s.Audit.Record(r.Context(), actor(r), "storage.snapshot.delete", "storage/"+t.Name+"/"+in.Share,
		map[string]string{"snapshot": in.Snapshot, "result": errText(err)})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	s.refreshStorage(t.ID, 0)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
