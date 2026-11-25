package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/catalog"
	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/siem"
)

var siemOnce sync.Mutex

// siemForwarder returns the server's forwarder, making one on its database and vault when
// main didn't set one (tests).
func (s *Server) siemForwarder() *core.SIEMForwarder {
	siemOnce.Lock()
	defer siemOnce.Unlock()
	if s.SIEM == nil {
		s.SIEM = &core.SIEMForwarder{DB: s.Store.DB, Targets: s.Targets, Vault: s.Vault, Log: s.Log}
	}
	return s.SIEM
}

// siemSource is one SIEM connection as the SIEM Forwarding page shows it.
type siemSource struct {
	ID        int64             `json:"id"`
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	Vendor    string            `json:"vendor"`
	Address   string            `json:"address"`
	Enabled   bool              `json:"enabled"`
	LastPoll  *time.Time        `json:"last_poll,omitempty"`
	LastError string            `json:"last_error,omitempty"` // connection test
	Options   map[string]string `json:"options"`
	Status    core.SIEMStatus   `json:"status"`
}

// listSIEM is the SIEM Forwarding page: every SIEM connection with its delivery counters and
// backlog, and the latest network events.
func (s *Server) listSIEM(w http.ResponseWriter, r *http.Request) {
	ts, err := s.Targets.List(r.Context(), core.CategorySIEM)
	if err != nil {
		s.fail(w, err)
		return
	}
	f := s.siemForwarder()
	out := struct {
		Sources []siemSource `json:"sources"`
		Events  []siem.Event `json:"events"`
	}{Sources: []siemSource{}}
	for i := range ts {
		t := &ts[i]
		st, err := f.StatusOf(r.Context(), t)
		if err != nil {
			s.fail(w, err)
			return
		}
		label := t.Kind
		if v, ok := catalog.ForTarget(t.Kind, t.Options); ok {
			label = v.Label
		}
		opts := map[string]string{}
		for _, k := range []string{siem.OptAudit, siem.OptNetwork, siem.OptMinSeverity, "format", "transport"} {
			if v, ok := t.Options[k]; ok {
				opts[k] = v
			}
		}
		out.Sources = append(out.Sources, siemSource{ID: t.ID, Name: t.Name, Kind: t.Kind, Vendor: label, Address: t.Address, Enabled: t.Enabled,
			LastPoll: t.LastPoll, LastError: t.LastError, Options: opts, Status: st})
	}
	if out.Events, err = core.RecentNetworkEvents(r.Context(), s.Store.DB, 50); err != nil {
		s.fail(w, err)
		return
	}
	if out.Events == nil {
		out.Events = []siem.Event{}
	}
	writeJSON(w, 200, out)
}

// siemTest delivers one test event to a SIEM connection now.
func (s *Server) siemTest(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	t, err := s.Targets.Get(r.Context(), id)
	if err != nil || t.Category != core.CategorySIEM {
		writeErr(w, 404, "no such SIEM connection")
		return
	}
	err = s.siemForwarder().SendTest(r.Context(), t, actor(r))
	_ = s.Audit.Record(r.Context(), actor(r), "siem.test", "target/"+t.Name, map[string]any{"ok": err == nil})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
