package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/iot"
)

// topology is the network map, with every node identified from NCC's other sources (VMs,
// storage, DNS records, IoT inventory, connections) and what people said about them.
func (s *Server) topology(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	snaps, err := core.LatestSnapshots(ctx, s.Store.DB)
	if err != nil {
		s.fail(w, err)
		return
	}
	g := core.BuildGraph(snaps, r.URL.Query().Get("clients") == "1")
	src, err := s.identitySources(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	core.Enrich(&g, snaps, src)
	writeJSON(w, 200, g)
}

// identitySources reads everything Enrich matches map nodes against.
func (s *Server) identitySources(ctx context.Context) (core.Sources, error) {
	var src core.Sources
	var err error
	if src.Targets, err = s.Targets.List(ctx, ""); err != nil {
		return src, err
	}
	if src.VMs, err = core.LatestVMInventories(ctx, s.Store.DB); err != nil {
		return src, err
	}
	if src.Storage, err = core.LatestStorage(ctx, s.Store.DB); err != nil {
		return src, err
	}
	if src.IoT, err = iot.List(ctx, s.Store.DB); err != nil {
		return src, err
	}
	if src.DNS, err = core.LatestDNSNames(ctx, s.Store.DB); err != nil {
		return src, err
	}
	if src.Overrides, err = core.IdentityOverrides(ctx, s.Store.DB); err != nil {
		return src, err
	}
	src.Resolve = hostLookups.get
	return src, nil
}

type identityIn struct {
	Role      string `json:"role"`
	Name      string `json:"name"`
	Confirmed bool   `json:"confirmed"`
}

// setNodeIdentity records what a map node really is, or confirms NCC's guess.
func (s *Server) setNodeIdentity(w http.ResponseWriter, r *http.Request) {
	var in identityIn
	if !readJSON(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	o := core.IdentityOverride{NodeID: id, Role: in.Role, Name: in.Name, Confirmed: in.Confirmed, By: actor(r)}
	if err := core.SetIdentityOverride(r.Context(), s.Store.DB, o); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	action := "topology.identify"
	if in.Confirmed {
		action = "topology.confirm"
	}
	_ = s.Audit.Record(r.Context(), actor(r), action, "node/"+id, map[string]any{"role": in.Role, "name": strings.TrimSpace(in.Name)})
	if s.Hub != nil {
		s.Hub.Publish("topology", map[string]any{"node": id})
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// clearNodeIdentity forgets what people said about a node, so NCC's own guess shows again.
func (s *Server) clearNodeIdentity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	found, err := core.DeleteIdentityOverride(r.Context(), s.Store.DB, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !found {
		writeErr(w, 404, "nothing was set for this node")
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "topology.identify.reset", "node/"+id, nil)
	if s.Hub != nil {
		s.Hub.Publish("topology", map[string]any{"node": id})
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// lookupCache resolves connection host names for the map without ever making a page load
// wait: a miss starts a lookup in the background and answers nothing until it lands.
type lookupCache struct {
	mu      sync.Mutex
	entries map[string]lookupEntry
}

type lookupEntry struct {
	addrs   []string
	at      time.Time
	pending bool
}

const lookupTTL = 10 * time.Minute

var hostLookups = &lookupCache{entries: map[string]lookupEntry{}}

func (c *lookupCache) get(host string) []string {
	host = strings.ToLower(host)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[host]
	if (!ok || time.Since(e.at) > lookupTTL) && !e.pending {
		e.pending = true
		c.entries[host] = e
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			addrs, _ := net.DefaultResolver.LookupHost(ctx, host)
			c.mu.Lock()
			c.entries[host] = lookupEntry{addrs: addrs, at: time.Now()}
			c.mu.Unlock()
		}()
	}
	return e.addrs
}
