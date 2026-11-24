package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/iot"
	"github.com/dertown/network-control-centre/internal/vault"
)

// Hub fans events out to Server-Sent-Event subscribers (the browser).
type Hub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[chan []byte]struct{}{}} }

// Subscribe returns a channel of JSON events and a cancel func.
func (h *Hub) Subscribe() (<-chan []byte, func()) {
	ch := make(chan []byte, 16)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
}

// Publish sends an event to every subscriber, dropping it for slow ones.
func (h *Hub) Publish(kind string, data any) {
	b, err := json.Marshal(map[string]any{"type": kind, "data": data})
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- b:
		default:
		}
	}
}

// Poller collects inventory from every enabled device target, and checks that
// every enabled DNS server answers, on an interval.
type Poller struct {
	DB       *sql.DB
	Targets  *Targets
	Vault    vault.Store
	Hub      *Hub
	Interval time.Duration
	Keep     int // snapshots kept per target
	Traffic  *Traffic
	Log      *slog.Logger

	mu      sync.Mutex
	running map[int64]bool
}

// Run polls until ctx ends.
func (p *Poller) Run(ctx context.Context) {
	if p.Keep <= 0 {
		p.Keep = 288
	}
	p.running = map[int64]bool{}
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	p.PollAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.PollAll(ctx)
		}
	}
}

// PollAll polls each enabled target concurrently.
func (p *Poller) PollAll(ctx context.Context) {
	ts, err := p.Targets.List(ctx, "")
	if err != nil {
		p.Log.Error("list targets", "err", err)
		return
	}
	var wg sync.WaitGroup
	for _, t := range ts {
		if !t.Enabled {
			continue
		}
		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			if _, err := p.poll(ctx, &t); err != nil && !errors.Is(err, vault.ErrSealed) {
				p.Log.Warn("poll failed", "target", t.Name, "err", err)
			}
		}(t)
	}
	wg.Wait()
}

// PollOne collects one device target now and stores the snapshot, or checks
// one DNS target, or reads the virtual machines of one hypervisor. DNS checks and
// hypervisors return a nil snapshot.
func (p *Poller) PollOne(ctx context.Context, id int64) (*inventory.Snapshot, error) {
	t, err := p.Targets.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return p.poll(ctx, t)
}

// poll is PollOne for a target already loaded (PollAll has just listed them all, so it
// doesn't read each one again).
func (p *Poller) poll(ctx context.Context, t *Target) (*inventory.Snapshot, error) {
	id := t.ID
	p.mu.Lock()
	if p.running == nil {
		p.running = map[int64]bool{}
	}
	if p.running[id] {
		p.mu.Unlock()
		return nil, errors.New("poll already running")
	}
	p.running[id] = true
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.running, id); p.mu.Unlock() }()

	switch t.Category {
	case CategoryDNS:
		err := p.checkDNS(ctx, t)
		p.finish(ctx, t, err, "dns_status", func() map[string]any { return map[string]any{} })
		return nil, err
	case CategoryHypervisor:
		inv, err := p.collectVMs(ctx, t)
		p.finish(ctx, t, err, "vms", func() map[string]any { return map[string]any{"vms": len(inv.VMs), "hosts": len(inv.Hosts)} })
		return nil, err
	case CategoryStorage:
		inv, err := p.collectStorage(ctx, t)
		p.finish(ctx, t, err, "storage", func() map[string]any {
			return map[string]any{"health": inv.System.Health, "alerts": len(inv.Alerts)}
		})
		return nil, err
	case CategorySmartHome:
		inv, err := p.collectSmartHome(ctx, t)
		p.finish(ctx, t, err, "smarthome", func() map[string]any {
			return map[string]any{"devices": len(inv.Devices), "alerts": len(inv.Alerts)}
		})
		return nil, err
	}
	snap, err := p.collect(ctx, t)
	p.finish(ctx, t, err, "snapshot", func() map[string]any {
		return map[string]any{"devices": len(snap.Devices), "clients": len(snap.Clients), "loops": len(snap.Loops)}
	})
	if err != nil {
		return nil, err
	}
	return snap, nil
}

// finish records the outcome of one poll on the target (last_poll, last_error) and tells
// the browsers: a "poll_error" event with the error, or a kind event with the fields detail
// returns (detail is only called on success, when the collected data is valid). Every
// event carries the target's name.
func (p *Poller) finish(ctx context.Context, t *Target, err error, kind string, detail func() map[string]any) {
	_ = p.Targets.RecordPoll(ctx, t.ID, err)
	if p.Hub == nil {
		return
	}
	ev := map[string]any{"target": t.Name}
	if err != nil {
		kind = "poll_error"
		ev["error"] = err.Error()
	} else {
		for k, v := range detail() {
			ev[k] = v
		}
	}
	p.Hub.Publish(kind, ev)
}

func (p *Poller) checkDNS(ctx context.Context, t *Target) error {
	prov, err := dns.Get(t.Kind)
	if err != nil {
		return err
	}
	creds, err := p.Vault.Get(ctx, t.SecretPath)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	err = dns.Check(cctx, prov, dns.Server{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Options: t.Options}, creds)
	// the resolver side (addresses, forwarders) for the DNS chain check; its failures are
	// reported by that check, not as a failing connection
	p.readResolver(ctx, t, prov, creds)
	return err
}

func (p *Poller) collect(ctx context.Context, t *Target) (*inventory.Snapshot, error) {
	d, err := drivers.Get(t.Kind)
	if err != nil {
		return nil, err
	}
	creds, err := p.Vault.Get(ctx, t.SecretPath)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	res, err := d.Collect(cctx, drivers.Target{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Options: t.Options}, creds)
	if err != nil {
		return nil, err
	}
	if len(res.OptionUpdates) > 0 {
		if err := p.Targets.MergeOptions(ctx, t.ID, res.OptionUpdates); err != nil {
			return nil, err
		}
	}
	if res.Traffic != nil && p.Traffic != nil {
		if err := p.Traffic.Record(ctx, res.Traffic); err != nil && p.Log != nil {
			p.Log.Warn("record traffic", "target", t.Name, "err", err)
		}
	}
	if err := SaveSnapshot(ctx, p.DB, t.ID, res.Snapshot, p.Keep); err != nil {
		return nil, err
	}
	if err := iot.Record(ctx, p.DB, t.ID, res.Snapshot); err != nil && p.Log != nil {
		p.Log.Warn("record IoT devices", "target", t.Name, "err", err)
	}
	return res.Snapshot, nil
}

// SaveSnapshot stores a snapshot and trims old ones.
func SaveSnapshot(ctx context.Context, db *sql.DB, targetID int64, s *inventory.Snapshot, keep int) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO snapshots (target_id, taken_at, data) VALUES (?,?,?)`,
		targetID, s.TakenAt.Format(time.RFC3339Nano), string(b)); err != nil {
		return err
	}
	if keep > 0 {
		_, err = db.ExecContext(ctx, `DELETE FROM snapshots WHERE target_id = ? AND id NOT IN
			(SELECT id FROM snapshots WHERE target_id = ? ORDER BY id DESC LIMIT ?)`, targetID, targetID, keep)
	}
	return err
}

// LatestSnapshots returns the newest snapshot of every enabled device target, ordered by
// target id.
//
// Nearly every page (Dashboard, Topology, Devices, VLANs, Wi-Fi, IoT, DNS check...) is built
// from these, and the Dashboard alone asks for six of them per live update, so decoded
// snapshots are cached by snapshot id: a call costs one small index query plus decoding only
// the snapshots that changed since the last call. The returned snapshots share their slices
// with the cache, so callers must treat them as read-only (copy a slice before sorting or
// appending to it, as the callers in this repository do).
func LatestSnapshots(ctx context.Context, db *sql.DB) ([]inventory.Snapshot, error) {
	rows, err := db.QueryContext(ctx, `SELECT s.target_id, MAX(s.id) FROM snapshots s
		JOIN targets t ON t.id = s.target_id WHERE t.enabled = 1
		GROUP BY s.target_id ORDER BY s.target_id`)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var tid, sid int64
		if err := rows.Scan(&tid, &sid); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, sid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	c := snapCacheFor(db)
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]inventory.Snapshot, 0, len(ids))
	keep := make(map[int64]*inventory.Snapshot, len(ids))
	for _, id := range ids {
		sn, ok := c.byID[id]
		if !ok {
			var raw string
			if err := db.QueryRowContext(ctx, `SELECT data FROM snapshots WHERE id = ?`, id).Scan(&raw); err != nil {
				if errors.Is(err, sql.ErrNoRows) { // trimmed between the two queries
					continue
				}
				return nil, err
			}
			var s inventory.Snapshot
			if err := json.Unmarshal([]byte(raw), &s); err != nil {
				sn = nil // undecodable: skipped, as before, and not retried until it changes
			} else {
				sn = &s
			}
		}
		keep[id] = sn
		if sn != nil {
			out = append(out, *sn)
		}
	}
	c.byID = keep // drops snapshots that were replaced, trimmed or belong to disabled targets
	return out, nil
}

// snapCache holds the decoded newest snapshots of one database, by snapshot id. A snapshot
// row never changes once written, so an id is a safe cache key.
type snapCache struct {
	mu   sync.Mutex
	byID map[int64]*inventory.Snapshot
}

var (
	snapCachesMu sync.Mutex
	snapCaches   = map[*sql.DB]*snapCache{}
)

func snapCacheFor(db *sql.DB) *snapCache {
	snapCachesMu.Lock()
	defer snapCachesMu.Unlock()
	c := snapCaches[db]
	if c == nil {
		c = &snapCache{byID: map[int64]*inventory.Snapshot{}}
		snapCaches[db] = c
	}
	return c
}
