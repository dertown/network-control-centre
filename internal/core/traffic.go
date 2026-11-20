package core

import (
	"context"
	"database/sql"
	"sort"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/inventory"
)

// Traffic keeps the newest traffic report of every device target and samples each
// client's byte counters, so usage over the last hour, day or week can be worked out.
type Traffic struct {
	DB *sql.DB
	// SampleEvery is how often counters are written to the database (default 5 minutes).
	SampleEvery time.Duration
	// Retain is how long samples are kept (default 8 days).
	Retain time.Duration

	mu         sync.Mutex
	latest     map[string]*inventory.TrafficReport
	lastSample map[string]time.Time
}

func (t *Traffic) defaults() {
	if t.SampleEvery <= 0 {
		t.SampleEvery = 5 * time.Minute
	}
	if t.Retain <= 0 {
		t.Retain = 8 * 24 * time.Hour
	}
	if t.latest == nil {
		t.latest = map[string]*inventory.TrafficReport{}
		t.lastSample = map[string]time.Time{}
	}
}

func (t *Traffic) sampleEvery() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.defaults()
	return t.SampleEvery
}

// Record stores a fresh report and, every SampleEvery, its counters.
func (t *Traffic) Record(ctx context.Context, rep *inventory.TrafficReport) error {
	t.mu.Lock()
	t.defaults()
	t.latest[rep.Target] = rep
	due := rep.TakenAt.Sub(t.lastSample[rep.Target]) >= t.SampleEvery
	if due {
		t.lastSample[rep.Target] = rep.TakenAt
	}
	retain := t.Retain
	t.mu.Unlock()
	if !due || t.DB == nil {
		return nil
	}
	tx, err := t.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	ts := rep.TakenAt.Unix()
	for _, c := range rep.Clients {
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO traffic_samples (mac, ts, down_bytes, up_bytes, name, ip)
			VALUES (?,?,?,?,?,?)`, c.MAC, ts, c.DownBytes, c.UpBytes, c.Name, c.IP); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_samples WHERE ts < ?`, rep.TakenAt.Add(-retain).Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

// Forget drops the in-memory report of a target, e.g. when it is deleted or disabled.
func (t *Traffic) Forget(target string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.latest, target)
}

// Latest returns the newest report of each target, sorted by target name.
func (t *Traffic) Latest() []inventory.TrafficReport {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]inventory.TrafficReport, 0, len(t.latest))
	for _, r := range t.latest {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// Usage is how much a client moved during a window.
type Usage struct {
	MAC       string `json:"mac"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
	DownBytes int64  `json:"down_bytes"`
	UpBytes   int64  `json:"up_bytes"`
}

type counter struct{ down, up int64 }

// UsageSince adds up each client's traffic from since until now. Counters reset when a
// client reconnects, so a drop is read as "started again from zero". current holds the
// newest counters (from the latest reports), which may be newer than the last sample.
func (t *Traffic) UsageSince(ctx context.Context, since time.Time, current []inventory.ClientTraffic) (map[string]*Usage, error) {
	out := map[string]*Usage{}
	prev := map[string]counter{}
	floor := since.Add(-2 * t.sampleEvery())
	haveSamples := false
	add := func(mac, name, ip string, ts int64, c counter) {
		u := out[mac]
		if u == nil {
			u = &Usage{MAC: mac}
			out[mac] = u
		}
		if name != "" {
			u.Name = name
		}
		if ip != "" {
			u.IP = ip
		}
		p, seen := prev[mac]
		prev[mac] = c
		if !seen {
			// A sample from just before the window is the baseline. A client first seen
			// inside the window connected during it, so everything it moved counts.
			if ts >= since.Unix() && haveSamples {
				u.DownBytes, u.UpBytes = c.down, c.up
			}
			return
		}
		u.DownBytes += delta(p.down, c.down)
		u.UpBytes += delta(p.up, c.up)
	}
	if t.DB != nil {
		rows, err := t.DB.QueryContext(ctx, `SELECT mac, ts, down_bytes, up_bytes, name, ip FROM traffic_samples
			WHERE ts >= ? ORDER BY mac, ts`, floor.Unix())
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		type row struct {
			mac, name, ip string
			ts            int64
			c             counter
		}
		var all []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.mac, &r.ts, &r.c.down, &r.c.up, &r.name, &r.ip); err != nil {
				return nil, err
			}
			if r.ts < since.Unix() {
				haveSamples = true // NCC was sampling before the window began
			}
			all = append(all, r)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		for _, r := range all {
			add(r.mac, r.name, r.ip, r.ts, r.c)
		}
	}
	now := time.Now().Unix()
	for _, c := range current {
		add(c.MAC, c.Name, c.IP, now, counter{c.DownBytes, c.UpBytes})
	}
	return out, nil
}

func delta(prev, cur int64) int64 {
	if cur >= prev {
		return cur - prev
	}
	return cur // counter reset: the client reconnected
}
