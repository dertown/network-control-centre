package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dertown/network-control-centre/internal/storage"
)

// sampleKeep is how long hourly volume use is kept for the capacity trend.
const sampleKeep = 90 * 24 * time.Hour

func (p *Poller) collectStorage(ctx context.Context, t *Target) (*storage.Inventory, error) {
	prov, err := storage.Get(t.Kind)
	if err != nil {
		return nil, err
	}
	creds, err := p.Vault.Get(ctx, t.SecretPath)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	res, err := prov.Collect(cctx, StorageTarget(t), creds)
	if res != nil && len(res.OptionUpdates) > 0 {
		if merr := p.Targets.MergeOptions(ctx, t.ID, res.OptionUpdates); merr != nil && err == nil {
			err = merr
		}
	}
	if err != nil {
		return nil, err
	}
	if err := SaveStorageInventory(ctx, p.DB, t.ID, res.Inventory); err != nil {
		return nil, err
	}
	return res.Inventory, nil
}

// StorageTarget converts a stored target for the storage providers.
func StorageTarget(t *Target) storage.Target {
	return storage.Target{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Options: t.Options}
}

// SaveStorageInventory replaces the stored read of one storage connection and records the
// hour's volume use.
func SaveStorageInventory(ctx context.Context, db *sql.DB, targetID int64, inv *storage.Inventory) error {
	b, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO storage_inventory (target_id, taken_at, data) VALUES (?,?,?)
		ON CONFLICT(target_id) DO UPDATE SET taken_at = excluded.taken_at, data = excluded.data`,
		targetID, inv.TakenAt.Format(time.RFC3339Nano), string(b)); err != nil {
		return err
	}
	hour := inv.TakenAt.Unix() / 3600
	for _, v := range inv.Volumes {
		if v.Total <= 0 {
			continue
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO storage_samples (target_id, volume, hour, used, total) VALUES (?,?,?,?,?)
			ON CONFLICT(target_id, volume, hour) DO UPDATE SET used = excluded.used, total = excluded.total`,
			targetID, v.ID, hour, v.Used, v.Total); err != nil {
			return err
		}
	}
	_, err = db.ExecContext(ctx, `DELETE FROM storage_samples WHERE target_id = ? AND hour < ?`,
		targetID, inv.TakenAt.Add(-sampleKeep).Unix()/3600)
	return err
}

// StorageEntry is the latest read of one connection.
type StorageEntry struct {
	TargetID  int64
	Inventory storage.Inventory
}

// LatestStorage returns the stored read of every enabled storage connection.
func LatestStorage(ctx context.Context, db *sql.DB) ([]StorageEntry, error) {
	rows, err := db.QueryContext(ctx, `SELECT s.target_id, s.data FROM storage_inventory s JOIN targets t ON t.id = s.target_id
		WHERE t.enabled = 1 ORDER BY t.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StorageEntry
	for rows.Next() {
		var e StorageEntry
		var raw string
		if err := rows.Scan(&e.TargetID, &raw); err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(raw), &e.Inventory) == nil {
			out = append(out, e)
		}
	}
	return out, rows.Err()
}

// CapacityPoint is one hour of a volume's use.
type CapacityPoint struct {
	Hour  int64 `json:"t"` // unix seconds at the start of the hour
	Used  int64 `json:"used"`
	Total int64 `json:"total"`
}

// CapacityHistory is a volume's use over time and a simple fill-rate projection.
type CapacityHistory struct {
	Volume    string          `json:"volume"`
	Points    []CapacityPoint `json:"points"`
	PerDay    int64           `json:"per_day"`                // bytes added per day (negative: shrinking)
	FullInDay *int            `json:"full_in_days,omitempty"` // days until full at that rate
}

// StorageHistory returns a connection's volume use for the last days, one point every
// step hours, with a growth estimate from a least-squares fit.
func StorageHistory(ctx context.Context, db *sql.DB, targetID int64, days int) ([]CapacityHistory, error) {
	since := time.Now().Add(-time.Duration(days)*24*time.Hour).Unix() / 3600
	rows, err := db.QueryContext(ctx, `SELECT volume, hour, used, total FROM storage_samples WHERE target_id = ? AND hour >= ?
		ORDER BY volume, hour`, targetID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byVol := map[string]*CapacityHistory{}
	var order []string
	for rows.Next() {
		var v string
		var p CapacityPoint
		if err := rows.Scan(&v, &p.Hour, &p.Used, &p.Total); err != nil {
			return nil, err
		}
		p.Hour *= 3600
		h := byVol[v]
		if h == nil {
			h = &CapacityHistory{Volume: v}
			byVol[v] = h
			order = append(order, v)
		}
		h.Points = append(h.Points, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]CapacityHistory, 0, len(order))
	for _, v := range order {
		h := byVol[v]
		project(h)
		h.Points = thin(h.Points, 120)
		out = append(out, *h)
	}
	return out, nil
}

// project fits used bytes against time and estimates days until the volume is full.
// It needs at least a day of data.
func project(h *CapacityHistory) {
	n := len(h.Points)
	if n < 2 || h.Points[n-1].Hour-h.Points[0].Hour < 86400 {
		return
	}
	t0 := float64(h.Points[0].Hour)
	var sx, sy, sxx, sxy float64
	for _, p := range h.Points {
		x := (float64(p.Hour) - t0) / 86400
		y := float64(p.Used)
		sx += x
		sy += y
		sxx += x * x
		sxy += x * y
	}
	fn := float64(n)
	den := fn*sxx - sx*sx
	if den == 0 {
		return
	}
	slope := (fn*sxy - sx*sy) / den // bytes per day
	h.PerDay = int64(slope)
	last := h.Points[n-1]
	if slope > 0 && last.Total > last.Used {
		d := int(float64(last.Total-last.Used) / slope)
		if d < 3650 {
			h.FullInDay = &d
		}
	}
}

// thin keeps at most max points, evenly spaced, always keeping the last one.
func thin(ps []CapacityPoint, max int) []CapacityPoint {
	if len(ps) <= max {
		return ps
	}
	out := make([]CapacityPoint, 0, max)
	step := float64(len(ps)-1) / float64(max-1)
	for i := 0; i < max; i++ {
		out = append(out, ps[int(float64(i)*step+0.5)])
	}
	return out
}
