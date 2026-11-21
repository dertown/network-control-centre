package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dertown/network-control-centre/internal/smarthome"
)

func (p *Poller) collectSmartHome(ctx context.Context, t *Target) (*smarthome.Inventory, error) {
	prov, err := smarthome.Get(t.Kind)
	if err != nil {
		return nil, err
	}
	creds, err := p.Vault.Get(ctx, t.SecretPath)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	res, err := prov.Collect(cctx, SmartHomeTarget(t), creds)
	if res != nil && len(res.OptionUpdates) > 0 {
		if merr := p.Targets.MergeOptions(ctx, t.ID, res.OptionUpdates); merr != nil && err == nil {
			err = merr
		}
	}
	if err != nil {
		return nil, err
	}
	return res.Inventory, SaveSmartHome(ctx, p.DB, t.ID, res.Inventory)
}

// SmartHomeTarget converts a stored target for the smart home providers.
func SmartHomeTarget(t *Target) smarthome.Target {
	return smarthome.Target{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Options: t.Options}
}

// SaveSmartHome replaces the stored read of one smart home hub.
func SaveSmartHome(ctx context.Context, db *sql.DB, targetID int64, inv *smarthome.Inventory) error {
	b, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO smarthome_inventory (target_id, taken_at, data) VALUES (?,?,?)
		ON CONFLICT(target_id) DO UPDATE SET taken_at = excluded.taken_at, data = excluded.data`,
		targetID, inv.TakenAt.Format(time.RFC3339Nano), string(b))
	return err
}

// SmartHomeEntry is the latest read of one hub.
type SmartHomeEntry struct {
	TargetID  int64
	Inventory smarthome.Inventory
}

// LatestSmartHome returns the stored read of every enabled smart home hub.
func LatestSmartHome(ctx context.Context, db *sql.DB) ([]SmartHomeEntry, error) {
	rows, err := db.QueryContext(ctx, `SELECT s.target_id, s.data FROM smarthome_inventory s JOIN targets t ON t.id = s.target_id
		WHERE t.enabled = 1 ORDER BY t.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SmartHomeEntry
	for rows.Next() {
		var e SmartHomeEntry
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

// SmartHomeFor returns the stored read of one hub, or nil.
func SmartHomeFor(ctx context.Context, db *sql.DB, targetID int64) (*smarthome.Inventory, error) {
	var raw string
	err := db.QueryRowContext(ctx, `SELECT data FROM smarthome_inventory WHERE target_id = ?`, targetID).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var inv smarthome.Inventory
	if err := json.Unmarshal([]byte(raw), &inv); err != nil {
		return nil, err
	}
	return &inv, nil
}
