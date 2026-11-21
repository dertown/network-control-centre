package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	hv "github.com/dertown/network-control-centre/internal/hypervisor"
)

func (p *Poller) collectVMs(ctx context.Context, t *Target) (*hv.Inventory, error) {
	prov, err := hv.Get(t.Kind)
	if err != nil {
		return nil, err
	}
	creds, err := p.Vault.Get(ctx, t.SecretPath)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	res, err := prov.Collect(cctx, hv.Target{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Options: t.Options}, creds)
	if res != nil && len(res.OptionUpdates) > 0 {
		if merr := p.Targets.MergeOptions(ctx, t.ID, res.OptionUpdates); merr != nil && err == nil {
			err = merr
		}
	}
	if err != nil {
		return nil, err
	}
	return res.Inventory, SaveVMInventory(ctx, p.DB, t.ID, res.Inventory)
}

// SaveVMInventory replaces the stored virtual machine list of one connection.
func SaveVMInventory(ctx context.Context, db *sql.DB, targetID int64, inv *hv.Inventory) error {
	b, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO vm_inventory (target_id, taken_at, data) VALUES (?,?,?)
		ON CONFLICT(target_id) DO UPDATE SET taken_at = excluded.taken_at, data = excluded.data`,
		targetID, inv.TakenAt.Format(time.RFC3339Nano), string(b))
	return err
}

// LatestVMInventories returns the stored virtual machine list of every enabled connection.
func LatestVMInventories(ctx context.Context, db *sql.DB) ([]hv.Inventory, error) {
	rows, err := db.QueryContext(ctx, `SELECT v.data FROM vm_inventory v JOIN targets t ON t.id = v.target_id
		WHERE t.enabled = 1 ORDER BY t.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []hv.Inventory
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var inv hv.Inventory
		if json.Unmarshal([]byte(raw), &inv) == nil {
			out = append(out, inv)
		}
	}
	return out, rows.Err()
}
