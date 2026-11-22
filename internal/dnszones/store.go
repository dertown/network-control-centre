// Package dnszones ties DNS zones to router networks (VLANs): which zone each VLAN's clients
// live in, a check that flags missing zones and mismatches, and a planner that creates zones
// and subdomains and assigns them to VLANs through a preview first.
//
// It is the one place zone and VLAN changes are planned, for people on the DNS page and for
// anything else that proposes them (an assistant, a script): build a PlanRequest, call
// BuildPlan to see the steps, then Apply.
package dnszones

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/dertown/network-control-centre/internal/dns"
)

// Assignment says which DNS zone a router network (VLAN) uses.
type Assignment struct {
	ID        int64     `json:"id"`
	ServerID  int64     `json:"server_id"`  // DNS server connection holding the zone
	Zone      string    `json:"zone"`       // fully qualified, trailing dot
	RouterID  int64     `json:"router_id"`  // router connection the network is on
	NetworkID string    `json:"network_id"` // the router's id for the network
	Network   string    `json:"network"`    // network name when assigned, for when it disappears
	VLAN      int       `json:"vlan"`       // VLAN id when assigned; 0 = untagged
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// List returns every assignment, ordered by router and VLAN.
func List(ctx context.Context, db *sql.DB) ([]Assignment, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, server_id, zone, router_id, network_id, network, vlan, updated_by, updated_at
		FROM dns_zone_vlans ORDER BY router_id, vlan, network`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Assignment{}
	for rows.Next() {
		var a Assignment
		var at string
		if err := rows.Scan(&a.ID, &a.ServerID, &a.Zone, &a.RouterID, &a.NetworkID, &a.Network, &a.VLAN, &a.UpdatedBy, &at); err != nil {
			return nil, err
		}
		a.UpdatedAt, _ = time.Parse(time.RFC3339Nano, at)
		out = append(out, a)
	}
	return out, rows.Err()
}

// Put saves an assignment. A network has one zone: assigning another replaces it.
func Put(ctx context.Context, db *sql.DB, a Assignment) (int64, error) {
	if a.RouterID == 0 || a.NetworkID == "" || a.ServerID == 0 {
		return 0, errors.New("an assignment needs a router, a network and a DNS server")
	}
	zone, err := dns.ValidateZoneName(a.Zone)
	if err != nil {
		return 0, err
	}
	if a.UpdatedAt.IsZero() {
		a.UpdatedAt = time.Now()
	}
	var id int64
	err = db.QueryRowContext(ctx, `INSERT INTO dns_zone_vlans (server_id, zone, router_id, network_id, network, vlan, updated_by, updated_at)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(router_id, network_id) DO UPDATE SET server_id = excluded.server_id, zone = excluded.zone,
			network = excluded.network, vlan = excluded.vlan, updated_by = excluded.updated_by, updated_at = excluded.updated_at
		RETURNING id`,
		a.ServerID, zone, a.RouterID, a.NetworkID, a.Network, a.VLAN, a.UpdatedBy, a.UpdatedAt.UTC().Format(time.RFC3339Nano)).Scan(&id)
	return id, err
}

// Get returns one assignment.
func Get(ctx context.Context, db *sql.DB, id int64) (*Assignment, error) {
	all, err := List(ctx, db)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, sql.ErrNoRows
}

// Delete removes an assignment. It does not touch the zone or the router.
func Delete(ctx context.Context, db *sql.DB, id int64) error {
	res, err := db.ExecContext(ctx, `DELETE FROM dns_zone_vlans WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
