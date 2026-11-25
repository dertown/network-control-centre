package core

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// IdentityOverrides returns what people said map nodes are, by node id.
func IdentityOverrides(ctx context.Context, db *sql.DB) (map[string]IdentityOverride, error) {
	rows, err := db.QueryContext(ctx, `SELECT node_id, role, name, confirmed, updated_by, updated_at FROM topology_identity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]IdentityOverride{}
	for rows.Next() {
		var o IdentityOverride
		var at string
		if err := rows.Scan(&o.NodeID, &o.Role, &o.Name, &o.Confirmed, &o.By, &at); err != nil {
			return nil, err
		}
		o.At, _ = time.Parse(time.RFC3339Nano, at)
		out[o.NodeID] = o
	}
	return out, rows.Err()
}

// SetIdentityOverride saves what a person said a node is, replacing what they said before.
func SetIdentityOverride(ctx context.Context, db *sql.DB, o IdentityOverride) error {
	o.NodeID = strings.TrimSpace(o.NodeID)
	o.Name = strings.TrimSpace(o.Name)
	if o.NodeID == "" || len(o.NodeID) > 200 {
		return errors.New("which node?")
	}
	if !ValidRole(o.Role) {
		return errors.New("choose what the device is")
	}
	if !utf8.ValidString(o.Name) || utf8.RuneCountInString(o.Name) > 64 || strings.ContainsAny(o.Name, "\r\n\t") {
		return errors.New("names are up to 64 characters on one line")
	}
	if o.At.IsZero() {
		o.At = time.Now().UTC()
	}
	_, err := db.ExecContext(ctx, `INSERT INTO topology_identity (node_id, role, name, confirmed, updated_by, updated_at) VALUES (?,?,?,?,?,?)
		ON CONFLICT(node_id) DO UPDATE SET role = excluded.role, name = excluded.name, confirmed = excluded.confirmed,
		updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		o.NodeID, o.Role, o.Name, o.Confirmed, o.By, o.At.Format(time.RFC3339Nano))
	return err
}

// DeleteIdentityOverride forgets what a person said about a node, so NCC's guess shows again.
// It reports whether there was anything to forget.
func DeleteIdentityOverride(ctx context.Context, db *sql.DB, nodeID string) (bool, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM topology_identity WHERE node_id = ?`, nodeID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
