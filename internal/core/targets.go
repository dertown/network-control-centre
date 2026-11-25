// Package core ties targets, polling, snapshots and topology together.
package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Target categories.
const (
	CategoryDevice = "device"
	CategoryDNS    = "dns"
	// CategoryHypervisor is a Proxmox VE or VMware vCenter/ESXi connection.
	CategoryHypervisor = "hypervisor"
	// CategoryStorage is a NAS, SMB or NFS server, or a storage device read over SNMP.
	CategoryStorage = "storage"
	// CategorySmartHome is a smart home hub (Home Assistant).
	CategorySmartHome = "smarthome"
	// CategorySIEM is a SIEM NCC forwards its audit log and network events to.
	CategorySIEM = "siem"
)

// Target is a stored controller, device or DNS server.
type Target struct {
	ID         int64             `json:"id"`
	Kind       string            `json:"kind"`
	Category   string            `json:"category"`
	Name       string            `json:"name"`
	Address    string            `json:"address"`
	Options    map[string]string `json:"options"`
	SecretPath string            `json:"secret_path"`
	Enabled    bool              `json:"enabled"`
	LastPoll   *time.Time        `json:"last_poll,omitempty"`
	LastError  string            `json:"last_error"`
}

// Targets is the target repository.
type Targets struct{ DB *sql.DB }

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)

// ErrNoTarget is returned for unknown ids.
var ErrNoTarget = errors.New("target not found")

const targetCols = `id, kind, category, name, address, options, secret_path, enabled, last_poll, last_error`

func scanTarget(sc interface{ Scan(...any) error }) (*Target, error) {
	var t Target
	var opts string
	var lp sql.NullString
	if err := sc.Scan(&t.ID, &t.Kind, &t.Category, &t.Name, &t.Address, &opts, &t.SecretPath, &t.Enabled, &lp, &t.LastError); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(opts), &t.Options)
	if t.Options == nil {
		t.Options = map[string]string{}
	}
	if lp.Valid {
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05"} {
			if ts, err := time.Parse(layout, lp.String); err == nil {
				t.LastPoll = &ts
				break
			}
		}
	}
	return &t, nil
}

// Create stores a new target.
func (r *Targets) Create(ctx context.Context, t *Target) error {
	if !nameRe.MatchString(t.Name) {
		return errors.New("name may use letters, digits, dot, dash and underscore (max 63)")
	}
	if t.Category != CategoryDevice && t.Category != CategoryDNS && t.Category != CategoryHypervisor && t.Category != CategoryStorage &&
		t.Category != CategorySmartHome && t.Category != CategorySIEM {
		return fmt.Errorf("unknown category %q", t.Category)
	}
	if t.Options == nil {
		t.Options = map[string]string{}
	}
	t.SecretPath = "targets/" + t.Category + "/" + t.Name
	opts, _ := json.Marshal(t.Options)
	res, err := r.DB.ExecContext(ctx, `INSERT INTO targets (kind, category, name, address, options, secret_path, enabled)
		VALUES (?,?,?,?,?,?,?)`, t.Kind, t.Category, t.Name, t.Address, string(opts), t.SecretPath, t.Enabled)
	if err != nil {
		return err
	}
	t.ID, _ = res.LastInsertId()
	return nil
}

// Get loads one target.
func (r *Targets) Get(ctx context.Context, id int64) (*Target, error) {
	t, err := scanTarget(r.DB.QueryRowContext(ctx, `SELECT `+targetCols+` FROM targets WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoTarget
	}
	return t, err
}

// List returns targets, optionally of one category.
func (r *Targets) List(ctx context.Context, category string) ([]Target, error) {
	q := `SELECT ` + targetCols + ` FROM targets`
	var args []any
	if category != "" {
		q += ` WHERE category = ?`
		args = append(args, category)
	}
	q += ` ORDER BY name`
	rows, err := r.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// Update saves address, options and enabled.
func (r *Targets) Update(ctx context.Context, t *Target) error {
	opts, _ := json.Marshal(t.Options)
	_, err := r.DB.ExecContext(ctx, `UPDATE targets SET address = ?, options = ?, enabled = ? WHERE id = ?`,
		t.Address, string(opts), t.Enabled, t.ID)
	return err
}

// MergeOptions sets some option keys without touching the rest.
func (r *Targets) MergeOptions(ctx context.Context, id int64, upd map[string]string) error {
	t, err := r.Get(ctx, id)
	if err != nil {
		return err
	}
	for k, v := range upd {
		t.Options[k] = v
	}
	return r.Update(ctx, t)
}

// RecordPoll stores the outcome of a poll.
func (r *Targets) RecordPoll(ctx context.Context, id int64, pollErr error) error {
	msg := ""
	if pollErr != nil {
		msg = pollErr.Error()
	}
	_, err := r.DB.ExecContext(ctx, `UPDATE targets SET last_poll = ?, last_error = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), msg, id)
	return err
}

// Delete removes a target and its snapshots.
func (r *Targets) Delete(ctx context.Context, id int64) error {
	_, err := r.DB.ExecContext(ctx, `DELETE FROM targets WHERE id = ?`, id)
	return err
}
