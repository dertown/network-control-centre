// Package audit writes an append-only, hash-chained audit log.
//
// Each entry's hash covers the previous entry's hash, so deleting or editing
// any row breaks the chain and Verify reports where.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Entry is one audit record.
type Entry struct {
	ID       int64     `json:"id"`
	TS       time.Time `json:"ts"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Target   string    `json:"target"`
	Detail   string    `json:"detail"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
}

// Log is the audit log.
type Log struct {
	db *sql.DB
	mu sync.Mutex
}

// New returns a Log on db (tables come from the store migrations).
func New(db *sql.DB) *Log { return &Log{db: db} }

func hashOf(prev string, ts time.Time, actor, action, target, detail string) string {
	h := sha256.New()
	for _, s := range []string{prev, ts.UTC().Format(time.RFC3339Nano), actor, action, target, detail} {
		fmt.Fprintf(h, "%d:%s|", len(s), s)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Record appends an entry. detail may be any JSON-marshalable value; it must never hold secret values.
func (l *Log) Record(ctx context.Context, actor, action, target string, detail any) error {
	var d string
	switch v := detail.(type) {
	case nil:
	case string:
		d = v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		d = string(b)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var prev string
	err := l.db.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	ts := time.Now().UTC()
	h := hashOf(prev, ts, actor, action, target, d)
	_, err = l.db.ExecContext(ctx,
		`INSERT INTO audit_log (ts, actor, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?)`,
		ts.Format(time.RFC3339Nano), actor, action, target, d, prev, h)
	return err
}

// List returns the newest entries first.
func (l *Log) List(ctx context.Context, limit int) ([]Entry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := l.db.QueryContext(ctx,
		`SELECT id, ts, actor, action, target, detail, prev_hash, hash FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.TS, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Verify walks the chain and returns the id of the first broken entry, or 0 if intact.
func (l *Log) Verify(ctx context.Context) (int64, error) {
	rows, err := l.db.QueryContext(ctx,
		`SELECT id, ts, actor, action, target, detail, prev_hash, hash FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var e Entry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return 0, err
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil || e.PrevHash != prev || hashOf(prev, t, e.Actor, e.Action, e.Target, e.Detail) != e.Hash {
			return e.ID, nil
		}
		prev = e.Hash
	}
	return 0, rows.Err()
}
