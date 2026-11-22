// Package store owns the NCC SQLite database.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// Store wraps the database handle.
type Store struct {
	DB *sql.DB
}

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL,
		totp_secret TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS sessions (
		token_hash TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		csrf TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY,
		ts TIMESTAMP NOT NULL,
		actor TEXT NOT NULL,
		action TEXT NOT NULL,
		target TEXT NOT NULL,
		detail TEXT NOT NULL,
		prev_hash TEXT NOT NULL,
		hash TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS targets (
		id INTEGER PRIMARY KEY,
		kind TEXT NOT NULL,          -- device driver or dns provider kind, e.g. unifi, powerdns
		category TEXT NOT NULL,      -- device | dns
		name TEXT NOT NULL UNIQUE,
		address TEXT NOT NULL,
		options TEXT NOT NULL DEFAULT '{}',
		secret_path TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		last_poll TIMESTAMP,
		last_error TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS snapshots (
		id INTEGER PRIMARY KEY,
		target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
		taken_at TIMESTAMP NOT NULL,
		data TEXT NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS snapshots_target ON snapshots(target_id, taken_at)`,
	`CREATE TABLE IF NOT EXISTS local_secrets (
		path TEXT PRIMARY KEY,
		version INTEGER NOT NULL,
		wrapped_key BLOB NOT NULL,
		nonce BLOB NOT NULL,
		ciphertext BLOB NOT NULL,
		updated_at TIMESTAMP NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS vault_meta (
		k TEXT PRIMARY KEY,
		v BLOB NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS certificates (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		subject TEXT NOT NULL,
		issuer TEXT NOT NULL,
		sans TEXT NOT NULL,
		serial TEXT NOT NULL,
		not_before TIMESTAMP NOT NULL,
		not_after TIMESTAMP NOT NULL,
		fingerprint TEXT NOT NULL,
		cert_pem TEXT NOT NULL,
		key_secret_path TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	// traffic_samples holds each client's byte counters every few minutes, so NCC can
	// say how much a client used in the last hour or day.
	`CREATE TABLE IF NOT EXISTS traffic_samples (
		mac TEXT NOT NULL,
		ts INTEGER NOT NULL,          -- unix seconds
		down_bytes INTEGER NOT NULL,  -- counter since the client connected
		up_bytes INTEGER NOT NULL,
		name TEXT NOT NULL DEFAULT '',
		ip TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (mac, ts)
	)`,
	// dns_queries counts DNS lookups per client address, site (e.g. youtube.com) and hour.
	`CREATE TABLE IF NOT EXISTS dns_queries (
		client_ip TEXT NOT NULL,
		site TEXT NOT NULL,
		hour INTEGER NOT NULL,        -- unix seconds, truncated to the hour
		count INTEGER NOT NULL,
		PRIMARY KEY (client_ip, site, hour)
	)`,
	`CREATE INDEX IF NOT EXISTS dns_queries_hour ON dns_queries(hour)`,
	// vm_inventory holds the latest virtual machine list from each Proxmox or VMware connection.
	`CREATE TABLE IF NOT EXISTS vm_inventory (
		target_id INTEGER PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
		taken_at TIMESTAMP NOT NULL,
		data TEXT NOT NULL
	)`,
	// cert_deploy_targets are servers NCC installs certificates on; cert_deployments is their history.
	`CREATE TABLE IF NOT EXISTS cert_deploy_targets (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		kind TEXT NOT NULL,
		host TEXT NOT NULL,
		port INTEGER NOT NULL,
		options TEXT NOT NULL DEFAULT '{}',
		secret_path TEXT NOT NULL,
		cert_id INTEGER NOT NULL DEFAULT 0,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS cert_deployments (
		id INTEGER PRIMARY KEY,
		target_id INTEGER NOT NULL REFERENCES cert_deploy_targets(id) ON DELETE CASCADE,
		target_name TEXT NOT NULL,
		cert_id INTEGER NOT NULL,
		cert_name TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		actor TEXT NOT NULL,
		started TEXT NOT NULL,
		finished TEXT,
		status TEXT NOT NULL,
		verified TEXT NOT NULL DEFAULT '',
		steps TEXT NOT NULL DEFAULT '[]',
		error TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS cert_deployments_target ON cert_deployments(target_id, id)`,
	// storage_inventory holds the latest read of each NAS, SMB, NFS or SNMP storage connection;
	// storage_samples keeps hourly volume use for the capacity trend.
	`CREATE TABLE IF NOT EXISTS storage_inventory (
		target_id INTEGER PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
		taken_at TIMESTAMP NOT NULL,
		data TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS storage_samples (
		target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
		volume TEXT NOT NULL,
		hour INTEGER NOT NULL,
		used INTEGER NOT NULL,
		total INTEGER NOT NULL,
		PRIMARY KEY (target_id, volume, hour)
	)`,
	// smarthome_inventory holds the latest read of each smart home hub (Home Assistant):
	// rooms, devices and entity states.
	`CREATE TABLE IF NOT EXISTS smarthome_inventory (
		target_id INTEGER PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
		taken_at TIMESTAMP NOT NULL,
		data TEXT NOT NULL
	)`,
	// iot_devices is the IoT inventory: network clients NCC recognised as IoT devices (or
	// people added), what the network last saw of each, and what people recorded about it.
	`CREATE TABLE IF NOT EXISTS iot_devices (
		mac TEXT PRIMARY KEY,
		target_id INTEGER,
		client TEXT NOT NULL DEFAULT '{}',
		first_seen TIMESTAMP NOT NULL,
		last_seen TIMESTAMP NOT NULL,
		online INTEGER NOT NULL DEFAULT 0,
		auto_type TEXT NOT NULL DEFAULT '',
		type TEXT NOT NULL DEFAULT '',
		label TEXT NOT NULL DEFAULT '',
		owner TEXT NOT NULL DEFAULT '',
		site TEXT NOT NULL DEFAULT '',
		building TEXT NOT NULL DEFAULT '',
		floor TEXT NOT NULL DEFAULT '',
		room TEXT NOT NULL DEFAULT '',
		notes TEXT NOT NULL DEFAULT '',
		ignored INTEGER NOT NULL DEFAULT 0,
		network_ok INTEGER NOT NULL DEFAULT 0,
		network_ok_reason TEXT NOT NULL DEFAULT '',
		updated_at TIMESTAMP,
		updated_by TEXT NOT NULL DEFAULT ''
	)`,
	// dns_resolver_status holds what each DNS server connection last reported about the
	// resolver clients use: its addresses and where it forwards internet queries.
	`CREATE TABLE IF NOT EXISTS dns_resolver_status (
		target_id INTEGER PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
		checked_at TIMESTAMP NOT NULL,
		data TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS iot_settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`,
	// dns_zone_vlans says which DNS zone each router network (VLAN) uses.
	`CREATE TABLE IF NOT EXISTS dns_zone_vlans (
		id INTEGER PRIMARY KEY,
		server_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
		zone TEXT NOT NULL,
		router_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
		network_id TEXT NOT NULL,
		network TEXT NOT NULL DEFAULT '',
		vlan INTEGER NOT NULL DEFAULT 0,
		updated_by TEXT NOT NULL DEFAULT '',
		updated_at TIMESTAMP NOT NULL,
		UNIQUE (router_id, network_id)
	)`,
}

// Open opens (and migrates) the database in dataDir.
func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	return OpenPath(filepath.Join(dataDir, "ncc.db"))
}

// OpenPath opens a database at an explicit path (":memory:" works for tests).
func OpenPath(path string) (*Store, error) {
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	} else {
		dsn = "file::memory:?_pragma=foreign_keys(1)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: one writer; keeps :memory: databases shared too
	for i, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			return nil, fmt.Errorf("migration %d: %w", i, err)
		}
	}
	return &Store{DB: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.DB.Close() }

// Tx runs fn in a transaction.
func (s *Store) Tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
