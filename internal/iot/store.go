package iot

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/inventory"
)

// Device is one IoT device: what the network last saw of it and what people recorded.
type Device struct {
	MAC      string `json:"mac"`
	Name     string `json:"name"`               // label, else the network's name for it, else the MAC
	Label    string `json:"label"`              // the name people gave it in NCC
	Hostname string `json:"hostname,omitempty"` // the name the network knows it by
	IP       string `json:"ip,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Type     string `json:"type"`      // the type people set, else the guessed one, else other
	AutoType string `json:"auto_type"` // NCC's guess from vendor and name

	NetworkID  string `json:"network_id,omitempty"`
	Network    string `json:"network,omitempty"`
	VLAN       int    `json:"vlan,omitempty"`
	Wired      bool   `json:"wired"`
	SSID       string `json:"ssid,omitempty"`
	SwitchMAC  string `json:"switch_mac,omitempty"`
	SwitchPort int    `json:"switch_port,omitempty"`
	APMAC      string `json:"ap_mac,omitempty"`
	Uplink     string `json:"uplink,omitempty"` // "Rack switch port 5" or "Lounge AP", filled in by the API

	TargetID  int64     `json:"target_id,omitempty"`
	Target    string    `json:"target,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Online    bool      `json:"online"`

	Owner           string     `json:"owner"`
	Site            string     `json:"site"`
	Building        string     `json:"building"`
	Floor           string     `json:"floor"`
	Room            string     `json:"room"`
	Notes           string     `json:"notes"`
	Ignored         bool       `json:"ignored"`    // not an IoT device after all; kept so it isn't found again
	NetworkOK       bool       `json:"network_ok"` // allowed off the IoT networks
	NetworkOKReason string     `json:"network_ok_reason,omitempty"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
	UpdatedBy       string     `json:"updated_by,omitempty"`

	// From a smart home hub that knows the device by its MAC.
	Model    string `json:"model,omitempty"`
	Firmware string `json:"firmware,omitempty"`

	Issues []string `json:"issues"`
}

// Issues.
const (
	IssueWrongNetwork = "wrong_network" // on a network that isn't an IoT network
	IssueOffline      = "offline"       // not seen in the latest read of its network
	IssueNoLocation   = "no_location"
	IssueNoOwner      = "no_owner"
)

// Record updates the inventory from a fresh read of one network: clients already in the
// inventory are refreshed, new ones that look like IoT devices are added, and devices of
// that network that were not seen are marked offline.
func Record(ctx context.Context, db *sql.DB, targetID int64, snap *inventory.Snapshot) error {
	if snap == nil {
		return nil
	}
	known := map[string]bool{}
	rows, err := db.QueryContext(ctx, `SELECT mac FROM iot_devices`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			rows.Close()
			return err
		}
		known[m] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	at := snap.TakenAt.UTC().Format(time.RFC3339Nano)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, c := range snap.Clients {
		mac := NormMAC(c.MAC)
		if mac == "" {
			continue
		}
		c.MAC = mac
		b, _ := json.Marshal(c)
		typ, ok := Classify(c.Vendor, c.Name)
		switch {
		case known[mac]:
			if _, err := tx.ExecContext(ctx, `UPDATE iot_devices SET target_id = ?, client = ?, last_seen = ?, online = 1,
				auto_type = CASE WHEN ? <> '' THEN ? ELSE auto_type END WHERE mac = ?`, targetID, string(b), at, typ, typ, mac); err != nil {
				return err
			}
		case ok:
			if _, err := tx.ExecContext(ctx, `INSERT INTO iot_devices (mac, target_id, client, first_seen, last_seen, online, auto_type)
				VALUES (?,?,?,?,?,1,?)`, mac, targetID, string(b), at, at, typ); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE iot_devices SET online = 0 WHERE target_id = ? AND last_seen <> ?`, targetID, at); err != nil {
		return err
	}
	return tx.Commit()
}

// Add puts a network client in the inventory by hand (or brings back one marked not IoT).
func Add(ctx context.Context, db *sql.DB, targetID int64, c inventory.Client, seen time.Time, online bool, typ, by string) error {
	c.MAC = NormMAC(c.MAC)
	if c.MAC == "" {
		return errors.New("a MAC address is needed")
	}
	if typ != "" && !ValidType(typ) {
		return errors.New("unknown device type " + typ)
	}
	auto, _ := Classify(c.Vendor, c.Name)
	b, _ := json.Marshal(c)
	at := seen.UTC().Format(time.RFC3339Nano)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := db.ExecContext(ctx, `INSERT INTO iot_devices (mac, target_id, client, first_seen, last_seen, online, auto_type, type, updated_at, updated_by)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(mac) DO UPDATE SET ignored = 0, type = CASE WHEN excluded.type <> '' THEN excluded.type ELSE iot_devices.type END,
			updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		c.MAC, targetID, string(b), at, at, online, auto, typ, now, by)
	return err
}

// Patch is a change to the recorded details of one or more devices; nil fields stay as they are.
type Patch struct {
	Type            *string `json:"type"`
	Label           *string `json:"label"`
	Owner           *string `json:"owner"`
	Site            *string `json:"site"`
	Building        *string `json:"building"`
	Floor           *string `json:"floor"`
	Room            *string `json:"room"`
	Notes           *string `json:"notes"`
	Ignored         *bool   `json:"ignored"`
	NetworkOK       *bool   `json:"network_ok"`
	NetworkOKReason *string `json:"network_ok_reason"`
}

// Empty reports whether the patch changes nothing.
func (p Patch) Empty() bool { return len(p.sets()) == 0 }

type set struct {
	col string
	val any
}

func (p Patch) sets() []set {
	var out []set
	str := func(col string, v *string, limit int) {
		if v != nil {
			s := strings.TrimSpace(*v)
			if len(s) > limit {
				s = s[:limit]
			}
			out = append(out, set{col, s})
		}
	}
	str("type", p.Type, 32)
	str("label", p.Label, 120)
	str("owner", p.Owner, 120)
	str("site", p.Site, 120)
	str("building", p.Building, 120)
	str("floor", p.Floor, 60)
	str("room", p.Room, 120)
	str("notes", p.Notes, 2000)
	str("network_ok_reason", p.NetworkOKReason, 300)
	if p.Ignored != nil {
		out = append(out, set{"ignored", *p.Ignored})
	}
	if p.NetworkOK != nil {
		out = append(out, set{"network_ok", *p.NetworkOK})
	}
	return out
}

// Update applies a patch to the given devices and returns how many it changed.
func Update(ctx context.Context, db *sql.DB, macs []string, p Patch, by string) (int, error) {
	if p.Type != nil && *p.Type != "" && !ValidType(*p.Type) {
		return 0, errors.New("unknown device type " + *p.Type)
	}
	sets := p.sets()
	if len(sets) == 0 {
		return 0, errors.New("nothing to change")
	}
	q := "UPDATE iot_devices SET updated_at = ?, updated_by = ?"
	args := []any{time.Now().UTC().Format(time.RFC3339Nano), by}
	for _, s := range sets {
		q += ", " + s.col + " = ?"
		args = append(args, s.val)
	}
	q += " WHERE mac = ?"
	n := 0
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, m := range macs {
		res, err := tx.ExecContext(ctx, q, append(args, NormMAC(m))...)
		if err != nil {
			return 0, err
		}
		k, _ := res.RowsAffected()
		n += int(k)
	}
	return n, tx.Commit()
}

// Delete forgets a device. It is found again on the next read if it still looks like IoT;
// mark it ignored to keep it out.
func Delete(ctx context.Context, db *sql.DB, mac string) (bool, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM iot_devices WHERE mac = ?`, NormMAC(mac))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// List returns every device in the inventory, ignored ones included, sorted by name.
func List(ctx context.Context, db *sql.DB) ([]Device, error) {
	rows, err := db.QueryContext(ctx, `SELECT mac, COALESCE(target_id, 0), client, first_seen, last_seen, online, auto_type, type, label,
		owner, site, building, floor, room, notes, ignored, network_ok, network_ok_reason, updated_at, updated_by FROM iot_devices`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		var d Device
		var client, first, last string
		var updated sql.NullString
		if err := rows.Scan(&d.MAC, &d.TargetID, &client, &first, &last, &d.Online, &d.AutoType, &d.Type, &d.Label,
			&d.Owner, &d.Site, &d.Building, &d.Floor, &d.Room, &d.Notes, &d.Ignored, &d.NetworkOK, &d.NetworkOKReason,
			&updated, &d.UpdatedBy); err != nil {
			return nil, err
		}
		var c inventory.Client
		_ = json.Unmarshal([]byte(client), &c)
		d.Hostname, d.IP, d.Vendor = c.Name, c.IP, c.Vendor
		d.NetworkID, d.Network, d.VLAN, d.Wired, d.SSID = c.NetworkID, c.Network, c.VLAN, c.Wired, c.SSID
		d.SwitchMAC, d.SwitchPort, d.APMAC = c.SwitchMAC, c.SwitchPort, c.APMAC
		d.FirstSeen, _ = time.Parse(time.RFC3339Nano, first)
		d.LastSeen, _ = time.Parse(time.RFC3339Nano, last)
		if updated.Valid {
			if t, err := time.Parse(time.RFC3339Nano, updated.String); err == nil {
				d.UpdatedAt = &t
			}
		}
		d.Name = firstOf(d.Label, d.Hostname, d.MAC)
		if d.Type == "" {
			d.Type = firstOf(d.AutoType, TypeOther)
		}
		d.Issues = []string{}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, rows.Err()
}

// Assess fills in each device's issues, given the networks meant for IoT devices.
func Assess(devs []Device, iotNetworks map[string]bool) {
	for i := range devs {
		d := &devs[i]
		d.Issues = []string{}
		if d.Ignored {
			continue
		}
		if d.NetworkID != "" && !iotNetworks[d.NetworkID] && !d.NetworkOK {
			d.Issues = append(d.Issues, IssueWrongNetwork)
		}
		if !d.Online {
			d.Issues = append(d.Issues, IssueOffline)
		}
		if d.Site == "" && d.Building == "" && d.Floor == "" && d.Room == "" {
			d.Issues = append(d.Issues, IssueNoLocation)
		}
		if d.Owner == "" {
			d.Issues = append(d.Issues, IssueNoOwner)
		}
	}
}

const keyNetworks = "iot_networks"

// IoTNetworks returns the network ids chosen as IoT networks, and whether anyone chose.
func IoTNetworks(ctx context.Context, db *sql.DB) ([]string, bool, error) {
	var raw string
	err := db.QueryRowContext(ctx, `SELECT value FROM iot_settings WHERE key = ?`, keyNetworks).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil, false, err
	}
	return ids, true, nil
}

// SetIoTNetworks chooses the IoT networks; nil goes back to guessing them from their names.
func SetIoTNetworks(ctx context.Context, db *sql.DB, ids []string) error {
	if ids == nil {
		_, err := db.ExecContext(ctx, `DELETE FROM iot_settings WHERE key = ?`, keyNetworks)
		return err
	}
	b, _ := json.Marshal(ids)
	_, err := db.ExecContext(ctx, `INSERT INTO iot_settings (key, value) VALUES (?,?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, keyNetworks, string(b))
	return err
}

// DefaultIoTNetwork guesses whether a network is meant for IoT devices from its name and
// firewall zone.
func DefaultIoTNetwork(n inventory.Network) bool {
	return IsIoTNetwork(n.Name) || IsIoTNetwork(n.ZoneName)
}

// NormMAC lowercases a MAC address and uses colons; it returns "" for anything else.
func NormMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer("-", ":", ".", "").Replace(s)
	if len(s) == 12 && !strings.Contains(s, ":") {
		var b strings.Builder
		for i := 0; i < 12; i += 2 {
			if i > 0 {
				b.WriteByte(':')
			}
			b.WriteString(s[i : i+2])
		}
		s = b.String()
	}
	if len(s) != 17 {
		return ""
	}
	for i, r := range s {
		if i%3 == 2 {
			if r != ':' {
				return ""
			}
		} else if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return ""
		}
	}
	return s
}

func firstOf(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
