package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/siem"
	"github.com/dertown/network-control-centre/internal/storage"
	"github.com/dertown/network-control-centre/internal/vault"
)

// ---- network events: what NCC notices while polling, journalled for the SIEMs ----

// networkEventKeep is how long network events stay in the journal.
const networkEventKeep = 30 * 24 * time.Hour

// RecordNetworkEvent adds an event to the journal the SIEM forwarder reads.
func RecordNetworkEvent(ctx context.Context, db *sql.DB, e siem.Event) (int64, error) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	f, _ := json.Marshal(e.Fields)
	res, err := db.ExecContext(ctx, `INSERT INTO siem_events (ts, type, severity, target, message, fields) VALUES (?,?,?,?,?,?)`,
		e.Time.UTC().Format(time.RFC3339Nano), e.Type, e.Severity, e.Target, e.Message, string(f))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// NetworkEvents returns journalled events after id, oldest first.
func NetworkEvents(ctx context.Context, db *sql.DB, after int64, limit int) ([]siem.Event, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, ts, type, severity, target, message, fields FROM siem_events WHERE id > ? ORDER BY id LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []siem.Event
	for rows.Next() {
		var e siem.Event
		var ts, fields string
		if err := rows.Scan(&e.ID, &ts, &e.Type, &e.Severity, &e.Target, &e.Message, &fields); err != nil {
			return nil, err
		}
		e.Source = siem.SourceNetwork
		e.Time, _ = time.Parse(time.RFC3339Nano, ts)
		_ = json.Unmarshal([]byte(fields), &e.Fields)
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecentNetworkEvents returns the newest journalled events, newest first.
func RecentNetworkEvents(ctx context.Context, db *sql.DB, limit int) ([]siem.Event, error) {
	var max int64
	_ = db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM siem_events`).Scan(&max)
	from := max - int64(limit)
	if from < 0 {
		from = 0
	}
	evs, err := NetworkEvents(ctx, db, from, limit)
	for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
		evs[i], evs[j] = evs[j], evs[i]
	}
	return evs, err
}

// noteChange stores the latest value of a watched condition and journals an event when it
// changed. The first value seen for a target only raises an event when bad says it is a
// problem, so adding a connection (or upgrading NCC) doesn't report every healthy device.
func (p *Poller) noteChange(ctx context.Context, t *Target, key, value string, bad bool, event func(prev string) *siem.Event) {
	if p.DB == nil {
		return
	}
	var prev string
	err := p.DB.QueryRowContext(ctx, `SELECT value FROM siem_state WHERE target_id = ? AND key = ?`, t.ID, key).Scan(&prev)
	known := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return
	}
	if known && prev == value {
		return
	}
	if _, err := p.DB.ExecContext(ctx, `INSERT INTO siem_state (target_id, key, value) VALUES (?,?,?)
		ON CONFLICT(target_id, key) DO UPDATE SET value = excluded.value`, t.ID, key, value); err != nil {
		return
	}
	if !known && !bad {
		return
	}
	e := event(prev)
	if e == nil {
		return
	}
	if e.Fields == nil {
		e.Fields = map[string]string{}
	}
	e.Fields["ncc_connection"] = t.Name
	e.Fields["ncc_category"] = t.Category
	e.Fields["ncc_kind"] = t.Kind
	if e.Target == "" {
		e.Target = "target/" + t.Name
	}
	if _, err := RecordNetworkEvent(ctx, p.DB, *e); err != nil && p.Log != nil {
		p.Log.Warn("record network event", "target", t.Name, "err", err)
	}
}

// noteConnection raises connection.down when a connection starts failing and
// connection.restored when it works again. A sealed vault is not the device's fault and is
// left out.
func (p *Poller) noteConnection(ctx context.Context, t *Target, err error) {
	if errors.Is(err, vault.ErrSealed) || errors.Is(err, context.Canceled) {
		return
	}
	v := "ok"
	if err != nil {
		v = "error"
	}
	p.noteChange(ctx, t, "connection", v, err != nil, func(prev string) *siem.Event {
		if err != nil {
			return &siem.Event{Type: "connection.down", Severity: siem.SevHigh,
				Message: fmt.Sprintf("NCC can't reach %s (%s at %s): %v", t.Name, t.Kind, t.Address, err),
				Fields:  map[string]string{"address": t.Address, "error": err.Error()}}
		}
		return &siem.Event{Type: "connection.restored", Severity: siem.SevLow,
			Message: fmt.Sprintf("%s (%s at %s) is reachable again.", t.Name, t.Kind, t.Address),
			Fields:  map[string]string{"address": t.Address}}
	})
}

// noteLoops raises network.loop for switching loops that weren't there on the last poll and
// network.loop_cleared when the last one goes.
func (p *Poller) noteLoops(ctx context.Context, t *Target, snap *inventory.Snapshot) {
	ids := make([]string, 0, len(snap.Loops))
	byID := map[string]inventory.Loop{}
	for _, l := range snap.Loops {
		ids = append(ids, l.ID)
		byID[l.ID] = l
	}
	sort.Strings(ids)
	p.noteChange(ctx, t, "loops", strings.Join(ids, ","), len(ids) > 0, func(prev string) *siem.Event {
		if len(ids) == 0 {
			return &siem.Event{Type: "network.loop_cleared", Severity: siem.SevLow, Message: fmt.Sprintf("No switching loops remain on %s.", t.Name)}
		}
		old := map[string]bool{}
		for _, id := range strings.Split(prev, ",") {
			old[id] = true
		}
		var fresh []string
		sev := siem.SevMedium
		for _, id := range ids {
			if old[id] {
				continue
			}
			l := byID[id]
			fresh = append(fresh, l.Summary)
			if l.Severity == "critical" {
				sev = siem.SevCritical
			} else if l.Severity == "warning" && sev < siem.SevHigh {
				sev = siem.SevHigh
			}
		}
		if len(fresh) == 0 {
			return nil // a loop went away, others remain
		}
		return &siem.Event{Type: "network.loop", Severity: sev,
			Message: fmt.Sprintf("Switching loop on %s: %s", t.Name, strings.Join(fresh, "; ")),
			Fields:  map[string]string{"loops": fmt.Sprint(len(ids))}}
	})
}

// noteStorage raises storage.health when a storage device's health changes.
func (p *Poller) noteStorage(ctx context.Context, t *Target, inv *storage.Inventory) {
	h := inv.System.Health
	bad := h == storage.HealthWarning || h == storage.HealthCritical
	p.noteChange(ctx, t, "storage_health", h, bad, func(prev string) *siem.Event {
		sev := siem.SevLow
		switch h {
		case storage.HealthCritical:
			sev = siem.SevCritical
		case storage.HealthWarning:
			sev = siem.SevMedium
		case storage.HealthUnknown:
			return nil
		}
		var why []string
		for i, a := range inv.Alerts {
			if i == 3 {
				break
			}
			why = append(why, a.Subject+": "+a.Message)
		}
		msg := fmt.Sprintf("Storage %s is now %s.", inv.Name(), h)
		if len(why) > 0 {
			msg += " " + strings.Join(why, " ")
		}
		return &siem.Event{Type: "storage.health", Severity: sev, Message: msg,
			Fields: map[string]string{"health": h, "previous_health": prev, "alerts": fmt.Sprint(len(inv.Alerts))}}
	})
}

// ---- SIEM connections: the poll is the connection test ----

func (p *Poller) checkSIEM(ctx context.Context, t *Target) error {
	prov, err := siem.Get(t.Kind)
	if err != nil {
		return err
	}
	creds, err := p.Vault.Get(ctx, t.SecretPath)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := prov.Test(cctx, SIEMTarget(t), creds)
	if res != nil && len(res.OptionUpdates) > 0 {
		if merr := p.Targets.MergeOptions(ctx, t.ID, res.OptionUpdates); merr != nil && err == nil {
			err = merr
		}
	}
	info := ""
	if res != nil {
		info = res.Info
	}
	if err == nil {
		_, _ = p.DB.ExecContext(ctx, `INSERT INTO siem_status (target_id, info) VALUES (?,?)
			ON CONFLICT(target_id) DO UPDATE SET info = excluded.info`, t.ID, info)
	}
	return err
}

// SIEMTarget converts a stored target for the SIEM providers.
func SIEMTarget(t *Target) siem.Target {
	return siem.Target{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Options: t.Options}
}

// ---- the forwarder ----

// SIEMForwarder sends the audit log and the network event journal to every enabled SIEM
// connection, a batch at a time, keeping a cursor per connection and source. Delivery is at
// least once: a batch whose delivery fails, or whose cursor can't be saved, is sent again.
type SIEMForwarder struct {
	DB       *sql.DB
	Targets  *Targets
	Vault    vault.Store
	Log      *slog.Logger
	Interval time.Duration // default 5s
	Batch    int           // events per delivery, default 500

	mu      sync.Mutex
	backoff map[int64]backoffState
	running map[int64]bool
}

type backoffState struct {
	fails int
	until time.Time
}

// Run forwards until ctx ends.
func (f *SIEMForwarder) Run(ctx context.Context) {
	if f.Interval <= 0 {
		f.Interval = 5 * time.Second
	}
	t := time.NewTicker(f.Interval)
	defer t.Stop()
	last := time.Time{}
	for {
		f.FlushAll(ctx)
		if time.Since(last) > time.Hour {
			last = time.Now()
			_, _ = f.DB.ExecContext(ctx, `DELETE FROM siem_events WHERE ts < ?`, time.Now().Add(-networkEventKeep).UTC().Format(time.RFC3339Nano))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// FlushAll delivers pending events to every enabled SIEM connection not in back-off.
func (f *SIEMForwarder) FlushAll(ctx context.Context) {
	ts, err := f.Targets.List(ctx, CategorySIEM)
	if err != nil {
		return
	}
	var wg sync.WaitGroup
	for i := range ts {
		t := ts[i]
		if !t.Enabled || !f.due(t.ID) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.Flush(ctx, &t); err != nil && !errors.Is(err, vault.ErrSealed) && f.Log != nil {
				f.Log.Warn("SIEM delivery failed", "target", t.Name, "err", err)
			}
		}()
	}
	wg.Wait()
}

func (f *SIEMForwarder) due(id int64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.backoff[id]
	return !ok || time.Now().After(b.until)
}

func (f *SIEMForwarder) result(id int64, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.backoff == nil {
		f.backoff = map[int64]backoffState{}
	}
	if err == nil {
		delete(f.backoff, id)
		return
	}
	b := f.backoff[id]
	b.fails++
	wait := 5 * time.Second << min(b.fails, 6) // 10s, 20s ... 5m20s
	if wait > 5*time.Minute {
		wait = 5 * time.Minute
	}
	b.until = time.Now().Add(wait)
	f.backoff[id] = b
}

// cursor returns how far a connection has got in a source. A connection's first look starts
// at the end (only new events), or at the beginning of the audit log with backfill on.
func (f *SIEMForwarder) cursor(ctx context.Context, t *Target, source string) (int64, error) {
	var id int64
	err := f.DB.QueryRowContext(ctx, `SELECT last_id FROM siem_cursors WHERE target_id = ? AND source = ?`, t.ID, source).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if !(source == siem.SourceAudit && t.Options[siem.OptBackfill] == "on") {
		table := "audit_log"
		if source == siem.SourceNetwork {
			table = "siem_events"
		}
		if err := f.DB.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM `+table).Scan(&id); err != nil {
			return 0, err
		}
	}
	return id, f.setCursor(ctx, t.ID, source, id)
}

func (f *SIEMForwarder) setCursor(ctx context.Context, targetID int64, source string, id int64) error {
	_, err := f.DB.ExecContext(ctx, `INSERT INTO siem_cursors (target_id, source, last_id) VALUES (?,?,?)
		ON CONFLICT(target_id, source) DO UPDATE SET last_id = excluded.last_id`, targetID, source, id)
	return err
}

// auditEvents reads audit log entries after id as events.
func auditEvents(ctx context.Context, db *sql.DB, after int64, limit int) ([]siem.Event, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, ts, actor, action, target, detail FROM audit_log WHERE id > ? ORDER BY id LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []siem.Event
	for rows.Next() {
		var e siem.Event
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Type, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		e.Source = siem.SourceAudit
		e.Time, _ = time.Parse(time.RFC3339Nano, ts)
		e.Severity = siem.SeverityFor(e.Type)
		e.Message = auditMessage(e)
		out = append(out, e)
	}
	return out, rows.Err()
}

func auditMessage(e siem.Event) string {
	who := e.Actor
	if who == "" {
		who = "someone"
	}
	if e.Type == "login.failed" {
		return fmt.Sprintf("Failed NCC sign-in as %s", who)
	}
	if e.Target != "" && e.Target != "ncc" {
		return fmt.Sprintf("%s: %s on %s", who, e.Type, e.Target)
	}
	return fmt.Sprintf("%s: %s", who, e.Type)
}

// Flush delivers what is pending for one connection, a batch per source per call, and
// returns how many events it delivered.
func (f *SIEMForwarder) Flush(ctx context.Context, t *Target) (int, error) {
	f.mu.Lock()
	if f.running == nil {
		f.running = map[int64]bool{}
	}
	if f.running[t.ID] {
		f.mu.Unlock()
		return 0, nil
	}
	f.running[t.ID] = true
	f.mu.Unlock()
	defer func() { f.mu.Lock(); delete(f.running, t.ID); f.mu.Unlock() }()

	batch := f.Batch
	if batch <= 0 {
		batch = 500
	}
	prov, err := siem.Get(t.Kind)
	if err != nil {
		return 0, err
	}
	var creds map[string]string
	sent := 0
	for _, src := range []struct {
		name string
		read func(context.Context, *sql.DB, int64, int) ([]siem.Event, error)
	}{{siem.SourceAudit, auditEvents}, {siem.SourceNetwork, NetworkEvents}} {
		if (src.name == siem.SourceAudit && t.Options[siem.OptAudit] != "on") || (src.name == siem.SourceNetwork && t.Options[siem.OptNetwork] != "on") {
			continue
		}
		cur, err := f.cursor(ctx, t, src.name)
		if err != nil {
			return sent, err
		}
		evs, err := src.read(ctx, f.DB, cur, batch)
		if err != nil || len(evs) == 0 {
			if err != nil {
				return sent, err
			}
			continue
		}
		last := evs[len(evs)-1].ID
		var want []siem.Event
		for _, e := range evs {
			if siem.Wants(t.Options, e) {
				want = append(want, e)
			}
		}
		if len(want) > 0 {
			if creds == nil {
				if creds, err = f.Vault.Get(ctx, t.SecretPath); err != nil {
					return sent, err
				}
			}
			n, err := f.deliver(ctx, t, prov, creds, want)
			sent += n
			if err != nil {
				if n > 0 { // partly delivered: move past what got through
					_ = f.setCursor(ctx, t.ID, src.name, want[n-1].ID)
				}
				return sent, err
			}
		}
		if err := f.setCursor(ctx, t.ID, src.name, last); err != nil {
			return sent, err
		}
	}
	return sent, nil
}

// deliver sends events and records the outcome on the connection's status.
func (f *SIEMForwarder) deliver(ctx context.Context, t *Target, prov siem.Provider, creds map[string]string, evs []siem.Event) (int, error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	res, err := prov.Send(cctx, SIEMTarget(t), creds, evs)
	if res != nil && len(res.OptionUpdates) > 0 {
		_ = f.Targets.MergeOptions(ctx, t.ID, res.OptionUpdates)
	}
	n := len(evs)
	if err != nil {
		n = 0
		var pe *siem.PartialError
		if errors.As(err, &pe) {
			n = pe.Sent
		}
	}
	f.record(ctx, t.ID, n, len(evs)-n, err)
	f.result(t.ID, err)
	return n, err
}

func (f *SIEMForwarder) record(ctx context.Context, id int64, sent, failed int, err error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	var sentAt any
	if sent > 0 {
		sentAt = now
	}
	_, _ = f.DB.ExecContext(ctx, `INSERT INTO siem_status (target_id, sent, failed, last_sent_at, last_attempt_at, last_error) VALUES (?,?,?,?,?,?)
		ON CONFLICT(target_id) DO UPDATE SET sent = sent + excluded.sent, failed = failed + excluded.failed,
		last_sent_at = COALESCE(excluded.last_sent_at, last_sent_at), last_attempt_at = excluded.last_attempt_at, last_error = excluded.last_error`,
		id, sent, failed, sentAt, now, msg)
}

// SendTest delivers one test event to a connection right away.
func (f *SIEMForwarder) SendTest(ctx context.Context, t *Target, actor string) error {
	prov, err := siem.Get(t.Kind)
	if err != nil {
		return err
	}
	creds, err := f.Vault.Get(ctx, t.SecretPath)
	if err != nil {
		return err
	}
	_, err = f.deliver(ctx, t, prov, creds, []siem.Event{siem.TestEvent(actor)})
	return err
}

// SIEMStatus is what the SIEM page shows for one connection.
type SIEMStatus struct {
	Sent          int64      `json:"sent"`
	Failed        int64      `json:"failed"`
	LastSentAt    *time.Time `json:"last_sent_at,omitempty"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	Info          string     `json:"info,omitempty"`
	// Pending counts events not yet delivered, per source (before the severity filter).
	Pending map[string]int64 `json:"pending"`
}

// StatusOf reads one connection's delivery counters and backlog.
func (f *SIEMForwarder) StatusOf(ctx context.Context, t *Target) (SIEMStatus, error) {
	st := SIEMStatus{Pending: map[string]int64{}}
	var sentAt, attemptAt sql.NullString
	err := f.DB.QueryRowContext(ctx, `SELECT sent, failed, last_sent_at, last_attempt_at, last_error, info FROM siem_status WHERE target_id = ?`, t.ID).
		Scan(&st.Sent, &st.Failed, &sentAt, &attemptAt, &st.LastError, &st.Info)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return st, err
	}
	parse := func(s sql.NullString) *time.Time {
		if !s.Valid {
			return nil
		}
		if ts, err := time.Parse(time.RFC3339Nano, s.String); err == nil {
			return &ts
		}
		return nil
	}
	st.LastSentAt, st.LastAttemptAt = parse(sentAt), parse(attemptAt)
	for _, src := range []struct{ name, table, opt string }{{siem.SourceAudit, "audit_log", siem.OptAudit}, {siem.SourceNetwork, "siem_events", siem.OptNetwork}} {
		if t.Options[src.opt] != "on" {
			continue
		}
		var cur sql.NullInt64
		_ = f.DB.QueryRowContext(ctx, `SELECT last_id FROM siem_cursors WHERE target_id = ? AND source = ?`, t.ID, src.name).Scan(&cur)
		if !cur.Valid {
			continue // not started yet
		}
		var n int64
		_ = f.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+src.table+` WHERE id > ?`, cur.Int64).Scan(&n)
		st.Pending[src.name] = n
	}
	return st, nil
}
