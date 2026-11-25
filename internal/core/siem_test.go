package core

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/dertown/network-control-centre/internal/audit"
	"github.com/dertown/network-control-centre/internal/catalog"
	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/siem"
	"github.com/dertown/network-control-centre/internal/storage"
	"github.com/dertown/network-control-centre/internal/store"
	"github.com/dertown/network-control-centre/internal/vault"
)

// fakeSIEM records what it is sent; fail makes the next deliveries fail, partial makes them
// deliver only that many events.
type fakeSIEM struct {
	got     []siem.Event
	fail    error
	partial int
}

func (f *fakeSIEM) Kind() string { return "fakesiem" }
func (f *fakeSIEM) Test(context.Context, siem.Target, map[string]string) (*siem.Result, error) {
	return &siem.Result{Info: "fake ok"}, f.fail
}
func (f *fakeSIEM) Send(_ context.Context, _ siem.Target, _ map[string]string, evs []siem.Event) (*siem.Result, error) {
	if f.partial > 0 {
		n := f.partial
		f.got = append(f.got, evs[:n]...)
		return &siem.Result{}, &siem.PartialError{Sent: n, Err: errors.New("connection dropped")}
	}
	if f.fail != nil {
		return nil, f.fail
	}
	f.got = append(f.got, evs...)
	return &siem.Result{}, nil
}

var fake = &fakeSIEM{}

func init() { siem.Register(fake, catalog.Vendor{Label: "Fake SIEM"}) }

type memVault struct{ m map[string]vault.Secret }

func (v *memVault) Backend() string { return "mem" }
func (v *memVault) Put(_ context.Context, p string, s vault.Secret) (int, error) {
	v.m[p] = s
	return 1, nil
}
func (v *memVault) Get(_ context.Context, p string) (vault.Secret, error) {
	s, ok := v.m[p]
	if !ok {
		return nil, vault.ErrNotFound
	}
	return s, nil
}
func (v *memVault) List(context.Context, string) ([]string, error) { return nil, nil }
func (v *memVault) Delete(context.Context, string) error           { return nil }
func (v *memVault) Status(context.Context) vault.Status            { return vault.Status{Initialized: true} }

func siemFixture(t *testing.T, opts map[string]string) (*SIEMForwarder, *audit.Log, *Target, *Poller) {
	t.Helper()
	st, err := store.OpenPath(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	vs := &memVault{m: map[string]vault.Secret{}}
	targets := &Targets{DB: st.DB}
	al := audit.New(st.DB)
	ctx := context.Background()
	_ = al.Record(ctx, "admin", "login", "ncc", map[string]string{"ip": "10.0.0.1"}) // before the connection existed
	tg := &Target{Kind: "fakesiem", Category: CategorySIEM, Name: "siem1", Address: "https://siem", Options: opts, Enabled: true}
	if err := targets.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	_, _ = vs.Put(ctx, tg.SecretPath, vault.Secret{"token": "x"})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f := &SIEMForwarder{DB: st.DB, Targets: targets, Vault: vs, Log: log}
	p := &Poller{DB: st.DB, Targets: targets, Vault: vs, Log: log}
	*fake = fakeSIEM{}
	return f, al, tg, p
}

func TestForwarderSendsNewAuditAndNetworkEvents(t *testing.T) {
	f, al, tg, p := siemFixture(t, map[string]string{siem.OptAudit: "on", siem.OptNetwork: "on"})
	ctx := context.Background()

	// first look: the cursor starts at the end, so the earlier sign-in is not sent
	if n, err := f.Flush(ctx, tg); err != nil || n != 0 {
		t.Fatalf("first flush: %d %v", n, err)
	}
	_ = al.Record(ctx, "admin", "target.create", "target/udm", map[string]string{"kind": "unifi"})
	_ = al.Record(ctx, "eve", "login.failed", "ncc", map[string]string{"ip": "203.0.113.5"})
	dev := &Target{ID: tg.ID, Kind: "unifi", Category: CategoryDevice, Name: "udm", Address: "https://udm"}
	p.noteConnection(ctx, dev, errors.New("timeout"))

	n, err := f.Flush(ctx, tg)
	if err != nil || n != 3 {
		t.Fatalf("flush: %d %v", n, err)
	}
	if fake.got[0].Type != "target.create" || fake.got[1].Type != "login.failed" || fake.got[1].Severity != siem.SevHigh ||
		fake.got[1].ClientIP() != "203.0.113.5" {
		t.Errorf("audit events %+v", fake.got[:2])
	}
	if e := fake.got[2]; e.Source != siem.SourceNetwork || e.Type != "connection.down" || e.Fields["ncc_connection"] != "udm" {
		t.Errorf("network event %+v", e)
	}
	// nothing new: nothing sent
	if n, _ := f.Flush(ctx, tg); n != 0 {
		t.Errorf("resent %d", n)
	}
	st, _ := f.StatusOf(ctx, tg)
	if st.Sent != 3 || st.Pending[siem.SourceAudit] != 0 || st.LastSentAt == nil {
		t.Errorf("status %+v", st)
	}
}

func TestForwarderRetriesAndPartialDelivery(t *testing.T) {
	f, al, tg, _ := siemFixture(t, map[string]string{siem.OptAudit: "on", siem.OptBackfill: "on"})
	ctx := context.Background()
	_ = al.Record(ctx, "admin", "dns.change", "dns/example.com", nil)
	_ = al.Record(ctx, "admin", "target.delete", "target/old", nil)

	fake.fail = errors.New("503 busy")
	if _, err := f.Flush(ctx, tg); err == nil {
		t.Fatal("expected the delivery error")
	}
	st, _ := f.StatusOf(ctx, tg)
	if st.LastError != "503 busy" || st.Failed != 3 || st.Pending[siem.SourceAudit] != 3 {
		t.Errorf("after failure %+v", st)
	}
	if f.due(tg.ID) {
		t.Error("a failing connection should back off")
	}

	fake.fail = nil
	fake.partial = 1
	n, err := f.Flush(ctx, tg)
	if err == nil || n != 1 {
		t.Fatalf("partial: %d %v", n, err)
	}
	fake.partial = 0
	if n, err := f.Flush(ctx, tg); err != nil || n != 2 {
		t.Fatalf("rest: %d %v", n, err)
	}
	// backfill sent the sign-in from before the connection existed, each event once
	if len(fake.got) != 3 || fake.got[0].Type != "login" || fake.got[2].Type != "target.delete" {
		t.Errorf("got %+v", fake.got)
	}
	if st, _ := f.StatusOf(ctx, tg); st.LastError != "" || st.Sent != 3 {
		t.Errorf("status %+v", st)
	}
}

func TestForwarderFilters(t *testing.T) {
	f, al, tg, p := siemFixture(t, map[string]string{siem.OptAudit: "on", siem.OptMinSeverity: "5"})
	ctx := context.Background()
	_, _ = f.Flush(ctx, tg)
	_ = al.Record(ctx, "admin", "login", "ncc", nil)                                        // low: dropped
	_ = al.Record(ctx, "admin", "target.delete", "target/x", nil)                           // medium: sent
	p.noteConnection(ctx, &Target{ID: tg.ID, Name: "x", Kind: "unifi"}, errors.New("down")) // network events are off
	if n, err := f.Flush(ctx, tg); err != nil || n != 1 || fake.got[0].Type != "target.delete" {
		t.Fatalf("%d %v %+v", n, err, fake.got)
	}
}

func TestNetworkEventTransitions(t *testing.T) {
	_, _, tg, p := siemFixture(t, nil)
	ctx := context.Background()
	dev := &Target{ID: tg.ID, Kind: "unifi", Category: CategoryDevice, Name: "udm", Address: "https://udm"}
	count := func() int {
		evs, _ := NetworkEvents(ctx, p.DB, 0, 100)
		return len(evs)
	}
	p.noteConnection(ctx, dev, nil) // first sight, healthy: no event
	if count() != 0 {
		t.Fatal("healthy first poll raised an event")
	}
	p.noteConnection(ctx, dev, errors.New("timeout"))
	p.noteConnection(ctx, dev, errors.New("timeout again")) // still down: no repeat
	p.noteConnection(ctx, dev, vault.ErrSealed)             // not the device's fault
	p.noteConnection(ctx, dev, nil)
	evs, _ := NetworkEvents(ctx, p.DB, 0, 100)
	if len(evs) != 2 || evs[0].Type != "connection.down" || evs[1].Type != "connection.restored" {
		t.Fatalf("events %+v", evs)
	}

	snap := &inventory.Snapshot{Loops: []inventory.Loop{{ID: "l1", Severity: "critical", Summary: "sw1 port 3 ↔ sw1 port 4"}}}
	p.noteLoops(ctx, dev, snap)
	p.noteLoops(ctx, dev, snap)
	p.noteLoops(ctx, dev, &inventory.Snapshot{})
	evs, _ = NetworkEvents(ctx, p.DB, 2, 100)
	if len(evs) != 2 || evs[0].Type != "network.loop" || evs[0].Severity != siem.SevCritical || evs[1].Type != "network.loop_cleared" {
		t.Fatalf("loop events %+v", evs)
	}

	nas := &Target{ID: tg.ID, Kind: "qnap", Category: CategoryStorage, Name: "nas"}
	inv := &storage.Inventory{System: storage.System{Name: "nas", Health: storage.HealthCritical},
		Alerts: []storage.Alert{{Level: "critical", Subject: "Disk 2", Message: "SMART status is BAD."}}}
	p.noteStorage(ctx, nas, inv)
	evs, _ = NetworkEvents(ctx, p.DB, 4, 100)
	if len(evs) != 1 || evs[0].Type != "storage.health" || evs[0].Fields["health"] != "critical" {
		t.Fatalf("storage events %+v", evs)
	}
	recent, _ := RecentNetworkEvents(ctx, p.DB, 2)
	if len(recent) != 2 || recent[0].Type != "storage.health" {
		t.Errorf("recent %+v", recent)
	}
}

func TestCheckSIEMSavesInfo(t *testing.T) {
	f, _, tg, p := siemFixture(t, map[string]string{})
	ctx := context.Background()
	if err := p.checkSIEM(ctx, tg); err != nil {
		t.Fatal(err)
	}
	st, _ := f.StatusOf(ctx, tg)
	if st.Info != "fake ok" {
		t.Errorf("info %q", st.Info)
	}
}
