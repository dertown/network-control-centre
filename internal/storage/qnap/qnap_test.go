package qnap_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/dertown/network-control-centre/internal/mocklab"
	"github.com/dertown/network-control-centre/internal/storage"
	"github.com/dertown/network-control-centre/internal/storage/qnap"
)

func TestCollect(t *testing.T) {
	srv := httptest.NewTLSServer(mocklab.QNAP("pw"))
	defer srv.Close()
	tg := storage.Target{Name: "nas", Kind: "qnap", Address: srv.URL, Options: map[string]string{}}
	ctx := context.Background()

	if _, err := (qnap.Provider{}).Collect(ctx, tg, map[string]string{"username": "admin", "password": "nope"}); !errors.Is(err, qnap.ErrUnauthorized) {
		t.Fatalf("bad password: %v", err)
	}
	res, err := qnap.Provider{}.Collect(ctx, tg, map[string]string{"username": "admin", "password": "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if res.OptionUpdates[qnap.OptFingerprint] == "" {
		t.Error("certificate not pinned")
	}
	inv := res.Inventory
	s := inv.System
	if s.Model != "TS-464" || s.Name != "nas" || s.OS != "QTS" || s.TempC != 41 || s.CPUTempC != 49 || s.UptimeS < 23*86400 || s.MemBytes == 0 || s.MemUsed == 0 {
		t.Fatalf("system: %+v", s)
	}
	if s.CPUUsage < 0.07 || s.CPUUsage > 0.08 || len(s.Fans) != 1 || len(s.NICs) != 2 || !s.NICs[0].Up || s.NICs[1].Up {
		t.Fatalf("cpu/fans/nics: %+v", s)
	}
	if len(inv.Volumes) != 2 || inv.Volumes[0].Name != "Backup" || inv.Volumes[1].Total != 5_340<<30 {
		t.Fatalf("volumes: %+v", inv.Volumes)
	}
	if len(inv.Disks) != 4 || inv.Disks[3].Health != storage.HealthWarning || inv.Disks[2].TempC != 52 || inv.Disks[0].Size < 4e12 {
		t.Fatalf("disks: %+v", inv.Disks)
	}
	if len(inv.Shares) != 7 { // six on volumes plus a USB disk from File Station
		t.Fatalf("shares: %+v", inv.Shares)
	}
	if s.Update == "" || s.Health != storage.HealthWarning {
		t.Fatalf("update %q health %s", s.Update, s.Health)
	}
	if !inv.Has(storage.CapRestart) || inv.Has(storage.CapSnapshotCreate) {
		t.Fatalf("caps %v", inv.Capabilities)
	}

	creds := map[string]string{"username": "admin", "password": "pw"}
	if err := (qnap.Provider{}).CreateFolder(ctx, tg, creds, "Public", "2024/holiday"); err != nil {
		t.Fatal(err)
	}
	if err := (qnap.Provider{}).CreateFolder(ctx, tg, creds, "Public", "2024/holiday"); err == nil {
		t.Fatal("creating an existing folder should fail")
	}
	if err := (qnap.Provider{}).Power(ctx, tg, creds, "restart"); err != nil {
		t.Fatal(err)
	}
	if err := (qnap.Provider{}).CreateSnapshot(ctx, tg, creds, "Public", ""); !errors.Is(err, storage.ErrUnsupported) {
		t.Fatal(err)
	}
}
