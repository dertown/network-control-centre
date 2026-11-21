package synology

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/mocklab"
	"github.com/dertown/network-control-centre/internal/storage"
)

func TestCollectAndControl(t *testing.T) {
	srv := httptest.NewTLSServer(mocklab.Synology("pw"))
	defer srv.Close()
	tg := storage.Target{Name: "ds", Kind: "synology", Address: srv.URL, Options: map[string]string{}}
	ctx := context.Background()
	creds := map[string]string{"username": "ncc", "password": "pw"}

	if _, err := (Provider{}).Collect(ctx, tg, map[string]string{"username": "ncc", "password": "x"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("bad password: %v", err)
	}
	res, err := Provider{}.Collect(ctx, tg, creds)
	if err != nil {
		t.Fatal(err)
	}
	inv := res.Inventory
	if inv.System.Model != "DS920+" || inv.System.Name != "ds920" || inv.System.UptimeS != 1462*3600+12*60+40 || inv.System.CPUUsage < 0.12 {
		t.Fatalf("system %+v", inv.System)
	}
	if len(inv.Pools) != 1 || inv.Pools[0].RAID != "SHR" || len(inv.Volumes) != 1 || inv.Volumes[0].Pool != "Storage Pool 1" || inv.Volumes[0].FS != "btrfs" {
		t.Fatalf("pools %+v volumes %+v", inv.Pools, inv.Volumes)
	}
	if len(inv.Disks) != 4 || inv.Disks[3].Type != "ssd" || inv.Disks[0].Pool != "Storage Pool 1" || inv.Disks[0].Health != storage.HealthGood {
		t.Fatalf("disks %+v", inv.Disks)
	}
	if len(inv.Shares) != 4 || len(inv.Snapshots) != 4 || !inv.Has(storage.CapSnapshotDelete) {
		t.Fatalf("shares %d snaps %d caps %v", len(inv.Shares), len(inv.Snapshots), inv.Capabilities)
	}
	if inv.Snapshots[0].Created.IsZero() || inv.Snapshots[0].Created.Before(inv.Snapshots[1].Created) {
		t.Fatalf("snapshots not newest first: %+v", inv.Snapshots)
	}

	if err := (Provider{}).CreateShare(ctx, tg, creds, storage.ShareSpec{Name: "backups", Volume: "/volume1"}); err != nil {
		t.Fatal(err)
	}
	if err := (Provider{}).CreateShare(ctx, tg, creds, storage.ShareSpec{Name: "backups", Volume: "/volume1"}); err == nil {
		t.Fatal("duplicate share accepted")
	}
	if err := (Provider{}).CreateSnapshot(ctx, tg, creds, "docker", "before upgrade"); err != nil {
		t.Fatal(err)
	}
	res, _ = Provider{}.Collect(ctx, tg, creds)
	var id string
	for _, s := range res.Inventory.Snapshots {
		if s.Share == "docker" {
			id = s.ID
		}
	}
	if len(res.Inventory.Shares) != 5 || id == "" {
		t.Fatalf("after changes: %d shares, docker snapshot %q", len(res.Inventory.Shares), id)
	}
	if err := (Provider{}).DeleteSnapshot(ctx, tg, creds, "docker", id); err != nil {
		t.Fatal(err)
	}
	if err := (Provider{}).Power(ctx, tg, creds, "restart"); err != nil {
		t.Fatal(err)
	}
}

func TestParseSnapTime(t *testing.T) {
	got := parseSnapTime("GMT+01-2024.05.01-02.00.00")
	if !got.Equal(time.Date(2024, 5, 1, 1, 0, 0, 0, time.UTC)) {
		t.Fatalf("got %v", got)
	}
	if got := parseSnapTime("GMT-05:30-2024.05.01-02.00.00"); !got.Equal(time.Date(2024, 5, 1, 7, 30, 0, 0, time.UTC)) {
		t.Fatalf("half-hour zone: %v", got)
	}
}
