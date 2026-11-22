package iot

import (
	"context"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/store"
)

func TestRecordAndUpdate(t *testing.T) {
	st, err := store.OpenPath(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t0 := time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)
	snap := &inventory.Snapshot{Target: "office", TakenAt: t0, Clients: []inventory.Client{
		{MAC: "00:40:8C:00:00:01", Name: "cam-lobby", Vendor: "Axis Communications AB", NetworkID: "net_iot"},
		{MAC: "de:ad:00:00:00:04", Name: "phone", Vendor: "Apple", NetworkID: "net_default"},
		{MAC: "00:c0:b7:00:00:02", Name: "ups-1", Vendor: "American Power Conversion", NetworkID: "net_default"},
	}}
	if err := Record(ctx, st.DB, 1, snap); err != nil {
		t.Fatal(err)
	}
	devs, _ := List(ctx, st.DB)
	if len(devs) != 2 || devs[0].Name != "cam-lobby" || devs[0].Type != TypeCamera || !devs[0].Online || devs[1].Type != TypePower {
		t.Fatalf("devices: %+v", devs)
	}
	Assess(devs, map[string]bool{"net_iot": true})
	if !has(devs[1].Issues, IssueWrongNetwork) || has(devs[0].Issues, IssueWrongNetwork) || !has(devs[0].Issues, IssueNoLocation) {
		t.Fatalf("issues: %v %v", devs[0].Issues, devs[1].Issues)
	}

	site, owner, ok := "HQ", "Facilities", true
	n, err := Update(ctx, st.DB, []string{"00:40:8c:00:00:01", "00-C0-B7-00-00-02"}, Patch{Site: &site, Owner: &owner}, "derek")
	if err != nil || n != 2 {
		t.Fatalf("update: %d %v", n, err)
	}
	if _, err := Update(ctx, st.DB, []string{"00:c0:b7:00:00:02"}, Patch{NetworkOK: &ok}, "derek"); err != nil {
		t.Fatal(err)
	}
	bad := "toaster"
	if _, err := Update(ctx, st.DB, []string{"00:c0:b7:00:00:02"}, Patch{Type: &bad}, "derek"); err == nil {
		t.Fatal("unknown type accepted")
	}

	// the next read misses the UPS: it goes offline but keeps what people recorded
	snap2 := &inventory.Snapshot{Target: "office", TakenAt: t0.Add(time.Minute), Clients: snap.Clients[:2]}
	if err := Record(ctx, st.DB, 1, snap2); err != nil {
		t.Fatal(err)
	}
	devs, _ = List(ctx, st.DB)
	Assess(devs, map[string]bool{"net_iot": true})
	ups := devs[1]
	if ups.Online || ups.Site != "HQ" || ups.Owner != "Facilities" || !ups.NetworkOK || !has(ups.Issues, IssueOffline) || has(ups.Issues, IssueWrongNetwork) {
		t.Fatalf("ups: %+v", ups)
	}
	if !devs[0].LastSeen.Equal(t0.Add(time.Minute)) || !devs[0].FirstSeen.Equal(t0) {
		t.Fatalf("seen: %v %v", devs[0].FirstSeen, devs[0].LastSeen)
	}

	// a person adds the phone by hand; it stays in the inventory from then on
	if err := Add(ctx, st.DB, 1, snap.Clients[1], t0, true, TypePhone, "derek"); err != nil {
		t.Fatal(err)
	}
	devs, _ = List(ctx, st.DB)
	if len(devs) != 3 || devs[1].Name != "phone" || devs[1].Type != TypePhone {
		t.Fatalf("after add: %+v", devs)
	}

	// IoT networks: unset, then chosen, then back to guessing
	if _, set, _ := IoTNetworks(ctx, st.DB); set {
		t.Fatal("networks set on a fresh install")
	}
	_ = SetIoTNetworks(ctx, st.DB, []string{"net_iot", "net_cams"})
	if ids, set, _ := IoTNetworks(ctx, st.DB); !set || len(ids) != 2 {
		t.Fatalf("networks: %v %v", ids, set)
	}
	_ = SetIoTNetworks(ctx, st.DB, nil)
	if _, set, _ := IoTNetworks(ctx, st.DB); set {
		t.Fatal("networks still set")
	}
	if ok, _ := Delete(ctx, st.DB, "DE:AD:00:00:00:04"); !ok {
		t.Fatal("delete")
	}
}

func has(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
