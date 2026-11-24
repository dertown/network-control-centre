package core

import (
	"context"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/store"
)

func TestLatestSnapshotsFollowsNewPollsAndDisabledTargets(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenPath(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tg := &Targets{DB: st.DB}
	a := &Target{Kind: "unifi", Category: CategoryDevice, Name: "a", Address: "x", Enabled: true}
	b := &Target{Kind: "unifi", Category: CategoryDevice, Name: "b", Address: "y", Enabled: true}
	for _, x := range []*Target{a, b} {
		if err := tg.Create(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	save := func(id int64, name string, devices int) {
		s := &inventory.Snapshot{Target: name, TakenAt: time.Now()}
		for i := 0; i < devices; i++ {
			s.Devices = append(s.Devices, inventory.Device{ID: name})
		}
		if err := SaveSnapshot(ctx, st.DB, id, s, 3); err != nil {
			t.Fatal(err)
		}
	}
	count := func() map[string]int {
		snaps, err := LatestSnapshots(ctx, st.DB)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]int{}
		for _, s := range snaps {
			out[s.Target] = len(s.Devices)
		}
		return out
	}
	save(a.ID, "a", 1)
	save(b.ID, "b", 2)
	if got := count(); got["a"] != 1 || got["b"] != 2 {
		t.Fatalf("first read: %v", got)
	}
	save(a.ID, "a", 5)
	if got := count(); got["a"] != 5 || got["b"] != 2 {
		t.Fatalf("after a new poll: %v", got)
	}
	b.Enabled = false
	if err := tg.Update(ctx, b); err != nil {
		t.Fatal(err)
	}
	if got := count(); len(got) != 1 || got["a"] != 5 {
		t.Fatalf("disabled target still listed: %v", got)
	}
}
