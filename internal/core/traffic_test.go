package core

import (
	"context"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/inventory"
	"github.com/dertown/network-control-centre/internal/store"
)

func TestUsageSince(t *testing.T) {
	st, err := store.OpenPath(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	tr := &Traffic{DB: st.DB, SampleEvery: time.Minute}
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	rec := func(ago time.Duration, cs ...inventory.ClientTraffic) {
		if err := tr.Record(ctx, &inventory.TrafficReport{Target: "home", TakenAt: now.Add(-ago), Clients: cs}); err != nil {
			t.Fatal(err)
		}
	}
	c := func(mac string, down, up int64) inventory.ClientTraffic {
		return inventory.ClientTraffic{MAC: mac, Name: mac, DownBytes: down, UpBytes: up}
	}
	rec(3*time.Hour, c("a", 1000, 10))
	rec(61*time.Minute, c("a", 5000, 50))
	rec(30*time.Minute, c("a", 8000, 80))
	rec(20*time.Minute, c("a", 500, 5), c("b", 300, 3)) // a reconnected (counter reset); b is new
	current := []inventory.ClientTraffic{c("a", 900, 9), c("b", 1300, 13)}

	u, err := tr.UsageSince(ctx, now.Add(-time.Hour), current)
	if err != nil {
		t.Fatal(err)
	}
	// a: baseline 5000 (just before the window), +3000, reset +500, +400
	if u["a"].DownBytes != 3900 || u["a"].UpBytes != 39 {
		t.Errorf("a: %+v", u["a"])
	}
	// b connected inside the window: all of its 1300 counts
	if u["b"].DownBytes != 1300 || u["b"].UpBytes != 13 {
		t.Errorf("b: %+v", u["b"])
	}
}

func TestUsageSinceFreshInstall(t *testing.T) {
	st, _ := store.OpenPath(":memory:")
	tr := &Traffic{DB: st.DB}
	u, err := tr.UsageSince(context.Background(), time.Now().Add(-time.Hour),
		[]inventory.ClientTraffic{{MAC: "a", DownBytes: 1 << 30}})
	if err != nil {
		t.Fatal(err)
	}
	if u["a"].DownBytes != 0 {
		t.Errorf("with no history, counters since connect must not be read as last-hour usage: %+v", u["a"])
	}
}
