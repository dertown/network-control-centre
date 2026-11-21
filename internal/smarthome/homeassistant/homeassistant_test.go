package homeassistant

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dertown/network-control-centre/internal/mocklab"
	"github.com/dertown/network-control-centre/internal/smarthome"
)

func TestHomeAssistant(t *testing.T) {
	srv := httptest.NewServer(mocklab.HomeAssistant("tok"))
	defer srv.Close()
	ctx := context.Background()
	tgt := smarthome.Target{Name: "ha", Kind: "homeassistant", Address: srv.URL, Options: map[string]string{}}
	creds := map[string]string{"token": "tok"}
	p := Provider{}

	if _, err := p.Collect(ctx, tgt, map[string]string{"token": "wrong"}); err != ErrUnauthorized {
		t.Fatalf("wrong token: %v", err)
	}
	res, err := p.Collect(ctx, tgt, creds)
	if err != nil {
		t.Fatal(err)
	}
	inv := res.Inventory
	if !inv.Hub.Matter || !inv.Hub.Nest || inv.Hub.Version != "2026.11.2" || len(inv.Areas) != 6 {
		t.Fatalf("hub: %+v areas %d", inv.Hub, len(inv.Areas))
	}
	for _, e := range inv.Entities {
		switch {
		case e.Domain == "automation" || e.Domain == "sun" || e.Domain == "update":
			t.Fatalf("%s should be left out", e.ID)
		case strings.HasSuffix(e.ID, "_signal"):
			t.Fatalf("diagnostic sensor %s should be left out", e.ID)
		}
	}
	for _, d := range inv.Devices {
		if d.Name == "Home Assistant Core" {
			t.Fatal("service devices should be left out")
		}
	}
	lamp := inv.Entity("light.living_room_lamp")
	if lamp == nil || lamp.Area != "living_room" || lamp.Source != "Matter" || lamp.Brightness == nil || *lamp.Brightness != 70 || !lamp.Dimmable {
		t.Fatalf("lamp: %+v", lamp)
	}
	if th := inv.Entity("climate.thermostat"); th == nil || th.Source != "Google Nest" || *th.TargetTemp != 21 || len(th.HVACModes) != 4 {
		t.Fatalf("thermostat: %+v", th)
	}
	if l := inv.Entity("lock.front_door"); l == nil || l.Battery == nil || *l.Battery != 64 {
		t.Fatalf("lock battery: %+v", l)
	}
	var offline, lowBatt bool
	for _, a := range inv.Alerts {
		offline = offline || a.Subject == "Outdoor plug"
		lowBatt = lowBatt || (a.Subject == "Bedroom sensor" && a.Level == "critical")
	}
	if !offline || !lowBatt {
		t.Fatalf("alerts: %+v", inv.Alerts)
	}

	call, _, err := smarthome.Plan(inv.Entity("switch.coffee_machine_plug"), smarthome.Command{Action: smarthome.ActToggle})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := p.Call(ctx, tgt, creds, call)
	if err != nil || len(changed) != 1 || changed[0].State != "on" {
		t.Fatalf("toggle: %+v %v", changed, err)
	}
	if _, err := p.Call(ctx, tgt, creds, smarthome.Call{Domain: "switch", Service: "turn_on", Data: map[string]any{"entity_id": "switch.nope"}}); err == nil {
		t.Fatal("unknown entity accepted")
	}

	if err := p.PairMatter(ctx, tgt, creds, "00000000000", true); err == nil || !strings.Contains(err.Error(), "new one") {
		t.Fatalf("failed pairing: %v", err)
	}
	if err := p.PairMatter(ctx, tgt, creds, "34970112332", true); err != nil {
		t.Fatal(err)
	}
	res, _ = p.Collect(ctx, tgt, creds)
	if res.Inventory.Entity("switch.smart_plug_1") == nil {
		t.Fatal("paired plug missing")
	}
}
