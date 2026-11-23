package core

import (
	"strings"
	"testing"

	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/inventory"
)

// apSnap: AP 1 (2.4 GHz ch 6 at 40 MHz, busy; 5 GHz ch 36), AP 2 (2.4 ch 11, 5 ch 36), and
// Shed AP meshed over 5 GHz through AP 1. Neighbours crowd 2.4 GHz channel 6.
func apSnap() *inventory.Snapshot {
	return &inventory.Snapshot{Target: "udr",
		Devices: []inventory.Device{{ID: "ap1", Name: "AP 1"}, {ID: "ap2", Name: "AP 2"}, {ID: "shed", Name: "Shed AP"}},
		Links:   []inventory.Link{{A: "ap1", B: "shed", Medium: "wireless"}},
		Clients: []inventory.Client{
			{MAC: "1", Name: "laptop", IP: "192.168.1.10", APMAC: "ap1", Band: "5", SSID: "Home"},
			{MAC: "2", Name: "plug", IP: "192.168.30.5", APMAC: "ap1", Band: "2.4", SSID: "IoT"},
			{MAC: "3", Name: "phone", IP: "192.168.1.11", APMAC: "ap2", Band: "5", SSID: "Home"},
		},
		WiFi: &inventory.WiFi{
			SSIDs: []inventory.SSID{
				{ID: "home", Name: "Home", Enabled: true, Security: inventory.SecWPA2WPA3, Bands: []string{"2.4", "5"}},
				{ID: "iot", Name: "IoT", Enabled: true, Security: inventory.SecWPA2, Bands: []string{"2.4"}},
			},
			Radios: []inventory.Radio{
				{DeviceID: "ap1", DeviceName: "AP 1", Online: true, Band: "2.4", Channel: 6, WidthMHz: 40, Utilization: 75, Clients: 1},
				{DeviceID: "ap1", DeviceName: "AP 1", Online: true, Band: "5", Channel: 36, WidthMHz: 80, Clients: 1},
				{DeviceID: "ap2", DeviceName: "AP 2", Online: true, Band: "2.4", Channel: 11, WidthMHz: 20, Utilization: 20},
				{DeviceID: "ap2", DeviceName: "AP 2", Online: true, Band: "5", Channel: 36, WidthMHz: 80, Clients: 1},
				{DeviceID: "shed", DeviceName: "Shed AP", Online: true, Band: "5", Channel: 36, ChannelAuto: true, WidthMHz: 80},
			},
			Neighbors: []inventory.Neighbor{
				{BSSID: "n1", Band: "2.4", Channel: 6, Signal: -55, SeenBy: "ap1"},
				{BSSID: "n2", Band: "2.4", Channel: 6, Signal: -62, SeenBy: "ap1"},
				{BSSID: "n3", Band: "2.4", Channel: 1, Signal: -85, SeenBy: "ap1"},
				{BSSID: "n4", Band: "5", Channel: 149, Signal: -50, SeenBy: "ap1"},
			},
		},
	}
}

func TestCheckChannel(t *testing.T) {
	for _, c := range []struct {
		band      string
		ch, width int
		ok        bool
	}{
		{"2.4", 6, 20, true}, {"2.4", 0, 20, true}, {"2.4", 14, 20, false}, {"2.4", 6, 80, false},
		{"5", 36, 160, true}, {"5", 149, 160, false}, {"5", 165, 40, false}, {"5", 165, 20, true}, {"5", 37, 20, false},
		{"6", 37, 320, true}, {"6", 2, 20, false}, {"7", 1, 20, false},
	} {
		if err := CheckChannel(c.band, c.ch, c.width); (err == nil) != c.ok {
			t.Errorf("%s GHz ch %d %d MHz: %v", c.band, c.ch, c.width, err)
		}
	}
}

func TestSuggestChannel(t *testing.T) {
	snap := apSnap()
	s, err := SuggestChannel(snap, "ap1", "2.4")
	if err != nil {
		t.Fatal(err)
	}
	// 6 is crowded by neighbours, 11 is AP 2's: 1 is the quiet one
	if s.Channel != 1 || !s.Better || s.WidthMHz != 20 || !strings.Contains(s.Reason, "Channel 1") {
		t.Errorf("2.4: %+v", s)
	}
	s, _ = SuggestChannel(snap, "ap1", "5")
	// 36 is shared with AP 2 (and Shed), 149 has a loud neighbour, 52 is DFS: 100 wins
	if s.Channel == 36 || !s.Better || s.Options[0].Channel != s.Channel {
		t.Errorf("5: %+v", s)
	}
	// AP 1's 40 MHz channel 6 reaches up into 11, so AP 2 is better off on 1 too
	s, _ = SuggestChannel(snap, "ap2", "2.4")
	if !s.Better || s.Channel != 1 || !strings.Contains(s.Reason, "shared with AP 1") {
		t.Errorf("ap2: %+v", s)
	}
	// once AP 1 is on 1 at 20 MHz, 11 is quiet for AP 2
	snap.WiFi.Radios[0].Channel, snap.WiFi.Radios[0].WidthMHz = 1, 20
	s, _ = SuggestChannel(snap, "ap2", "2.4")
	if s.Better || s.Channel != 11 {
		t.Errorf("ap2 after: %+v", s)
	}
	snap = apSnap()
	all := ChannelSuggestions(snap)
	if len(all) != 5 {
		t.Fatalf("suggestions: %d", len(all))
	}
	// worked out together: AP 1 (busiest) moves to 1, so AP 2 stays on 11
	for _, s := range all {
		if s.Band == "2.4" && s.DeviceID == "ap1" && s.Channel != 1 {
			t.Errorf("ap1 together: %+v", s)
		}
		if s.Band == "2.4" && s.DeviceID == "ap2" && (s.Better || s.Channel != 11) {
			t.Errorf("ap2 together: %+v", s)
		}
	}
	if s, _ := SuggestChannel(snap, "shed", "5"); s.Better || !strings.Contains(s.Reason, "mesh") {
		t.Errorf("mesh child suggested a move: %+v", s)
	}
	// and the two 5 GHz radios on 36 are not both sent to the same channel
	five := map[int]int{}
	for _, s := range all {
		if s.Band == "5" && s.DeviceID != "shed" {
			five[s.Channel]++
		}
	}
	for ch, n := range five {
		if n > 1 {
			t.Errorf("5 GHz: %d radios on %d: %+v", n, ch, all)
		}
	}
}

func ip(n int) *int       { return &n }
func sp(s string) *string { return &s }

func TestPlanAPChange(t *testing.T) {
	snap := apSnap()
	// fixing the channel issue on AP 1's 2.4 GHz radio
	p, err := PlanAPChange(snap, "ap1", APRequest{Radios: []drivers.RadioSetting{{Band: "2.4", Channel: ip(1), WidthMHz: ip(20)}}}, Safety{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Changes) != 2 || len(p.Change.Radios) != 1 || *p.Change.Radios[0].Channel != 1 {
		t.Errorf("changes: %+v", p)
	}
	kinds := map[string]bool{}
	for _, f := range p.Resolves {
		kinds[f.Kind] = true
	}
	if !kinds["width-2g"] || !kinds["busy"] {
		t.Errorf("resolves: %+v", p.Resolves)
	}
	if !strings.Contains(strings.Join(p.Warnings, " "), "drop for a few seconds") {
		t.Errorf("no client warning: %v", p.Warnings)
	}

	// mesh parent: changing 5 GHz warns about Shed AP
	p, err = PlanAPChange(snap, "ap1", APRequest{Radios: []drivers.RadioSetting{{Band: "5", Channel: ip(100)}}}, Safety{})
	if err != nil || !strings.Contains(strings.Join(p.Warnings, " "), "Shed AP") || !strings.Contains(strings.Join(p.Warnings, " "), "DFS") {
		t.Errorf("mesh parent: %v %+v", err, p)
	}
	// mesh child: a fixed channel other than its parent's is refused; auto or the parent's is fine
	if _, err := PlanAPChange(snap, "shed", APRequest{Radios: []drivers.RadioSetting{{Band: "5", Channel: ip(149)}}}, Safety{}); err == nil || !strings.Contains(err.Error(), "mesh") {
		t.Errorf("mesh child moved: %v", err)
	}
	if _, err := PlanAPChange(snap, "shed", APRequest{Radios: []drivers.RadioSetting{{Band: "5", Channel: ip(36)}}}, Safety{}); err != nil {
		t.Errorf("mesh child on parent channel: %v", err)
	}
	// switching 5 GHz off on the mesh parent is refused
	if _, err := PlanAPChange(snap, "ap1", APRequest{SSIDs: []APSSIDToggle{{SSIDID: "home", Band: "5", On: false}}}, Safety{}); err == nil || !strings.Contains(err.Error(), "mesh") {
		t.Errorf("mesh band off: %v", err)
	}

	// the person's own laptop on AP 1: switching everything off there is refused
	if _, err := PlanAPChange(snap, "ap2", APRequest{SSIDs: []APSSIDToggle{{"home", "2.4", false}, {"iot", "2.4", false}, {"home", "5", false}}}, Safety{ViewerIP: "192.168.1.11"}); err == nil || !strings.Contains(err.Error(), "your own connection") {
		t.Errorf("own connection cut: %v", err)
	}
	// NCC on AP 2 at 5 GHz: turning off 2.4 there only is fine
	p, err = PlanAPChange(snap, "ap2", APRequest{SSIDs: []APSSIDToggle{{"home", "2.4", false}, {"iot", "2.4", false}}}, Safety{SelfIPs: []string{"192.168.1.11"}})
	if err != nil {
		t.Fatalf("2.4 off: %v", err)
	}
	if got := p.Change.SSIDsOff["2.4"]; len(got) != 2 || p.Changes[len(p.Changes)-1].Setting != "2.4 GHz radio" {
		t.Errorf("2.4 off: %+v", p)
	}
	// Home on AP 2 at 5 GHz off while NCC is on it: Home is still on AP 1 (5 GHz), so it's a warning
	p, err = PlanAPChange(snap, "ap2", APRequest{SSIDs: []APSSIDToggle{{"home", "5", false}}}, Safety{SelfIPs: []string{"192.168.1.11"}})
	if err != nil || !strings.Contains(strings.Join(p.Warnings, " "), "NCC's own connection") {
		t.Errorf("rejoin elsewhere: %v %+v", err, p)
	}

	// switching the IoT network off on 2.4 warns about 2.4-only devices
	p, err = PlanAPChange(snap, "ap1", APRequest{SSIDs: []APSSIDToggle{{"iot", "2.4", false}}}, Safety{})
	if err != nil || !strings.Contains(strings.Join(p.Warnings, " "), "only have 2.4 GHz") {
		t.Errorf("iot off: %v %+v", err, p)
	}
	// a network that doesn't use a band can't be switched on there
	if _, err := PlanAPChange(snap, "ap1", APRequest{SSIDs: []APSSIDToggle{{"iot", "5", true}}}, Safety{}); err == nil {
		t.Error("iot on 5 GHz")
	}

	// bad values
	for _, rs := range []drivers.RadioSetting{
		{Band: "2.4", Channel: ip(14)}, {Band: "5", WidthMHz: ip(320)}, {Band: "6"},
		{Band: "5", TxPowerMode: sp("custom")}, {Band: "5", TxPowerMode: sp("max")},
	} {
		if _, err := PlanAPChange(snap, "ap1", APRequest{Radios: []drivers.RadioSetting{rs}}, Safety{}); err == nil {
			t.Errorf("allowed: %+v", rs)
		}
	}
	if _, err := PlanAPChange(snap, "ap1", APRequest{Radios: []drivers.RadioSetting{{Band: "5", Channel: ip(36)}}}, Safety{}); err == nil || err.Error() != "nothing to change" {
		t.Errorf("no-op: %v", err)
	}
	p, err = PlanAPChange(snap, "ap1", APRequest{Radios: []drivers.RadioSetting{{Band: "5", TxPowerMode: sp("custom"), TxPower: ip(10)}}}, Safety{})
	if err != nil || p.Changes[0].To != "10 dBm" || !strings.Contains(strings.Join(p.Warnings, " "), "shrinks") {
		t.Errorf("power: %v %+v", err, p)
	}
}

func TestPlanWiFiBands(t *testing.T) {
	snap := apSnap()
	ch := &drivers.WLANChange{Bands: []string{"5", "2.4", "6"}}
	p, err := PlanWiFiChange(snap, "home", ch)
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(p.Warnings, " ")
	if p.Changes[0].To != "2.4, 5, 6 GHz" || !strings.Contains(w, "WPA3") || !strings.Contains(w, "6 GHz radio") {
		t.Errorf("bands: %+v", p)
	}
	if _, err := PlanWiFiChange(snap, "iot", &drivers.WLANChange{Bands: []string{"2.4", "6"}}); err == nil {
		t.Error("6 GHz on WPA2")
	}
	if _, err := PlanWiFiChange(snap, "iot", &drivers.WLANChange{Bands: []string{}}); err == nil {
		t.Error("no bands")
	}
	p, err = PlanWiFiChange(snap, "home", &drivers.WLANChange{Bands: []string{"5"}})
	if err != nil || !strings.Contains(strings.Join(p.Warnings, " "), "must move to 5 GHz") {
		// nobody is on Home at 2.4 GHz in this snapshot, so no warning is fine too
		if err != nil {
			t.Error(err)
		}
	}
}
