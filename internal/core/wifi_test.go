package core

import (
	"strings"
	"testing"

	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/inventory"
)

func wifiSnap() *inventory.Snapshot {
	return &inventory.Snapshot{Target: "udr", Networks: []inventory.Network{
		{ID: "lan", Name: "Default"}, {ID: "iot", Name: "IoT", VLAN: 30, Isolated: true}, {ID: "guest", Name: "Guest", VLAN: 20, Purpose: "guest"},
		{ID: "wan", Name: "WAN", Purpose: "wan"},
	}, WiFi: &inventory.WiFi{
		SSIDs: []inventory.SSID{
			{ID: "a", Name: "Home", Enabled: true, Security: inventory.SecWPA2, NetworkID: "lan", Clients: 3, Target: "udr"},
			{ID: "b", Name: "Cafe Guest", Enabled: true, Security: inventory.SecOpen, NetworkID: "lan", Target: "udr"},
			{ID: "c", Name: "Old", Enabled: false, Security: inventory.SecWEP, NetworkID: "lan", Target: "udr"},
			{ID: "d", Name: "Smart", Enabled: true, Security: inventory.SecWPA2, NetworkID: "iot", Target: "udr"},
		},
		Radios: []inventory.Radio{
			{DeviceID: "ap1", DeviceName: "AP 1", Online: true, Band: "2.4", Channel: 4, WidthMHz: 40},
			{DeviceID: "ap2", DeviceName: "AP 2", Online: true, Band: "5", Channel: 36, Utilization: 80},
			{DeviceID: "ap3", DeviceName: "AP 3", Online: true, Band: "5", Channel: 36},
			{DeviceID: "ap4", DeviceName: "AP 4", Online: false, Band: "2.4", Channel: 3},
		},
	}}
}

func TestWiFiFindings(t *testing.T) {
	var got []string
	for _, f := range WiFiFindings(wifiSnap()) {
		got = append(got, f.Severity+" "+f.SSID+f.Device+" "+f.Kind)
	}
	want := []string{
		"critical Cafe Guest open", // not marked guest, so treated as a private network
		"warning Cafe Guest guest-lan",
		"warning AP 1 width-2g",
		"warning AP 1 channel-2g",
		"warning AP 2 busy",
		"info AP 2, AP 3 same-channel",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestPlanWiFiChange(t *testing.T) {
	str := func(s string) *string { return &s }
	snap := wifiSnap()
	// open -> WPA2 needs a passphrase
	if _, err := PlanWiFiChange(snap, "b", &drivers.WLANChange{Security: str(inventory.SecWPA2)}); err == nil {
		t.Error("open to WPA2 without a passphrase allowed")
	}
	p, err := PlanWiFiChange(snap, "b", &drivers.WLANChange{Security: str(inventory.SecWPA2), Passphrase: str("a long guest passphrase"), NetworkID: str("guest")})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Changes) != 3 || len(p.Resolves) != 2 || len(p.Remaining) != 0 {
		t.Errorf("plan: %+v", p)
	}
	// unchanged fields are dropped; nothing left is an error
	if _, err := PlanWiFiChange(snap, "a", &drivers.WLANChange{Name: str(" Home "), NetworkID: str("lan")}); err == nil || err.Error() != "nothing to change" {
		t.Errorf("no-op: %v", err)
	}
	for _, ch := range []*drivers.WLANChange{
		{Name: str("Smart")},                       // duplicate name
		{NetworkID: str("wan")},                    // WAN
		{Security: str(inventory.SecWEP)},          // weak
		{Passphrase: str("pässwörd-unicode")},      // not ASCII
		{Passphrase: str(strings.Repeat("x", 64))}, // too long
	} {
		if _, err := PlanWiFiChange(snap, "a", ch); err == nil {
			t.Errorf("allowed: %+v", ch)
		}
	}
	p, _ = PlanWiFiChange(snap, "a", &drivers.WLANChange{Name: str("Home 2"), Security: str(inventory.SecWPA3)})
	if len(p.Warnings) != 3 { // rename, WPA3-only devices, reconnect
		t.Errorf("warnings: %v", p.Warnings)
	}
}
