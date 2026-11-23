package unifi

import (
	"testing"

	"github.com/dertown/network-control-centre/internal/drivers"
	inv "github.com/dertown/network-control-centre/internal/inventory"
)

func TestWLANSecurity(t *testing.T) {
	for _, c := range []struct {
		w    rawWLAN
		want string
	}{
		{rawWLAN{Security: "open"}, inv.SecOpen},
		{rawWLAN{Security: "wep"}, inv.SecWEP},
		{rawWLAN{Security: "wpaeap"}, inv.SecEnterprise},
		{rawWLAN{Security: "wpapsk", WPAMode: "wpa1"}, inv.SecWPA1},
		{rawWLAN{Security: "wpapsk", WPAMode: "auto"}, inv.SecWPA1WPA2},
		{rawWLAN{Security: "wpapsk", WPAMode: "wpa2"}, inv.SecWPA2},
		{rawWLAN{Security: "wpapsk", WPAMode: "wpa2", WPA3Support: true, WPA3Transition: true}, inv.SecWPA2WPA3},
		{rawWLAN{Security: "wpapsk", WPAMode: "wpa2", WPA3Support: true}, inv.SecWPA3},
	} {
		if got := wlanSecurity(c.w); got != c.want {
			t.Errorf("%+v: %s, want %s", c.w, got, c.want)
		}
	}
}

func TestApplyWLANChange(t *testing.T) {
	str := func(s string) *string { return &s }
	w := map[string]any{"name": "Old", "security": "open", "x_other": 1}
	if err := applyWLANChange(w, drivers.WLANChange{Passphrase: str("long enough")}); err == nil {
		t.Error("passphrase on an open network")
	}
	w = map[string]any{"name": "Old", "security": "open", "x_other": 1}
	if err := applyWLANChange(w, drivers.WLANChange{Security: str(inv.SecWPA3), Passphrase: str("long enough")}); err != nil {
		t.Fatal(err)
	}
	if w["security"] != "wpapsk" || w["wpa3_support"] != true || w["wpa3_transition"] != false || w["pmf_mode"] != "required" ||
		w["x_passphrase"] != "long enough" || w["x_other"] != 1 {
		t.Errorf("wpa3: %v", w)
	}
	w = map[string]any{"name": "Corp", "security": "wpaeap"}
	if err := applyWLANChange(w, drivers.WLANChange{Security: str(inv.SecWPA2)}); err == nil {
		t.Error("enterprise changed")
	}
	w = map[string]any{"name": "Iot", "security": "wpapsk", "x_passphrase": "12345678", "vlan": 30, "vlan_enabled": true}
	if err := applyWLANChange(w, drivers.WLANChange{NetworkID: str("net_iot")}); err != nil || w["networkconf_id"] != "net_iot" || w["vlan_enabled"] != nil {
		t.Errorf("network: %v %v", err, w)
	}
}

func TestApplyAPChange(t *testing.T) {
	n := func(v int) *int { return &v }
	s := func(v string) *string { return &v }
	dev := map[string]any{"name": "Lounge AP",
		"radio_table": []any{
			map[string]any{"name": "wifi0", "radio": "ng", "channel": 6, "ht": "40", "tx_power_mode": "high", "min_rssi_enabled": true},
			map[string]any{"name": "wifi1", "radio": "na", "channel": "auto", "ht": "80", "tx_power_mode": "auto"},
		},
		"wlan_overrides": []any{
			map[string]any{"wlan_id": "wl_home", "radio": "na", "radio_name": "wifi1", "enabled": false},
			map[string]any{"wlan_id": "wl_iot", "radio": "ng", "radio_name": "wifi0", "name": "IoT-Lounge"},
		},
	}
	body, err := applyAPChange(dev, drivers.APChange{
		Radios:   []drivers.RadioSetting{{Band: "2.4", Channel: n(1), WidthMHz: n(20)}, {Band: "5", TxPowerMode: s("custom"), TxPower: n(14)}},
		SSIDsOff: map[string][]string{"5": {}, "2.4": {"wl_guest"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rt := body["radio_table"].([]any)
	r0, r1 := rt[0].(map[string]any), rt[1].(map[string]any)
	if r0["channel"] != 1 || r0["ht"] != 20 || r0["min_rssi_enabled"] != true || r0["tx_power_mode"] != "high" {
		t.Errorf("2.4: %v", r0)
	}
	if r1["tx_power_mode"] != "custom" || r1["tx_power"] != 14 || r1["channel"] != "auto" {
		t.Errorf("5: %v", r1)
	}
	// the device itself is not changed
	if dev["radio_table"].([]any)[0].(map[string]any)["channel"] != 6 {
		t.Error("device changed in place")
	}
	ov := body["wlan_overrides"].([]any)
	if len(ov) != 3 {
		t.Fatalf("overrides: %v", ov)
	}
	home, iot, guest := ov[0].(map[string]any), ov[1].(map[string]any), ov[2].(map[string]any)
	if home["enabled"] != true || iot["name"] != "IoT-Lounge" || iot["enabled"] != true {
		t.Errorf("kept overrides: %v %v", home, iot)
	}
	if guest["wlan_id"] != "wl_guest" || guest["radio"] != "ng" || guest["radio_name"] != "wifi0" || guest["enabled"] != false {
		t.Errorf("new override: %v", guest)
	}
	if _, err := applyAPChange(dev, drivers.APChange{Radios: []drivers.RadioSetting{{Band: "6", Channel: n(37)}}}); err == nil {
		t.Error("no 6 GHz radio")
	}
	auto, _ := applyAPChange(dev, drivers.APChange{Radios: []drivers.RadioSetting{{Band: "2.4", Channel: n(0)}}})
	if auto["radio_table"].([]any)[0].(map[string]any)["channel"] != "auto" || auto["wlan_overrides"] != nil {
		t.Errorf("auto: %v", auto)
	}
}

func TestWLANBandsChange(t *testing.T) {
	w := map[string]any{"name": "Home", "security": "wpapsk", "x_passphrase": "long enough", "wlan_band": "both"}
	if err := applyWLANChange(w, drivers.WLANChange{Bands: []string{"5", "6"}}); err != nil {
		t.Fatal(err)
	}
	if b := w["wlan_bands"].([]string); len(b) != 2 || b[0] != "5g" || b[1] != "6g" || w["wlan_band"] != "5g" {
		t.Errorf("bands: %v", w)
	}
	if err := applyWLANChange(w, drivers.WLANChange{Bands: []string{}}); err == nil {
		t.Error("no bands")
	}
}
