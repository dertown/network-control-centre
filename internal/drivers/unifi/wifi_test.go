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
