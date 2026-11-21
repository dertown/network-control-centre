package smarthome

import (
	"strings"
	"testing"
)

func TestParsePairingCode(t *testing.T) {
	// The Matter SDK's example device: passcode 20202021, discriminator 3840.
	pc, err := ParsePairingCode("3497-011-2332")
	if err != nil {
		t.Fatal(err)
	}
	if pc.Code != "34970112332" || pc.Kind != "manual" || pc.Discriminator != 15 || pc.VendorPresent {
		t.Fatalf("got %+v", pc)
	}
	if strings.Contains(pc.Formatted, "2332") {
		t.Fatalf("formatted code should hide the passcode digits: %s", pc.Formatted)
	}
	if _, err := ParsePairingCode("3497 011 2332"); err != nil {
		t.Fatalf("spaces: %v", err)
	}
	if _, err := ParsePairingCode("3497-011-2333"); err == nil || !strings.Contains(err.Error(), "typo") {
		t.Fatalf("bad check digit accepted: %v", err)
	}
	for _, bad := range []string{"", "1234", "abcd-efg-hijk", "MT:", "MT:lower!case"} {
		if _, err := ParsePairingCode(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	// a forbidden passcode (12345678) with a correct check digit
	chunk2 := 12345678 & 0x3FFF
	chunk3 := 12345678 >> 14
	d := "0" + pad(chunk2, 5) + pad(chunk3, 4)
	d += string(VerhoeffDigit(d))
	if _, err := ParsePairingCode(d); err == nil {
		t.Fatalf("forbidden passcode accepted: %s", d)
	}
	// 21-digit codes carry vendor and product ids
	long := "4" + "49701" + "1233" + "65521" + "32769"
	long += string(VerhoeffDigit(long))
	if pc, err := ParsePairingCode(long); err != nil || !pc.VendorPresent {
		t.Fatalf("long code: %+v %v", pc, err)
	}
	if pc, err := ParsePairingCode("MT:Y.K9042C00KA0648G00"); err != nil || pc.Kind != "qr" {
		t.Fatalf("qr: %+v %v", pc, err)
	}
}

func pad(n, w int) string {
	s := strings.Repeat("0", w) + itoa(n)
	return s[len(s)-w:]
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestPlan(t *testing.T) {
	inv := &Inventory{
		Devices: []Device{{ID: "d1", Name: "Lock", Area: "hall"}, {ID: "d2", Name: "Sensor"}},
		Entities: []Entity{
			{ID: "light.k", Domain: "light", Name: "Kitchen", State: "on", Dimmable: true},
			{ID: "lock.front", Domain: "lock", Name: "Front door", State: "locked", Device: "d1"},
			{ID: "cover.garage", Domain: "cover", Name: "Garage", State: "closed", DeviceClass: "garage"},
			{ID: "cover.blind", Domain: "cover", Name: "Blind", State: "closed", DeviceClass: "blind"},
			{ID: "climate.t", Domain: "climate", Name: "Thermostat", State: "heat", MinTemp: 9, MaxTemp: 32, HVACModes: []string{"off", "heat"}},
			{ID: "switch.off", Domain: "switch", Name: "Offline", State: "unavailable", Device: "d2"},
			{ID: "sensor.b", Domain: "sensor", Name: "Sensor battery", State: "7", DeviceClass: "battery", Device: "d2"},
		},
	}
	inv.Finish()
	v := func(f float64) *float64 { return &f }

	if c, _, err := Plan(inv.Entity("light.k"), Command{Action: ActBrightness, Value: v(40)}); err != nil || c.Service != "turn_on" || c.Data["brightness_pct"] != 40 {
		t.Fatalf("brightness: %+v %v", c, err)
	}
	if c, _, _ := Plan(inv.Entity("light.k"), Command{Action: ActBrightness, Value: v(0)}); c.Service != "turn_off" {
		t.Fatalf("brightness 0 should turn off: %+v", c)
	}
	if _, _, err := Plan(inv.Entity("light.k"), Command{Action: ActBrightness, Value: v(140)}); err == nil {
		t.Fatal("brightness 140 accepted")
	}
	if _, _, err := Plan(inv.Entity("light.k"), Command{Action: ActUnlock}); err == nil {
		t.Fatal("unlock on a light accepted")
	}
	if _, _, err := Plan(inv.Entity("climate.t"), Command{Action: ActSetTemp, Value: v(50)}); err == nil {
		t.Fatal("50 degrees accepted")
	}
	if _, _, err := Plan(inv.Entity("climate.t"), Command{Action: ActSetMode, Mode: "dry"}); err == nil {
		t.Fatal("unknown hvac mode accepted")
	}
	if c, _, err := Plan(inv.Entity("climate.t"), Command{Action: ActSetTemp, Value: v(21.5)}); err != nil || c.Data["temperature"] != 21.5 {
		t.Fatalf("temp: %+v %v", c, err)
	}
	if _, _, err := Plan(inv.Entity("switch.off"), Command{Action: ActOn}); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("offline device: %v", err)
	}
	if !Sensitive(inv.Entity("lock.front"), ActUnlock) || Sensitive(inv.Entity("lock.front"), ActLock) {
		t.Fatal("unlocking is sensitive, locking isn't")
	}
	if !Sensitive(inv.Entity("cover.garage"), ActOpen) || Sensitive(inv.Entity("cover.blind"), ActOpen) {
		t.Fatal("opening a garage is sensitive, a blind isn't")
	}
	if inv.Entity("lock.front").Area != "hall" {
		t.Fatal("entity should take its device's area")
	}
	if len(inv.Alerts) != 1 || inv.Alerts[0].Level != "critical" || inv.Alerts[0].Subject != "Sensor" {
		t.Fatalf("alerts: %+v", inv.Alerts)
	}
}
