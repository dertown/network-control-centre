package iot

import "testing"

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		vendor, name, want string
	}{
		{"Brother", "Printer", TypePrinter},
		{"Samsung", "tv", TypeDisplay},
		{"Samsung", "lobby-display", TypeDisplay},
		{"Apple", "phone", ""},
		{"Apple", "laptop", ""},
		{"Google", "thermostat", TypeBuilding},
		{"Espressif Inc.", "kitchen-plug", TypePower},
		{"Ring LLC", "doorbell", TypeCamera},
		{"Dell", "desk-pc", ""},
		{"Synology", "nas", ""},
		{"Synology", "backups-nas", ""},
		{"Lenovo", "guest-laptop", ""},
		{"Sonos, Inc.", "lounge-speaker", TypeSpeaker},
		{"Signify Netherlands B.V.", "Hall lights", TypeLighting},
		{"Reolink Innovation", "garage-cam", TypeCamera},
		{"Axis Communications AB", "", TypeCamera},
		{"HP Inc.", "hp-printer-2f", TypePrinter},
		{"HP Inc.", "DESKTOP-4KQ2", ""},
		{"Polycom", "phone-reception", TypePhone},
		{"Crestron Electronics", "boardroom-cp4", TypeConference},
		{"BrightSign LLC", "lobby-signage", TypeDisplay},
		{"HID Global", "door-main-entrance", TypeAccess},
		{"American Power Conversion", "ups-server-room", TypePower},
		{"Tridium Inc", "bms-jace-01", TypeBuilding},
		{"Airthings ASA", "airq-3f-east", TypeSensor},
		{"", "zoom-room-4", TypeConference},
		{"", "printer2f", TypePrinter},
		{"Cisco Systems", "SEP001122334455", ""},
		{"", "ups-server-room", TypePower},
		{"", "server-room-sw", ""},
	} {
		got, ok := Classify(c.vendor, c.name)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("Classify(%q, %q) = %q, %v; want %q", c.vendor, c.name, got, ok, c.want)
		}
	}
}

func TestIsIoTNetwork(t *testing.T) {
	for name, want := range map[string]bool{"IoT": true, "iot-devices": true, "Cameras": true, "BMS": true, "Building systems": true,
		"OT": true, "Default": false, "Guest": false, "DMZ": false, "Hotspot": false, "Corporate": false} {
		if IsIoTNetwork(name) != want {
			t.Errorf("IsIoTNetwork(%q) != %v", name, want)
		}
	}
}

func TestNormMAC(t *testing.T) {
	for in, want := range map[string]string{"AA:BB:CC:DD:EE:FF": "aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff": "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff": "aa:bb:cc:dd:ee:ff", "aabbccddeeff": "aa:bb:cc:dd:ee:ff", "nope": "", "zz:bb:cc:dd:ee:ff": ""} {
		if got := NormMAC(in); got != want {
			t.Errorf("NormMAC(%q) = %q, want %q", in, got, want)
		}
	}
}
