package storage

import "testing"

func TestParseSize(t *testing.T) {
	if got := ParseSize("3.64 TB"); got < 4_002_000_000_000 || got > 4_003_000_000_000 {
		t.Errorf("3.64 TB = %d", got)
	}
	for in, want := range map[string]int64{"512 MB": 512 << 20,
		"1,024 KB": 1 << 20, "12345": 12345, "": 0, "2 TiB": 2 << 40, "-- ": 0} {
		if got := ParseSize(in); got != want {
			t.Errorf("ParseSize(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestHealthWord(t *testing.T) {
	for in, want := range map[string]string{"Good": HealthGood, "Ready": HealthGood, "normal": HealthGood, "Warning": HealthWarning,
		"Degraded": HealthWarning, "RAID syncing": HealthWarning, "crashed": HealthCritical, "Abnormal": HealthCritical, "": HealthUnknown, "zzz": HealthUnknown} {
		if got := HealthWord(in); got != want {
			t.Errorf("HealthWord(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestNatLess(t *testing.T) {
	if !natLess("Disk 2", "Disk 10") || natLess("Disk 10", "Disk 2") || !natLess("Disk 1", "Drive 1") {
		t.Fatal("natural order wrong")
	}
}

func TestFinishAlerts(t *testing.T) {
	inv := &Inventory{
		System:    System{TempC: 62, Fans: []Fan{{Name: "Fan 1", OK: false}}, Update: "5.2.2"},
		Disks:     []Disk{{Slot: "Disk 10", Health: HealthGood, TempC: 55}, {Slot: "Disk 2", Health: HealthCritical, SMART: "Abnormal"}, {Slot: "Disk 1", Type: "ssd", TempC: 55, Health: HealthGood}},
		Volumes:   []Volume{{Name: "DataVol1", Health: HealthGood, Total: 100, Used: 96}, {Name: "Backup", Health: HealthWarning, Status: "Degraded", Total: 100, Used: 10}},
		Shares:    []Share{{Name: "photo"}},
		Snapshots: []Snapshot{{Share: "photo"}, {Share: "photo"}},
	}
	inv.Finish()
	if inv.System.Health != HealthCritical {
		t.Fatalf("health %s", inv.System.Health)
	}
	if inv.Disks[0].Slot != "Disk 1" || inv.Disks[2].Slot != "Disk 10" {
		t.Fatalf("disk order %v", inv.Disks)
	}
	if inv.Shares[0].Snapshots != 2 {
		t.Fatalf("snapshot count %d", inv.Shares[0].Snapshots)
	}
	want := map[string]string{"Disk 2": HealthCritical, "Disk 10": HealthWarning, "DataVol1": HealthCritical, "Backup": HealthWarning,
		"System": HealthWarning, "Fan 1": HealthCritical, "Firmware": HealthWarning}
	got := map[string]string{}
	for _, a := range inv.Alerts {
		if got[a.Subject] == "" || rank(a.Level) > rank(got[a.Subject]) {
			got[a.Subject] = a.Level
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("alert for %s = %q, want %q (all: %+v)", k, got[k], v, inv.Alerts)
		}
	}
	if _, ok := got["Disk 1"]; ok {
		t.Errorf("a 55 °C SSD should not alert")
	}
	if inv.Alerts[0].Level != HealthCritical {
		t.Errorf("critical alerts first")
	}
}

func TestValidate(t *testing.T) {
	if (ShareSpec{Name: "Media", Volume: "/volume1"}).Validate() != nil {
		t.Fatal("good share refused")
	}
	for _, n := range []string{"", "../x", "a/b", "bad.", " lead", "x;rm"} {
		if (ShareSpec{Name: n, Volume: "v"}).Validate() == nil {
			t.Errorf("share %q accepted", n)
		}
	}
	if ValidFolder("2024/holiday") != nil || ValidFolder("a/../b") == nil || ValidFolder("") == nil || ValidFolder(`a\b`) == nil {
		t.Fatal("folder validation wrong")
	}
}
