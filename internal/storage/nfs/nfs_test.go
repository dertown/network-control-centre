package nfs

import "testing"

func xstr(b []byte, s string) []byte {
	b = be(b, uint32(len(s)))
	b = append(b, s...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func TestParseExports(t *testing.T) {
	var b []byte
	b = be(b, 1)
	b = xstr(b, "/volume1/media")
	b = be(b, 1)
	b = xstr(b, "192.168.1.0/24")
	b = be(b, 1)
	b = xstr(b, "10.0.0.5")
	b = be(b, 0)
	b = be(b, 1)
	b = xstr(b, "/export/open")
	b = be(b, 0)
	b = be(b, 0)
	got, err := ParseExports(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Dir != "/volume1/media" || len(got[0].Groups) != 2 || got[0].Groups[1] != "10.0.0.5" || len(got[1].Groups) != 0 {
		t.Fatalf("%+v", got)
	}
	if _, err := ParseExports(b[:10]); err == nil {
		t.Fatal("truncated reply accepted")
	}
}

func TestParseDump(t *testing.T) {
	b := be(nil, 1, 100003, 3, 6, 2049, 1, 100005, 3, 6, 20048, 0)
	got, err := ParseDump(b)
	if err != nil || len(got) != 2 || got[1].Port != 20048 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestHost(t *testing.T) {
	for in, want := range map[string]string{"nfs://nas.lan": "nas.lan", "192.168.1.5": "192.168.1.5", "nas:/volume1/x": "nas", "nas:2049": "nas"} {
		if got := Host(in); got != want {
			t.Errorf("Host(%q) = %q, want %q", in, got, want)
		}
	}
}
