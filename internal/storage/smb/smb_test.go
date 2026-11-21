package smb

import "testing"

func TestHostPort(t *testing.T) {
	for in, want := range map[string]string{"smb://nas": "nas:445", `\\fileserver\share`: "fileserver:445", "192.168.1.9": "192.168.1.9:445",
		"nas:4445": "nas:4445", "smb://nas:1445/share": "nas:1445"} {
		got, err := HostPort(in)
		if err != nil || got != want {
			t.Errorf("HostPort(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := HostPort(""); err == nil {
		t.Error("empty address accepted")
	}
}
